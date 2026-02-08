from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from openai import OpenAI

from .tools import default_tools, execute_tool_call, to_openai_tool_schema

SYSTEM_INSTRUCTIONS = (
    "You are a security discovery agent. "
    "Always call the fetch_documentation tool before analysis. "
    "Then build a concise STRIDE threat model from the documentation evidence. "
    "Map threats to MITRE ATT&CK techniques (Enterprise ATT&CK) using technique IDs "
    "(format Txxxx or Txxxx.xxx). "
    "Your final output must be only a JSON array, where each item is an object with keys: "
    "ttp_id, ttp_name, stride, and rationale. "
    "The stride field must be an array of one or more STRIDE categories."
)

DEFAULT_DISCOVERY_PROMPT = (
    "Fetch the documentation and perform threat modeling. "
    "Return only the MITRE ATT&CK TTP list as JSON."
)

THREAT_MODEL_SYSTEM_INSTRUCTIONS = """
you are performing a therat model for the service/app based on the given technical documentation, using STRIDE framework.
be honest and concise.
you must use this threat grammar structure:

[threat source] [prerequisites] can [threat action], which leads to [threat impact], negatively impacting [impacted assets].

Definitions and examples of each threat grammar field are provided below, threat grammar fields should be placed in [] square brackets:
[threat source]: The entity taking action. For example:
    An actor (a useful default).
    An internet-based actor.
    An internal or external actor.
[prerequisites]: Conditions or requirements that must be met for a threat source's action to be viable. For example:
    With access to another user's token.
    Who has administrator access.
    With user permissions.
    If there are no prerequisites, that might be a signal to decompose the threat into several statements. These would include multiple prerequisites for the same threat source.
[threat action]:
The action being performed by the threat source. For example:
    Spoof another user.
    Tamper with data stored in the database.
    Make thousands of concurrent requests.
[threat impact]:
The direct impact of a successful threat action. For example:
    Unauthorized access to the user's bank account information.
    Modifying the username for the all-time high score.
    A web application being unable to handle other user requests.
[impacted assets]:
The assets affected by a successful threat action. For example:
    User banking data.
    Video game high score list.
    The web application.

Sample statements

    An internet-based actor with access to another user's token can spoof another user, which leads to viewing the user's bank account information, negatively impacting user banking data.

    An internal actor who has administrator access can tamper with data stored in the database, which leads to modifying the username for the all-time high score, negatively impacting the video game high score list.

    An internet-based actor with user permissions can make thousands of concurrent requests, which leads to the application being unable to handle other user requests, negatively impacting the web application's responsiveness to valid requests.

When negative impacts to security objectives are known, you can expand your threat statement by adding [impacted goal] of [impacted asset]:
[threat source] [prerequisite] can [threat action], which leads to [threat impact], resulting in reduced [impacted goal] of [impacted asset].

The new threat grammar field is defined with examples below:
[impacted goal]
The information security or business objective that is negatively affected. This is most commonly the CIA triad:
    Confidentiality.
    Integrity.
    Availability.

Advanced sample statement:

An actor with user permissions can make thousands of concurrent requests, which leads to blocking user access to the application, resulting in reduced availability of the web application.
The threat grammar provides a structured but flexible way to record threats. [threat source], [prerequisites], and [threat action] are inputs that help you identify mitigations. [threat impact], [impacted goal], and [impacted assets] help you identify the impact of a given threat, and therefore prioritize the threats you want to mitigate.

Each field is optional provided your statement makes sense. As you think of threats, write down the elements that come to mind or feel important. In subsequent passes, you can fill in more elements.

You may also want to decompose threats into several statements for more specificity.
Here is an example of decomposition.

You might initially describe a threat as just: [threat impact] resulting in reduced [impacted goal] of [impacted asset].
It is fine if you don't know the [threat source], [prerequisite], or [threat action]. You should write the threat down anyway. For example:
Information is disclosed unintentionally from the S3 bucket resulting in reduced confidentiality of user vehicle registration documents.

In a later conversation with your team, you might realize this can be decomposed into two sub-threats:
    An actor with access to inspect traffic between the user and the S3 endpoint can view data-in-transit, resulting in reduced confidentiality of user vehicle registration documents.
    An internal actor can access the data stored in S3, resulting in reduced confidentiality of user vehicle registration documents.
""".strip()

DEFAULT_THREAT_MODEL_PROMPT = (
    "Fetch the technical documentation and produce concise STRIDE-based threat statements "
    "using the required threat grammar."
)


@dataclass(frozen=True)
class FunctionCall:
    name: str
    arguments: str
    call_id: str


def _get_field(obj: object, key: str, default: object | None = None) -> object | None:
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _response_id(response: object) -> str | None:
    candidate = _get_field(response, "id")
    if isinstance(candidate, str) and candidate:
        return candidate
    return None


def _extract_function_calls(response: object) -> list[FunctionCall]:
    output = _get_field(response, "output", [])
    if not isinstance(output, list):
        return []

    function_calls: list[FunctionCall] = []
    for item in output:
        if _get_field(item, "type") != "function_call":
            continue
        name = _get_field(item, "name", "")
        arguments = _get_field(item, "arguments", "{}")
        call_id = _get_field(item, "call_id", "")
        if isinstance(name, str) and isinstance(arguments, str) and isinstance(call_id, str) and call_id:
            function_calls.append(FunctionCall(name=name, arguments=arguments, call_id=call_id))
    return function_calls


def _extract_output_text(response: object) -> str:
    output_text = _get_field(response, "output_text")
    if isinstance(output_text, str) and output_text.strip():
        return output_text

    output = _get_field(response, "output", [])
    if not isinstance(output, list):
        return ""

    text_chunks: list[str] = []
    for item in output:
        if _get_field(item, "type") != "message":
            continue
        content = _get_field(item, "content", [])
        if not isinstance(content, list):
            continue
        for part in content:
            if _get_field(part, "type") not in {"output_text", "text"}:
                continue
            text = _get_field(part, "text", "")
            if isinstance(text, str):
                text_chunks.append(text)

    return "\n".join(text_chunks).strip()


class DiscoveryAgent:
    def __init__(
        self,
        docs_url: str,
        model: str = "gpt-5.2",
        instructions: str = SYSTEM_INSTRUCTIONS,
        client: OpenAI | None = None,
    ) -> None:
        self.docs_url = docs_url
        self.model = model
        self.instructions = instructions
        self.client = client or OpenAI()
        self.tools = default_tools(docs_url=docs_url)
        self._tool_schemas = to_openai_tool_schema(self.tools)
        self._previous_response_id: str | None = None

    def reset(self) -> None:
        self._previous_response_id = None

    def ask(self, user_input: str) -> str:
        response = self._create_response(
            input_data=user_input,
            previous_response_id=self._previous_response_id,
        )

        while True:
            function_calls = _extract_function_calls(response)
            if not function_calls:
                self._previous_response_id = _response_id(response)
                answer = _extract_output_text(response)
                return answer if answer else "[]"

            tool_outputs: list[dict[str, str]] = []
            for call in function_calls:
                tool_result = execute_tool_call(
                    tools=self.tools,
                    name=call.name,
                    arguments=call.arguments,
                )
                tool_outputs.append(
                    {
                        "type": "function_call_output",
                        "call_id": call.call_id,
                        "output": tool_result,
                    }
                )

            response = self._create_response(
                input_data=tool_outputs,
                previous_response_id=_response_id(response),
            )

    def discover_ttps(self, app_name: str | None = None) -> str:
        if app_name:
            prompt = (
                f"{DEFAULT_DISCOVERY_PROMPT} "
                f"Application name: {app_name}. "
                "Focus on practical attacker behavior and likely abuse paths."
            )
            return self.ask(prompt)
        return self.ask(DEFAULT_DISCOVERY_PROMPT)

    def _create_response(
        self,
        input_data: str | list[dict[str, str]],
        previous_response_id: str | None,
    ) -> Any:
        request_payload: dict[str, object] = {
            "model": self.model,
            "instructions": self.instructions,
            "input": input_data,
            "tools": self._tool_schemas,
        }
        if previous_response_id is not None:
            request_payload["previous_response_id"] = previous_response_id
        return self.client.responses.create(**request_payload)


class ThreatModelAgent(DiscoveryAgent):
    def __init__(
        self,
        docs_url: str,
        model: str = "gpt-5.2",
        instructions: str = THREAT_MODEL_SYSTEM_INSTRUCTIONS,
        client: OpenAI | None = None,
    ) -> None:
        super().__init__(
            docs_url=docs_url,
            model=model,
            instructions=instructions,
            client=client,
        )

    def model_threats(self, app_name: str | None = None) -> str:
        if app_name:
            prompt = (
                f"{DEFAULT_THREAT_MODEL_PROMPT} "
                f"Application name: {app_name}. "
                "Focus on realistic abuse paths and practical impacts."
            )
            return self.ask(prompt)
        return self.ask(DEFAULT_THREAT_MODEL_PROMPT)
