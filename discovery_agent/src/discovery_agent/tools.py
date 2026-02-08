from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen


@dataclass(frozen=True)
class ToolDefinition:
    name: str
    description: str
    parameters: dict[str, Any]
    handler: Callable[[dict[str, Any]], dict[str, Any]]


class ToolError(Exception):
    """Raised when a tool call is malformed."""


class _HTMLTextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._parts: list[str] = []
        self._in_title = False
        self.title = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        del attrs
        if tag.lower() == "title":
            self._in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        text = data.strip()
        if not text:
            return
        self._parts.append(text)
        if self._in_title and not self.title:
            self.title = text

    def plain_text(self) -> str:
        return re.sub(r"\s+", " ", " ".join(self._parts)).strip()


def _fetch_documentation_handler(docs_url: str) -> Callable[[dict[str, Any]], dict[str, Any]]:
    def _handler(_args: dict[str, Any]) -> dict[str, Any]:
        request = Request(
            docs_url,
            headers={
                "User-Agent": "discovery-agent/0.1 (+https://localhost)",
                "Accept": "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.8",
            },
        )
        try:
            with urlopen(request, timeout=20) as response:
                raw = response.read(500_000)
                content_type = response.headers.get("Content-Type", "")
        except URLError as exc:
            raise ToolError(f"failed to fetch documentation URL: {exc}") from exc

        decoded = raw.decode("utf-8", errors="ignore")
        parser = _HTMLTextExtractor()
        parser.feed(decoded)
        text = parser.plain_text()

        max_chars = 20_000
        truncated = len(text) > max_chars
        excerpt = text[:max_chars]

        return {
            "url": docs_url,
            "content_type": content_type,
            "title": parser.title,
            "content": excerpt,
            "content_length": len(text),
            "truncated": truncated,
        }

    return _handler


def default_tools(docs_url: str) -> dict[str, ToolDefinition]:
    return {
        "fetch_documentation": ToolDefinition(
            name="fetch_documentation",
            description=(
                "Fetch the predefined application documentation page. "
                "Use this before creating the threat model."
            ),
            parameters={
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
            handler=_fetch_documentation_handler(docs_url),
        ),
    }


def to_openai_tool_schema(tools: dict[str, ToolDefinition]) -> list[dict[str, Any]]:
    schemas: list[dict[str, Any]] = []
    for tool in tools.values():
        schemas.append(
            {
                "type": "function",
                "name": tool.name,
                "description": tool.description,
                "parameters": tool.parameters,
                "strict": True,
            }
        )
    return schemas


def execute_tool_call(tools: dict[str, ToolDefinition], name: str, arguments: str) -> str:
    tool = tools.get(name)
    if tool is None:
        return json.dumps({"error": f"unknown tool: {name}"})

    try:
        parsed = json.loads(arguments)
    except json.JSONDecodeError:
        return json.dumps({"error": "tool arguments are not valid JSON"})

    if not isinstance(parsed, dict):
        return json.dumps({"error": "tool arguments must be a JSON object"})

    try:
        result = tool.handler(parsed)
    except ToolError as exc:
        return json.dumps({"error": str(exc)})

    return json.dumps(result)
