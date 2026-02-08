from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

if __package__ in {None, ""}:
    # Allow direct execution: `python src/discovery_agent/cli.py`.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from discovery_agent.agent import DiscoveryAgent, ThreatModelAgent
else:
    from .agent import DiscoveryAgent, ThreatModelAgent


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run discovery or threat-model agent against app documentation."
    )
    parser.add_argument(
        "--agent",
        choices=("discovery", "threat-model"),
        default=os.environ.get("DISCOVERY_AGENT_TYPE", "discovery"),
        help=(
            "Agent type to run: discovery (STRIDE->MITRE TTP JSON) or "
            "threat-model (structured STRIDE threat statements). "
            "Default: DISCOVERY_AGENT_TYPE env var or discovery."
        ),
    )
    parser.add_argument(
        "--docs-url",
        default=os.environ.get("DISCOVERY_DOCS_URL"),
        help="Documentation URL to fetch (default: DISCOVERY_DOCS_URL env var).",
    )
    parser.add_argument(
        "--model",
        default=os.environ.get("OPENAI_MODEL", "gpt-5.2"),
        help="OpenAI model name (default: OPENAI_MODEL env var or gpt-5.2).",
    )
    parser.add_argument(
        "--app-name",
        default=None,
        help="Optional app name to include in analysis context.",
    )
    parser.add_argument(
        "--prompt",
        default=None,
        help=(
            "Optional custom prompt. If omitted, default STRIDE-to-MITRE discovery prompt is used."
        ),
    )
    return parser


def _require_api_key() -> None:
    if os.environ.get("OPENAI_API_KEY"):
        return
    raise SystemExit("OPENAI_API_KEY is not set. Export it first.")


def _require_docs_url(docs_url: str | None) -> str:
    if isinstance(docs_url, str) and docs_url.strip():
        return docs_url.strip()
    raise SystemExit("Documentation URL missing. Set --docs-url or DISCOVERY_DOCS_URL.")


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    _require_api_key()
    docs_url = _require_docs_url(args.docs_url)

    try:
        if args.agent == "threat-model":
            agent = ThreatModelAgent(
                docs_url=docs_url,
                model=args.model,
            )
            if isinstance(args.prompt, str):
                output = agent.ask(args.prompt)
            else:
                output = agent.model_threats(app_name=args.app_name)
        else:
            agent = DiscoveryAgent(
                docs_url=docs_url,
                model=args.model,
            )
            if isinstance(args.prompt, str):
                output = agent.ask(args.prompt)
            else:
                output = agent.discover_ttps(app_name=args.app_name)
    except Exception as exc:
        raise SystemExit(f"error: {exc}") from exc

    print(output)


if __name__ == "__main__":
    main()
