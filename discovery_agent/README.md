# Discovery Agent (STRIDE + MITRE ATT&CK)

Specialized agent that:
- fetches a predefined documentation URL via tool call
- performs STRIDE threat modeling from that evidence
- outputs MITRE ATT&CK TTPs as JSON

## Output format

The final output is a JSON array:

```json
[
  {
    "ttp_id": "T1190",
    "ttp_name": "Exploit Public-Facing Application",
    "stride": ["Tampering", "Elevation of Privilege"],
    "rationale": "Documentation shows externally reachable API surface and weak input handling."
  }
]
```

## Setup

```bash
cd DNR/discovery_agent
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Set environment:

```bash
export OPENAI_API_KEY="<your-key>"
export OPENAI_MODEL="gpt-5.2"
export DISCOVERY_DOCS_URL="https://docs.example.com"
```

## Run

Default flow:

```bash
discovery-agent
```

Add optional app context:

```bash
discovery-agent --app-name "Payments API"
```

Custom prompt:

```bash
discovery-agent --prompt "Fetch docs and return top 10 ATT&CK TTPs as JSON."
```

## Files

```text
discovery_agent/
├── pyproject.toml
├── requirements.txt
├── requirements-dev.txt
└── src/discovery_agent/
    ├── __init__.py
    ├── __main__.py
    ├── agent.py
    ├── cli.py
    └── tools.py
```
