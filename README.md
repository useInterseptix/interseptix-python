# Interseptix Python SDK

Zero-config IAM and policy enforcement for AI agents.

Two lines of code. Your agent runs unchanged. Interseptix intercepts every outbound HTTP call — enforcing policies, redacting PII, and logging everything with a cryptographic signature.

## Install

```bash
pip install interseptix
```

## Quickstart

```python
import os
from interseptix import InterseptixClient

sdk = InterseptixClient(api_key=os.environ["INTERSEPTIX_API_KEY"])
sdk.set_agent(agent_id=os.environ["AGENT_ID"])

# Run your agent exactly as before — nothing else changes
agent = create_react_agent(llm, tools=[...])
agent.invoke({"messages": [("user", "Process refund for order 123")]})
```

That's it. Scopes and policies are configured in your [dashboard](https://interseptix.com) and enforced automatically on every call your agent makes.

## What happens behind the scenes

Every HTTP call your agent makes is intercepted before it executes:

- **Out of scope** → blocked, `PermissionError` raised
- **Matches a deny rule** → blocked
- **Exceeds rate limit** → blocked
- **Requires human approval** → held in queue
- **Contains PII** → redacted before logging
- **Everything** → logged with a cryptographic signature

## Environment variables

| Variable | Description |
|---|---|
| `INTERSEPTIX_API_KEY` | Your org API key from the dashboard |
| `AGENT_ID` | The agent's ID issued on registration |
| `INTERSEPTIX_BASE_URL` | Override API URL (default: `https://interseptix.com/v1`) |

## Requirements

- Python 3.9+
- `httpx` (installed automatically)

## Links

- Dashboard: [interseptix.com](https://interseptix.com)
- Issues: [github.com/useInterseptix/interseptix-python/issues](https://github.com/useInterseptix/interseptix-python/issues)
