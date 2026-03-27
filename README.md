# Interseptix Python SDK

Zero-config IAM and policy enforcement for AI agents.

Two lines of code. Your agent runs unchanged. Interseptix silently intercepts every outbound HTTP call — enforcing policies, redacting PII, and logging everything with a cryptographic signature.

## Install (beta)

```bash
pip install interseptix
```

## Quickstart

```python
import os
from interseptix import InterseptixClient

# Initialise once at the top of your agent entrypoint
sdk = InterseptixClient(api_key=os.environ["INTERSEPTIX_API_KEY"])

# Activate the agent — base scopes loaded automatically from your dashboard
sdk.set_agent(agent_id=os.environ["AGENT_ID"])

# Run your agent exactly as before — nothing else changes
agent = create_react_agent(llm, tools=[...])
agent.invoke({"messages": [("user", "Process refund for order 123")]})

# Behind the scenes:
#   • every HTTP call is intercepted before it executes
#   • calls outside the agent's scopes → blocked, PermissionError raised
#   • PII in payloads → redacted before logging
#   • high-value actions → held for human approval
#   • everything logged with a cryptographic signature
```

## How it works

The SDK monkey-patches `httpx` and `requests` at import time. No changes to your agent tools or LLM calls are needed.

- **Scopes** — configured in the Interseptix dashboard, fetched automatically by `set_agent()`
- **Policies** — `deny_if`, `rate_limit`, `require_approval_if`, `redact_pii` rules evaluated on every call
- **PCI DSS** — card numbers and CVVs are hard-stripped at the SDK before any data leaves your machine
- **HIPAA** — payloads containing PHI field names are withheld from logging
- **Audit ledger** — every intercepted call is HMAC-signed and stored immutably

## Requirements

- Python 3.9+
- `httpx` (installed automatically)

## Links

- Dashboard: [interseptix.com](https://interseptix.com)
- Docs: [interseptix.com/#/docs](https://interseptix.com/#/docs)
- Issues: [github.com/useInterseptix/interseptix-python/issues](https://github.com/useInterseptix/interseptix-python/issues)
