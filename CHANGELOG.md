# Changelog

## 0.3.0

### Added
- **Framework integrations** (`interseptix.integrations`):
  - `interseptix_agent(client, agent_id, scopes=...)` — a context manager that
    binds an agent identity to the current thread. Every HTTP call inside the
    block is evaluated and audited under that agent.
  - `interseptix.integrations.crewai.guarded_kickoff(...)` / `guard_agent(...)`
    for running a CrewAI crew under an agent context. Generic — no `crewai`
    dependency.

### Changed
- **Local scope evaluation now supports verb wildcards.** In addition to
  `*:resource` and `*:*`, a scope like `write:*` now grants that verb on any
  resource, matching the server-side and Node SDK logic. If you relied on
  `write:*` being ignored, review your agent scopes before upgrading.
- Diagnostics now go through the `interseptix.sdk` logger instead of `print()`.
- Rules-refresh failures back off exponentially (up to 5 minutes) instead of
  retrying on a fixed interval.

### Notes
- This release changes local enforcement behavior (verb wildcards), so it is a
  minor version bump rather than a patch. Pin `interseptix==0.2.2` if you need
  the previous scope semantics.
