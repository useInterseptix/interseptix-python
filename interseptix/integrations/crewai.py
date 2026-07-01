"""
CrewAI integration for Interseptix.

Generic by design — this module does **not** import ``crewai``, so it adds no
dependency and won't break across CrewAI versions. It binds an Interseptix agent
identity around a crew's execution so every tool HTTP call is guarded.

Usage::

    from interseptix import Interseptix
    from interseptix.integrations.crewai import guarded_kickoff

    client = Interseptix(api_key="isx_live_...")
    crew = Crew(agents=[...], tasks=[...])

    result = guarded_kickoff(crew, client, "agt_123", scopes=["read:orders"])
"""

from typing import List, Optional

from . import interseptix_agent


def guarded_kickoff(
    crew,
    client,
    agent_id: str,
    scopes: Optional[List[str]] = None,
    **kickoff_kwargs,
):
    """Run ``crew.kickoff(**kickoff_kwargs)`` under an Interseptix agent context.

    Any HTTP call a CrewAI tool makes during the run is evaluated against the
    agent's scopes and policies, and recorded in the audit ledger.
    """
    with interseptix_agent(client, agent_id, scopes):
        return crew.kickoff(**kickoff_kwargs)


def guard_agent(client, agent_id: str, scopes: Optional[List[str]] = None):
    """Return a context manager binding an Interseptix agent — a thin alias of
    :func:`interseptix.integrations.interseptix_agent` for CrewAI users who want
    to wrap a custom execution block rather than a single ``kickoff``."""
    return interseptix_agent(client, agent_id, scopes)


__all__ = ["guarded_kickoff", "guard_agent"]
