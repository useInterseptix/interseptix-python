"""
Framework integrations for the Interseptix SDK.

The core primitive here is :func:`interseptix_agent`, a context manager that
binds an agent identity to the current thread. Because the SDK patches
``httpx``/``requests`` globally, every HTTP call made inside the ``with`` block
is attributed, evaluated, and audited under that agent — no matter how deep in
framework code it originates.

Framework-specific conveniences (CrewAI, etc.) build on this primitive.
"""

from contextlib import contextmanager
from typing import Iterator, List, Optional

from interseptix import _ctx


@contextmanager
def interseptix_agent(
    client,
    agent_id: str,
    scopes: Optional[List[str]] = None,
    *,
    fetch_scopes: bool = True,
) -> Iterator:
    """Bind ``agent_id`` to the current thread for the duration of the block.

    Args:
        client: An :class:`interseptix.Interseptix` instance.
        agent_id: The agent passport id (``agt_...``).
        scopes: Extra scopes to grant on top of the agent's dashboard config.
        fetch_scopes: When True (default), fetch the agent's effective scopes
            from the control plane via ``client.set_agent``. Set False to bind
            using only the explicitly provided ``scopes`` (no network call).

    The previous thread context is restored on exit, so nested blocks and
    concurrent agents behave correctly.
    """
    ctx = _ctx()
    prev_agent, prev_scopes = ctx.agent_id, list(ctx.scopes)
    try:
        if fetch_scopes:
            client.set_agent(agent_id, scopes=scopes)
        else:
            ctx.agent_id = agent_id
            ctx.scopes = list(scopes or [])
        yield client
    finally:
        ctx.agent_id = prev_agent
        ctx.scopes = prev_scopes


__all__ = ["interseptix_agent"]
