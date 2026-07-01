"""Tests for the framework integration helpers.

These avoid any real network or framework dependency by using a fake client
whose ``set_agent`` simply mutates the thread-local context — exactly what the
real client does after fetching effective scopes.
"""

from interseptix import _ctx
from interseptix.integrations import interseptix_agent
from interseptix.integrations.crewai import guarded_kickoff, guard_agent


class FakeClient:
    """Stand-in for interseptix.Interseptix — sets thread context like set_agent does."""

    def __init__(self):
        self.calls = []

    def set_agent(self, agent_id, scopes=None):
        self.calls.append((agent_id, scopes))
        c = _ctx()
        c.agent_id = agent_id
        c.scopes = list(scopes or [])


def _reset_ctx():
    c = _ctx()
    c.agent_id = None
    c.scopes = []


def test_context_is_set_inside_and_restored_after():
    _reset_ctx()
    client = FakeClient()
    with interseptix_agent(client, "agt_1", ["read:orders"]):
        assert _ctx().agent_id == "agt_1"
        assert _ctx().scopes == ["read:orders"]
    assert _ctx().agent_id is None
    assert _ctx().scopes == []
    assert client.calls == [("agt_1", ["read:orders"])]


def test_context_restores_previous_agent_when_nested():
    _reset_ctx()
    client = FakeClient()
    with interseptix_agent(client, "agt_outer", ["read:a"]):
        with interseptix_agent(client, "agt_inner", ["read:b"]):
            assert _ctx().agent_id == "agt_inner"
        # inner block exited — outer must be restored
        assert _ctx().agent_id == "agt_outer"
        assert _ctx().scopes == ["read:a"]
    assert _ctx().agent_id is None


def test_fetch_scopes_false_skips_client_call():
    _reset_ctx()
    client = FakeClient()
    with interseptix_agent(client, "agt_1", ["write:x"], fetch_scopes=False):
        assert _ctx().agent_id == "agt_1"
        assert _ctx().scopes == ["write:x"]
    assert client.calls == []  # no network path taken


def test_context_restored_even_on_exception():
    _reset_ctx()
    client = FakeClient()
    try:
        with interseptix_agent(client, "agt_1", [], fetch_scopes=False):
            raise ValueError("boom")
    except ValueError:
        pass
    assert _ctx().agent_id is None


def test_guarded_kickoff_runs_crew_in_context():
    _reset_ctx()
    seen = {}

    class FakeCrew:
        def kickoff(self, **kwargs):
            seen["agent_id"] = _ctx().agent_id
            seen["kwargs"] = kwargs
            return "crew-result"

    result = guarded_kickoff(FakeCrew(), FakeClient(), "agt_9", ["write:y"], inputs={"q": 1})
    assert result == "crew-result"
    assert seen["agent_id"] == "agt_9"
    assert seen["kwargs"] == {"inputs": {"q": 1}}
    assert _ctx().agent_id is None  # restored after kickoff


def test_guard_agent_returns_context_manager():
    _reset_ctx()
    with guard_agent(FakeClient(), "agt_5", ["read:z"]):
        assert _ctx().agent_id == "agt_5"
    assert _ctx().agent_id is None
