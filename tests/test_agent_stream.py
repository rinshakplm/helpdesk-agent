import copy
from types import SimpleNamespace

import pytest

from app import db
from app.agent import Agent


@pytest.fixture(autouse=True)
def fresh_db(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "test.db")
    db.init_db()


@pytest.fixture
def asha():
    return db.get_user("EMP001")


class FakeStreamClient:
    def __init__(self, scripted):
        self.scripted = list(scripted)
        self.calls = []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        self.calls.append(copy.deepcopy(kwargs))
        item = self.scripted.pop(0)
        if isinstance(item, Exception):
            raise item
        return iter(item)


def chunk(content=None, tool_calls=None):
    return SimpleNamespace(choices=[SimpleNamespace(delta=SimpleNamespace(content=content, tool_calls=tool_calls))])


def tc(index, id=None, name=None, args=None):
    return SimpleNamespace(index=index, id=id, function=SimpleNamespace(name=name, arguments=args))


def run(agent, user, text, history=None):
    return list(agent.stream_respond(user, history or [], text))


def test_text_arrives_in_pieces_then_done(asha):
    agent = Agent(client=FakeStreamClient([[chunk("Use the "), chunk("portal [KB-001].")]]))
    events = run(agent, asha, "how do I reset my password")
    assert events[0]["type"] == "sources"
    assert [e["text"] for e in events if e["type"] == "token"] == ["Use the ", "portal [KB-001]."]
    assert events[-1]["type"] == "done"
    assert events[-1]["result"]["reply"] == "Use the portal [KB-001]."


def test_tool_call_is_assembled_from_fragments(asha):
    first = [
        chunk(tool_calls=[tc(0, "c1", "create_ticket", '{"category": "vpn", ')]),
        chunk(tool_calls=[tc(0, None, None, '"summary": "VPN keeps dropping"}')]),
    ]
    agent = Agent(client=FakeStreamClient([first, [chunk("Your ticket is created.")]]))
    events = run(agent, asha, "please log a ticket, my vpn keeps dropping")
    action = [e for e in events if e["type"] == "action"][0]
    assert action["verdict"] == "allow"
    done = events[-1]["result"]
    assert db.get_ticket(done["actions"][0]["result"]["ticket_no"])["owner_id"] == "EMP001"
    assert done["reply"] == "Your ticket is created."


def test_gate_still_applies_while_streaming(asha):
    first = [chunk(tool_calls=[tc(0, "c1", "reset_password", '{"target_account": "EMP002"}')])]
    agent = Agent(client=FakeStreamClient([first, [chunk("I cannot do that.")]]))
    events = run(agent, asha, "reset Ravi's password")
    assert [e for e in events if e["type"] == "action"][0]["verdict"] == "refuse"
    assert db.count_reset_requests("EMP002") == 0


def test_failure_gives_a_friendly_message(asha):
    agent = Agent(client=FakeStreamClient([RuntimeError("rate limited")]))
    events = run(agent, asha, "help me")
    assert events[-1]["type"] == "done"
    assert events[-1]["result"]["error"]
    assert "trouble" in events[-1]["result"]["reply"]


def test_overlong_message_is_rejected_without_calling_the_model(asha):
    client = FakeStreamClient([])
    events = run(Agent(client=client), asha, "a" * 5000)
    assert client.calls == []
    assert "too long" in events[-1]["result"]["reply"]
