import json
import sqlite3

import pytest
from fastapi.testclient import TestClient

from app import approvals, db, main, metrics, tools

SECRET = "x" * 48


@pytest.fixture(autouse=True)
def fresh(tmp_path, monkeypatch):
    monkeypatch.setenv("JWT_SECRET", SECRET)
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "test.db")
    db.init_db()


@pytest.fixture
def client():
    return TestClient(main.create_app(agent=object()))


def user(emp):
    return db.get_user(emp)


def request_access(emp, resource, reason="Need it for my project"):
    out = tools.run_action(user(emp), "request_access", {"resource": resource, "reason": reason})
    return db.list_approvals()[0]["id"], out["result"]["ticket_no"]


def header(client, emp):
    r = client.post("/api/login", json={"employee_id": emp, "password": db.DEMO_PASSWORD})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def decide(emp, approval_id, step, decision="approve", note=""):
    return approvals.decide(user(emp), approval_id, step, decision, note)


def test_reason_is_stored_with_the_request():
    approval_id, _ = request_access("EMP001", "Marketing shared drive", "Joining the campaign team")
    assert db.get_approval(approval_id)["reason"] == "Joining the campaign team"


def test_standard_request_needs_only_the_line_manager():
    approval_id, ticket_no = request_access("EMP001", "Marketing shared drive")
    result = decide("MGR001", approval_id, "line manager")
    assert result["status"] == "approved"
    assert db.get_ticket(ticket_no)["status"] == "approved"


def test_admin_steps_open_only_after_the_line_manager_approves():
    approval_id, _ = request_access("EMP001", "Production database")
    with pytest.raises(approvals.ApprovalError) as e:
        decide("ADM001", approval_id, "system owner")
    assert "opens after" in e.value.message


def test_sensitive_request_needs_three_different_people():
    approval_id, ticket_no = request_access("EMP001", "Production database")
    decide("MGR001", approval_id, "line manager")
    decide("ADM001", approval_id, "system owner")
    with pytest.raises(approvals.ApprovalError) as e:
        decide("ADM001", approval_id, "security review")  # same person again
    assert "more than one step" in e.value.message
    assert db.get_approval(approval_id)["status"] == "pending"
    result = decide("ADM002", approval_id, "security review")
    assert result["status"] == "approved"
    assert db.get_ticket(ticket_no)["status"] == "approved"


def test_a_rejection_ends_the_request():
    approval_id, ticket_no = request_access("EMP001", "Marketing shared drive")
    assert decide("MGR001", approval_id, "line manager", "reject", "Not needed")["status"] == "rejected"
    assert db.get_ticket(ticket_no)["status"] == "rejected"
    with pytest.raises(approvals.ApprovalError) as e:
        decide("MGR001", approval_id, "line manager")
    assert "already been decided" in e.value.message


def test_nobody_can_decide_their_own_request():
    with db.get_conn() as c:
        c.execute("UPDATE users SET manager_id='MGR001' WHERE employee_id='ADM001'")
    approval_id, _ = request_access("ADM001", "Production database")
    decide("MGR001", approval_id, "line manager")
    with pytest.raises(approvals.ApprovalError) as e:
        decide("ADM001", approval_id, "system owner")
    assert "your own request" in e.value.message


def test_only_the_requesters_own_manager_can_approve():
    with db.get_conn() as c:
        c.execute("INSERT INTO users VALUES ('MGR002','Other Manager','o@nimbus.example','manager',NULL,'x')")
    approval_id, _ = request_access("EMP001", "Marketing shared drive")
    with pytest.raises(approvals.ApprovalError) as e:
        decide("MGR002", approval_id, "line manager")
    assert e.value.status_code == 404  # not even visible to them


def test_employees_cannot_use_approval_endpoints(client):
    h = header(client, "EMP001")
    assert client.get("/api/approvals", headers=h).status_code == 403
    assert client.post("/api/approvals/1/decision", json={"step": "line manager", "decision": "approve"}, headers=h).status_code == 403


def test_manager_sees_only_their_teams_requests(client):
    with db.get_conn() as c:
        c.execute("INSERT INTO users VALUES ('MGR002','Other Manager','o@nimbus.example','manager',NULL,'x')")
    request_access("EMP001", "Marketing shared drive")
    assert client.get("/api/approvals", headers=header(client, "MGR001")).json()["waiting_count"] == 1
    # MGR002 has a valid user row but no login of their own, so check through the module instead
    mgr2 = db.get_user("MGR002")
    assert [a for a in db.list_approvals() if approvals.visible_to(mgr2, a)] == []


def test_decision_through_the_api(client):
    approval_id, _ = request_access("EMP001", "Marketing shared drive")
    r = client.post(f"/api/approvals/{approval_id}/decision",
                    json={"step": "line manager", "decision": "approve", "note": "Fine"}, headers=header(client, "MGR001"))
    assert r.status_code == 200 and r.json()["status"] == "approved"
    again = client.post(f"/api/approvals/{approval_id}/decision",
                        json={"step": "line manager", "decision": "approve"}, headers=header(client, "MGR001"))
    assert again.status_code == 403


def test_decisions_are_written_to_the_audit_log():
    approval_id, _ = request_access("EMP001", "Marketing shared drive")
    decide("MGR001", approval_id, "line manager")
    assert any(e["event"] == "approval_decision" and e["detail"]["decision"] == "approved" for e in db.list_audit())


def test_dashboard_and_audit_are_admin_only(client):
    for emp in ("EMP001", "MGR001"):
        h = header(client, emp)
        assert client.get("/api/admin/metrics", headers=h).status_code == 403
        assert client.get("/api/admin/audit", headers=h).status_code == 403
    h = header(client, "ADM001")
    assert client.get("/api/admin/metrics", headers=h).status_code == 200
    assert client.get("/api/admin/audit", headers=h).status_code == 200


def test_metrics_are_calculated_from_the_audit_log():
    asha = user("EMP001")
    db.audit("EMP001", "chat_turn", {"message": "a", "sources": ["KB-001"], "actions": [], "latency_ms": 1000})
    db.audit("EMP001", "chat_turn", {"message": "b", "sources": [], "actions": [{"action": "escalate_to_human", "verdict": "allow", "rule": "X"}], "latency_ms": 3000})
    db.audit("EMP001", "chat_turn", {"message": "c", "sources": ["KB-001", "KB-003"], "actions": [], "latency_ms": 2000})
    db.audit("EMP001", "action_decision", {"action": "reset_password", "verdict": "refuse", "rule": "INVALID_PARAMETERS"})
    db.audit("EMP001", "action_decision", {"action": "create_ticket", "verdict": "allow", "rule": "ALWAYS_ALLOWED"})
    m = metrics.compute(7)
    assert m["turns"] == 3 and m["escalated_turns"] == 1
    assert m["handled_without_person_pct"] == 66.7
    assert m["grounded_pct"] == 66.7
    assert m["avg_latency_ms"] == 2000
    assert m["verdicts"] == {"refuse": 1, "allow": 1}
    assert m["top_sources"][0] == {"doc_id": "KB-001", "count": 2}
    assert m["blocked_by_rule"] == [{"rule": "INVALID_PARAMETERS", "count": 1}]
    assert sum(d["count"] for d in m["per_day"]) == 3


def test_metrics_with_no_data_do_not_crash():
    m = metrics.compute(7)
    assert m["turns"] == 0 and m["handled_without_person_pct"] is None and m["avg_latency_ms"] is None


def test_admin_can_update_a_ticket_but_not_one_under_approval(client):
    t1 = db.create_ticket("EMP001", "vpn", "VPN issue here", "normal", "open")
    h = header(client, "ADM001")
    assert client.patch(f"/api/admin/tickets/{t1}", json={"status": "in_progress"}, headers=h).status_code == 200
    assert db.get_ticket(t1)["status"] == "in_progress"
    _, t2 = request_access("EMP001", "Marketing shared drive")
    assert client.patch(f"/api/admin/tickets/{t2}", json={"status": "resolved"}, headers=h).status_code == 409
    assert client.patch(f"/api/admin/tickets/{t1}", json={"status": "resolved"}, headers=header(client, "EMP001")).status_code == 403
    assert client.patch(f"/api/admin/tickets/{t1}", json={"status": "deleted"}, headers=h).status_code == 422


def test_old_databases_are_upgraded(tmp_path, monkeypatch):
    old = tmp_path / "old.db"
    con = sqlite3.connect(old)
    con.executescript("""
        CREATE TABLE approvals (id INTEGER PRIMARY KEY AUTOINCREMENT, ticket_no TEXT NOT NULL, requester_id TEXT NOT NULL,
          resource TEXT NOT NULL, sensitive INTEGER NOT NULL, required_approvers TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL);
    """)
    con.commit(); con.close()
    monkeypatch.setattr(db, "DB_PATH", old)
    db.init_db()
    with db.get_conn() as c:
        cols = {r["name"] for r in c.execute("PRAGMA table_info(approvals)")}
        users = c.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    assert {"reason", "decisions"} <= cols and users == len(db.DEMO_USERS)


def test_metrics_accept_every_period_the_dashboard_offers(client):
    h = header(client, "ADM001")
    for days in (0, 1, 7, 30):
        assert client.get(f"/api/admin/metrics?days={days}", headers=h).status_code == 200
    assert client.get("/api/admin/metrics?days=5", headers=h).status_code == 422


def test_daily_message_cap_protects_the_shared_key(monkeypatch):
    monkeypatch.setattr(main, "DAILY_CHAT_CAP", 2)

    class Quiet:
        def stream_respond(self, user, history, text):
            yield {"type": "done", "result": {"reply": "ok", "error": None}}

    c = TestClient(main.create_app(agent=Quiet()))
    h = header(c, "EMP001")
    codes = [c.post("/api/chat", json={"message": "hi"}, headers=h).status_code for _ in range(3)]
    assert codes == [200, 200, 429]
