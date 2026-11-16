import re

import pytest

from app import db, policy, tools


@pytest.fixture(autouse=True)
def fresh_db(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "test.db")
    db.init_db()


@pytest.fixture
def asha():
    return db.get_user("EMP001")


@pytest.fixture
def ravi():
    return db.get_user("EMP002")


@pytest.fixture
def admin():
    return db.get_user("ADM001")


def test_unknown_action_is_refused(asha):
    d = policy.evaluate(asha, "delete_user", {"target": "EMP002"})
    assert d.verdict == "refuse" and d.rule == "ACTION_NOT_IN_CATALOGUE"


def test_another_account_cannot_be_named(asha):
    d = policy.evaluate(asha, "reset_password", {"target_account": "EMP002"})
    assert d.verdict == "refuse" and d.rule == "INVALID_PARAMETERS"


def test_reset_without_code_needs_verification(asha):
    d = policy.evaluate(asha, "reset_password", {})
    assert d.verdict == "needs_verification"


def test_wrong_code_is_not_allowed(asha):
    db.store_otp("EMP001", "123456")
    d = policy.evaluate(asha, "reset_password", {"otp": "000000"})
    assert d.verdict != "allow"


def test_correct_code_is_allowed(asha):
    db.store_otp("EMP001", "123456")
    d = policy.evaluate(asha, "reset_password", {"otp": "123456"})
    assert d.verdict == "allow"


def test_code_locks_after_three_wrong_attempts(asha):
    db.store_otp("EMP001", "123456")
    for _ in range(3):
        policy.evaluate(asha, "reset_password", {"otp": "000000"})
    d = policy.evaluate(asha, "reset_password", {"otp": "123456"})
    assert d.verdict != "allow"


def test_reset_rate_limit(asha):
    for _ in range(3):
        db.record_reset_request("EMP001")
    d = policy.evaluate(asha, "reset_password", {})
    assert d.verdict == "refuse" and d.rule == "RESET_RATE_LIMIT"


def test_access_is_never_auto_granted(asha):
    d = policy.evaluate(asha, "request_access", {"resource": "Marketing shared drive", "reason": "Joining the campaign team"})
    assert d.verdict == "needs_approval"
    assert d.details["sensitive"] is False


def test_sensitive_access_needs_extra_approvers(asha):
    d = policy.evaluate(asha, "request_access", {"resource": "Production database", "reason": "Need to debug an issue"})
    assert d.details["sensitive"] is True
    assert "security review" in d.details["approvers"]


def test_only_the_owner_can_see_a_ticket(asha, ravi):
    ticket_no = db.create_ticket("EMP001", "vpn", "VPN keeps dropping", "normal", "open")
    assert policy.evaluate(asha, "check_ticket_status", {"ticket_no": ticket_no}).verdict == "allow"
    assert policy.evaluate(ravi, "check_ticket_status", {"ticket_no": ticket_no}).verdict == "refuse"


def test_admin_can_see_any_ticket(admin):
    ticket_no = db.create_ticket("EMP001", "vpn", "VPN keeps dropping", "normal", "open")
    assert policy.evaluate(admin, "check_ticket_status", {"ticket_no": ticket_no}).verdict == "allow"


def test_phishing_report_creates_a_high_priority_ticket(asha):
    out = tools.run_action(asha, "report_phishing", {"description": "Email asking for my password"})
    assert out["verdict"] == "allow"
    assert db.get_ticket(out["result"]["ticket_no"])["priority"] == "high"


def test_one_time_code_is_never_returned_to_the_caller(asha, capsys):
    out = tools.run_action(asha, "reset_password", {})
    code = re.search(r"\b(\d{6})\b", capsys.readouterr().out).group(1)
    assert code not in str(out)
