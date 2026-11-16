"""Database layer: SQLite storage for users, tickets, approvals, one-time codes and the audit log."""
import hashlib
import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "helpdesk.db"
ph = PasswordHasher()
# Used so that logging in with an unknown employee ID takes as long as a wrong password.
DUMMY_HASH = ph.hash("this-is-not-a-real-password")

DEMO_PASSWORD = "Demo@12345!"  # demo accounts only, never reuse a real password

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    employee_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    role TEXT NOT NULL,
    manager_id TEXT,
    password_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tickets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_no TEXT UNIQUE,
    owner_id TEXT NOT NULL,
    category TEXT NOT NULL,
    summary TEXT NOT NULL,
    priority TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS approvals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_no TEXT NOT NULL,
    requester_id TEXT NOT NULL,
    resource TEXT NOT NULL,
    sensitive INTEGER NOT NULL,
    required_approvers TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    decisions TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS reset_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    employee_id TEXT NOT NULL,
    ts TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS otp_codes (
    employee_id TEXT PRIMARY KEY,
    code_hash TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    employee_id TEXT,
    event TEXT NOT NULL,
    detail TEXT NOT NULL
);
"""

DEMO_USERS = [
    ("EMP001", "Asha Nair", "asha.nair@nimbus.example", "employee", "MGR001"),
    ("EMP002", "Ravi Kumar", "ravi.kumar@nimbus.example", "employee", "MGR001"),
    ("MGR001", "Meera Iyer", "meera.iyer@nimbus.example", "manager", None),
    ("ADM001", "Karthik Rao", "karthik.rao@nimbus.example", "it_admin", None),
    ("ADM002", "Divya Menon", "divya.menon@nimbus.example", "it_admin", None),
]


def now():
    return datetime.now(timezone.utc)


def now_iso():
    return now().isoformat(timespec="seconds")


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with get_conn() as c:
        c.executescript(SCHEMA)
        # Older databases: add the columns that approvals now need.
        cols = {r["name"] for r in c.execute("PRAGMA table_info(approvals)")}
        if "reason" not in cols:
            c.execute("ALTER TABLE approvals ADD COLUMN reason TEXT NOT NULL DEFAULT ''")
        if "decisions" not in cols:
            c.execute("ALTER TABLE approvals ADD COLUMN decisions TEXT NOT NULL DEFAULT '{}'")
        existing = {r["employee_id"] for r in c.execute("SELECT employee_id FROM users")}
        missing = [u for u in DEMO_USERS if u[0] not in existing]
        if missing:
            password_hash = ph.hash(DEMO_PASSWORD)
            c.executemany(
                "INSERT INTO users VALUES (?,?,?,?,?,?)",
                [(*u, password_hash) for u in missing],
            )


# ---------- users ----------
def get_user(employee_id):
    with get_conn() as c:
        row = c.execute(
            "SELECT employee_id, name, email, role, manager_id FROM users WHERE employee_id=?",
            (employee_id,),
        ).fetchone()
    return dict(row) if row else None


def verify_login(employee_id, password):
    with get_conn() as c:
        row = c.execute(
            "SELECT password_hash FROM users WHERE employee_id=?", (employee_id,)
        ).fetchone()
    if row is None:
        try:
            ph.verify(DUMMY_HASH, password)  # same work as a real check, so timing reveals nothing
        except (VerificationError, InvalidHashError):
            pass
        return None
    try:
        ph.verify(row["password_hash"], password)
    except (VerificationError, InvalidHashError):
        return None
    return get_user(employee_id)


# ---------- tickets and approvals ----------
def create_ticket(owner_id, category, summary, priority, status):
    with get_conn() as c:
        cur = c.execute(
            "INSERT INTO tickets (ticket_no, owner_id, category, summary, priority, status, created_at)"
            " VALUES (?,?,?,?,?,?,?)",
            (f"TMP-{uuid.uuid4().hex}", owner_id, category, summary, priority, status, now_iso()),
        )
        ticket_no = f"TCK-{1000 + cur.lastrowid}"
        c.execute("UPDATE tickets SET ticket_no=? WHERE id=?", (ticket_no, cur.lastrowid))
    return ticket_no


def get_ticket(ticket_no):
    with get_conn() as c:
        row = c.execute("SELECT * FROM tickets WHERE ticket_no=?", (ticket_no,)).fetchone()
    return dict(row) if row else None


def list_tickets(owner_id=None, limit=100):
    """Tickets for one owner, or every ticket when owner_id is None (admins only)."""
    query = "SELECT ticket_no, owner_id, category, summary, priority, status, created_at FROM tickets"
    args = []
    if owner_id is not None:
        query += " WHERE owner_id=?"
        args.append(owner_id)
    query += " ORDER BY id DESC LIMIT ?"
    args.append(limit)
    with get_conn() as c:
        return [dict(r) for r in c.execute(query, args).fetchall()]


def create_approval(ticket_no, requester_id, resource, sensitive, approvers, reason=""):
    with get_conn() as c:
        c.execute(
            "INSERT INTO approvals (ticket_no, requester_id, resource, sensitive,"
            " required_approvers, status, created_at, reason) VALUES (?,?,?,?,?,?,?,?)",
            (ticket_no, requester_id, resource, int(sensitive), json.dumps(approvers), "pending", now_iso(), reason),
        )


_APPROVAL_SELECT = (
    "SELECT a.*, u.name AS requester_name, u.manager_id AS requester_manager "
    "FROM approvals a JOIN users u ON u.employee_id = a.requester_id"
)


def get_approval(approval_id):
    with get_conn() as c:
        row = c.execute(_APPROVAL_SELECT + " WHERE a.id=?", (approval_id,)).fetchone()
    return dict(row) if row else None


def list_approvals(limit=200):
    with get_conn() as c:
        rows = c.execute(_APPROVAL_SELECT + " ORDER BY a.id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]


def save_decision(approval_id, decisions, status):
    with get_conn() as c:
        c.execute(
            "UPDATE approvals SET decisions=?, status=? WHERE id=?",
            (json.dumps(decisions), status, approval_id),
        )


def set_ticket_status(ticket_no, status):
    with get_conn() as c:
        c.execute("UPDATE tickets SET status=? WHERE ticket_no=?", (status, ticket_no))


def list_audit(limit=100):
    with get_conn() as c:
        rows = c.execute(
            "SELECT id, ts, employee_id, event, detail FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    out = []
    for r in rows:
        try:
            detail = json.loads(r["detail"])
        except (TypeError, ValueError):
            detail = {}
        out.append({"id": r["id"], "ts": r["ts"], "employee_id": r["employee_id"], "event": r["event"], "detail": detail})
    return out


# ---------- password reset: rate limit and one-time codes ----------
def record_reset_request(employee_id):
    with get_conn() as c:
        c.execute(
            "INSERT INTO reset_requests (employee_id, ts) VALUES (?,?)",
            (employee_id, now_iso()),
        )


def count_reset_requests(employee_id, hours=24):
    cutoff = (now() - timedelta(hours=hours)).isoformat(timespec="seconds")
    with get_conn() as c:
        return c.execute(
            "SELECT COUNT(*) FROM reset_requests WHERE employee_id=? AND ts>?",
            (employee_id, cutoff),
        ).fetchone()[0]


def _hash_code(code):
    return hashlib.sha256(code.encode()).hexdigest()


def store_otp(employee_id, code, minutes=5):
    expires = (now() + timedelta(minutes=minutes)).isoformat(timespec="seconds")
    with get_conn() as c:
        c.execute(
            "INSERT OR REPLACE INTO otp_codes (employee_id, code_hash, expires_at, attempts)"
            " VALUES (?,?,?,0)",
            (employee_id, _hash_code(code), expires),
        )


def check_otp(employee_id, code):
    """Returns 'ok', 'invalid', 'locked', 'expired' or 'none'."""
    with get_conn() as c:
        row = c.execute(
            "SELECT * FROM otp_codes WHERE employee_id=?", (employee_id,)
        ).fetchone()
        if row is None:
            return "none"
        if datetime.fromisoformat(row["expires_at"]) < now():
            c.execute("DELETE FROM otp_codes WHERE employee_id=?", (employee_id,))
            return "expired"
        if row["attempts"] >= 3:
            return "locked"
        if row["code_hash"] == _hash_code(code):
            return "ok"
        c.execute(
            "UPDATE otp_codes SET attempts = attempts + 1 WHERE employee_id=?",
            (employee_id,),
        )
        return "invalid"


def clear_otp(employee_id):
    with get_conn() as c:
        c.execute("DELETE FROM otp_codes WHERE employee_id=?", (employee_id,))


# ---------- audit log ----------
def audit(employee_id, event, detail=None):
    with get_conn() as c:
        c.execute(
            "INSERT INTO audit_log (ts, employee_id, event, detail) VALUES (?,?,?,?)",
            (now_iso(), employee_id, event, json.dumps(detail or {})),
        )


if __name__ == "__main__":
    init_db()
    print(f"Database ready at {DB_PATH}")
    for u in DEMO_USERS:
        print(f"  {u[0]}  {u[1]}  ({u[3]})")
    print(f"All demo accounts use the password: {DEMO_PASSWORD}")
