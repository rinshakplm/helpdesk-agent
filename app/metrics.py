"""Dashboard numbers, worked out from the audit log and the tickets table."""
import json
from collections import Counter
from datetime import timedelta

from app import db

AXIS_DAYS = {1: 7, 7: 7, 30: 30, 0: 14}


def _pct(part, whole):
    return round(100 * part / whole, 1) if whole else None


def compute(days=7):
    query = "SELECT ts, event, detail FROM audit_log"
    args = []
    if days:
        query += " WHERE ts >= ?"
        args.append((db.now() - timedelta(days=days)).isoformat(timespec="seconds"))
    query += " ORDER BY id DESC LIMIT 20000"
    with db.get_conn() as c:
        rows = c.execute(query, args).fetchall()

    turns = escalated = grounded = 0
    latencies, per_day, sources = [], Counter(), Counter()
    verdicts, blocked_rules = Counter(), Counter()
    failed_logins = model_errors = rejected_messages = 0

    for r in rows:
        try:
            d = json.loads(r["detail"])
        except (TypeError, ValueError):
            d = {}
        ev = r["event"]
        if ev == "chat_turn":
            turns += 1
            per_day[r["ts"][:10]] += 1
            if any(a.get("action") == "escalate_to_human" and a.get("verdict") == "allow" for a in d.get("actions", [])):
                escalated += 1
            srcs = d.get("sources", [])
            if srcs:
                grounded += 1
            for doc in set(srcs):
                sources[doc] += 1
            if isinstance(d.get("latency_ms"), (int, float)):
                latencies.append(d["latency_ms"])
        elif ev == "action_decision":
            verdicts[d.get("verdict", "unknown")] += 1
            if d.get("verdict") == "refuse":
                blocked_rules[d.get("rule", "unknown")] += 1
        elif ev == "login_failed":
            failed_logins += 1
        elif ev == "model_error":
            model_errors += 1
        elif ev == "message_rejected":
            rejected_messages += 1

    latencies.sort()
    today = db.now().date()
    axis = [(today - timedelta(days=i)).isoformat() for i in reversed(range(AXIS_DAYS.get(days, 7)))]

    with db.get_conn() as c:
        by_status = {r["status"]: r["n"] for r in c.execute("SELECT status, COUNT(*) AS n FROM tickets GROUP BY status")}
        by_priority = {r["priority"]: r["n"] for r in c.execute("SELECT priority, COUNT(*) AS n FROM tickets GROUP BY priority")}
        pending = c.execute("SELECT COUNT(*) FROM approvals WHERE status='pending'").fetchone()[0]

    return {
        "days": days,
        "turns": turns,
        "escalated_turns": escalated,
        "handled_without_person_pct": _pct(turns - escalated, turns),
        "grounded_turns": grounded,
        "grounded_pct": _pct(grounded, turns),
        "avg_latency_ms": round(sum(latencies) / len(latencies)) if latencies else None,
        "p95_latency_ms": latencies[int(0.95 * (len(latencies) - 1))] if latencies else None,
        "per_day": [{"date": d, "count": per_day.get(d, 0)} for d in axis],
        "verdicts": dict(verdicts),
        "blocked_by_rule": [{"rule": k, "count": v} for k, v in blocked_rules.most_common(8)],
        "top_sources": [{"doc_id": k, "count": v} for k, v in sources.most_common(8)],
        "failed_logins": failed_logins,
        "model_errors": model_errors,
        "rejected_messages": rejected_messages,
        "tickets_by_status": by_status,
        "tickets_by_priority": by_priority,
        "pending_approvals": pending,
    }
