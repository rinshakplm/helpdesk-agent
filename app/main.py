"""FastAPI backend: login, streaming chat and tickets.

Run with:  uvicorn app.main:app --reload
"""
import json
import os
import threading
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app import approvals, auth, db, metrics

LOGIN_MAX_FAILURES = 5
LOGIN_WINDOW_SECONDS = 15 * 60
CHAT_LIMIT = 20
CHAT_WINDOW_SECONDS = 60
DAILY_CHAT_CAP = int(os.getenv("DAILY_CHAT_CAP", "300"))  # total messages per day, protects the shared API key
MAX_SESSIONS = 1000
MAX_HISTORY_MESSAGES = 20
STATIC_DIR = Path(__file__).resolve().parent.parent / "static"

bearer = HTTPBearer(auto_error=False)


class SlidingWindow:
    """Allow at most `limit` events per `seconds` for each key. Kept in memory (fine for one server)."""

    def __init__(self, limit, seconds):
        self.limit = limit
        self.seconds = seconds
        self.events = defaultdict(deque)
        self.lock = threading.Lock()

    def _trim(self, key, now):
        q = self.events[key]
        while q and q[0] <= now - self.seconds:
            q.popleft()
        return q

    def is_blocked(self, key):
        with self.lock:
            return len(self._trim(key, time.time())) >= self.limit

    def hit(self, key):
        """Record an event. Returns False if the limit was already reached."""
        with self.lock:
            now = time.time()
            q = self._trim(key, now)
            if len(q) >= self.limit:
                return False
            q.append(now)
            return True

    def reset(self, key):
        with self.lock:
            self.events.pop(key, None)


class LoginIn(BaseModel):
    employee_id: str = Field(min_length=1, max_length=20)
    password: str = Field(min_length=1, max_length=200)


class ChatIn(BaseModel):
    message: str = Field(min_length=1, max_length=2000)
    session_id: str = Field(default="default", max_length=64, pattern=r"^[A-Za-z0-9_-]+$")


def current_user(creds: HTTPAuthorizationCredentials = Depends(bearer)):
    if creds is None:
        raise HTTPException(status_code=401, detail="Not signed in.")
    employee_id = auth.decode_token(creds.credentials)
    user = db.get_user(employee_id) if employee_id else None
    if user is None:
        raise HTTPException(status_code=401, detail="Your session is not valid. Please sign in again.")
    return user  # the role comes from the database, never from the token


def require_roles(*roles):
    def dependency(user=Depends(current_user)):
        if user["role"] not in roles:
            raise HTTPException(status_code=403, detail="You do not have access to this.")
        return user

    return dependency


class DecisionIn(BaseModel):
    step: Literal["line manager", "system owner", "security review"]
    decision: Literal["approve", "reject"]
    note: str = Field(default="", max_length=200)


class TicketStatusIn(BaseModel):
    status: Literal["open", "in_progress", "resolved"]


def create_app(agent=None):
    @asynccontextmanager
    async def lifespan(app):
        auth.require_secret()  # refuse to start with a weak or missing secret
        db.init_db()
        yield

    app = FastAPI(title="Nimbus IT Helpdesk Agent", lifespan=lifespan)
    app.state.agent = agent
    app.state.sessions = {}
    app.state.daily = {"date": "", "n": 0}
    app.state.login_limiter = SlidingWindow(LOGIN_MAX_FAILURES, LOGIN_WINDOW_SECONDS)
    app.state.chat_limiter = SlidingWindow(CHAT_LIMIT, CHAT_WINDOW_SECONDS)

    def get_agent():
        if app.state.agent is None:
            from app.agent import Agent  # created on first use, so the server starts without a model key

            app.state.agent = Agent()
        return app.state.agent

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = response.headers.get("Cache-Control", "no-store")
        return response

    @app.get("/api/health")
    def health():
        return {"status": "ok"}

    @app.post("/api/login")
    def login(body: LoginIn, request: Request):
        employee_id = body.employee_id.strip().upper()
        ip = request.client.host if request.client else "unknown"
        key = f"{ip}|{employee_id}"
        limiter = app.state.login_limiter
        if limiter.is_blocked(key):
            raise HTTPException(status_code=429, detail="Too many failed attempts. Please wait 15 minutes and try again.")
        user = db.verify_login(employee_id, body.password)
        if user is None:
            limiter.hit(key)
            db.audit(employee_id[:20], "login_failed", {"ip": ip})
            # One message for both "no such user" and "wrong password".
            raise HTTPException(status_code=401, detail="Incorrect employee ID or password.")
        limiter.reset(key)
        db.audit(user["employee_id"], "login_success", {"ip": ip})
        return {"access_token": auth.create_token(user["employee_id"]), "token_type": "bearer", "user": user}

    @app.get("/api/me")
    def me(user=Depends(current_user)):
        return user

    @app.post("/api/chat")
    def chat(body: ChatIn, request: Request, user=Depends(current_user)):
        if not app.state.chat_limiter.hit(user["employee_id"]):
            raise HTTPException(status_code=429, detail="You are sending messages too quickly. Please slow down.")
        today = time.strftime("%Y-%m-%d", time.gmtime())
        daily = app.state.daily
        if daily["date"] != today:
            daily["date"], daily["n"] = today, 0
        if daily["n"] >= DAILY_CHAT_CAP:
            raise HTTPException(status_code=429, detail="The demo has reached its daily message limit. Please try again tomorrow.")
        daily["n"] += 1
        agent_obj = get_agent()
        sessions = app.state.sessions
        key = (user["employee_id"], body.session_id)
        if key not in sessions and len(sessions) >= MAX_SESSIONS:
            sessions.pop(next(iter(sessions)))  # drop the oldest conversation
        history = sessions.setdefault(key, [])

        def event_stream():
            final = None
            for event in agent_obj.stream_respond(user, list(history), body.message):
                if event["type"] == "done":
                    final = event["result"]
                yield f"data: {json.dumps(event)}\n\n"
            if final and not final.get("error"):
                history.append({"role": "user", "content": body.message})
                history.append({"role": "assistant", "content": final["reply"]})
                del history[:-MAX_HISTORY_MESSAGES]

        return StreamingResponse(
            event_stream(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    @app.get("/api/tickets")
    def tickets(user=Depends(current_user)):
        owner = None if user["role"] == "it_admin" else user["employee_id"]
        return {"tickets": db.list_tickets(owner)}

    # ---------- approvals (managers and IT admins) ----------
    @app.get("/api/approvals")
    def approvals_list(view: Literal["waiting", "history"] = "waiting", user=Depends(require_roles("manager", "it_admin"))):
        items = [approvals.present(a, user) for a in db.list_approvals() if approvals.visible_to(user, a)]
        waiting = [i for i in items if i["available"]]
        history = [i for i in items if not i["available"]]
        return {"waiting_count": len(waiting), "items": waiting if view == "waiting" else history}

    @app.post("/api/approvals/{approval_id}/decision")
    def approvals_decide(approval_id: int, body: DecisionIn, user=Depends(require_roles("manager", "it_admin"))):
        try:
            return approvals.decide(user, approval_id, body.step, body.decision, body.note)
        except approvals.ApprovalError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.message)

    # ---------- IT admin only ----------
    @app.get("/api/admin/metrics")
    def admin_metrics(days: int = 7, user=Depends(require_roles("it_admin"))):
        if days not in (0, 1, 7, 30):
            raise HTTPException(status_code=422, detail="Choose 1, 7, 30 or 0 (all time) days.")
        return metrics.compute(days)

    @app.get("/api/admin/audit")
    def admin_audit(limit: int = 100, user=Depends(require_roles("it_admin"))):
        return {"events": db.list_audit(max(1, min(limit, 500)))}

    @app.patch("/api/admin/tickets/{ticket_no}")
    def admin_update_ticket(ticket_no: str, body: TicketStatusIn, user=Depends(require_roles("it_admin"))):
        ticket = db.get_ticket(ticket_no) if ticket_no.startswith("TCK-") else None
        if ticket is None:
            raise HTTPException(status_code=404, detail="Ticket not found.")
        if ticket["status"] in ("pending_approval", "rejected"):
            raise HTTPException(status_code=409, detail="This ticket is controlled by the approval workflow.")
        db.set_ticket_status(ticket_no, body.status)
        db.audit(user["employee_id"], "ticket_status_changed", {"ticket_no": ticket_no, "from": ticket["status"], "to": body.status})
        return {"ticket_no": ticket_no, "status": body.status}

    if (STATIC_DIR / "index.html").exists():
        app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")

    return app


app = create_app()
