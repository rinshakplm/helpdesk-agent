"""Policy gate: plain code that decides what the AI is allowed to do.

The language model only PROPOSES an action. This module decides.
The user's identity comes from the login session, never from the model.
"""
import re
from dataclasses import dataclass, field
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app import db

MAX_RESETS_PER_DAY = 3
NO_ACCESS_MSG = "No ticket with that number is visible to you."


@dataclass
class Decision:
    verdict: str  # allow | needs_verification | needs_approval | refuse
    rule: str
    message: str
    details: dict = field(default_factory=dict)


class _Strict(BaseModel):
    # Extra fields are rejected, so the model cannot smuggle in a target account.
    model_config = ConfigDict(extra="forbid")


class CreateTicket(_Strict):
    category: Literal["password", "vpn", "phishing", "access", "mfa", "device", "software", "network", "other"]
    summary: str = Field(min_length=5, max_length=300)


class CheckTicketStatus(_Strict):
    ticket_no: str = Field(pattern=r"^TCK-\d{4,}$")


class ReportPhishing(_Strict):
    description: str = Field(min_length=5, max_length=500)


class RequestAccess(_Strict):
    resource: str = Field(min_length=3, max_length=120)
    reason: str = Field(min_length=5, max_length=300)


class ResetPassword(_Strict):
    # There is deliberately no account field: users can only reset their own password.
    otp: Optional[str] = Field(default=None, pattern=r"^\d{6}$")


class EscalateToHuman(_Strict):
    reason: str = Field(min_length=3, max_length=300)


ACTION_MODELS = {
    "create_ticket": CreateTicket,
    "check_ticket_status": CheckTicketStatus,
    "report_phishing": ReportPhishing,
    "request_access": RequestAccess,
    "reset_password": ResetPassword,
    "escalate_to_human": EscalateToHuman,
}

SENSITIVE_WORDS = {
    "finance", "financial", "payroll", "production", "prod", "customer",
    "customers", "database", "admin", "administrator", "hr", "secrets", "vault",
}


def _always_allow(user, data):
    return Decision("allow", "ALWAYS_ALLOWED", "Allowed.")


def _check_ticket_status(user, data):
    ticket = db.get_ticket(data.ticket_no)
    if ticket is None or (ticket["owner_id"] != user["employee_id"] and user["role"] != "it_admin"):
        # Same message either way, so the answer does not reveal whether a ticket exists.
        return Decision("refuse", "TICKET_NOT_VISIBLE", NO_ACCESS_MSG)
    return Decision("allow", "TICKET_OWNER_OR_ADMIN", "Allowed.")


def _request_access(user, data):
    words = set(re.findall(r"[a-z]+", data.resource.lower()))
    sensitive = bool(words & SENSITIVE_WORDS)
    approvers = ["line manager"]
    if sensitive:
        approvers += ["system owner", "security review"]
    return Decision(
        "needs_approval",
        "ACCESS_SENSITIVE" if sensitive else "ACCESS_STANDARD",
        "Access is never granted in chat. It has been sent for approval.",
        {"sensitive": sensitive, "approvers": approvers},
    )


def _reset_password(user, data):
    emp = user["employee_id"]
    status = db.check_otp(emp, data.otp) if data.otp else "none"
    if status == "ok":
        return Decision("allow", "RESET_VERIFIED", "Identity verified.")
    if status == "invalid":
        return Decision("refuse", "OTP_INVALID", "That code is not correct.")
    if status == "locked":
        return Decision("refuse", "OTP_LOCKED", "Too many wrong attempts. Please request a new code.")
    # No active code (none, expired, or nothing supplied): this starts a new reset request.
    if db.count_reset_requests(emp) >= MAX_RESETS_PER_DAY:
        return Decision("refuse", "RESET_RATE_LIMIT", "Reset limit reached for the last 24 hours. Please contact the Service Desk.")
    return Decision("needs_verification", "RESET_NEEDS_VERIFICATION", "A one-time code must be confirmed first.")


_RULES = {
    "create_ticket": _always_allow,
    "report_phishing": _always_allow,
    "escalate_to_human": _always_allow,
    "check_ticket_status": _check_ticket_status,
    "request_access": _request_access,
    "reset_password": _reset_password,
}


def evaluate(user, action, params):
    model = ACTION_MODELS.get(action)
    if model is None:
        return Decision("refuse", "ACTION_NOT_IN_CATALOGUE", "That action is not something I am allowed to do.")
    try:
        data = model(**(params or {}))
    except (ValidationError, TypeError):
        return Decision("refuse", "INVALID_PARAMETERS", "The request was not valid, so it was not carried out.")
    return _RULES[action](user, data)
