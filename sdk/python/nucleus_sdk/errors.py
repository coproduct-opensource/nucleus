from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class NucleusError(Exception):
    message: str
    kind: Optional[str] = None
    status: Optional[int] = None
    operation: Optional[str] = None

    def __str__(self) -> str:
        return self.message


class ApprovalRequired(NucleusError):
    pass


class AccessDenied(NucleusError):
    pass


class AuthError(NucleusError):
    pass


class SpecError(NucleusError):
    pass


class RequestError(NucleusError):
    pass


def from_error_payload(payload: dict, status: int) -> NucleusError:
    message = payload.get("error", "request failed")
    kind = payload.get("kind")
    operation = payload.get("operation")

    if kind == "approval_required":
        return ApprovalRequired(message, kind=kind, status=status, operation=operation)

    if kind in {
        "path_denied",
        "command_denied",
        "sandbox_escape",
        "trifecta_blocked",
        "insufficient_capability",
        "dns_not_allowed",
    }:
        return AccessDenied(message, kind=kind, status=status, operation=operation)

    if kind == "auth_error":
        return AuthError(message, kind=kind, status=status, operation=operation)

    if kind in {"spec_error", "serde_error", "body_error", "validation_error"}:
        return SpecError(message, kind=kind, status=status, operation=operation)

    return RequestError(message, kind=kind, status=status, operation=operation)
