"""
Operator authorization tickets for Loki.
Tickets require an explicitly provisioned signing key and persistent revocation.
"""
from __future__ import annotations

from typing import Dict, List, Optional, Tuple
from pathlib import Path
from urllib.parse import urlsplit
import base64
import hashlib
import hmac
import json
import os
import threading
import time
import uuid

from pydantic import BaseModel, Field

from loki.config import settings


class OperatorAuthorizationTicket(BaseModel):
    ticket_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    assessment_id: str
    approved_targets: List[str]
    issued_at: float = Field(default_factory=time.time)
    expires_at: float
    issued_by: str


class OperatorAuthorizationManager:
    """Issue, verify, and persist revocation of operator authorization tickets."""

    _lock = threading.RLock()

    @classmethod
    def _secret_key(cls) -> bytes:
        """Load an explicitly configured secret; never use a source-code default."""
        key = os.environ.get("LOKI_AUTH_SIGNING_KEY", "").encode("utf-8")
        if len(key) < 32:
            raise RuntimeError(
                "LOKI_AUTH_SIGNING_KEY must be configured with at least 32 bytes "
                "of high-entropy secret material before operator tickets can be used."
            )
        return key

    @classmethod
    def _revocation_path(cls) -> Path:
        configured = os.environ.get("LOKI_AUTH_REVOCATION_FILE")
        return Path(configured).expanduser() if configured else Path.home() / ".loki" / "revoked_tickets.json"

    @classmethod
    def _load_revocations(cls) -> Dict[str, str]:
        path = cls._revocation_path()
        if not path.exists():
            return {}
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in data.items()
        ):
            raise ValueError("Authorization revocation store has an invalid format.")
        return data

    @classmethod
    def _save_revocations(cls, revocations: Dict[str, str]) -> None:
        path = cls._revocation_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        temp = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
        try:
            fd = os.open(str(temp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(revocations, handle, sort_keys=True)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp, path)
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
        finally:
            try:
                temp.unlink(missing_ok=True)
            except OSError:
                pass

    @staticmethod
    def _host(value: str) -> str:
        value = value.strip()
        parsed = urlsplit(value if "://" in value else f"//{value}")
        return (parsed.hostname or value).rstrip(".").lower()

    @classmethod
    def _sign_payload(cls, payload: str) -> str:
        return hmac.new(cls._secret_key(), payload.encode("utf-8"), hashlib.sha256).hexdigest()

    @classmethod
    def issue_ticket(
        cls,
        assessment_id: str,
        approved_targets: List[str],
        valid_seconds: float = 3600.0,
        operator: str = "operator",
        operator_token: Optional[str] = None,
    ) -> str:
        """Create a ticket only after validating the independently provisioned operator credential."""
        expected_operator_token = settings.operator_token
        if (
            not expected_operator_token
            or len(expected_operator_token.encode("utf-8")) < 32
            or not operator_token
            or not hmac.compare_digest(operator_token, expected_operator_token)
        ):
            raise PermissionError("Valid LOKI_OPERATOR_TOKEN is required to issue authorization tickets.")
        if not assessment_id or not assessment_id.strip():
            raise ValueError("assessment_id is required.")
        if not operator or not operator.strip():
            raise ValueError("An operator identity is required.")
        if not 1 <= float(valid_seconds) <= 86400:
            raise ValueError("Ticket validity must be between 1 and 86400 seconds.")
        targets = sorted({
            cls._host(target)
            for target in approved_targets
            if isinstance(target, str) and target.strip()
        })
        if not targets or any(not target for target in targets):
            raise ValueError("At least one valid approved target is required.")

        now = time.time()
        ticket = OperatorAuthorizationTicket(
            assessment_id=assessment_id.strip(),
            approved_targets=targets,
            issued_at=now,
            expires_at=now + float(valid_seconds),
            issued_by=operator.strip(),
        )
        payload = ticket.model_dump_json()
        encoded = base64.urlsafe_b64encode(payload.encode("utf-8")).decode("ascii")
        return f"{encoded}.{cls._sign_payload(payload)}"

    @classmethod
    def verify_ticket(
        cls,
        token_str: str,
        assessment_id: str,
        target: Optional[str] = None,
    ) -> Tuple[bool, str, Optional[OperatorAuthorizationTicket]]:
        """Verify signature, expiry, persistent revocation, assessment and target binding."""
        if not assessment_id or not assessment_id.strip():
            return False, "An active assessment ID is required to validate an authorization ticket.", None
        if not token_str or token_str.count(".") != 1:
            return False, "Invalid token format.", None

        encoded, signature = token_str.strip().split(".", 1)
        try:
            payload = base64.b64decode(
                encoded.encode("ascii") + b"=" * (-len(encoded) % 4),
                altchars=b"-_",
                validate=True,
            ).decode("utf-8")
            expected = cls._sign_payload(payload)
        except Exception:
            return False, "Ticket signing key is unavailable or ticket decoding failed.", None

        if not hmac.compare_digest(signature, expected):
            return False, "Invalid cryptographic signature on authorization ticket.", None
        try:
            ticket = OperatorAuthorizationTicket.model_validate_json(payload)
        except Exception:
            return False, "Ticket payload is invalid.", None

        now = time.time()
        if ticket.issued_at > now + 30:
            return False, "Ticket issue time is in the future.", ticket
        if now >= ticket.expires_at:
            return False, "Authorization ticket has expired.", ticket
        if not hmac.compare_digest(ticket.assessment_id, assessment_id.strip()):
            return False, "Ticket does not belong to the active assessment.", ticket

        try:
            with cls._lock:
                revocations = cls._load_revocations()
        except Exception:
            return False, "Authorization revocation store is unavailable or corrupt; failing closed.", ticket
        if ticket.ticket_id in revocations:
            return False, f"Ticket has been revoked: {revocations[ticket.ticket_id]}", ticket

        if target:
            host = cls._host(target)
            if not any(host == approved or host.endswith(f".{approved}") for approved in ticket.approved_targets):
                return False, "Target is not covered by this operator ticket.", ticket
        return True, "Ticket verified for the active assessment.", ticket

    @classmethod
    def revoke_ticket(cls, ticket_id: str, reason: str = "Operator revoked ticket") -> None:
        """Persist revocation; storage errors are raised and never silently ignored."""
        if not ticket_id or not ticket_id.strip():
            raise ValueError("ticket_id is required.")
        with cls._lock:
            revocations = cls._load_revocations()
            revocations[ticket_id] = reason[:500]
            cls._save_revocations(revocations)
