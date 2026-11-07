"""
Cryptographically Verified Operator Authorization Management for Loki 2.0.
Issues and validates time-limited, signed, revocable operator authorization tickets.
Prevents autonomous LLM self-authorization and ensures strictly auditable scope expansion.
"""

from typing import Dict, List, Optional, Tuple
import hashlib
import hmac
import json
import os
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
    issued_by: str = "operator"
    is_revoked: bool = False
    revocation_reason: Optional[str] = None


class OperatorAuthorizationManager:
    """Manages creation, verification, and revocation of operator authorization tickets."""

    _secret_key: bytes = os.getenv("LOKI_AUTH_SIGNING_KEY", "loki-sec-master-key-2026").encode("utf-8")
    _revoked_tickets: Dict[str, str] = {}  # ticket_id -> reason

    @classmethod
    def _sign_payload(cls, payload_json: str) -> str:
        """Compute HMAC-SHA256 signature for ticket payload."""
        return hmac.new(cls._secret_key, payload_json.encode("utf-8"), hashlib.sha256).hexdigest()

    @classmethod
    def issue_ticket(
        cls,
        assessment_id: str,
        approved_targets: List[str],
        valid_seconds: float = 3600.0,
        operator: str = "lead_operator",
    ) -> str:
        """Generate a signed, time-limited operator ticket token."""
        now = time.time()
        ticket = OperatorAuthorizationTicket(
            assessment_id=assessment_id,
            approved_targets=[t.strip().lower() for t in approved_targets if t.strip()],
            issued_at=now,
            expires_at=now + valid_seconds,
            issued_by=operator,
        )
        payload = ticket.model_dump_json()
        sig = cls._sign_payload(payload)
        import base64
        token_str = f"{base64.urlsafe_b64encode(payload.encode()).decode()}.{sig}"
        return token_str

    @classmethod
    def verify_ticket(
        cls,
        token_str: str,
        assessment_id: Optional[str] = None,
        target: Optional[str] = None,
    ) -> Tuple[bool, str, Optional[OperatorAuthorizationTicket]]:
        """
        Cryptographically verify signature, validity, expiration, and scope coverage.
        Returns (is_valid, reason, ticket).
        """
        if not token_str or "." not in token_str:
            return False, "Invalid token format.", None

        parts = token_str.strip().split(".")
        if len(parts) != 2:
            return False, "Malformed token structure.", None

        b64_payload, signature = parts
        import base64
        try:
            payload_json = base64.urlsafe_b64decode(b64_payload.encode()).decode("utf-8")
        except Exception:
            return False, "Failed to decode ticket payload.", None

        # Verify cryptographic HMAC signature
        expected_sig = cls._sign_payload(payload_json)
        if not hmac.compare_digest(signature, expected_sig):
            return False, "Invalid cryptographic signature on authorization ticket.", None

        try:
            data = json.loads(payload_json)
            ticket = OperatorAuthorizationTicket(**data)
        except Exception as e:
            return False, f"Ticket parsing failed: {str(e)}", None

        # Check revocation
        if ticket.ticket_id in cls._revoked_tickets:
            return False, f"Ticket has been revoked: {cls._revoked_tickets[ticket.ticket_id]}", ticket

        # Check expiration
        now = time.time()
        if now > ticket.expires_at:
            return False, f"Authorization ticket expired {round(now - ticket.expires_at, 1)} seconds ago.", ticket

        # Check assessment binding if specified
        if assessment_id and ticket.assessment_id != assessment_id:
            return False, f"Ticket assessment '{ticket.assessment_id}' does not match active assessment '{assessment_id}'.", ticket

        # Check target coverage if specified
        if target:
            target_clean = target.strip().lower()
            if not any(
                target_clean == t or target_clean.endswith(f".{t}")
                for t in ticket.approved_targets
            ):
                return False, f"Target '{target}' is not covered by approved ticket targets: {ticket.approved_targets}", ticket

        return True, "Ticket verified and authorized by operator.", ticket

    @classmethod
    def revoke_ticket(cls, ticket_id: str, reason: str = "Operator revoked ticket") -> None:
        """Mark a ticket as revoked."""
        cls._revoked_tickets[ticket_id] = reason
