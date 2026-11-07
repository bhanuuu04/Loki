"""
Shared Assessment Security Context for Loki 2.0.1.
Ensures a single shared owner for ScopeManager, PolicyEngine,
ExecutionGateway, AuditLogger, and AssessmentStore.
Guarantees scope modifications propagate instantly to all agents and registries
without stale singleton or instance desynchronization.
"""

from __future__ import annotations
from typing import Optional, TYPE_CHECKING
import threading

from loki.security.scope_manager import ScopeManager, ScopeConfig
from loki.security.policy_engine import PolicyEngine, ExecutionMode
from loki.security.audit_logger import AuditLogger
from loki.security.gateway import ExecutionGateway

if TYPE_CHECKING:
    from loki.assessment.db import DatabaseManager
    from loki.assessment.store import AssessmentStore


class AssessmentSecurityContext:
    """
    Central authority managing shared security state across Loki runtime.
    Maintains stable object references so mutating scope propagates to all
    active agents, registries, and gateways.
    """

    _lock = threading.Lock()
    _default_instance: Optional["AssessmentSecurityContext"] = None

    def __init__(
        self,
        scope_manager: Optional[ScopeManager] = None,
        audit_logger: Optional[AuditLogger] = None,
        policy_engine: Optional[PolicyEngine] = None,
        gateway: Optional[ExecutionGateway] = None,
        db_manager: Optional[DatabaseManager] = None,
        assessment_store: Optional[AssessmentStore] = None,
    ):
        self.active_assessment_id: Optional[str] = None
        self.scope_manager = scope_manager or ScopeManager(
            ScopeConfig(
                assessment_name="Loki Assessment Session",
                targets=["127.0.0.1", "localhost"],
                allow_subdomains=True,
                allow_loopback=True,
            )
        )
        self.audit_logger = audit_logger or AuditLogger()
        self.policy_engine = policy_engine or PolicyEngine(
            scope_manager=self.scope_manager,
            audit_logger=self.audit_logger,
            mode=ExecutionMode.SAFE,
        )
        # Ensure policy engine uses this exact scope manager
        self.policy_engine.scope_manager = self.scope_manager
        self.policy_engine.audit_logger = self.audit_logger

        self.gateway = gateway or ExecutionGateway(
            scope_manager=self.scope_manager,
            policy_engine=self.policy_engine,
            audit_logger=self.audit_logger,
        )
        # Ensure gateway references this exact scope manager & policy engine
        self.gateway.scope_manager = self.scope_manager
        self.gateway.policy_engine = self.policy_engine
        self.gateway.audit_logger = self.audit_logger

        if db_manager is not None:
            self.db = db_manager
        else:
            from loki.assessment.db import DatabaseManager as _DBManager
            self.db = _DBManager()

        if assessment_store is not None:
            self.assessment_store = assessment_store
        else:
            from loki.assessment.store import AssessmentStore as _AssessmentStore
            self.assessment_store = _AssessmentStore(db_manager=self.db)

    @classmethod
    def get_default(cls) -> "AssessmentSecurityContext":
        """Thread-safe retrieval of the global assessment security context."""
        with cls._lock:
            if cls._default_instance is None:
                cls._default_instance = cls()
            return cls._default_instance

    @classmethod
    def reset_default(cls, context: Optional["AssessmentSecurityContext"] = None) -> "AssessmentSecurityContext":
        """Reset or override default context (useful for test isolation)."""
        with cls._lock:
            cls._default_instance = context or cls()
            return cls._default_instance

    def configure_scope(
        self,
        config: ScopeConfig,
        mode: ExecutionMode = ExecutionMode.SAFE,
        author: str = "operator",
        reason: Optional[str] = None,
    ) -> None:
        """
        Updates the shared scope in-place.
        Propagates immediately to all agents, registries, and gateways.
        """
        self.scope_manager.set_config(config, author=author, reason=reason)
        self.policy_engine.set_mode(mode)
        # Re-verify references
        self.policy_engine.scope_manager = self.scope_manager
        self.gateway.scope_manager = self.scope_manager
        self.gateway.policy_engine = self.policy_engine
