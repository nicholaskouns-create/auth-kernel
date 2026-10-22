"""FlowShield: deterministic defense against unsafe compositions of authorized agent actions.

Local-only reference monitor. No network access or credentials required.
"""
from dataclasses import dataclass, field
from typing import FrozenSet, Tuple

@dataclass(frozen=True)
class Action:
    actor: str
    task: str
    operation: str
    resource: str
    recipient: str = ""
    labels: FrozenSet[str] = frozenset()
    trusted_origin: bool = True

@dataclass
class FlowShield:
    """One instance per authenticated task; caller owns persistence and isolation."""
    task: str
    actor: str
    approved_recipients: FrozenSet[str] = frozenset()
    approved_operations: FrozenSet[str] = frozenset({"read", "summarize", "send"})
    history: list = field(default_factory=list)

    def check(self, action: Action) -> Tuple[bool, str]:
        if action.actor != self.actor or action.task != self.task:
            return False, "identity_or_task_drift"
        if not action.trusted_origin:
            return False, "untrusted_instruction_origin"
        if action.operation not in self.approved_operations:
            return False, "operation_out_of_scope"
        if action.operation in {"send", "transfer", "export"}:
            if not action.recipient or action.recipient not in self.approved_recipients:
                return False, "unapproved_destination"
            sensitive = any("sensitive" in prior.labels for prior in self.history)
            if sensitive and action.operation in {"send", "export"}:
                return False, "sensitive_flow_requires_explicit_declassification"
        return True, "allow"

    def record(self, action: Action):
        allowed, reason = self.check(action)
        if not allowed:
            raise PermissionError(reason)
        self.history.append(action)
        return reason
