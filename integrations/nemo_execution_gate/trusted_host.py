"""Host-only authorization context for NeMo action registration.

The trusted application approves exact calls before running NeMo. Model arguments
never contain tokens. Do not expose HostSession or the gate to model tools.
"""
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Callable
from gate import ExecutionGate, Refused, digest

_active_session = ContextVar('nemo_execution_gate_host_session', default=None)

@dataclass(frozen=True)
class ApprovedCall:
    tool: str
    args_hash: str
    token: str
    grant_id: str

class HostSession:
    def __init__(self, gate: ExecutionGate):
        self._gate = gate
        self._approved = {}

    def approve(self, tool: str, args: dict, grant_id: str, ttl: int = 60):
        """Host-side policy decision; MUST NOT be called by model code."""
        key = (tool, digest(args))
        if key in self._approved:
            raise ValueError('duplicate approval for exact call')
        token = self._gate.issue(tool, args, grant_id, ttl)
        self._approved[key] = ApprovedCall(tool, key[1], token, grant_id)

    @contextmanager
    def activate(self):
        if _active_session.get() is not None:
            raise RuntimeError('nested host authorization session')
        marker = _active_session.set(self)
        try:
            yield self
        finally:
            _active_session.reset(marker)

    def take(self, tool: str, args: dict):
        # Exact-match lookup, no model-provided token or grant ID.
        approval = self._approved.pop((tool, digest(args)), None)
        if approval is None:
            raise Refused('not_host_approved')
        return approval


def nemo_host_action(gate: ExecutionGate, tool_name: str, target: Callable):
    """Callable for rails.register_action(action=..., name=...).

    NeMo supplies only model-selected business kwargs. Authorization is obtained
    from the trusted host context and is not accepted as an action argument.
    """
    async def guarded_action(**kwargs):
        # Reject attempted control-plane parameter injection, even when a
        # business tool would otherwise accept such a parameter.
        if any(k in kwargs for k in ('authorization_token', 'grant_id', '_host_session')):
            raise Refused('control_argument_forbidden')
        session = _active_session.get()
        if session is None or session._gate is not gate:
            raise Refused('no_trusted_host_session')
        approval = session.take(tool_name, kwargs)
        return await gate.invoke(tool_name, kwargs, approval.token, approval.grant_id, target)
    guarded_action.__name__ = tool_name
    return guarded_action
