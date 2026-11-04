"""Deterministic local MCP-style boundary harness; no external calls."""
import asyncio
from dataclasses import dataclass
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).parent.parent/'nemo_execution_gate'))
from gate import ExecutionGate, NonceStore, Refused
from trusted_host import HostSession, nemo_host_action

@dataclass(frozen=True)
class Principal:
    user: str
    session: str
    permissions: frozenset

class Lab:
    def __init__(self):
        self.gate=ExecutionGate(b'lab-only-not-for-production-secret-32',NonceStore())
        self.events=[]
        self.actions={name:nemo_host_action(self.gate,name,self._target(name)) for name in ('read_record','write_record','export_record')}

    def _target(self,name):
        def target(**kwargs):
            self.events.append((name,kwargs))
            return {'status':'executed','tool':name}
        return target

    def host_approve(self,principal,tool,args,delegate=None):
        # Host authorization is explicitly separate from model proposals.
        if tool not in principal.permissions:
            raise Refused('principal_not_permitted')
        if delegate is not None and tool not in delegate.permissions:
            raise Refused('delegate_not_permitted')
        host=HostSession(self.gate)
        # Scope includes principal + session and optional delegate in trusted grant ID.
        grant=f'{principal.user}:{principal.session}:{delegate.user if delegate else "self"}'
        host.approve(tool,args,grant)
        return host

    async def invoke(self,host,tool,args):
        with host.activate():
            return await self.actions[tool](**args)
