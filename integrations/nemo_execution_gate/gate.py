"""Optional execution-boundary adapter for NeMo action/tool integrations.

The trusted host issues grants. The model must never possess the signing key.
For distributed execution, replace SQLite with a shared transactional nonce store.
"""
import asyncio
import hashlib
import hmac
import inspect
import json
import secrets
import sqlite3
import time
import threading
from dataclasses import dataclass
from typing import Callable


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def digest(args):
    if not isinstance(args, dict):
        raise ValueError('arguments must be an object')
    return hashlib.sha256(canonical(args)).hexdigest()


class Refused(PermissionError):
    pass


class NonceStore:
    """SQLite-backed one-time nonce consumption, atomic across processes sharing a DB."""
    def __init__(self, path=':memory:'):
        self.db = sqlite3.connect(path, timeout=10, check_same_thread=False, isolation_level=None)
        self.lock = threading.Lock()
        self.db.execute('CREATE TABLE IF NOT EXISTS spent (nonce TEXT PRIMARY KEY, expires INTEGER NOT NULL)')

    def spend(self, nonce, expires):
        with self.lock:
            try:
                self.db.execute('INSERT INTO spent(nonce,expires) VALUES (?,?)', (nonce, expires))
            except sqlite3.IntegrityError as exc:
                raise Refused('nonce_spent') from exc


@dataclass
class ExecutionGate:
    key: bytes
    store: NonceStore
    audience: str = 'nemo-execution-gate-v1'

    def issue(self, tool, args, grant_id, ttl=60):
        """TRUSTED HOST ONLY: authorize a previously approved exact action."""
        if not (isinstance(tool, str) and tool and isinstance(grant_id, str) and grant_id):
            raise ValueError('invalid grant')
        if not (1 <= ttl <= 3600):
            raise ValueError('ttl outside bounds')
        payload = dict(v=1, aud=self.audience, tool=tool, args_sha256=digest(args),
                       grant_id=grant_id, nonce=secrets.token_hex(16), exp=int(time.time())+ttl)
        mac = hmac.new(self.key, canonical(payload), hashlib.sha256).hexdigest()
        return json.dumps({'payload': payload, 'mac': mac}, separators=(',', ':'))

    def verify_and_spend(self, token, tool, args, grant_id):
        if not token:
            raise Refused('token_missing')
        try:
            parsed = json.loads(token)
            payload, mac = parsed['payload'], parsed['mac']
            if not isinstance(mac, str) or len(mac) != 64:
                raise ValueError('invalid mac')
            expected = hmac.new(self.key, canonical(payload), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, mac):
                raise Refused('bad_mac')
            if payload['v'] != 1 or payload['aud'] != self.audience:
                raise Refused('wrong_audience')
            if payload['tool'] != tool or payload['grant_id'] != grant_id:
                raise Refused('scope_mismatch')
            if payload['args_sha256'] != digest(args):
                raise Refused('args_mismatch')
            if int(time.time()) >= payload['exp']:
                raise Refused('expired')
            nonce = payload['nonce']
            if not isinstance(nonce, str) or len(nonce) != 32:
                raise Refused('bad_nonce')
            self.store.spend(nonce, payload['exp'])
        except Refused:
            raise
        except (ValueError, TypeError, KeyError, AttributeError) as exc:
            raise Refused('malformed_token') from exc

    async def invoke(self, tool_name, args, token, grant_id, target: Callable):
        self.verify_and_spend(token, tool_name, args, grant_id)
        result = target(**args)
        return await result if inspect.isawaitable(result) else result

    def nemo_action(self, tool_name, target: Callable, grant_id: str):
        """Register returned callable with LLMRails.register_action(..., name=tool_name).
        The trusted caller must inject token out-of-band, not via model-generated args.
        """
        async def guarded_action(*, authorization_token=None, **kwargs):
            return await self.invoke(tool_name, kwargs, authorization_token, grant_id, target)
        guarded_action.__name__ = tool_name
        return guarded_action
