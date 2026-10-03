"""Authorization kernel.

Invoke := Candidate and G_syn and X and Active(subj)
G_syn  := Issued and InWindow and ToolOk and ArgsOk
X      := Bound and Fresh

Issued means the presented record matches the stored issue record.
ALLOW re-checks the signature, then claims the nonce under a lock.
A valid signature does not by itself invoke.
Verify is HMAC-SHA256 over canonical JSON.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import threading
from dataclasses import dataclass, field, replace
from typing import Any


def mac(key: str, msg: str) -> str:
    return hmac.new(key.encode(), msg.encode(), hashlib.sha256).hexdigest()


def verify(key: object, msg: object, sig: object) -> bool:
    if not isinstance(key, str) or not isinstance(msg, str) or not isinstance(sig, str):
        return False
    if not key or not sig:
        return False
    try:
        return hmac.compare_digest(mac(key, msg), sig)
    except Exception:
        return False


def canon(obj: dict) -> str | None:
    try:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError):
        return None


@dataclass(frozen=True)
class Record:
    subj: str
    tool: str
    args: dict
    nonce: str
    issuer: str
    nbf: int
    exp: int
    sig: str = ""
    formed: bool = True

    def present(self) -> bool:
        return all([
            isinstance(self.subj, str) and self.subj,
            isinstance(self.tool, str) and self.tool,
            isinstance(self.nonce, str) and self.nonce,
            isinstance(self.issuer, str) and self.issuer,
            isinstance(self.nbf, int),
            isinstance(self.exp, int),
            isinstance(self.args, dict),
        ])

    def body(self) -> dict:
        return {
            "args": self.args,
            "exp": self.exp,
            "issuer": self.issuer,
            "nbf": self.nbf,
            "nonce": self.nonce,
            "subj": self.subj,
            "tool": self.tool,
        }

    def canonical(self) -> str | None:
        return canon(self.body()) if self.present() else None


@dataclass(frozen=True)
class IssueRec:
    nonce: str
    issuer: str
    canonical: str


@dataclass
class Ledger:
    issuers: set[str] = field(default_factory=set)
    keys: dict[str, str] = field(default_factory=dict)
    authority_keys: dict[str, str] = field(default_factory=dict)
    issue_recs: dict[str, IssueRec] = field(default_factory=dict)
    revoked: set[str] = field(default_factory=set)
    tools: set[str] = field(default_factory=set)
    disabled: set[str] = field(default_factory=set)
    grants: dict[str, set[str]] = field(default_factory=dict)
    schemas: dict[str, set[str]] = field(default_factory=dict)
    bindings: dict[str, tuple[str, int, int]] = field(default_factory=dict)
    amnesty: set[str] = field(default_factory=set)
    nonce_state: dict[str, str] = field(default_factory=dict)
    t: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)

    def snapshot(self) -> "Ledger":
        nxt = replace(self)
        nxt.issuers = set(self.issuers)
        nxt.keys = dict(self.keys)
        nxt.authority_keys = dict(self.authority_keys)
        nxt.issue_recs = dict(self.issue_recs)
        nxt.revoked = set(self.revoked)
        nxt.tools = set(self.tools)
        nxt.disabled = set(self.disabled)
        nxt.grants = {k: set(v) for k, v in self.grants.items()}
        nxt.schemas = {k: set(v) for k, v in self.schemas.items()}
        nxt.bindings = dict(self.bindings)
        nxt.amnesty = set(self.amnesty)
        nxt.nonce_state = dict(self.nonce_state)
        nxt.lock = self.lock
        return nxt

    def claim(self, nonce: str) -> bool:
        with self.lock:
            if self.nonce_state.get(nonce) != "ISSUED":
                return False
            self.nonce_state[nonce] = "SPENT"
            return True


def sign_record(d: Record, key: str) -> Record:
    body = d.canonical()
    if body is None:
        raise ValueError("record is not canonical")
    return replace(d, sig=mac(key, body))


def sign_act(key: str, kind: str, body: dict) -> str:
    msg = canon({"kind": kind, "body": body})
    if msg is None:
        raise ValueError("act is not canonical")
    return mac(key, msg)


def valid_sig(d: Record, s: Ledger) -> bool:
    body = d.canonical()
    key = s.keys.get(d.issuer)
    if body is None or key is None:
        return False
    return verify(key, body, d.sig)


def act_ok(s: Ledger, authority: str, kind: str, body: dict, sig: object) -> bool:
    key = s.authority_keys.get(authority)
    msg = canon({"kind": kind, "body": body})
    if key is None or msg is None:
        return False
    return verify(key, msg, sig)


def amnestied(a: str, s: Ledger) -> bool:
    return a in s.amnesty


def active(a: str, s: Ledger) -> bool:
    if amnestied(a, s):
        return False
    binding = s.bindings.get(a)
    if binding is None:
        return False
    _principal, nbf, exp = binding
    return nbf <= s.t < exp


def candidate(d: Record, s: Ledger) -> bool:
    return d.formed and d.canonical() is not None and not amnestied(d.subj, s)


def issued(d: Record, s: Ledger) -> bool:
    rec = s.issue_recs.get(d.nonce)
    body = d.canonical()
    if rec is None or body is None:
        return False
    return (
        rec.issuer == d.issuer
        and rec.canonical == body
        and d.issuer in s.issuers
        and d.nonce not in s.revoked
    )


def in_window(d: Record, s: Ledger) -> bool:
    return d.nbf <= s.t < d.exp


def tool_ok(d: Record, s: Ledger) -> bool:
    return (
        d.tool in s.tools
        and d.tool not in s.disabled
        and d.tool in s.grants.get(d.subj, set())
    )


def args_ok(d: Record, s: Ledger, limit: int = 10_000) -> bool:
    body = canon({"args": d.args})
    required = s.schemas.get(d.tool, set())
    return body is not None and len(body) <= limit and required.issubset(d.args)


def bound(d: Record, s: Ledger) -> bool:
    return active(d.subj, s)


def fresh(d: Record, s: Ledger) -> bool:
    return s.nonce_state.get(d.nonce) == "ISSUED"


def invoke(d: Record, s: Ledger) -> bool:
    return all([
        candidate(d, s),
        issued(d, s),
        in_window(d, s),
        tool_ok(d, s),
        args_ok(d, s),
        bound(d, s),
        fresh(d, s),
        active(d.subj, s),
    ])


def failed(d: Record, s: Ledger) -> str | None:
    checks = [
        ("Active", lambda: active(d.subj, s)),
        ("Candidate", lambda: candidate(d, s)),
        ("Issued", lambda: issued(d, s)),
        ("InWindow", lambda: in_window(d, s)),
        ("ToolOk", lambda: tool_ok(d, s)),
        ("ArgsOk", lambda: args_ok(d, s)),
        ("Bound", lambda: bound(d, s)),
        ("Fresh", lambda: fresh(d, s)),
    ]
    for name, fn in checks:
        if not fn():
            return name
    return None


def allow(d: Record, s: Ledger) -> tuple[bool, Ledger, str]:
    miss = failed(d, s)
    if miss is not None:
        return False, s, miss
    if not valid_sig(d, s):
        return False, s, "NotValidSig"
    if not s.claim(d.nonce):
        return False, s, "Fresh"
    return True, s.snapshot(), "ALLOW"


def register_issuer(s: Ledger, issuer: str, key: str) -> tuple[bool, Ledger, str]:
    if not issuer or not key:
        return False, s, "NotIssuer"
    nxt = s.snapshot()
    nxt.issuers.add(issuer)
    nxt.keys[issuer] = key
    return True, nxt, "REGISTER_ISSUER"


def register_authority(s: Ledger, authority: str, key: str) -> tuple[bool, Ledger, str]:
    if not authority or not key:
        return False, s, "NotAuthority"
    nxt = s.snapshot()
    nxt.authority_keys[authority] = key
    return True, nxt, "REGISTER_AUTHORITY"


def register_tool(s: Ledger, tool: str) -> tuple[bool, Ledger, str]:
    if not tool:
        return False, s, "NotTool"
    nxt = s.snapshot()
    nxt.tools.add(tool)
    return True, nxt, "REGISTER_TOOL"


def register_schema(s: Ledger, tool: str, keys: set[str]) -> tuple[bool, Ledger, str]:
    if tool not in s.tools:
        return False, s, "NotTool"
    nxt = s.snapshot()
    nxt.schemas[tool] = set(keys)
    return True, nxt, "REGISTER_SCHEMA"


def issue(s: Ledger, d: Record) -> tuple[bool, Ledger, str]:
    body = d.canonical()
    if d.issuer not in s.issuers:
        return False, s, "NotIssuer"
    if body is None or not valid_sig(d, s):
        return False, s, "NotValidSig"
    with s.lock:
        if d.nonce in s.nonce_state:
            return False, s, "NotFreshNonce"
        s.issue_recs[d.nonce] = IssueRec(d.nonce, d.issuer, body)
        s.nonce_state[d.nonce] = "ISSUED"
    return True, s.snapshot(), "ISSUE"


def revoke(s: Ledger, nonce: str, authority: str, sig: str) -> tuple[bool, Ledger, str]:
    if nonce not in s.issue_recs:
        return False, s, "NotIssueRec"
    if not act_ok(s, authority, "REVOKE", {"nonce": nonce}, sig):
        return False, s, "NotActSig"
    nxt = s.snapshot()
    nxt.revoked.add(nonce)
    return True, nxt, "REVOKE"


def bind(s: Ledger, subj: str, principal: str, nbf: int, exp: int, authority: str, sig: str) -> tuple[bool, Ledger, str]:
    body = {"subj": subj, "principal": principal, "nbf": nbf, "exp": exp}
    if not act_ok(s, authority, "BIND", body, sig):
        return False, s, "NotActSig"
    if subj in s.amnesty:
        return False, s, "Amnesty"
    if exp <= nbf:
        return False, s, "NotWindow"
    nxt = s.snapshot()
    nxt.bindings[subj] = (principal, nbf, exp)
    return True, nxt, "BIND"


def grant(s: Ledger, subj: str, tool: str, authority: str, sig: str) -> tuple[bool, Ledger, str]:
    if tool not in s.tools:
        return False, s, "NotTool"
    if not act_ok(s, authority, "GRANT", {"subj": subj, "tool": tool}, sig):
        return False, s, "NotActSig"
    nxt = s.snapshot()
    nxt.grants.setdefault(subj, set()).add(tool)
    return True, nxt, "GRANT"


def disable(s: Ledger, tool: str, authority: str, sig: str) -> tuple[bool, Ledger, str]:
    if tool not in s.tools:
        return False, s, "NotTool"
    if not act_ok(s, authority, "DISABLE", {"tool": tool}, sig):
        return False, s, "NotActSig"
    nxt = s.snapshot()
    nxt.disabled.add(tool)
    return True, nxt, "DISABLE"


def tick(s: Ledger, t: int) -> tuple[bool, Ledger, str]:
    if not isinstance(t, int) or t < s.t:
        return False, s, "NotClock"
    nxt = s.snapshot()
    nxt.t = t
    return True, nxt, "TICK"


def apply_amnesty(s: Ledger, subj: str, authority: str, sig: str) -> tuple[bool, Ledger, str]:
    if not act_ok(s, authority, "AMNESTY", {"subj": subj}, sig):
        return False, s, "NotActSig"
    if subj not in s.bindings:
        return False, s, "NotBind"
    nxt = s.snapshot()
    nxt.amnesty.add(subj)
    return True, nxt, "AMNESTY"


def live() -> tuple[Ledger, Record, str]:
    iss, auth = "iss-key", "auth-key"
    s = Ledger()
    _, s, _ = register_issuer(s, "iss-1", iss)
    _, s, _ = register_authority(s, "auth-1", auth)
    _, s, _ = register_tool(s, "echo")
    _, s, _ = register_schema(s, "echo", {"msg"})
    _, s, _ = tick(s, 10)
    d = sign_record(Record("a|b", "echo", {"msg": "ok"}, "n1", "iss-1", 0, 50), iss)
    _, s, _ = issue(s, d)
    _, s, _ = bind(s, "a|b", "p", 0, 100, "auth-1", sign_act(auth, "BIND", {
        "subj": "a|b", "principal": "p", "nbf": 0, "exp": 100,
    }))
    _, s, _ = grant(s, "a|b", "echo", "auth-1", sign_act(auth, "GRANT", {
        "subj": "a|b", "tool": "echo",
    }))
    return s, d, auth


def demo() -> dict[str, Any]:
    s, d, auth = live()
    ok, s2, tag = allow(d, s)
    replay_ok, _, replay_tag = allow(d, s)
    _, _, args_tag = allow(replace(d, args={"msg": "no"}), s)
    empty = Ledger(t=10, keys={"iss-1": "iss-key"})
    s3, d3, _ = live()
    results: list[str] = []

    def once() -> None:
        won, _, name = allow(d3, s3)
        results.append("ALLOW" if won else name)

    threads = [threading.Thread(target=once) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return {
        "allow": [ok, tag, s2.nonce_state["n1"]],
        "replay": [replay_ok, replay_tag],
        "swapped_args": args_tag,
        "non_string_sig": valid_sig(replace(d, sig=12345), s),
        "observes_only": valid_sig(d, empty) and not invoke(d, empty),
        "concurrent_one_winner": results.count("ALLOW") == 1,
    }


if __name__ == "__main__":
    print(json.dumps(demo(), indent=2))
