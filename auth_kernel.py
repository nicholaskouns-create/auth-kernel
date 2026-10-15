"""Authorization kernel.

Invoke(r) := Candidate and G_syn and X(r) and Active(subj)
G_syn     := Issued and InWindow and ToolOk and ArgsOk
X(r)      := Bound(r) and Fresh
Bound(r)  := Active(subj) and principal(subj) == r

One ledger holds authority. Every transition runs under its lock, so a
decision and the nonce it spends are a single step, and a spent nonce,
a revocation, or an amnesty binds every later decision.

Issued means the presented record matches the stored issue record.
ALLOW re-checks the signature, then spends the nonce.
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

Step = tuple[bool, "Ledger", str]


def mac(key: str, msg: str) -> str:
    return hmac.new(key.encode(), msg.encode(), hashlib.sha256).hexdigest()


def verify(key: object, msg: object, sig: object) -> bool:
    if not isinstance(key, str) or not isinstance(msg, str) or not isinstance(sig, str):
        return False
    if not key or not sig:
        return False
    try:
        return hmac.compare_digest(mac(key, msg).encode(), sig.encode())
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
    """The single authoritative state. Transitions mutate it in place under `lock`."""

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


# ---------------------------------------------------------------- predicates

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


def bound(d: Record, s: Ledger, requester: object) -> bool:
    """The requester must be the principal the subject is bound to."""
    binding = s.bindings.get(d.subj)
    return (
        isinstance(requester, str)
        and binding is not None
        and binding[0] == requester
        and active(d.subj, s)
    )


def fresh(d: Record, s: Ledger) -> bool:
    return s.nonce_state.get(d.nonce) == "ISSUED"


def invoke(d: Record, s: Ledger, requester: object) -> bool:
    return failed(d, s, requester) is None


def failed(d: Record, s: Ledger, requester: object) -> str | None:
    checks = (
        ("Active", lambda: active(d.subj, s)),
        ("Candidate", lambda: candidate(d, s)),
        ("Issued", lambda: issued(d, s)),
        ("InWindow", lambda: in_window(d, s)),
        ("ToolOk", lambda: tool_ok(d, s)),
        ("ArgsOk", lambda: args_ok(d, s)),
        ("Bound", lambda: bound(d, s, requester)),
        ("Fresh", lambda: fresh(d, s)),
    )
    for name, holds in checks:
        if not holds():
            return name
    return None


# ---------------------------------------------------------------- transitions

def allow(d: Record, s: Ledger, requester: object) -> Step:
    """Decide and spend in one locked step. Refusal does not write."""
    with s.lock:
        miss = failed(d, s, requester)
        if miss is not None:
            return False, s, miss
        if not valid_sig(d, s):
            return False, s, "NotValidSig"
        s.nonce_state[d.nonce] = "SPENT"
    return True, s, "ALLOW"


def register_issuer(s: Ledger, issuer: str, key: str) -> Step:
    if not issuer or not key:
        return False, s, "NotIssuer"
    with s.lock:
        s.issuers.add(issuer)
        s.keys[issuer] = key
    return True, s, "REGISTER_ISSUER"


def register_authority(s: Ledger, authority: str, key: str) -> Step:
    if not authority or not key:
        return False, s, "NotAuthority"
    with s.lock:
        s.authority_keys[authority] = key
    return True, s, "REGISTER_AUTHORITY"


def register_tool(s: Ledger, tool: str) -> Step:
    if not tool:
        return False, s, "NotTool"
    with s.lock:
        s.tools.add(tool)
    return True, s, "REGISTER_TOOL"


def register_schema(s: Ledger, tool: str, keys: set[str]) -> Step:
    with s.lock:
        if tool not in s.tools:
            return False, s, "NotTool"
        s.schemas[tool] = set(keys)
    return True, s, "REGISTER_SCHEMA"


def issue(s: Ledger, d: Record) -> Step:
    body = d.canonical()
    with s.lock:
        if d.issuer not in s.issuers:
            return False, s, "NotIssuer"
        if body is None or not valid_sig(d, s):
            return False, s, "NotValidSig"
        if d.nonce in s.nonce_state:
            return False, s, "NotFreshNonce"
        s.issue_recs[d.nonce] = IssueRec(d.nonce, d.issuer, body)
        s.nonce_state[d.nonce] = "ISSUED"
    return True, s, "ISSUE"


def revoke(s: Ledger, nonce: str, authority: str, sig: str) -> Step:
    with s.lock:
        if nonce not in s.issue_recs:
            return False, s, "NotIssueRec"
        if not act_ok(s, authority, "REVOKE", {"nonce": nonce}, sig):
            return False, s, "NotActSig"
        s.revoked.add(nonce)
    return True, s, "REVOKE"


def bind(s: Ledger, subj: str, principal: str, nbf: int, exp: int, authority: str, sig: str) -> Step:
    body = {"subj": subj, "principal": principal, "nbf": nbf, "exp": exp}
    with s.lock:
        if not act_ok(s, authority, "BIND", body, sig):
            return False, s, "NotActSig"
        if subj in s.amnesty:
            return False, s, "Amnesty"
        if exp <= nbf:
            return False, s, "NotWindow"
        s.bindings[subj] = (principal, nbf, exp)
    return True, s, "BIND"


def grant(s: Ledger, subj: str, tool: str, authority: str, sig: str) -> Step:
    with s.lock:
        if tool not in s.tools:
            return False, s, "NotTool"
        if not act_ok(s, authority, "GRANT", {"subj": subj, "tool": tool}, sig):
            return False, s, "NotActSig"
        s.grants.setdefault(subj, set()).add(tool)
    return True, s, "GRANT"


def disable(s: Ledger, tool: str, authority: str, sig: str) -> Step:
    with s.lock:
        if tool not in s.tools:
            return False, s, "NotTool"
        if not act_ok(s, authority, "DISABLE", {"tool": tool}, sig):
            return False, s, "NotActSig"
        s.disabled.add(tool)
    return True, s, "DISABLE"


def tick(s: Ledger, t: int) -> Step:
    with s.lock:
        if not isinstance(t, int) or t < s.t:
            return False, s, "NotClock"
        s.t = t
    return True, s, "TICK"


def apply_amnesty(s: Ledger, subj: str, authority: str, sig: str) -> Step:
    with s.lock:
        if not act_ok(s, authority, "AMNESTY", {"subj": subj}, sig):
            return False, s, "NotActSig"
        if subj not in s.bindings:
            return False, s, "NotBind"
        s.amnesty.add(subj)
    return True, s, "AMNESTY"


# ---------------------------------------------------------------- demonstration

def live() -> tuple[Ledger, Record, str]:
    iss, auth = "iss-key", "auth-key"
    s = Ledger()
    register_issuer(s, "iss-1", iss)
    register_authority(s, "auth-1", auth)
    register_tool(s, "echo")
    register_schema(s, "echo", {"msg"})
    tick(s, 10)
    d = sign_record(Record("a|b", "echo", {"msg": "ok"}, "n1", "iss-1", 0, 50), iss)
    issue(s, d)
    bind(s, "a|b", "p", 0, 100, "auth-1", sign_act(auth, "BIND", {
        "subj": "a|b", "principal": "p", "nbf": 0, "exp": 100,
    }))
    grant(s, "a|b", "echo", "auth-1", sign_act(auth, "GRANT", {
        "subj": "a|b", "tool": "echo",
    }))
    return s, d, auth


def demo() -> dict[str, Any]:
    s, d, auth = live()
    ok, _, tag = allow(d, s, "p")
    replay_ok, _, replay_tag = allow(d, s, "p")
    _, _, args_tag = allow(replace(d, args={"msg": "no"}), s, "p")

    s2, d2, _ = live()
    _, _, principal_tag = allow(d2, s2, "q")
    revoke(s2, "n1", "auth-1", sign_act(auth, "REVOKE", {"nonce": "n1"}))
    _, _, revoked_tag = allow(d2, s2, "p")

    empty = Ledger(t=10, keys={"iss-1": "iss-key"})
    s3, d3, _ = live()
    results: list[str] = []

    def once() -> None:
        won, _, name = allow(d3, s3, "p")
        results.append("ALLOW" if won else name)

    threads = [threading.Thread(target=once) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return {
        "allow": [ok, tag, s.nonce_state["n1"]],
        "replay": [replay_ok, replay_tag],
        "swapped_args": args_tag,
        "wrong_principal": principal_tag,
        "revoked": revoked_tag,
        "non_string_sig": valid_sig(replace(d, sig=12345), s),
        "observes_only": valid_sig(d, empty) and not invoke(d, empty, "p"),
        "concurrent_one_winner": results.count("ALLOW") == 1,
    }


if __name__ == "__main__":
    print(json.dumps(demo(), indent=2))
