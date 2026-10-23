"""FlowShield fail-closed Ed25519 receipt verification and durable nonce consumption.
Requires cryptography package. This is an application verifier, not GitHub OIDC validation.
Do not expose directly to untrusted network callers without authenticated transport and OIDC.
"""
import base64, hashlib, json, sqlite3, time
from datetime import datetime, timezone
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

class SecurityError(Exception): pass

class ReceiptGate:
    def __init__(self, db_path, trusted_keys, allowed_actions):
        if not trusted_keys or not allowed_actions:
            raise SecurityError("explicit trusted keys and actions required")
        self.trusted_keys = trusted_keys
        self.allowed_actions = set(allowed_actions)
        self.db_path = str(db_path)
        with sqlite3.connect(self.db_path, timeout=15) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("""CREATE TABLE IF NOT EXISTS accepted(
              issuer TEXT NOT NULL, nonce TEXT NOT NULL, digest TEXT NOT NULL,
              repo TEXT NOT NULL, commit_sha TEXT NOT NULL, action TEXT NOT NULL,
              accepted_at INTEGER NOT NULL, PRIMARY KEY(issuer,nonce))""")
    def authorize(self, receipt, *, issuer, repo, commit_sha, action, now=None, max_age=300):
        now = int(time.time() if now is None else now)
        if action not in self.allowed_actions: raise SecurityError("action not permitted")
        if issuer not in self.trusted_keys: raise SecurityError("unknown issuer")
        if not isinstance(receipt, dict): raise SecurityError("invalid receipt")
        signature = receipt.get("signature")
        digest = receipt.get("digest")
        body = {k:v for k,v in receipt.items() if k not in ("signature","digest")}
        if body.get("schema") != "e47-signed-tick-v1": raise SecurityError("schema mismatch")
        if body.get("repository") != repo or body.get("commit") != commit_sha:
            raise SecurityError("scope mismatch")
        if not isinstance(body.get("run"), str) or not body["run"]:
            raise SecurityError("run missing")
        if not isinstance(body.get("nonce"), str) or len(body["nonce"]) > 128 or len(body["nonce"]) < 16:
            raise SecurityError("invalid nonce")
        if not isinstance(body.get("tau"), (float,int)) or not (0 <= body["tau"] < 1e12):
            raise SecurityError("invalid clock")
        try:
            observed = datetime.fromisoformat(body["observed_at_utc"].replace("Z","+00:00"))
            if observed.tzinfo is None: raise ValueError("missing timezone")
            if abs(now - observed.timestamp()) > max_age: raise SecurityError("stale receipt")
            if not isinstance(digest,str) or len(digest)!=64: raise ValueError("digest")
            calculated = hashlib.sha256(canonical(body)).hexdigest()
            if calculated != digest: raise SecurityError("digest mismatch")
            public = Ed25519PublicKey.from_public_bytes(base64.b64decode(self.trusted_keys[issuer], validate=True))
            public.verify(base64.b64decode(signature,validate=True), bytes.fromhex(digest))
        except (KeyError,TypeError,ValueError) as e:
            raise SecurityError("invalid receipt encoding") from e
        except Exception as e:
            if isinstance(e, SecurityError): raise
            raise SecurityError("signature invalid") from e
        # BEGIN IMMEDIATE serializes writes; unique constraint is the replay decision.
        with sqlite3.connect(self.db_path, timeout=15, isolation_level=None) as db:
            try:
                db.execute("BEGIN IMMEDIATE")
                db.execute("INSERT INTO accepted VALUES (?,?,?,?,?,?,?)",
                  (issuer,body["nonce"],digest,repo,commit_sha,action,now))
                db.execute("COMMIT")
            except sqlite3.IntegrityError as e:
                db.execute("ROLLBACK")
                raise SecurityError("replayed nonce") from e
        return {"authorized":True,"digest":digest,"issuer":issuer,"action":action}
