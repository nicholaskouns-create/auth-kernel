# Authorization kernel

Invoke requires Candidate, the syntactic gate, a live nonce, and an active subject.

A valid signature observes. It does not derive Invoke.

ALLOW spends one nonce under a lock. Refusal does not write.

The issue record stores the canonical JSON body, including arguments. ALLOW re-verifies HMAC-SHA256 before the claim.

```
python auth_kernel.py
```

Rules: `RULES.txt`. Implementation: `auth_kernel.py`.
