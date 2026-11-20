#!/usr/bin/env python3
"""Build an executable auth-kernel policy artifact with an isolated audit entry point."""
import argparse
from pathlib import Path
from zipfile import ZipFile, ZipInfo

ENTRY_POINT = '''import json
import sys
from dataclasses import replace
from auth_kernel import allow, live, revoke, sign_act, tick


def audit_case(name):
    ledger, record, authority_key = live()
    requester = "p"
    if name == "inactive":
        # Expire the binding without expiring the signed record.
        ledger.bindings[record.subj] = (requester, 0, 10)
    elif name == "wrong_principal":
        requester = "other"
    elif name == "ungranted":
        ledger.grants.clear()
    elif name == "revoked":
        ok, _, _ = revoke(ledger, record.nonce, "auth-1", sign_act(authority_key, "REVOKE", {"nonce": record.nonce}))
        if not ok:
            raise ValueError("Revocation fixture failed")
    elif name == "invalid_signature":
        record = replace(record, sig="")
    elif name == "out_of_scope":
        tick(ledger, record.exp)
    elif name not in {"active", "replay"}:
        raise ValueError("Unknown audit case")
    decisions = [allow(record, ledger, requester)[0]]
    if name == "replay":
        decisions.append(allow(record, ledger, requester)[0])
    return decisions


request = json.load(sys.stdin)
if not isinstance(request, list) or len(request) > 8:
    raise ValueError("Expected up to eight audit cases")
print(json.dumps({case: audit_case(case) for case in request}))
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    source = Path(__file__).resolve().parents[1] / "auth_kernel.py"
    with ZipFile(args.output, "x") as artifact:
        artifact.writestr(ZipInfo("auth_kernel.py"), source.read_bytes())
        artifact.writestr(ZipInfo("__main__.py"), ENTRY_POINT)


if __name__ == "__main__":
    main()
