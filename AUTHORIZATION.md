# Reusing the authorization kernel

Issue a candidate for a specific active subject and bind that subject to the requesting principal in the ledger. The signed canonical JSON body includes the verb and arguments. On invocation, require the ledger's subject/principal binding and verify the full body with the same canonicalization used at issuance. The locked allow operation rechecks authentication and state and spends the nonce atomically. Revocation, amnesty and nonce state persist through the shared ledger. Keep invocation and tests on the normal kernel entry point.

For payment integration, carry the authorized transaction details through to the exact downstream operation. A verification result attests to authorization on the kernel boundary. Execution and settlement have their own lifecycle.

From the repository root, run `python validation/authorization_invariant_20261008.py` and `python -m unittest discover -s validation -v`. The first compares the implementation to the reference invariant and the second exercises transaction intent and the other authorization regressions.
