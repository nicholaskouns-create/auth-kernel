"""Banking argument-binding regression checks against the actual kernel."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import unittest

from auth_kernel import (
    Ledger, Record, allow, bind, grant, issue, register_authority,
    register_issuer, register_schema, register_tool, revoke, sign_act,
    sign_record, tick,
)


class TransactionIntentTests(unittest.TestCase):
    def setUp(self):
        self.s = Ledger()
        # Fixture-only keys, never credentials for an external service.
        register_issuer(self.s, 'issuer', 'test-issuer-key')
        register_authority(self.s, 'authority', 'test-authority-key')
        register_tool(self.s, 'transfer')
        args = dict(task_id='invoice-17', source_account='account-A',
                    recipient='account-B', currency='USD', amount_minor=2500)
        register_schema(self.s, 'transfer', set(args))
        body = dict(subj='agent', principal='alice', nbf=0, exp=100)
        bind(self.s, **body, authority='authority',
             sig=sign_act('test-authority-key', 'BIND', body))
        body = dict(subj='agent', tool='transfer')
        grant(self.s, **body, authority='authority',
              sig=sign_act('test-authority-key', 'GRANT', body))
        tick(self.s, 10)
        self.d = sign_record(Record('agent', 'transfer', args, 'payment-17',
                                    'issuer', 10, 20), 'test-issuer-key')
        self.assertTrue(issue(self.s, self.d)[0])

    def refuse(self, record, requester='alice', reason=None):
        before = dict(self.s.nonce_state)
        ok, _, tag = allow(record, self.s, requester)
        self.assertFalse(ok)
        if reason:
            self.assertEqual(tag, reason)
        self.assertEqual(self.s.nonce_state, before)

    def test_exact_transaction_and_replay(self):
        self.assertTrue(allow(self.d, self.s, 'alice')[0])
        self.assertEqual(self.s.nonce_state['payment-17'], 'SPENT')
        self.refuse(self.d, reason='Fresh')

    def test_each_argument_is_bound_even_if_resigned(self):
        changes = dict(task_id='invoice-18', source_account='account-C',
                       recipient='attacker', currency='EUR', amount_minor=2501)
        for field, value in changes.items():
            for resign in (False, True):
                with self.subTest(field=field, resign=resign):
                    changed = replace(self.d, args={**self.d.args, field: value})
                    if resign:
                        changed = sign_record(changed, 'test-issuer-key')
                    self.refuse(changed, reason='Issued')
        self.assertTrue(allow(self.d, self.s, 'alice')[0])

    def test_extra_or_missing_arguments_refused(self):
        self.refuse(replace(self.d, args={**self.d.args, 'override': True}),
                    reason='Issued')
        self.refuse(replace(self.d, args={k: v for k, v in self.d.args.items()
                                         if k != 'recipient'}), reason='Issued')

    def test_wrong_principal(self):
        self.refuse(self.d, 'mallory', 'Bound')

    def test_expiry_is_exclusive(self):
        tick(self.s, 20)
        self.refuse(self.d, reason='InWindow')

    def test_not_yet_valid(self):
        future = sign_record(replace(self.d, nonce='future', nbf=11),
                             'test-issuer-key')
        self.assertTrue(issue(self.s, future)[0])
        self.refuse(future, reason='InWindow')

    def test_revoked_record(self):
        revoke(self.s, self.d.nonce, 'authority',
               sign_act('test-authority-key', 'REVOKE', {'nonce': self.d.nonce}))
        self.refuse(self.d, reason='Issued')

    def test_signature_required_in_addition_to_issue(self):
        self.refuse(replace(self.d, sig='0' * 64), reason='NotValidSig')

    def test_concurrent_replay_has_one_authorization(self):
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: allow(self.d, self.s, 'alice')[0],
                                    range(32)))
        self.assertEqual(sum(results), 1)


if __name__ == '__main__':
    unittest.main()
