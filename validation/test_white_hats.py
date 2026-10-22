import json
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from white_hats import Store, Transfer


class WhiteHatsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'ledger.db'
        self.s = Store(self.path, clock=lambda: 100)
        self.t = Transfer('task', 'source', 'recipient', 'USD', 10)
        self.s.root('root', 'owner', 'agent', self.t, 100, 200)

    def prepare(self, nonce='n', transfer=None, grant='root', **context):
        args = dict(principal='owner', actor='agent', task='task')
        args.update(context)
        return self.s.prepare(grant, nonce, transfer or self.t, **args)

    def state(self):
        with self.s.transaction() as db:
            return ([tuple(r) for r in db.execute('SELECT id,spent FROM grants ORDER BY id')],
                    [tuple(r) for r in db.execute('SELECT nonce,payload,state FROM outbox ORDER BY nonce')])

    def test_restart_replay_and_rollback(self):
        self.prepare()
        before = self.state()
        self.s = Store(self.path, clock=lambda: 100)
        with self.assertRaises(sqlite3.IntegrityError):
            self.prepare()
        self.assertEqual(self.state(), before)

    def test_scope_and_identity_substitution(self):
        before = self.state()
        for field in ('task', 'account', 'recipient', 'currency'):
            with self.subTest(field=field), self.assertRaises(PermissionError):
                self.prepare(transfer=replace(self.t, **{field: 'other'}))
        for field in ('principal', 'actor', 'task'):
            with self.subTest(field=field), self.assertRaises(PermissionError):
                self.prepare(**{field: 'other'})
        self.assertEqual(self.state(), before)

    def test_invalid_amounts(self):
        for amount in (True, 0, -1, 1.0, float('nan'), 2**63):
            with self.subTest(amount=amount), self.assertRaises(ValueError):
                self.prepare(transfer=replace(self.t, amount=amount))

    def child(self, name='child', **kwargs):
        args = dict(actor='agent', child_actor='worker', budget=100, expires=180)
        args.update(kwargs)
        self.s.delegate('root', name, **args)

    def test_delegation_narrows_and_revocation_cascades(self):
        for args in (dict(budget=101), dict(expires=201), dict(actor='attacker')):
            with self.assertRaises(PermissionError):
                self.child(**args)
        self.child()
        self.prepare(grant='child', actor='worker')
        with self.assertRaises(PermissionError):
            self.s.revoke('root', principal='attacker')
        self.s.revoke('root', principal='owner')
        with self.assertRaises(PermissionError):
            self.prepare('later', grant='child', actor='worker')

    def test_sibling_budgets_are_shared(self):
        self.child('one')
        self.child('two')
        self.prepare('a', replace(self.t, amount=60), 'one', actor='worker')
        before = self.state()
        with self.assertRaises(PermissionError):
            self.prepare('b', replace(self.t, amount=60), 'two', actor='worker')
        self.assertEqual(self.state(), before)

    def test_concurrent_independent_connections_cannot_overspend(self):
        def attempt(i):
            s = Store(self.path, clock=lambda: 100)
            try:
                s.prepare('root', str(i), self.t, principal='owner', actor='agent', task='task')
                return True
            except PermissionError:
                return False
        with ThreadPoolExecutor(max_workers=8) as pool:
            self.assertEqual(sum(pool.map(attempt, range(24))), 10)
        self.assertEqual(self.state()[0], [('root', 100)])

    def test_concurrent_same_nonce(self):
        def attempt(_):
            try:
                self.prepare()
                return True
            except sqlite3.IntegrityError:
                return False
        with ThreadPoolExecutor(max_workers=8) as pool:
            self.assertEqual(sum(pool.map(attempt, range(16))), 1)
        self.assertEqual(self.state()[0], [('root', 10)])

    def test_expired_ancestor(self):
        self.child()
        self.s.clock = lambda: 200
        with self.assertRaises(PermissionError):
            self.prepare(grant='child', actor='worker')

    def test_dispatch_snapshot_crash_retry_idempotency(self):
        self.prepare()
        # A provider commits but its response is lost: retry must use identical data.
        delivered = {}
        calls = []
        def provider(**request):
            calls.append(request)
            key, payload = request['idempotency_key'], request['payload']
            if key in delivered:
                self.assertEqual(delivered[key], payload)
            delivered[key] = payload
            if len(calls) == 1:
                raise TimeoutError('response lost after provider committed')
        with self.assertRaises(TimeoutError):
            self.s.dispatch('n', provider)
        self.s = Store(self.path, clock=lambda: 100)
        self.assertTrue(self.s.dispatch('n', provider))
        self.assertFalse(self.s.dispatch('n', provider))
        self.assertEqual(len(delivered), 1)
        self.assertEqual(calls[0], calls[1])
        self.assertEqual(json.loads(delivered['n']), self.t.__dict__)
        self.assertEqual(self.state()[0], [('root', 10)])

    def test_revocation_does_not_rewrite_committed_dispatch(self):
        self.prepare()
        self.s.revoke('root', principal='owner')
        sent = []
        self.assertTrue(self.s.dispatch('n', lambda **args: sent.append(args)))
        self.assertEqual(json.loads(sent[0]['payload'])['recipient'], 'recipient')


if __name__ == '__main__':
    unittest.main()
