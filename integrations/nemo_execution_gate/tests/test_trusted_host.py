import asyncio
import unittest
from gate import ExecutionGate, NonceStore, Refused
from trusted_host import HostSession, nemo_host_action

class TrustedHostTests(unittest.TestCase):
    def setUp(self):
        self.gate = ExecutionGate(b'c'*32, NonceStore())
        self.calls = []
        self.action = nemo_host_action(self.gate, 'transfer', lambda **kw: self.calls.append(kw) or 'ok')
        self.args = {'destination': 'approved', 'amount': 10}

    def call(self, **kw):
        return asyncio.run(self.action(**kw))

    def test_host_approved(self):
        host = HostSession(self.gate)
        host.approve('transfer', self.args, 'grant1')
        with host.activate():
            self.assertEqual(self.call(**self.args), 'ok')
        self.assertEqual(len(self.calls), 1)

    def test_no_session(self):
        with self.assertRaisesRegex(Refused, 'no_trusted_host_session'):
            self.call(**self.args)

    def test_unapproved(self):
        with HostSession(self.gate).activate():
            with self.assertRaisesRegex(Refused, 'not_host_approved'):
                self.call(**self.args)

    def test_model_token_injection_rejected(self):
        host = HostSession(self.gate)
        host.approve('transfer', self.args, 'grant1')
        with host.activate():
            with self.assertRaisesRegex(Refused, 'control_argument_forbidden'):
                self.call(**self.args, authorization_token='forged')
        self.assertFalse(self.calls)

    def test_model_grant_injection_rejected(self):
        with HostSession(self.gate).activate():
            with self.assertRaisesRegex(Refused, 'control_argument_forbidden'):
                self.call(**self.args, grant_id='grant1')

    def test_argument_change_rejected(self):
        host = HostSession(self.gate)
        host.approve('transfer', self.args, 'grant1')
        with host.activate():
            with self.assertRaisesRegex(Refused, 'not_host_approved'):
                self.call(destination='other', amount=10)

    def test_replay_rejected(self):
        host = HostSession(self.gate)
        host.approve('transfer', self.args, 'grant1')
        with host.activate():
            self.call(**self.args)
            with self.assertRaisesRegex(Refused, 'not_host_approved'):
                self.call(**self.args)
        self.assertEqual(len(self.calls), 1)

    def test_session_not_leaked(self):
        host = HostSession(self.gate)
        host.approve('transfer', self.args, 'grant1')
        with host.activate():
            pass
        with self.assertRaisesRegex(Refused, 'no_trusted_host_session'):
            self.call(**self.args)

    def test_cross_gate_rejected(self):
        other = ExecutionGate(b'd'*32, NonceStore())
        with HostSession(other).activate():
            with self.assertRaisesRegex(Refused, 'no_trusted_host_session'):
                self.call(**self.args)

    def test_duplicate_approval_rejected(self):
        host = HostSession(self.gate)
        host.approve('transfer', self.args, 'grant1')
        with self.assertRaisesRegex(ValueError, 'duplicate approval'):
            host.approve('transfer', self.args, 'grant2')

    def test_nested_session_rejected(self):
        with HostSession(self.gate).activate():
            with self.assertRaisesRegex(RuntimeError, 'nested'):
                with HostSession(self.gate).activate():
                    pass

    def test_async_target(self):
        async def target(**kw): return kw['amount']
        action = nemo_host_action(self.gate, 'async_transfer', target)
        host = HostSession(self.gate)
        host.approve('async_transfer', self.args, 'grant1')
        with host.activate():
            self.assertEqual(asyncio.run(action(**self.args)), 10)

if __name__ == '__main__': unittest.main()
