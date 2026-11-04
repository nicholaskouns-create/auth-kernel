import asyncio
import json
import os
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from gate import ExecutionGate, NonceStore, Refused

class GateTests(unittest.TestCase):
    def setUp(self):
        self.g = ExecutionGate(b'a'*32, NonceStore())
        self.calls = []
        self.target = lambda **kw: self.calls.append(kw) or 'ok'
        self.args = {'destination': 'approved', 'amount': 1000}
        self.token = self.g.issue('acct_ops', self.args, 'g1')

    def run_call(self, token=None, args=None, tool='acct_ops', grant='g1'):
        return asyncio.run(self.g.invoke(tool, self.args if args is None else args,
                                         token, grant, self.target))

    def test_authorized(self):
        self.assertEqual(self.run_call(self.token), 'ok')
        self.assertEqual(len(self.calls), 1)

    def test_missing(self):
        with self.assertRaisesRegex(Refused, 'token_missing'): self.run_call()
        self.assertFalse(self.calls)

    def test_argument_substitution(self):
        with self.assertRaisesRegex(Refused, 'args_mismatch'):
            self.run_call(self.token, {'destination':'forbidden','amount':1000})
        self.assertFalse(self.calls)

    def test_replay(self):
        self.run_call(self.token)
        with self.assertRaisesRegex(Refused, 'nonce_spent'): self.run_call(self.token)
        self.assertEqual(len(self.calls), 1)

    def test_wrong_tool(self):
        with self.assertRaisesRegex(Refused, 'scope_mismatch'): self.run_call(self.token, tool='delete')

    def test_wrong_grant(self):
        with self.assertRaisesRegex(Refused, 'scope_mismatch'): self.run_call(self.token, grant='g2')

    def test_tamper(self):
        obj=json.loads(self.token); obj['payload']['tool']='delete'
        with self.assertRaisesRegex(Refused, 'bad_mac'): self.run_call(json.dumps(obj))

    def test_wrong_key(self):
        other=ExecutionGate(b'b'*32, NonceStore())
        with self.assertRaisesRegex(Refused, 'bad_mac'):
            asyncio.run(other.invoke('acct_ops',self.args,self.token,'g1',self.target))

    def test_expired(self):
        obj=json.loads(self.token); obj['payload']['exp']=0
        import hmac,hashlib
        from gate import canonical
        obj['mac']=hmac.new(self.g.key,canonical(obj['payload']),hashlib.sha256).hexdigest()
        with self.assertRaisesRegex(Refused, 'expired'): self.run_call(json.dumps(obj))

    def test_malformed(self):
        with self.assertRaisesRegex(Refused, 'malformed_token'): self.run_call('not-json')

    def test_canonical_dict_order(self):
        self.assertEqual(self.run_call(self.token, {'amount':1000,'destination':'approved'}), 'ok')

    def test_nan_rejected(self):
        with self.assertRaises(ValueError): self.g.issue('x',{'a':float('nan')},'g')

    def test_concurrent_single_use(self):
        with ThreadPoolExecutor(max_workers=8) as pool:
            futures=[pool.submit(self.run_call,self.token) for _ in range(8)]
        self.assertEqual(sum(f.result()=='ok' for f in futures if not f.exception()),1)
        self.assertEqual(len(self.calls),1)

    def test_async_target(self):
        async def target(**kwargs): return kwargs['amount']
        self.assertEqual(asyncio.run(self.g.invoke('acct_ops',self.args,self.token,'g1',target)),1000)

    def test_action_wrapper(self):
        action=self.g.nemo_action('acct_ops',self.target,'g1')
        self.assertEqual(asyncio.run(action(authorization_token=self.token,**self.args)),'ok')

    def test_action_wrapper_no_token(self):
        action=self.g.nemo_action('acct_ops',self.target,'g1')
        with self.assertRaisesRegex(Refused,'token_missing'):
            asyncio.run(action(**self.args))

if __name__ == '__main__': unittest.main()
