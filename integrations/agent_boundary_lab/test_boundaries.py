import asyncio
import unittest
from boundary_lab import Lab, Principal, Refused

class BoundaryTests(unittest.TestCase):
    def setUp(self):
        self.lab=Lab()
        self.alice=Principal('alice','session-a',frozenset({'read_record','write_record','export_record'}))
        self.bob=Principal('bob','session-b',frozenset({'read_record'}))
        self.child=Principal('alice-child','delegated-1',frozenset({'read_record'}))
        self.args={'record_id':'synthetic-A','destination':'owned-sink'}

    def call(self,host,tool='read_record',args=None):
        return asyncio.run(self.lab.invoke(host,tool,self.args if args is None else args))

    def test_token_injection(self):
        host=self.lab.host_approve(self.alice,'read_record',self.args)
        with self.assertRaisesRegex(Refused,'control_argument_forbidden'):
            self.call(host,args={**self.args,'authorization_token':'forged'})
        self.assertEqual(self.lab.events,[])

    def test_argument_substitution(self):
        host=self.lab.host_approve(self.alice,'read_record',self.args)
        with self.assertRaisesRegex(Refused,'not_host_approved'):
            self.call(host,args={**self.args,'record_id':'synthetic-B'})
        self.assertEqual(self.lab.events,[])

    def test_replay(self):
        host=self.lab.host_approve(self.alice,'read_record',self.args)
        self.call(host)
        with self.assertRaises(Refused): self.call(host)
        self.assertEqual(len(self.lab.events),1)

    def test_cross_session_without_approval(self):
        alice_host=self.lab.host_approve(self.alice,'read_record',self.args)
        bob_host=HostSessionShim(self.lab.gate)
        with self.assertRaisesRegex(Refused,'not_host_approved'):
            self.call(bob_host)
        self.assertEqual(self.lab.events,[])
        self.call(alice_host)

    def test_cross_session_privilege(self):
        with self.assertRaisesRegex(Refused,'principal_not_permitted'):
            self.lab.host_approve(self.bob,'export_record',self.args)
        self.assertEqual(self.lab.events,[])

    def test_delegation_attenuation(self):
        with self.assertRaisesRegex(Refused,'delegate_not_permitted'):
            self.lab.host_approve(self.alice,'write_record',self.args,delegate=self.child)
        self.assertEqual(self.lab.events,[])

    def test_delegated_read_allowed(self):
        host=self.lab.host_approve(self.alice,'read_record',self.args,delegate=self.child)
        self.assertEqual(self.call(host)['status'],'executed')

    def test_model_grant_override(self):
        host=self.lab.host_approve(self.alice,'read_record',self.args)
        with self.assertRaisesRegex(Refused,'control_argument_forbidden'):
            self.call(host,args={**self.args,'grant_id':'admin'})

    def test_wrong_tool(self):
        host=self.lab.host_approve(self.alice,'read_record',self.args)
        with self.assertRaisesRegex(Refused,'not_host_approved'):
            self.call(host,tool='write_record')

    def test_unapproved_mcp_tool(self):
        host=HostSessionShim(self.lab.gate)
        with self.assertRaisesRegex(Refused,'not_host_approved'):
            self.call(host)

    def test_no_host_context(self):
        with self.assertRaisesRegex(Refused,'no_trusted_host_session'):
            asyncio.run(self.lab.actions['read_record'](**self.args))

class HostSessionShim:
    def __init__(self,gate):
        from boundary_lab import HostSession
        self.session=HostSession(gate)
    def activate(self): return self.session.activate()

if __name__=='__main__': unittest.main()
