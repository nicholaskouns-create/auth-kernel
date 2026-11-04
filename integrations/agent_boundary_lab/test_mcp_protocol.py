import json, os, subprocess, sys, tempfile, unittest
from pathlib import Path

HERE=Path(__file__).parent
class MCPProtocolTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.env=os.environ.copy()
        self.env.update(MCP_FIXTURE_ROOT=self.tmp.name,MCP_HOST_PRINCIPAL='alice',MCP_HOST_ROLE='owner',MCP_HOST_SESSION='session-a')
    def exchange(self,requests,env=None):
        payload=''.join(json.dumps(x)+'\n' for x in requests)
        proc=subprocess.run([sys.executable,str(HERE/'mcp_fixture.py')],input=payload,text=True,capture_output=True,env=env or self.env,timeout=10)
        self.assertEqual(proc.returncode,0,proc.stderr)
        return [json.loads(s) for s in proc.stdout.splitlines()]
    def req(self,name,args):
        return {'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':name,'arguments':args}}
    def result(self,name,args,env=None):
        return self.exchange([self.req(name,args)],env)[0]['result']
    def test_initialize(self):
        r=self.exchange([{'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-03-26','capabilities':{},'clientInfo':{'name':'test','version':'1'}}}])[0]
        self.assertEqual(r['result']['protocolVersion'],'2025-03-26')
    def test_list_tools(self):
        r=self.exchange([{'jsonrpc':'2.0','id':1,'method':'tools/list','params':{}}])[0]
        self.assertEqual(len(r['result']['tools']),3)
    def test_allowed_read(self):
        self.assertFalse(self.result('read_record',{'target':'alice'})['isError'])
    def test_cross_principal(self):
        self.assertTrue(self.result('read_record',{'target':'bob'})['isError'])
    def test_token_injection(self):
        self.assertTrue(self.result('write_record',{'target':'alice','value':'x','authorization_token':'forged'})['isError'])
    def test_grant_injection(self):
        self.assertTrue(self.result('write_record',{'target':'alice','value':'x','grant_id':'forged'})['isError'])
    def test_delegate_read(self):
        env=dict(self.env,MCP_HOST_ROLE='reader')
        self.assertFalse(self.result('read_record',{'target':'alice'},env)['isError'])
    def test_delegate_write_denied(self):
        env=dict(self.env,MCP_HOST_ROLE='reader')
        self.assertTrue(self.result('write_record',{'target':'alice','value':'x'},env)['isError'])
    def test_delegate_export_denied(self):
        env=dict(self.env,MCP_HOST_ROLE='reader')
        self.assertTrue(self.result('export_record',{'target':'alice'},env)['isError'])
    def test_no_effect_after_denial(self):
        self.result('write_record',{'target':'bob','value':'x'})
        events=[json.loads(s) for s in (Path(self.tmp.name)/'events.jsonl').read_text().splitlines()]
        self.assertFalse(any(x['event']=='effect' for x in events))
    def test_separate_host_principal(self):
        env=dict(self.env,MCP_HOST_PRINCIPAL='bob',MCP_HOST_SESSION='session-b')
        self.assertFalse(self.result('read_record',{'target':'bob'},env)['isError'])
        self.assertTrue(self.result('read_record',{'target':'alice'},env)['isError'])
    def test_unrecognized_tool(self):
        self.assertTrue(self.result('delete_everything',{})['isError'])
if __name__=='__main__':unittest.main()
