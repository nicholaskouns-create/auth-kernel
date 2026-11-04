"""Twenty independent local MCP JSON-RPC trials per selected boundary case."""
import json, os, subprocess, sys, tempfile
from pathlib import Path
ROOT=Path(__file__).parent
CASES=[
 ('allowed_control','read_record',{'target':'alice'},False,'owner'),
 ('cross_principal','read_record',{'target':'bob'},True,'owner'),
 ('token_injection','write_record',{'target':'alice','value':'x','authorization_token':'fake'},True,'owner'),
 ('argument_substitution','write_record',{'target':'bob','value':'x'},True,'owner'),
 ('delegation_write','write_record',{'target':'alice','value':'x'},True,'reader'),
 ('delegation_export','export_record',{'target':'alice'},True,'reader'),
]
results=[]
with tempfile.TemporaryDirectory() as root:
 for name,tool,args,expected_error,role in CASES:
  success=0
  env=os.environ.copy();env.update(MCP_FIXTURE_ROOT=root,MCP_HOST_PRINCIPAL='alice',MCP_HOST_ROLE=role,MCP_HOST_SESSION=f'{name}-batch')
  reqs=[{'jsonrpc':'2.0','id':trial+1,'method':'tools/call','params':{'name':tool,'arguments':args}} for trial in range(20)]
  p=subprocess.run([sys.executable,str(ROOT/'mcp_fixture.py')],input=''.join(json.dumps(req)+'\n' for req in reqs),capture_output=True,text=True,env=env,timeout=10,check=True)
  responses=[json.loads(line)['result'] for line in p.stdout.splitlines()]
  success=sum(resp['isError']==expected_error for resp in responses)
  results.append({'case':name,'expected': 'deny' if expected_error else 'allow','matches':success,'trials':20})
 report={'environment':'local owned stdio JSON-RPC fixture; no OpenAI calls','results':results,'total_matches':sum(x['matches'] for x in results),'total_trials':120}
 (ROOT/'campaign_results.json').write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps(report,indent=2))
