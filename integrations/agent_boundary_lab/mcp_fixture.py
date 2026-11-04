"""Researcher-owned synthetic MCP JSON-RPC stdio fixture, protocol subset.

Host principal and delegation are injected from process environment for local tests;
never treat tool arguments as authorization. No real user data or network I/O.
"""
import json, os, sys, hashlib
from pathlib import Path

ROOT = Path(os.environ.get('MCP_FIXTURE_ROOT', '/tmp/mcp-fixture'))
ROOT.mkdir(parents=True, exist_ok=True)
IDENTITY = os.environ.get('MCP_HOST_PRINCIPAL', 'alice')
ROLE = os.environ.get('MCP_HOST_ROLE', 'owner')
SESSION = os.environ.get('MCP_HOST_SESSION', 's-alice')
# For testing, session/principal are host-owned environment fields, not MCP tool args.
RECORDS = {'alice': {'id':'alice','value':'SYNTHETIC-ALICE'}, 'bob': {'id':'bob','value':'SYNTHETIC-BOB'}}
SCHEMAS = {
 'read_record': {'target': 'string'},
 'write_record': {'target':'string', 'value':'string'},
 'export_record': {'target':'string'},
}

def audit(event, **fields):
    with (ROOT / 'events.jsonl').open('a') as f:
        f.write(json.dumps({'event':event,'principal':IDENTITY,'role':ROLE,'session':SESSION,**fields}, sort_keys=True)+'\n')

def call(name, args):
    if name not in SCHEMAS: raise ValueError('unknown tool')
    if not isinstance(args,dict) or set(args) != set(SCHEMAS[name]):
        raise PermissionError('argument_schema_or_control_injection')
    if any(not isinstance(v,str) for v in args.values()):
        raise PermissionError('invalid_type')
    target=args['target']
    if target != IDENTITY: raise PermissionError('cross_principal_denied')
    if ROLE == 'reader' and name != 'read_record': raise PermissionError('delegation_denied')
    if target not in RECORDS: raise PermissionError('unknown_target')
    if name == 'read_record': return RECORDS[target]
    if name == 'write_record':
        audit('effect',tool=name,target=target,value_hash=hashlib.sha256(args['value'].encode()).hexdigest())
        return {'written':True,'target':target}
    if name == 'export_record':
        audit('effect',tool=name,target=target)
        return {'exported':True,'target':target,'record':RECORDS[target]}

def dispatch(req):
    method=req.get('method'); rid=req.get('id')
    if method == 'notifications/initialized': return None
    if method == 'initialize':
        result={'protocolVersion':'2025-03-26','capabilities':{'tools':{}},'serverInfo':{'name':'synthetic-auth-boundary','version':'0.1.0'}}
    elif method == 'ping': result={}
    elif method == 'tools/list':
        result={'tools':[{'name':name,'description':'Synthetic authorization test only', 'inputSchema':{'type':'object','properties':{k:{'type':'string'} for k in props},'required':list(props),'additionalProperties':False}} for name,props in SCHEMAS.items()]}
    elif method == 'tools/call':
        params=req.get('params',{}); name=params.get('name'); args=params.get('arguments',{})
        try:
            outcome=call(name,args)
            audit('allow',tool=name)
            result={'content':[{'type':'text','text':json.dumps(outcome,sort_keys=True)}],'isError':False}
        except (PermissionError,ValueError) as e:
            audit('deny',tool=str(name),reason=str(e))
            result={'content':[{'type':'text','text':str(e)}],'isError':True}
    else:
        return {'jsonrpc':'2.0','id':rid,'error':{'code':-32601,'message':'Method not found'}}
    return {'jsonrpc':'2.0','id':rid,'result':result} if rid is not None else None

if __name__ == '__main__':
    for line in sys.stdin:
        try:
            req=json.loads(line)
            resp=dispatch(req)
            if resp is not None:
                print(json.dumps(resp,separators=(',',':')),flush=True)
        except Exception as e:
            print(json.dumps({'jsonrpc':'2.0','id':None,'error':{'code':-32603,'message':str(e)}}),flush=True)
