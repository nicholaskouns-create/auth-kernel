/* FlowShield 2.0: pure, bounded authority-chain analysis. No host authority or network access. */
export const VERSION="2.0";
const int=(x,name)=>{if(!Number.isSafeInteger(x)||x<0)throw Error(name+" must be a nonnegative safe integer");return x};
const text=(x,name)=>{if(typeof x!=="string"||!x.trim())throw Error(name+" must be a nonempty string");return x};

export function analyze(input={}){
 const grants=input.grants||[],actions=input.actions||[],limit=Math.min(1000,Math.max(1,input.maxStates||300));
 if(!Array.isArray(grants)||!Array.isArray(actions)||grants.length>100||actions.length>1000)throw Error("Invalid bounded input");
 const by=new Map(),spent=new Map(),trace=[],provenance=[],denials=[];
 for(const g of grants){
  text(g.id,"grant id");if(by.has(g.id))throw Error("duplicate grant "+g.id);
  text(g.principal,"principal");text(g.task,"task");text(g.account,"account");text(g.recipient,"recipient");text(g.currency,"currency");
  int(g.budget,"budget");int(g.expires,"expiry");int(g.issued??0,"issued");
  if(g.expires<(g.issued??0))throw Error("expiry before issue");
  by.set(g.id,g);spent.set(g.id,0);
 }
 function chain(id){
  const out=[],seen=new Set();let g=by.get(id);
  if(!g)throw Error("unknown grant "+id);
  while(g){if(seen.has(g.id))throw Error("delegation cycle");seen.add(g.id);out.push(g);g=g.parent?by.get(g.parent):null;if(out.at(-1).parent&&!g)throw Error("missing parent");}
  return out;
 }
 for(const g of grants){const c=chain(g.id);for(let i=1;i<c.length;i++){const p=c[i],child=c[i-1];for(const k of ["principal","task","account","recipient","currency"])if(child[k]!==p[k])throw Error("delegation expands "+k);if(child.expires>p.expires||child.budget>p.budget|| (child.issued??0)<(p.issued??0))throw Error("delegation expands time or budget");}}
 const used=new Set();
 for(let i=0;i<actions.length;i++){
  const a=actions[i];if(!a||typeof a!=="object"||Array.isArray(a))throw Error("action "+i+" must be an object");const reasons=[];let c=[];
  try{c=chain(a.grant)}catch(e){reasons.push(e.message)}
  if(typeof a.id!=="string"||!a.id.trim()||used.has(a.id))reasons.push("replay_or_missing_action_id");
  if(!Number.isSafeInteger(a.at)||a.at<0)reasons.push("invalid_time");
  if(!Number.isSafeInteger(a.amount)||a.amount<=0)reasons.push("invalid_amount");
  if(a.trusted!==true)reasons.push("untrusted_origin");
  if(a.authenticated!==true)reasons.push("unauthenticated_actor");
  if(c.length){
   const leaf=c[0];
   if(a.actor!==leaf.principal||a.task!==leaf.task||a.account!==leaf.account||a.recipient!==leaf.recipient||a.currency!==leaf.currency)reasons.push("authority_scope_drift");
   if(c.some(g=>g.revoked||a.at< (g.issued??0)||a.at>g.expires))reasons.push("expired_or_revoked_ancestor");
   if(c.some(g=>Number.isSafeInteger(a.amount)&&a.amount>g.budget-spent.get(g.id)))reasons.push("ancestor_budget_exceeded");
  }
  if(c.length&&Number.isSafeInteger(a.amount)&&a.amount>0&&c.some(g=>!Number.isSafeInteger(spent.get(g.id)+a.amount)))reasons.push("unsafe_budget_arithmetic");
  const allow=reasons.length===0;
  if(allow){used.add(a.id);for(const g of c)spent.set(g.id,spent.get(g.id)+a.amount);}
  const record={index:i,id:a.id||null,actor:a.actor||null,grant:a.grant||null,decision:allow?"ALLOW":"BLOCK",reasons,ancestorChain:c.map(g=>g.id),amount:a.amount??null,at:a.at??null,origin:a.origin||"unspecified"};
  trace.push(record);provenance.push({action:a.id||null,origin:record.origin,actor:record.actor,authority:record.ancestorChain,decision:record.decision});
  if(!allow)denials.push({reason:reasons[0],counterexample:trace.slice(0,i+1)});
 }
 const remaining=Object.fromEntries([...spent].map(([id,v])=>[id,by.get(id).budget-v]));
 const forecasts=[];
 for(const g of grants){const c=chain(g.id);forecasts.push({grant:g.id,remaining:Math.min(...c.map(x=>remaining[x.id])),ancestorChain:c.map(x=>x.id),expires:Math.min(...c.map(x=>x.expires))})}
 return {version:VERSION,model:"deterministic_authority_chain",verdict:denials.length?"BLOCK":"ALLOW",trace,denials,provenance,remaining,forecasts,complete:actions.length<=limit,scope:"provided actions and grants; not live transactions",exploration:{visited:Math.min(actions.length,limit),truncated:actions.length>limit,mode:"supplied_sequence_only"}};
}
export const example={
 grants:[{id:"root",principal:"agent-A",task:"invoice",account:"acct-1",recipient:"vendor-1",currency:"USD",budget:10000,issued:0,expires:100},{id:"child",parent:"root",principal:"agent-A",task:"invoice",account:"acct-1",recipient:"vendor-1",currency:"USD",budget:8000,issued:10,expires:90}],
 actions:[{id:"pay-1",grant:"child",actor:"agent-A",task:"invoice",account:"acct-1",recipient:"vendor-1",currency:"USD",amount:6000,at:20,trusted:true,authenticated:true,origin:"invoice:123"},{id:"pay-2",grant:"child",actor:"agent-A",task:"invoice",account:"acct-1",recipient:"vendor-1",currency:"USD",amount:3000,at:21,trusted:true,authenticated:true,origin:"invoice:124"}]
};
