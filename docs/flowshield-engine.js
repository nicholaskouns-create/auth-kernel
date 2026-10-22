/* FlowShield 1.0 deterministic predictive engine. Independent, browser/edge compatible. */
export const OPERATIONS=["read","summarize","send","export","transfer","delegate","approve"];
export function normalizePolicy(p={}){
 const as=(x,fallback)=>Array.isArray(x)?x.map(String):fallback;
 return {actor:String(p.actor||"agent"),task:String(p.task||"audit"),operations:as(p.operations,["read","summarize","send","export","delegate"]),recipients:as(p.recipients,["approved"]),maxDepth:Math.max(1,Math.min(8,Number(p.maxDepth)||4)),maxStates:Math.max(10,Math.min(3000,Number(p.maxStates)||600))};
}
export function transition(state,action,policy){
 const s={...state};
 if(action.actor!==policy.actor||action.task!==policy.task)return {allowed:false,reason:"identity_or_task_drift",state:s};
 if(action.trusted===false)return {allowed:false,reason:"untrusted_instruction_origin",state:s};
 if(!policy.operations.includes(action.operation))return {allowed:false,reason:"operation_out_of_scope",state:s};
 if(["send","export","transfer"].includes(action.operation)&&!policy.recipients.includes(action.recipient))return {allowed:false,reason:"unapproved_destination",state:s};
 if(["send","export"].includes(action.operation)&&s.sensitive)return {allowed:false,reason:"sensitive_flow_requires_explicit_declassification",state:s};
 if(action.operation==="delegate" && !action.delegationBound)return {allowed:false,reason:"unbounded_delegation",state:s};
 if(action.operation==="read" && action.sensitive)s.sensitive=true;
 if(action.operation==="delegate")s.delegated=true;
 if(action.operation==="transfer")s.transferred=true;
 return {allowed:true,reason:"allow",state:s};
}
export function predict(input={}){
 const p=normalizePolicy(input.policy||{}), sequences=Array.isArray(input.sequence)?input.sequence:[];
 const history=[]; let state={sensitive:false,delegated:false,transferred:false};
 for(const action of sequences.slice(0,128)){
  const r=transition(state,action,p);history.push({...r,action}); if(!r.allowed)return {version:"1.0",verdict:"BLOCK",reason:r.reason,history,prediction:explore(p,state),model:"bounded_symbolic"};
  state=r.state;
 }
 return {version:"1.0",verdict:"ALLOW",reason:"allowed_within_modeled_policy",history,prediction:explore(p,state),model:"bounded_symbolic"};
}
export function explore(p0={},initial={sensitive:false,delegated:false,transferred:false}){
 const p=normalizePolicy(p0), ops=p.operations;
 const candidates=[];
 for(const op of ops){
   candidates.push({actor:p.actor,task:p.task,operation:op,recipient:p.recipients[0]||"",trusted:true,delegationBound:true,sensitive:op==="read"});
   if(["send","export","transfer"].includes(op))candidates.push({actor:p.actor,task:p.task,operation:op,recipient:"unapproved",trusted:true});
   if(op==="delegate")candidates.push({actor:p.actor,task:p.task,operation:op,delegationBound:false,trusted:true});
 }
 candidates.push({actor:p.actor,task:p.task,operation:"read",trusted:false});
 const queue=[{state:initial,path:[]}],seen=new Set([JSON.stringify(initial)]),findings=[];
 let visited=0,head=0,truncated=false;
 while(head<queue.length&&visited<p.maxStates){
  const node=queue[head++];visited++;
  if(node.path.length>=p.maxDepth)continue;
  for(const action of candidates){
   const result=transition(node.state,action,p),path=[...node.path,action];
   if(!result.allowed){
    if(!findings.some(f=>f.reason===result.reason))findings.push({reason:result.reason,depth:path.length,trace:path});
   }else{
    const key=JSON.stringify(result.state);
    if(!seen.has(key)){seen.add(key);queue.push({state:result.state,path});}
   }
  }
 }
 if(head<queue.length)truncated=true;
 return {depth:p.maxDepth,visited,uniqueStates:seen.size,findings,complete:!truncated,scope:"abstract candidate actions, not executable exploits"};
}
export const scenarios=[
 {name:"Customer data exfiltration",policy:{actor:"agent",task:"audit",operations:["read","send"],recipients:["approved"]},sequence:[{actor:"agent",task:"audit",operation:"read",sensitive:true,trusted:true},{actor:"agent",task:"audit",operation:"send",recipient:"approved",trusted:true}]},
 {name:"Untrusted instruction injection",policy:{actor:"agent",task:"audit",operations:["read"],recipients:[]},sequence:[{actor:"agent",task:"audit",operation:"read",trusted:false}]},
 {name:"Safe report",policy:{actor:"agent",task:"audit",operations:["read","summarize"],recipients:[]},sequence:[{actor:"agent",task:"audit",operation:"read",sensitive:false,trusted:true},{actor:"agent",task:"audit",operation:"summarize",trusted:true}]},
 {name:"Unbounded delegated access",policy:{actor:"agent",task:"audit",operations:["delegate"],recipients:[]},sequence:[{actor:"agent",task:"audit",operation:"delegate",delegationBound:false,trusted:true}]}
];
