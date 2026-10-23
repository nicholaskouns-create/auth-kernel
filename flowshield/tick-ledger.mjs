// FlowShield tick-signed transaction ledger. Node.js >=20, ESM.
// Supply a persistent signing key, durable append-only store, and trusted clock attestation in production.
import {createHash, sign, verify, generateKeyPairSync} from 'node:crypto';
const canonical = x => JSON.stringify(x, Object.keys(x).sort());
const hash = x => createHash('sha256').update(x).digest('hex');
export class TickLedger {
 constructor({privateKey, publicKey, clockTick, append, clockSource='host-unattested'}) {
  Object.assign(this,{privateKey,publicKey,clockTick,append,clockSource});
  this.sequence=0; this.previousHash='0'.repeat(64); this.lastMono=process.hrtime.bigint();
 }
 async record({actor,action,transactionId,payload,telemetry={}}) {
  if(!actor||!action||!transactionId) throw Error('identity, action and transactionId required');
  const now=process.hrtime.bigint(); if(now<this.lastMono) throw Error('monotonic clock reversal');
  const tick=await this.clockTick();
  if(!Number.isSafeInteger(tick)||tick<0) throw Error('invalid quantum clock tick');
  const receipt={version:1,sequence:this.sequence+1,transactionId,actor,action,
   timestamp:new Date().toISOString(),monotonicNs:now.toString(),tick,
   clockSource:this.clockSource,payloadHash:hash(canonical(payload)),
   telemetryHash:hash(canonical(telemetry)),previousHash:this.previousHash};
  const digest=hash(canonical(receipt));
  const signature=sign(null,Buffer.from(digest,'hex'),this.privateKey).toString('base64');
  const event={...receipt,digest,signature};
  await this.append(event); // append MUST durably persist before acknowledging transaction
  this.sequence++;this.previousHash=digest;this.lastMono=now;
  return event;
 }
 static verify(event,publicKey) {
  const {digest,signature,...receipt}=event;
  return hash(canonical(receipt))===digest &&
   verify(null,Buffer.from(digest,'hex'),publicKey,Buffer.from(signature,'base64'));
 }
}
export function demoKeys(){return generateKeyPairSync('ed25519');}
