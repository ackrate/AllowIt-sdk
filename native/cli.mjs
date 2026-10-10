#!/usr/bin/env node
import {readFile,writeFile,mkdir,lstat} from 'node:fs/promises';
import {resolve,dirname} from 'node:path';
import {Keypair,PublicKey} from '@solana/web3.js';
import {NativePolicySDK,validatePolicy,decimal} from './index.mjs';
import {FileJournal,requireJournalPlatform} from './journal.mjs';
import {PolicyLifecycle} from './lifecycle.mjs';
const usage='allowit policy generate PROMPT | import EXECUTOR_JSON | deploy | fund AMOUNT | execute TOKEN_ACCOUNT AMOUNT | status | revoke | withdraw AMOUNT | tune AMOUNT';
const args=process.argv.slice(2);let json=false;
const clean=[];let literal=false;for(const arg of args){if(arg==='--'&&!literal){literal=true;continue;}if(arg==='--json'&&!literal){json=true;continue;}clean.push(arg);}const command=clean.shift();
const stateDirectory=resolve(process.env.ALLOWIT_POLICY_DIR??'.allowit');
const policyFile=resolve(process.env.ALLOWIT_POLICY_FILE??stateDirectory+'/policy.json');
let journal;
let sdk;
async function loadSigner(name){
 const path=process.env[name];if(!path)throw Error(`Configure ${name} with a dedicated test-network key file`);
 const info=await lstat(path);if(info.isSymbolicLink()||!info.isFile()||info.mode&0o077)throw Error('Signer key file must be a private regular file (0600)');
 const data=JSON.parse(await readFile(path,'utf8'));if(!Array.isArray(data)||data.length!==64||data.some(n=>!Number.isInteger(n)||n<0||n>255))throw Error('Invalid signer file');
 return Keypair.fromSecretKey(Uint8Array.from(data));
}
async function savePolicy(policy){await mkdir(dirname(policyFile),{recursive:true,mode:0o700});try{await writeFile(policyFile,JSON.stringify(policy,null,2)+'\n',{mode:0o600,flag:'wx'});}catch(e){if(e.code==='EEXIST')throw Error('A policy already exists here. Choose a new ALLOWIT_POLICY_DIR; keep the previous policy and journal for recovery.');throw e;}}
async function main(){
 if(!command||['help','--help'].includes(command)){console.log(usage);return;}
 requireJournalPlatform();journal=new FileJournal(stateDirectory+'/journal');
 if(Number(process.versions.node.split('.')[0])<22)throw Error('Node >=22 is required');
 let context=null;try{context=JSON.parse(await readFile(stateDirectory+'/context.json','utf8'));}catch(e){if(e.code!=='ENOENT')throw Error('Unreadable policy context');}
if(context){for(const [name,value]of [['ALLOWIT_NETWORK',context.network],['ALLOWIT_MINT',context.mint],['ALLOWIT_EXECUTOR',context.executor]])if(process.env[name]&&process.env[name]!==value)throw Error('Environment '+name+' differs from the imported policy context');}
sdk=new NativePolicySDK({network:process.env.ALLOWIT_NETWORK??context?.network??'solana:testnet',rpcUrl:process.env.ALLOWIT_RPC_URL??(context?.network==='solana:devnet'?'https://api.devnet.solana.com':'https://api.testnet.solana.com'),mint:process.env.ALLOWIT_MINT??context?.mint,executor:process.env.ALLOWIT_EXECUTOR??context?.executor,deployment:context?.deployment});

 if(command==='import'){
  if(clean.length!==1)throw Error('policy import takes one executor.json path');const bundle=JSON.parse(await readFile(clean[0],'utf8'));
  if(bundle.version!==1||!bundle.context)throw Error('Invalid executor bundle');const policy=await validatePolicy(bundle.policy),c=bundle.context;
  if(c.policyId!==policy.id||c.network!==policy.network||typeof c.owner!=='string')throw Error('Bundle network/owner mismatch');
  const imported=new NativePolicySDK({network:c.network,mint:c.mint,executor:c.executor,deployment:c.deployment});imported.publicBinding(policy,c.owner);
  const canonical=await imported.bundle(policy,c.owner);await journal.locked(async()=>{let present;try{present=await readFile(stateDirectory+'/context.json','utf8');}catch(e){if(e.code!=='ENOENT')throw e;}const text=JSON.stringify(canonical.context,null,2)+'\n';try{await lstat(policyFile);throw Error('A policy already exists here. Choose a new ALLOWIT_POLICY_DIR; keep the previous policy and journal for recovery.');}catch(e){if(e.code!=='ENOENT')throw e;}if(present&&present!==text)throw Error('A different public context already exists here; choose a new policy directory');if(!present)await writeFile(stateDirectory+'/context.json',text,{mode:0o600,flag:'wx'});await savePolicy(policy);});
  console.log(json?JSON.stringify({policyId:policy.id,owner:c.owner,imported:true}):`Imported policy ${policy.id}. Configure only ALLOWIT_EXECUTOR_KEYPAIR on the executor device; never the owner key.`);return;
 }
 if(command==='generate'){
  if(clean.length!==1)throw Error('policy generate takes exactly one prompt');const policy=await sdk.generate(clean[0]);await savePolicy(policy);
  if(json)console.log(JSON.stringify(policy));else console.log(`Policy ${policy.id}\nNetwork: ${policy.network}\nDaily limit: ${policy.dailyLimit} test tokens\n\n${policy.rust}\n\nSaved ${policyFile}`);return;
 }
 const expected={deploy:0,fund:1,execute:2,status:0,revoke:0,withdraw:1,tune:1};
 if(expected[command]===undefined||clean.length!==expected[command])throw Error(usage);
 const policy=await validatePolicy(JSON.parse(await readFile(policyFile,'utf8')));
 if(context&&context.policyId!==policy.id)throw Error('Saved context belongs to a different policy instance');
 const deploymentFile=process.env.ALLOWIT_DEPLOYMENT_FILE;if(deploymentFile){const deployment=JSON.parse(await readFile(deploymentFile,'utf8'));if(context&&['network','sourceBundle','policy','policyData','custody'].some(k=>deployment[k]!==context.deployment[k]))throw Error('Deployment differs from the imported policy context');sdk.config.deployment=deployment;}
 if(!sdk.config.deployment)throw Error('Configure ALLOWIT_DEPLOYMENT_FILE or import the executor bundle');
 const ownerRole=!['execute','status'].includes(command);
 const owner=ownerRole?await loadSigner('ALLOWIT_OWNER_KEYPAIR'):null;
 const ownerAddress=owner?.publicKey.toBase58()??process.env.ALLOWIT_OWNER??context?.owner;
 if(context&&ownerAddress!==context.owner)throw Error('Configured owner differs from the imported policy');
 if(ownerRole&&!context){const bundle=await sdk.bundle(policy,ownerAddress);await mkdir(stateDirectory,{recursive:true,mode:0o700});await writeFile(stateDirectory+'/context.json',JSON.stringify(bundle.context,null,2)+'\n',{mode:0o600,flag:'wx'});}
 if(!ownerAddress)throw Error('Configure ALLOWIT_OWNER with the vault owner public key for execute/status; no owner key is needed');
 const lifecycle=new PolicyLifecycle(sdk,journal,async(tx,role)=>{const signer=role==='executor'?await loadSigner('ALLOWIT_EXECUTOR_KEYPAIR'):owner;if(!signer)throw Error('Owner signing is unavailable in executor mode');if(!tx.feePayer.equals(signer.publicKey))throw Error('Configured signer does not match the prepared fee payer');tx.sign(signer);return tx;});
 if(command==='status'){
  const records=await journal.entries(),operations=[];for(const r of records){try{operations.push(publicResult(await lifecycle.recover(r.id,policy,ownerAddress)));}catch(e){operations.push({id:r.id,status:'uncertain',error:'Saved operation could not be verified against this configuration'});}}
  const last=await journal.read('last');const operation=operations.find(r=>r.id===last?.id)??null;const state=await sdk.state(policy,ownerAddress,true);
  const output={policyId:policy.id,network:policy.network,state,operations,operation};
  if(json)console.log(JSON.stringify(output));else {console.log(`Policy ${policy.id}\n${state?`Vault ${state.vault}\nApproved: ${state.approved}\nBalance: ${decimal(state.balance)}\nSpent today counter: ${decimal(state.spent)}`:'Not deployed'}`);if(operation)console.log(`Last operation: ${operation.status}\n${operation.transactionUrl}`);}return;
 }
 const options=command==='execute'?{recipient:clean[0],amount:clean[1]}:clean.length?{amount:clean[0]}:{};
 if(['fund','withdraw'].includes(command))options.additionalOwnerOperation=process.env.ALLOWIT_ADDITIONAL_OWNER_OPERATION==='1';
 let result=await lifecycle.submit(policy,ownerAddress,command,options,process.env.ALLOWIT_REQUEST_ID);
 const replayed=result.replayed===true;const until=Date.now()+60_000;
 while(!['settled','failed'].includes(result.status)&&result.blockhashExpired!==true&&Date.now()<until){await new Promise(r=>setTimeout(r,1000));result=await lifecycle.recover(result.id,policy,ownerAddress);}
 if(replayed)result={...result,replayed:true};
 const output=publicResult(result);
 if(result.status==='settled'&&command==='deploy'){
  const state=await sdk.state(policy,ownerAddress,true);output.skill=sdk.skill(policy,state);await writeFile(stateDirectory+'/SKILL.md',output.skill,{mode:0o600});
 }
 if(json)console.log(JSON.stringify(output));else {console.log(`Policy ${policy.id}\n${command}: ${result.replayed?'replayed ('+result.status+')':result.status}\nRequest: ${result.id}\n${result.transactionUrl}`);if(output.skill)console.log('\n'+output.skill);}
 if(result.blockhashExpired===true)console.error('The original operation remains uncertain and cannot be broadcast again. For an explicitly additional fund/withdraw, set both a fresh ALLOWIT_REQUEST_ID and ALLOWIT_ADDITIONAL_OWNER_OPERATION=1; retain the old proof.');
 if(result.decisionCode==='EXPIRED_UNEXECUTED')console.error('This request expired without execution. For a deliberate retry, set a new ALLOWIT_REQUEST_ID; keep the original journal.');
 if(result.status==='failed')process.exitCode=20;else if(result.status!=='settled')process.exitCode=5;else if(result.replayed)process.exitCode=6;
}
function publicResult(r){const {signedBytes,intent,...publicFields}=r;return publicFields;}
main().catch(error=>{const message=error instanceof Error?error.message:'Lifecycle failed';console.error(message);process.exitCode=error?.code==='POLICY_DENIED'?20:3;});
