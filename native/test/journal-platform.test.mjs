import {test} from 'node:test';
import assert from 'node:assert/strict';
import {existsSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {mkdtemp,writeFile,rm} from 'node:fs/promises';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {createServer} from 'node:http';
import {fileURLToPath} from 'node:url';
import {FileJournal,requireJournalPlatform} from '../journal.mjs';

test('unsupported file journal fails before creating state, loading a signer, or contacting RPC',async()=>{
 if(['linux','darwin','freebsd','openbsd','netbsd'].includes(process.platform)){
  assert.doesNotThrow(requireJournalPlatform);return;
 }
 const directory=await mkdtemp(join(tmpdir(),'allowit-platform-'));
 const path=join(directory,'policy'),key=join(directory,'invalid-key.json');
 await writeFile(key,'{"sentinel":"must not be parsed as a signer"}');
 let rpcCalls=0;
 const server=createServer((request,response)=>{rpcCalls++;response.writeHead(500);response.end();});
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 try {
  assert.throws(()=>new FileJournal(path),/local POSIX filesystem/);
  const env={...process.env,ALLOWIT_POLICY_DIR:path,ALLOWIT_OWNER_KEYPAIR:key,ALLOWIT_EXECUTOR_KEYPAIR:key,ALLOWIT_RPC_URL:`http://127.0.0.1:${server.address().port}`};
  for(const args of [['generate','Spend up to 5 test tokens per day'],['deploy'],['execute','unused-recipient','1']]) {
   await assert.rejects(promisify(execFile)(process.execPath,[fileURLToPath(new URL('../cli.mjs',import.meta.url)),...args],{env,timeout:15000}),
    error=>error.code===3&&/local POSIX filesystem/.test(error.stderr));
  }
  assert.equal(rpcCalls,0);
  assert.equal(existsSync(path),false);
 } finally {
  await new Promise(resolve=>server.close(resolve));
  await rm(directory,{recursive:true,force:true});
 }
});
