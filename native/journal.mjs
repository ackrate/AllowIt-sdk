import {mkdir,open,readFile,rename,unlink,rmdir,stat,readdir} from 'node:fs/promises';
import {join} from 'node:path';
import {randomUUID} from 'node:crypto';
export function requireJournalPlatform(){
 if(!['linux','darwin','freebsd','openbsd','netbsd'].includes(process.platform))throw Error('Native file journals require a local POSIX filesystem. On Windows, use Linux/WSL with state in its Linux filesystem, not /mnt/c or /mnt/d. Keep existing journals for recovery; pending operations remain uncertain.');
}
/** Local CLI store. A deployed HTTP gateway must use its own durable transactional store. */
export class FileJournal{
 constructor(directory){requireJournalPlatform();this.directory=directory;}
 async initialize(){await mkdir(this.directory,{recursive:true,mode:0o700});const info=await stat(this.directory);if(info.mode&0o077)throw Error('Journal directory must be private (0700)');}
 async read(name){try{return JSON.parse(await readFile(join(this.directory,name+'.json'),'utf8'));}catch(e){if(e.code==='ENOENT')return null;throw Error('Unreadable journal; recover it before submitting');}}
 async entries(prefix='request-'){await this.initialize();const names=(await readdir(this.directory)).filter(n=>n.startsWith(prefix)&&n.endsWith('.json'));return Promise.all(names.map(n=>this.read(n.slice(0,-5))));}
 async write(name,value){
  const destination=join(this.directory,name+'.json'),temp=destination+'.'+randomUUID();const handle=await open(temp,'wx',0o600);
  try{await handle.writeFile(JSON.stringify(value,null,2)+'\n');await handle.sync();}finally{await handle.close();}
  await rename(temp,destination);const d=await open(this.directory,'r');try{await d.sync();}finally{await d.close();}
 }
 async locked(run){
  await this.initialize();const lock=join(this.directory,'.lock');
  try{await mkdir(lock,{mode:0o700});}catch(e){if(e.code!=='EEXIST')throw e;throw Error('Another lifecycle operation is active, or a crashed process needs journal lock recovery');}
  try{return await run();}finally{await rmdir(lock);}
 }
 async clear(name){await unlink(join(this.directory,name+'.json')).catch(e=>{if(e.code!=='ENOENT')throw e;});}
}
