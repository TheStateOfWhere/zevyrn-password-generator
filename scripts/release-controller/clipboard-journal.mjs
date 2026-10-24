import fs from 'node:fs';import crypto from 'node:crypto';
export function safeFailure(error,stage){return {stage,classification:error.code||error.name||'Error',name:error.name||'Error',messageSHA256:crypto.createHash('sha256').update(String(error.message||'')).digest('hex'),evidence:error.evidence||null,originalFailure:error.originalFailure||null,cleanupFailure:error.cleanupFailure||null};}
export function clipboardJournal(file,identity){
 const fd=fs.openSync(file,'wx',0o600);let sequence=0,closed=false;
 const journal={record(observation){if(closed)throw Object.assign(new Error('DIAGNOSTIC_CLOSED'),{code:'DIAGNOSTIC_WRITE_FAILED'});const row={...observation,schemaVersion:2,authoritative:false,identity,sequence:sequence++,UTC:new Date().toISOString()};try{const bytes=Buffer.from(JSON.stringify(row)+'\n');let offset=0;while(offset<bytes.length){const written=fs.writeSync(fd,bytes,offset,bytes.length-offset);if(written<=0)throw Error('SHORT_DIAGNOSTIC_WRITE');offset+=written;}fs.fsyncSync(fd);}catch(e){throw Object.assign(new Error('DIAGNOSTIC_WRITE_FAILED'),{code:'DIAGNOSTIC_WRITE_FAILED',evidence:{errorName:e.name}});}},close(){if(!closed){closed=true;fs.closeSync(fd);}}};
 try{journal.record({stage:'start',outcome:'IN_PROGRESS'});}catch(e){journal.close();throw e;}return journal;
}
export async function withClipboardJournal(file,identity,action){
 const journal=clipboardJournal(file,identity);let primary=null;
 try{const result=await action(journal);journal.record({stage:'adapter-complete',outcome:'PASS_DIAGNOSTICS_ONLY'});return result;}
 catch(error){primary=error;try{journal.record({stage:'adapter-failure',outcome:'FAIL',failure:safeFailure(error,error.stage||'adapter')});}catch(diagnostic){diagnostic.originalFailure=safeFailure(error,error.stage||'adapter');throw diagnostic;}throw error;}
 finally{try{journal.close();}catch(error){if(primary)primary.cleanupFailure=safeFailure(error,'diagnostic-close');else throw error;}}
}
