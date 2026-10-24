import {test} from 'node:test';
import assert from 'node:assert/strict';
import {windowsTextComparison,validateNative} from '../clipboard-acceptance.mjs';
import {safeFailure} from '../clipboard-journal.mjs';
test('single password remains strictly equal',()=>{
 assert.equal(windowsTextComparison('synthetic','synthetic').matches,true);
 for(const observed of ['synthetic\n','synthetic ','Synthetic','synthetiç'])assert.equal(windowsTextComparison('synthetic',observed).matches,false);
});
test('multiline conversion changes observation CRLF only',()=>{
 const proof=windowsTextComparison('first\n\nsecond','first\r\n\r\nsecond');assert.equal(proof.matches,true);assert.equal(proof.rawExact,false);
 assert.notEqual(proof.observedSHA256,proof.comparisonSHA256);
 for(const altered of ['first\r\nsecond','first\r\n\r\nseconD','first\r\n\r\nsecond ','first\r\r\n\r\nsecond'])assert.equal(windowsTextComparison('first\n\nsecond',altered).matches,false);
});
test('missing native identity is never success',()=>{
 assert.throws(()=>validateNative(null,{nonce:'synthetic',action:'read',session:{},text:'synthetic'},0,''),e=>e.code==='NATIVE_EVIDENCE_IDENTITY');
});
test('partial diagnostics omit text values',()=>{
 const proof=safeFailure({name:'SyntheticFailure',code:'NATIVE_PROCESS_FAILED',message:'DO_NOT_LOG_SYNTHETIC_VALUE',stage:'native'},'native');
 assert.doesNotMatch(JSON.stringify(proof),/DO_NOT_LOG_SYNTHETIC_VALUE/);
});
