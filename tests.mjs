import test,{after} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {grades,lessons,questionsFor} from './public/content.js';
const temp=await fs.mkdtemp(path.join(os.tmpdir(),'english-garden-test-'));process.env.DATA_DIR=temp;
const {server,normalizeProgress}=await import('./server.mjs');
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));const base=`http://127.0.0.1:${server.address().port}`;
after(async()=>{await new Promise(resolve=>server.close(resolve));await fs.rm(temp,{recursive:true,force:true});});
async function post(route,data,cookie='',origin=base){return fetch(base+'/api/'+route,{method:'POST',headers:{'Content-Type':'application/json',Cookie:cookie,Origin:origin},body:JSON.stringify(data)});}
test('Each stage has complete bilingual activities with unambiguous answers',()=>{
 assert.equal(grades.length,7);assert.equal(lessons.length,28);assert.equal(new Set(lessons.map(l=>l.id)).size,28);
 for(let grade=0;grade<7;grade++)assert.equal(lessons.filter(l=>l.grade===grade).length,4);
 const ids=new Set();for(const l of lessons){assert.equal(l.vocab.length,6);assert.equal(l.dialogue.length,4);assert.ok(l.objective&&l.explanation&&l.sentenceAr);for(const w of l.vocab){assert.ok(w.en&&w.ar&&w.emoji);assert.ok(!ids.has(w.id));ids.add(w.id);}const questions=questionsFor(l);assert.equal(questions.length,8);for(const q of questions){assert.equal(q.options.filter(x=>x===q.answer).length,1);assert.equal(new Set(q.options).size,q.options.length);assert.equal(q.options.length,3);}}
 assert.equal(ids.size,168);
});
test('Progress is bounded and invalid lesson IDs are discarded',()=>{const p=normalizeProgress({grade:999,scores:{'g1-0':500,'g9-0':80},nickname:'x'.repeat(100),words:{'g1-0-0':{right:-2,wrong:Infinity}},avatar:'unknown'});assert.equal(p.grade,6);assert.deepEqual(p.scores,{'g1-0':100});assert.equal(p.nickname.length,30);assert.equal(p.avatar,'fox');assert.equal(p.words['g1-0-0'].right,0);});
test('Parent signup, authentication, progress isolation, logout, password hashing and CSRF',async()=>{
 let response=await post('signup',{email:'parent@example.test',password:'Testing123!',progress:{grade:2,nickname:'مستكشف',scores:{'g2-0':75}}});assert.equal(response.status,200);const cookie=response.headers.get('set-cookie').split(';')[0];assert.match(response.headers.get('set-cookie'),/HttpOnly/);let result=await response.json();assert.equal(result.progress.nickname,'مستكشف');assert.ok(!('hash'in result));
 response=await fetch(base+'/api/me',{headers:{Cookie:cookie}});result=await response.json();assert.equal(result.progress.scores['g2-0'],75);
 response=await post('progress',{progress:{grade:2,scores:{'g2-0':20,'g2-1':100},days:['2026-10-08']}},cookie);assert.equal(response.status,200);result=await response.json();assert.equal(result.progress.scores['g2-0'],75);assert.equal(result.progress.scores['g2-1'],100);
 assert.equal((await post('progress',{progress:{}})).status,401);
 assert.equal((await post('progress',{progress:{}},cookie,'https://evil.example')).status,403);
 assert.equal((await post('signup',{email:'parent@example.test',password:'Testing123!'})).status,409);
 assert.equal((await post('login',{email:'parent@example.test',password:'incorrect!'})).status,401);
 const stored=await fs.readFile(path.join(temp,'accounts.json'),'utf8');assert.ok(!stored.includes('Testing123!'));assert.ok(JSON.parse(stored)[0].hash.length===64);
 assert.equal((await fetch(base+'/data/accounts.json')).status,404);
 assert.equal((await post('logout',{},cookie)).status,200);
 result=await (await fetch(base+'/api/me',{headers:{Cookie:cookie}})).json();assert.equal(result.account,null);
 response=await post('login',{email:'parent@example.test',password:'Testing123!'});assert.equal(response.status,200);result=await response.json();assert.equal(result.progress.scores['g2-1'],100);
 const second=await post('signup',{email:'second@example.test',password:'OtherTest123!'});result=await second.json();assert.deepEqual(result.progress.scores,{});
});
test('All offline-shell assets are served',async()=>{for(const file of ['/','/app.js','/content.js','/style.css','/sw.js','/icon.svg','/manifest.webmanifest'])assert.equal((await fetch(base+file)).status,200);});
