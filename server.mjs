import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import {promisify} from 'node:util';
import {fileURLToPath} from 'node:url';
const root=path.dirname(fileURLToPath(import.meta.url)), publicDir=path.join(root,'public'), dataDir=process.env.DATA_DIR||path.join(root,'data');
const pbkdf2=promisify(crypto.pbkdf2), sessions=new Map(), attempts=new Map();
await fs.mkdir(dataDir,{recursive:true});
let users=[];try{users=JSON.parse(await fs.readFile(path.join(dataDir,'accounts.json'),'utf8'));}catch(e){if(e.code!=='ENOENT')throw e;}
let pending=Promise.resolve();
function persist(){pending=pending.catch(()=>{}).then(async()=>{await fs.writeFile(path.join(dataDir,'accounts.tmp'),JSON.stringify(users));await fs.rename(path.join(dataDir,'accounts.tmp'),path.join(dataDir,'accounts.json'));});return pending;}
export function normalizeProgress(p={}){
 const scores={};for(const [id,v] of Object.entries(p.scores||{}).slice(0,100)){if(/^g[0-6]-[0-3]$/.test(id)&&Number.isFinite(Number(v)))scores[id]=Math.max(0,Math.min(100,Math.round(Number(v))));}
 const words={};for(const [id,v] of Object.entries(p.words||{}).slice(0,500)){if(/^g[0-6]-[0-3]-[0-5]$/.test(id))words[id]={right:Math.min(9999,Math.max(0,Math.round(Number(v.right)||0))),wrong:Math.min(9999,Math.max(0,Math.round(Number(v.wrong)||0)))};}
 const days=[...new Set((p.days||[]).filter(d=>/^\d{4}-\d{2}-\d{2}$/.test(d)))].sort().slice(-365);
 return {grade:Math.min(6,Math.max(0,Math.round(Number(p.grade)||0))),nickname:String(p.nickname||'بطل الحديقة').slice(0,30),avatar:['fox','cat','rabbit'].includes(p.avatar)?p.avatar:'fox',scores,words,days};
}
function json(res,status,value){res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'});res.end(JSON.stringify(value));}
function account(req){const sid=(req.headers.cookie||'').split(';').map(s=>s.trim()).find(s=>s.startsWith('eg_session='))?.slice(11);const session=sessions.get(sid);if(!session||session.expires<Date.now()){sessions.delete(sid);return null;}return users.find(u=>u.id===session.uid);}
function createSession(res,user){const sid=crypto.randomBytes(32).toString('hex');sessions.set(sid,{uid:user.id,expires:Date.now()+7*86400000});res.setHeader('Set-Cookie',`eg_session=${sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age=604800`);}
async function body(req){let chunks=[],size=0;for await(const chunk of req){size+=chunk.length;if(size>100000)throw new Error('PAYLOAD');chunks.push(chunk);}return JSON.parse(Buffer.concat(chunks).toString()||'{}');}
const mime={'.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'text/javascript; charset=utf-8','.json':'application/json; charset=utf-8','.webmanifest':'application/manifest+json','.svg':'image/svg+xml'};
const server=http.createServer(async(req,res)=>{
 res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Referrer-Policy','same-origin');res.setHeader('X-Frame-Options','DENY');
 try{
  const url=new URL(req.url,'http://localhost');
  if(url.pathname.startsWith('/api/')){
   if(req.method==='POST'&&req.headers.origin&&new URL(req.headers.origin).host!==req.headers.host)return json(res,403,{error:'طلب غير مسموح.'});
   if(req.method==='POST'&&!(req.headers['content-type']||'').startsWith('application/json'))return json(res,415,{error:'صيغة الطلب غير صحيحة.'});
   if(url.pathname==='/api/me'&&req.method==='GET'){const u=account(req);return json(res,200,u?{account:{email:u.email},progress:u.progress}:{account:null});}
   if(['/api/signup','/api/login'].includes(url.pathname)&&req.method==='POST'){
    const key=req.socket.remoteAddress, now=Date.now();let limit=attempts.get(key);if(!limit||limit.until<now)limit={count:0,until:now+15*60000};attempts.set(key,limit);if(++limit.count>20)return json(res,429,{error:'محاولات كثيرة. حاول مجدداً بعد 15 دقيقة.'});
    const input=await body(req),email=String(input.email||'').trim().toLowerCase(),password=String(input.password||'');
    if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||email.length>150||password.length<8||password.length>128)return json(res,400,{error:'أدخل بريد ولي الأمر وكلمة مرور من 8 أحرف على الأقل.'});
    let user=users.find(u=>u.email===email);
    if(url.pathname==='/api/signup'){
     if(user)return json(res,409,{error:'هذا البريد مسجل. استخدم تسجيل الدخول.'});
     const salt=crypto.randomBytes(16).toString('hex'),hash=(await pbkdf2(password,salt,210000,32,'sha256')).toString('hex');
     if(users.some(u=>u.email===email))return json(res,409,{error:'هذا البريد مسجل بالفعل.'});
     user={id:crypto.randomUUID(),email,salt,hash,progress:normalizeProgress(input.progress)};users.push(user);await persist();
    }else{
     const candidate=await pbkdf2(password,user?.salt||'dummy-verification-salt',210000,32,'sha256');
     if(!user||!crypto.timingSafeEqual(candidate,Buffer.from(user.hash,'hex')))return json(res,401,{error:'البريد أو كلمة المرور غير صحيحة.'});
    }
    createSession(res,user);return json(res,200,{account:{email:user.email},progress:user.progress});
   }
   if(url.pathname==='/api/progress'&&req.method==='POST'){const u=account(req);if(!u)return json(res,401,{error:'سجّل الدخول لحفظ تقدمك في الحساب.'});const input=await body(req),next=normalizeProgress(input.progress);for(const [id,score] of Object.entries(u.progress.scores||{}))next.scores[id]=Math.max(score,next.scores[id]||0);next.days=[...new Set([...(u.progress.days||[]),...next.days])].sort().slice(-365);for(const [id,word] of Object.entries(u.progress.words||{})){next.words[id]={right:Math.max(word.right,next.words[id]?.right||0),wrong:Math.max(word.wrong,next.words[id]?.wrong||0)};}u.progress=next;await persist();return json(res,200,{progress:u.progress});}
   if(url.pathname==='/api/logout'&&req.method==='POST'){const sid=(req.headers.cookie||'').split(';').map(s=>s.trim()).find(s=>s.startsWith('eg_session='))?.slice(11);sessions.delete(sid);res.setHeader('Set-Cookie','eg_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');return json(res,200,{ok:true});}
   return json(res,404,{error:'غير موجود.'});
  }
  if(req.method!=='GET'&&req.method!=='HEAD'){res.writeHead(405);return res.end();}
  const pathname=decodeURIComponent(url.pathname),file=path.resolve(publicDir,'.'+(pathname==='/'?'/index.html':pathname));
  if(!file.startsWith(publicDir+path.sep)){res.writeHead(403);return res.end();}
  let data;try{data=await fs.readFile(file);}catch{res.writeHead(404);return res.end('Not found');}
  res.writeHead(200,{'Content-Type':mime[path.extname(file)]||'application/octet-stream','Cache-Control':'no-cache'});res.end(req.method==='HEAD'?undefined:data);
 }catch(e){console.error(e.message);json(res,e.message==='PAYLOAD'?413:500,{error:'تعذر تنفيذ الطلب. حاول مجدداً.'});}
});
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url))server.listen(Number(process.env.PORT)||8091,'127.0.0.1',()=>console.log('English Garden: http://localhost:'+(process.env.PORT||8091)));
export {server};
