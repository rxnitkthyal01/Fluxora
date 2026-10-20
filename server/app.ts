import express, { type Request } from 'express';
import cors from 'cors';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import { db } from './db.js';
import { decryptStored, encryptStored } from './crypto.js';
import { endpointSchema, redactHeaders, redactPayload, redactText, redactUrl, validateReplayUrl, isPublicIp } from './security.js';
import { pubsub } from './pubsub.js';
import { authStatus, changeUserRole, createInitialUser, currentUser, deleteUser, issueSessionForUser, listUsers, loginUser, logout, registerUser, requireAdmin, requireSession } from './auth.js';

export const app = express();

const allowedHosts = new Set((process.env.ALLOWED_HOSTS ?? 'localhost,127.0.0.1,::1').split(',').map(x => x.trim().toLowerCase()).filter(Boolean));
const allowedOrigins = new Set((process.env.CLIENT_ORIGIN ?? 'http://127.0.0.1:5173,http://localhost:5173,http://127.0.0.1:3001,http://localhost:3001').split(',').map(x => x.trim()).filter(Boolean));

app.use((req, res, next) => {
  const host = (req.hostname || '').replace(/^\[|\]$/g, '').toLowerCase();
  if (!allowedHosts.has(host)) return res.status(403).json({ error: 'Host is not allowed' });
  const origin = req.get('origin');
  if (origin && !allowedOrigins.has(origin)) return res.status(403).json({ error: 'Origin is not allowed' });
  next();
});
app.use(cors({ origin(origin, callback) {
  if (!origin || allowedOrigins.has(origin)) return callback(null, true);
  return callback(new Error('Origin is not allowed'));
} }));
app.use(express.json({ limit: '256kb' }));
app.use(express.text({ type: ['text/*', 'application/xml'], limit: '256kb' }));

const requests = new Map<string, { count: number; resetAt: number }>();
const authAttempts = new Map<string, { count: number; resetAt: number }>();
const loginAttempts = new Map<string, { count: number; resetAt: number }>();
app.use((req, res, next) => {
  const key = req.ip || 'local';
  const now = Date.now();
  let entry = requests.get(key);
  if (!entry || entry.resetAt <= now) {
    entry = { count: 0, resetAt: now + 60_000 };
    requests.set(key, entry);
  }
  entry.count += 1;
  if (entry.count > 120) return res.status(429).json({ error: 'Too many requests. Try again shortly.' });
  next();
});

app.get('/api/health', (_req, res) => res.json({ ok: true }));
app.get('/api/auth/status', async (_req, res) => {
  try { res.setHeader('Cache-Control', 'no-store'); res.json(await authStatus()); } catch { res.status(500).json({ error: 'Authentication service unavailable' }); }
});
const limitAuthAttempts: express.RequestHandler = (req, res, next) => {
  const key = req.ip || 'local'; const now = Date.now(); let entry = authAttempts.get(key);
  if (entry?.resetAt && entry.resetAt <= now) { authAttempts.delete(key); entry = undefined; }
  if ((entry?.count ?? 0) >= 10) return res.status(429).json({ error: 'Too many sign-in attempts. Try again in 15 minutes.' });
  next();
};
const loginAttemptKey=(req:express.Request)=>createHash('sha256').update(`${req.ip||'local'}\0${String(req.body?.username??'').trim().toLowerCase().slice(0,128)}`).digest('hex');
const limitLoginAttempts:express.RequestHandler=(req,res,next)=>{const key=loginAttemptKey(req),now=Date.now(),entry=loginAttempts.get(key);if(entry&&entry.resetAt<=now)loginAttempts.delete(key);else if((entry?.count??0)>=8){res.setHeader('Cache-Control','no-store');return res.status(429).json({error:'Too many sign-in attempts for this account. Try again in 15 minutes.'});}next();};
const recordAuthFailure = (req: express.Request) => { const key=req.ip||'local',now=Date.now(),entry=authAttempts.get(key);authAttempts.set(key,entry&&entry.resetAt>now?{...entry,count:entry.count+1}:{count:1,resetAt:now+15*60_000}); };
const recordLoginFailure=(req:express.Request)=>{recordAuthFailure(req);const key=loginAttemptKey(req),now=Date.now(),entry=loginAttempts.get(key);loginAttempts.set(key,entry&&entry.resetAt>now?{...entry,count:entry.count+1}:{count:1,resetAt:now+15*60_000});};
const clearAuthFailures = (req: express.Request) => { authAttempts.delete(req.ip||'local');loginAttempts.delete(loginAttemptKey(req)); };
app.use('/api/auth/login', limitAuthAttempts,limitLoginAttempts);
app.use('/api/auth/setup', limitAuthAttempts);
app.use('/api/auth/register', limitAuthAttempts);
app.post('/api/auth/setup', async (req, res) => {
  try {
    const { username, password, setupKey = '' } = req.body ?? {};
    const user = await createInitialUser(String(username ?? ''), String(password ?? ''), String(setupKey), req.ip ?? '');
    await issueSessionForUser(user.id, req, res);
    clearAuthFailures(req); res.status(201).json({ user });
  } catch (error) { recordAuthFailure(req); res.status(400).json({ error: error instanceof Error ? error.message : 'Account setup failed' }); }
});
app.post('/api/auth/login', async (req, res) => {
  try {
    const user = await loginUser(String(req.body?.username ?? ''), String(req.body?.password ?? ''), req, res);
    clearAuthFailures(req); res.setHeader('Cache-Control', 'no-store'); res.json({ user });
  } catch { recordLoginFailure(req);res.setHeader('Cache-Control','no-store');res.status(401).json({ error: 'Invalid username or password' }); }
});
app.post('/api/auth/register', async (req,res)=>{
  try {const user=await registerUser(String(req.body?.username??''),String(req.body?.password??''));await issueSessionForUser(user.id,req,res);res.status(201).json({user});}
  catch(error){recordAuthFailure(req);res.status(400).json({error:error instanceof Error?error.message:'Account creation failed'});}
});
app.get('/api/auth/me', async (req, res, next) => {
  try { const user = await currentUser(req); if (!user) return res.status(401).json({ error: 'Sign in to access this workspace' }); res.setHeader('Cache-Control', 'no-store'); res.json({ user }); } catch (error) { next(error); }
});
app.post('/api/auth/logout', async (req, res, next) => {
  try { await logout(req, res); res.status(204).end(); } catch (error) { next(error); }
});
app.use('/api', requireSession);
app.use('/api/admin', requireAdmin);
app.get('/api/admin/users',async (_req,res)=>res.json(await listUsers()));
app.patch('/api/admin/users/:id',async (req,res)=>{if(req.params.id===res.locals.user.id&&req.body?.role!=='admin')return res.status(400).json({error:'You cannot remove your own administrator access'});try{res.json(await changeUserRole(req.params.id,String(req.body?.role??'')));}catch(error){res.status(error instanceof Error&&error.message==='User not found'?404:400).json({error:error instanceof Error?error.message:'Could not update user'});}});
app.delete('/api/admin/users/:id',async (req,res)=>{if(req.params.id===res.locals.user.id)return res.status(400).json({error:'You cannot delete your own account'});try{await deleteUser(req.params.id);res.status(204).end();}catch(error){res.status(error instanceof Error&&error.message==='User not found'?404:400).json({error:error instanceof Error?error.message:'Could not delete user'});}});
app.get('/api/events', (req, res) => {
  res.status(200);
  res.set({ 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache, no-transform', Connection: 'keep-alive' });
  res.flushHeaders();
  res.write(': connected\n\n');
  const unsubscribe = pubsub.subscribe((type, data) => {
    if (!res.writableEnded) res.write(`event: ${type}\ndata: ${JSON.stringify(data)}\n\n`);
  });
  const heartbeat = setInterval(() => { if (!res.writableEnded) res.write(': keep-alive\n\n'); }, 25_000);
  req.on('close', () => { clearInterval(heartbeat); unsubscribe(); });
});

type Row = { id:string; name:string; method:string; route:string; status:number; response:string; headers:string; delay:number; timeout_ms:number|null; scenario:string|null; scenario_count:number; created_at:string; updated_at:string };
const stamp=()=>new Date().toISOString();
const parse=(x:string|null|undefined)=>{try{return x?JSON.parse(x):null}catch{return null}};
const safeBody=(x:string|null)=>{try{return JSON.stringify(redactPayload(JSON.parse(x??'null')))}catch{return x}};
const clean=(r:Row)=>({id:r.id,name:r.name,method:r.method,route:r.route,status:r.status,response:parse(decryptStored(r.response)),headers:parse(decryptStored(r.headers)),delay:r.delay,timeoutMs:r.timeout_ms,scenario:parse(decryptStored(r.scenario)),scenarioCount:r.scenario_count,createdAt:r.created_at,updatedAt:r.updated_at});

app.get('/api/endpoints',async (_req,res)=>res.json((await db.prepare('SELECT * FROM endpoints ORDER BY created_at DESC').all()).map(r=>clean(r as Row))));
app.post('/api/endpoints',async (req,res)=>{const v=endpointSchema.safeParse(req.body);if(!v.success)return res.status(400).json({error:'Invalid endpoint configuration',details:v.error.flatten()});const d=v.data,id=randomUUID(),now=stamp();try{await db.prepare('INSERT INTO endpoints(id,name,method,route,status,response,headers,delay,timeout_ms,scenario,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)').run(id,d.name,d.method,d.route,d.status,encryptStored(JSON.stringify(d.response)),encryptStored(JSON.stringify(d.headers)),d.delay,d.timeoutMs??null,d.scenario?encryptStored(JSON.stringify(d.scenario)):null,now,now);const row=clean(await db.prepare('SELECT * FROM endpoints WHERE id=?').get(id) as Row);pubsub.publish('dashboard',{type:'endpoint',endpoint:row});res.status(201).json(row);}catch(e){res.status(409).json({error:'Route already exists'});}});
app.put('/api/endpoints/:id',async (req,res)=>{const v=endpointSchema.safeParse(req.body);if(!v.success)return res.status(400).json({error:'Invalid endpoint configuration'});const d=v.data,now=stamp();const out=await db.prepare('UPDATE endpoints SET name=?,method=?,route=?,status=?,response=?,headers=?,delay=?,timeout_ms=?,scenario=?,updated_at=? WHERE id=?').run(d.name,d.method,d.route,d.status,encryptStored(JSON.stringify(d.response)),encryptStored(JSON.stringify(d.headers)),d.delay,d.timeoutMs??null,d.scenario?encryptStored(JSON.stringify(d.scenario)):null,now,req.params.id);if(!out.changes)return res.status(404).json({error:'Endpoint not found'});res.json(clean(await db.prepare('SELECT * FROM endpoints WHERE id=?').get(req.params.id) as Row));});
app.delete('/api/endpoints/:id',async (req,res)=>{const out=await db.prepare('DELETE FROM endpoints WHERE id=?').run(req.params.id);if(!out.changes)return res.status(404).json({error:'Endpoint not found'});res.status(204).end();});
app.post('/api/endpoints/:id/reset',async (req,res)=>{const out=await db.prepare('UPDATE endpoints SET scenario_count=0 WHERE id=?').run(req.params.id);if(!out.changes)return res.status(404).json({error:'Endpoint not found'});res.json({ok:true});});
app.get('/api/history',async (req,res)=>{
  const q=String(req.query.q??'').trim().slice(0,100).toLowerCase();
  const method=String(req.query.method??'').trim().toUpperCase();
  const status=Number(req.query.status)||0;
  const where:string[]=[];const params:unknown[]=[];
  if(method){where.push('method=?');params.push(method);}
  if(status){where.push('status=?');params.push(status);}
  if(q){const pattern=`%${q.replace(/[!%_]/g,'!$&')}%`;where.push("(LOWER(url) LIKE ? ESCAPE '!' OR history_search_body(request_body) LIKE ? ESCAPE '!')");params.push(pattern,pattern);}
  const sql=`SELECT * FROM history${where.length?` WHERE ${where.join(' AND ')}`:''} ORDER BY created_at DESC LIMIT 300`;
  const rows=await db.prepare(sql).all(...params) as any[];
  const items=rows.map(x=>{const requestHeaders=decryptStored(x.request_headers),requestBody=decryptStored(x.request_body),responseHeaders=decryptStored(x.response_headers),responseBody=decryptStored(x.response_body);return {...x,url:redactUrl(String(x.url).replace(/(\/hooks\/)[A-Za-z0-9_-]{24,64}/,'$1[private id]')),error:x.error?redactText(String(x.error)):null,request_headers:redactHeaders(parse(requestHeaders)??{}),request_body:redactPayload(parse(requestBody)??requestBody),response_headers:redactHeaders(parse(responseHeaders)??{}),response_body:redactPayload(parse(responseBody)??responseBody)}});
  res.json(items);
});
app.get('/api/webhooks',async (_req,res)=>{const rows=await db.prepare('SELECT * FROM webhooks ORDER BY created_at DESC LIMIT 200').all() as any[];res.json(rows.map(x=>({...x,headers:redactHeaders(parse(decryptStored(x.headers))??{}),body:safeBody(decryptStored(x.body)),query:redactPayload(parse(decryptStored(x.query)))})));});
app.get('/api/webhook-endpoints',async (_req,res)=>{const rows=await db.prepare('SELECT e.id,e.created_at,e.revoked_at,COUNT(w.id) AS event_count FROM webhook_endpoints e LEFT JOIN webhooks w ON w.receiver_id=e.id GROUP BY e.id ORDER BY e.created_at DESC LIMIT 100').all() as any[];res.json(rows.map(x=>({id:x.id,createdAt:x.created_at,revokedAt:x.revoked_at,eventCount:x.event_count,active:!x.revoked_at})));});
app.post('/api/webhooks',async (req,res)=>{const token=randomBytes(32).toString('base64url'),id=randomUUID(),createdAt=stamp(),tokenHash=createHash('sha256').update(token).digest('hex');await db.prepare('INSERT INTO webhook_endpoints(id,token_hash,created_at) VALUES(?,?,?)').run(id,tokenHash,createdAt);pubsub.publish('dashboard',{type:'webhook-endpoint'});res.status(201).json({id,url:`${req.protocol}://${req.get('host')}/hooks/${token}`,createdAt});});
app.delete('/api/webhook-endpoints/:id',async (req,res)=>{const out=await db.prepare('UPDATE webhook_endpoints SET revoked_at=? WHERE id=? AND revoked_at IS NULL').run(stamp(),req.params.id);if(!out.changes)return res.status(404).json({error:'Active webhook endpoint not found'});pubsub.publish('dashboard',{type:'webhook-endpoint-revoked'});res.status(204).end();});
app.post('/api/webhooks/:id/replay',async (req,res)=>{const event=await db.prepare('SELECT * FROM webhooks WHERE id=?').get(req.params.id) as any;if(!event)return res.status(404).json({error:'Webhook event not found'});let dest:URL;try{dest=await validateReplayUrl(String(req.body?.destination??''));}catch(e){return res.status(400).json({error:(e as Error).message});}try{const headers=Object.fromEntries(Object.entries(parse(decryptStored(event.headers))??{}).filter(([k])=>!['host','content-length','connection','cookie','authorization','transfer-encoding'].includes(k.toLowerCase())).map(([k,v])=>[k,Array.isArray(v)?v.join(', '):String(v)]));const result=await pinnedReplay(dest,event.method,headers,['GET','HEAD'].includes(event.method)?undefined:decryptStored(event.body)??undefined);res.json({ok:true,status:result.status,statusText:result.statusText});}catch{return res.status(502).json({error:'Replay request failed'});}});
app.all('/hooks/:id',async (req,res)=>{if(!/^[A-Za-z0-9_-]{40,64}$/.test(req.params.id))return res.status(404).end();const receiver=await db.prepare('SELECT id FROM webhook_endpoints WHERE token_hash=? AND revoked_at IS NULL').get(createHash('sha256').update(req.params.id).digest('hex')) as {id:string}|undefined;if(!receiver)return res.status(404).json({error:'Webhook endpoint not found'});const body=typeof req.body==='string'?req.body:Buffer.isBuffer(req.body)?req.body.toString('utf8'):JSON.stringify(req.body??null);const ev={id:randomUUID(),method:req.method,headers:redactHeaders(req.headers),body,query:req.query,ip:'redacted',created_at:stamp()};const headers=encryptStored(JSON.stringify(ev.headers)),encryptedBody=encryptStored(body),query=encryptStored(JSON.stringify(ev.query));await db.prepare('INSERT INTO webhooks(id,receiver_id,method,headers,body,query,ip,created_at) VALUES(?,?,?,?,?,?,?,?)').run(ev.id,receiver.id,ev.method,headers,encryptedBody,query,ev.ip,ev.created_at);await db.prepare('INSERT INTO history(id,kind,method,url,status,request_headers,request_body,response_headers,response_body,duration,error,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)').run(randomUUID(),'webhook',req.method,'/hooks/[private id]',202,encryptStored(JSON.stringify(ev.headers)),encryptStored(body),null,null,0,null,ev.created_at);pubsub.publish('webhook',{id:ev.id,receiverId:receiver.id,method:ev.method,created_at:ev.created_at});res.status(202).json({received:true,id:ev.id});});
// Mock route is deliberately last so application routes cannot be shadowed.
app.all('/mock/*',(req,res)=>runMock(req,res));
app.use((err:unknown,_req:Request,res:express.Response,_next:express.NextFunction)=>{if(err instanceof SyntaxError)return res.status(400).json({error:'Malformed JSON request'});const status=Number((err as {status?:number})?.status);if(status===413)return res.status(413).json({error:'Request body exceeds the 256 KB limit'});res.status(500).json({error:'Internal server error'});});

async function runMock(req:Request,res:express.Response){const path=req.path.replace(/^\/mock/,'')||'/';const row=await db.prepare('SELECT * FROM endpoints WHERE route=? AND method=?').get(path,req.method) as Row|undefined;if(!row)return res.status(404).json({error:'No mock endpoint matches this method and route'});const started=Date.now();let status=row.status,response=parse(decryptStored(row.response)),headers=parse(decryptStored(row.headers))??{},delay=row.delay,timeout=row.timeout_ms;
 try {const scenario=parse(decryptStored(row.scenario));if(scenario&&Array.isArray(scenario.sequence)&&scenario.sequence.length){const count=row.scenario_count;const step=scenario.sequence[Math.min(count,scenario.sequence.length-1)];status=step.status??status;response=step.response??response;headers={...headers,...(step.headers??{})};delay=step.delay??delay;timeout=step.timeoutMs??timeout;await db.prepare('UPDATE endpoints SET scenario_count=scenario_count+1 WHERE id=?').run(row.id);}else if(scenario&&Array.isArray(scenario.conditions)){const hit=scenario.conditions.find((c:any)=>{const x=c.when??{};return(!x.method||x.method===req.method)&&(!x.query||Object.entries(x.query).every(([k,v])=>req.query[k]===v))&&(!x.header||Object.entries(x.header).every(([k,v])=>req.get(k)===v))&&(!x.body||Object.entries(x.body).every(([k,v])=>(req.body as any)?.[k]===v));});if(hit){status=hit.status??status;response=hit.response??response;headers={...headers,...(hit.headers??{})};delay=hit.delay??delay;timeout=hit.timeoutMs??timeout;}}}catch{}
 const finishHistory=async (s:number|null,body:unknown,error:string|null)=>{const st=await db.prepare('INSERT INTO history(id,kind,method,url,status,request_headers,request_body,response_headers,response_body,duration,error,created_at,endpoint_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)'); await st.run(randomUUID(),'api',req.method,redactUrl(req.originalUrl),s,encryptStored(JSON.stringify(redactHeaders(req.headers))),req.body===undefined?null:encryptStored(JSON.stringify(req.body)),encryptStored(JSON.stringify(redactHeaders(headers))),body===undefined?null:encryptStored(JSON.stringify(body)),Date.now()-started,error?redactText(error):null,stamp(),row.id);};
 if(timeout&&timeout>0){setTimeout(async ()=>{await finishHistory(null,null,'Simulated client-side timeout');pubsub.publish('dashboard',{type:'timeout',method:req.method,url:req.originalUrl,status:null});req.socket.destroy();},timeout);return;}
 if(delay)await new Promise(r=>setTimeout(r,delay));for(const [k,v] of Object.entries(headers))if(/^[a-z0-9-]+$/i.test(k))res.setHeader(k,String(v));res.setHeader('X-Mock-Endpoint',row.id);await finishHistory(status,response,null);pubsub.publish('dashboard',{type:'request',method:req.method,url:req.originalUrl,status});res.status(status).json(response);
}
async function pinnedReplay(url:URL,method:string,headers:Record<string,string>,body?:string):Promise<{status:number;statusText:string}>{
 const dns=await import('node:dns/promises');const hostname=url.hostname.replace(/^\[|\]$/g,'');const records=await dns.lookup(hostname,{all:true,verbatim:true});
 if(!records.length||records.some(x=>!isPublicIp(x.address)))throw new Error('Destination no longer resolves only to public addresses');
 const target=records[0];const transport=url.protocol==='https:'?https:http;
 return await new Promise((resolve,reject)=>{const req=transport.request({protocol:url.protocol,hostname:target.address,family:target.family,port:url.port||undefined,path:`${url.pathname}${url.search}`,method,headers:{...headers,host:url.host},servername:url.protocol==='https:'&&net.isIP(hostname)===0?hostname:undefined,timeout:8000},r=>{r.resume();r.on('end',()=>resolve({status:r.statusCode??502,statusText:r.statusMessage??''}));});const timer=setTimeout(()=>req.destroy(new Error('Replay timeout')),8000);req.on('error',e=>{clearTimeout(timer);reject(e)});req.on('close',()=>clearTimeout(timer));if(body)req.write(body);req.end();});
}
