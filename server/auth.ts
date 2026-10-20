import { createHash, randomBytes, scrypt as scryptCallback, timingSafeEqual } from 'node:crypto';
import type { Request, RequestHandler, Response } from 'express';
import net from 'node:net';
import { db } from './db.js';

function derive(password: string, salt: Buffer | string) {
  return new Promise<Buffer>((resolve, reject) => scryptCallback(password, salt, 64, { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 }, (error, key) => error ? reject(error) : resolve(key as Buffer)));
}
const COOKIE = 'fluxora_session';
const SESSION_TTL_MS = 12 * 60 * 60 * 1000;
const hash = (value: string) => createHash('sha256').update(value).digest('hex');
const timestamp = () => new Date().toISOString();

function cookieValue(req: Request) {
  const item = (req.headers.cookie ?? '').split(';').map(x => x.trim()).find(x => x.startsWith(`${COOKIE}=`));
  return item ? decodeURIComponent(item.slice(COOKIE.length + 1)) : '';
}

function setCookie(res: Response, token: string, secure: boolean) {
  res.setHeader('Set-Cookie', `${COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${SESSION_TTL_MS / 1000}${secure ? '; Secure' : ''}`);
}

async function sessionUser(req: Request) {
  const token = cookieValue(req);
  if (!/^[a-f\d]{64}$/i.test(token)) return null;
  const row = await db.prepare('SELECT u.id,u.username,u.role FROM auth_sessions s JOIN auth_users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?').get(hash(token), timestamp()) as { id: string; username: string; role: 'admin'|'user' } | undefined;
  return row ?? null;
}

export const requireSession: RequestHandler = (req, res, next) => {
  void sessionUser(req).then(user => { if(!user)return res.status(401).json({ error: 'Sign in to access this workspace' });res.locals.user=user;next(); }).catch(next);
};
export const requireAdmin: RequestHandler = (_req,res,next)=>res.locals.user?.role==='admin'?next():res.status(403).json({error:'Administrator access required'});

export function validateUsername(username: string) {
  const cleanName=username.trim();
  if(!/^[a-zA-Z0-9._-]{3,48}$/.test(cleanName))throw new Error('Username must be 3 to 48 letters, numbers, dots, underscores, or hyphens');
  return cleanName;
}
export function validatePassword(password: string) {
  if(password.length<12||password.length>128)throw new Error('Use at least 12 characters and no more than 128');
  const variety=[/[a-z]/.test(password),/[A-Z]/.test(password),/\d/.test(password),/[^A-Za-z0-9]/.test(password)].filter(Boolean).length;
  if(variety<3)throw new Error('Use at least 3 of these: lowercase, uppercase, number, and symbol');
}
async function makePasswordHash(password:string){const salt=randomBytes(16);const passwordHash=await derive(password,salt);return{salt:salt.toString('hex'),hash:passwordHash.toString('hex')};}

export async function authStatus() {
  const row = await db.prepare('SELECT COUNT(*) AS count FROM auth_users').get() as { count: number };
  return { setupRequired: row.count === 0, setupKeyRequired: Boolean(process.env.FLUXORA_AUTH_SETUP_KEY) };
}

export async function createInitialUser(username: string, password: string, setupKey: string, ip: string) {
  if (process.env.FLUXORA_ADMIN_USERNAME) throw new Error('The administrator account is provisioned from workspace configuration');
  const cleanName=validateUsername(username);validatePassword(password);
  const requiredKey = process.env.FLUXORA_AUTH_SETUP_KEY;
  if (requiredKey) {
    const expected = Buffer.from(hash(requiredKey), 'hex');
    const received = Buffer.from(hash(setupKey), 'hex');
    if (!timingSafeEqual(expected, received)) throw new Error('Setup key is invalid');
  } else {
    const address = ip.replace(/^::ffff:/, '');
    if (!(net.isIP(address) === 4 && address.startsWith('127.')) && address !== '::1') throw new Error('Set FLUXORA_AUTH_SETUP_KEY before creating an account remotely');
  }
  const credentials=await makePasswordHash(password);
  const user = { id: randomBytes(16).toString('hex'), username: cleanName, role:'admin' as const };
  await db.transaction(async () => {
    const count = await db.prepare('SELECT COUNT(*) AS count FROM auth_users').get() as { count: number };
    if (count.count !== 0) throw new Error('Workspace account has already been created');
    await db.prepare('INSERT INTO auth_users(id,username,password_salt,password_hash,role,created_at) VALUES(?,?,?,?,?,?)').run(user.id, user.username, credentials.salt, credentials.hash, user.role, timestamp());
  });
  return user;
}

export async function registerUser(username:string,password:string){
  const cleanName=validateUsername(username);validatePassword(password);
  const admin=await db.prepare("SELECT id FROM auth_users WHERE role='admin' LIMIT 1").get();
  if(!admin)throw new Error('Workspace setup is not complete');
  const credentials=await makePasswordHash(password),user={id:randomBytes(16).toString('hex'),username:cleanName,role:'user' as const};
  await db.prepare('INSERT INTO auth_users(id,username,password_salt,password_hash,role,created_at) VALUES(?,?,?,?,?,?)').run(user.id,user.username,credentials.salt,credentials.hash,user.role,timestamp());
  return user;
}

export async function seedConfiguredAdmin(){
  const username=process.env.FLUXORA_ADMIN_USERNAME,password=process.env.FLUXORA_ADMIN_PASSWORD;
  const initialized=await db.prepare("SELECT value FROM auth_config WHERE key='configured_admin_initialized'").get();
  if(initialized)return;
  if(!username&&!password)return;
  if(!username||!password)throw new Error('Set both FLUXORA_ADMIN_USERNAME and FLUXORA_ADMIN_PASSWORD for the initial administrator setup');
  const cleanName=validateUsername(username);validatePassword(password);const credentials=await makePasswordHash(password);
  await db.transaction(async()=>{
    const named=await db.prepare('SELECT id FROM auth_users WHERE username=? COLLATE NOCASE').get(cleanName) as {id:string}|undefined;
    const currentAdmin=await db.prepare("SELECT id FROM auth_users WHERE role='admin' ORDER BY created_at LIMIT 1").get() as {id:string}|undefined;
    const target=named??currentAdmin;
    if(!target){await db.prepare('INSERT INTO auth_users(id,username,password_salt,password_hash,role,created_at) VALUES(?,?,?,?,?,?)').run(randomBytes(16).toString('hex'),cleanName,credentials.salt,credentials.hash,'admin',timestamp());return;}
    await db.prepare('DELETE FROM auth_sessions WHERE user_id IN (SELECT id FROM auth_users WHERE role=\'admin\' AND id<>?)').run(target.id);
    await db.prepare("UPDATE auth_users SET role='user' WHERE role='admin' AND id<>?").run(target.id);
    await db.prepare("UPDATE auth_users SET username=?,password_salt=?,password_hash=?,role='admin' WHERE id=?").run(cleanName,credentials.salt,credentials.hash,target.id);
    await db.prepare('DELETE FROM auth_sessions WHERE user_id=?').run(target.id);
    await db.prepare("INSERT INTO auth_config(key,value) VALUES('configured_admin_initialized','true')").run();
  });
}

export async function listUsers(){return db.prepare('SELECT id,username,role,created_at AS createdAt FROM auth_users ORDER BY created_at').all();}
export async function changeUserRole(id:string,role:string){
  if(!['admin','user'].includes(role))throw new Error('Role must be admin or user');
  const user=await db.prepare('SELECT id,role FROM auth_users WHERE id=?').get(id) as {id:string;role:string}|undefined;
  if(!user)throw new Error('User not found');
  if(role==='admin'&&user.role!=='admin')throw new Error('Additional administrator accounts are disabled');
  if(user.role==='admin'&&role==='user'){
    const count=await db.prepare("SELECT COUNT(*) AS count FROM auth_users WHERE role='admin'").get() as {count:number};
    if(count.count<2)throw new Error('The workspace must keep at least one administrator');
  }
  await db.prepare('UPDATE auth_users SET role=? WHERE id=?').run(role,id);
  return db.prepare('SELECT id,username,role,created_at AS createdAt FROM auth_users WHERE id=?').get(id);
}
export async function deleteUser(id:string){
  const user=await db.prepare('SELECT id,role FROM auth_users WHERE id=?').get(id) as {id:string;role:string}|undefined;
  if(!user)throw new Error('User not found');
  if(user.role==='admin'){
    const count=await db.prepare("SELECT COUNT(*) AS count FROM auth_users WHERE role='admin'").get() as {count:number};
    if(count.count<2)throw new Error('The workspace must keep at least one administrator');
  }
  await db.prepare('DELETE FROM auth_sessions WHERE user_id=?').run(id);
  await db.prepare('DELETE FROM auth_users WHERE id=?').run(id);
}

export async function loginUser(username: string, password: string, req: Request, res: Response) {
  const user = await db.prepare('SELECT id,username,password_salt,password_hash,role FROM auth_users WHERE username=? COLLATE NOCASE').get(username.trim()) as { id: string; username: string; password_salt: string; password_hash: string; role:'admin'|'user' } | undefined;
  if (!user || password.length > 128) throw new Error('Invalid username or password');
  const candidate = await derive(password, Buffer.from(user.password_salt, 'hex'));
  const stored = Buffer.from(user.password_hash, 'hex');
  if (stored.length !== candidate.length || !timingSafeEqual(stored, candidate)) throw new Error('Invalid username or password');
  const token = randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + SESSION_TTL_MS).toISOString();
  await db.prepare('DELETE FROM auth_sessions WHERE expires_at<=?').run(timestamp());
  await db.prepare('INSERT INTO auth_sessions(token_hash,user_id,expires_at,created_at) VALUES(?,?,?,?)').run(hash(token), user.id, expiresAt, timestamp());
  setCookie(res, token, req.secure || process.env.COOKIE_SECURE === 'true');
  return { id: user.id, username: user.username, role:user.role };
}

export async function currentUser(req: Request) { return sessionUser(req); }

export async function logout(req: Request, res: Response) {
  const token = cookieValue(req);
  if (/^[a-f\d]{64}$/i.test(token)) await db.prepare('DELETE FROM auth_sessions WHERE token_hash=?').run(hash(token));
  res.setHeader('Set-Cookie', `${COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${req.secure || process.env.COOKIE_SECURE === 'true' ? '; Secure' : ''}`);
}

export async function issueSessionForUser(userId: string, req: Request, res: Response) {
  const token = randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + SESSION_TTL_MS).toISOString();
  await db.prepare('INSERT INTO auth_sessions(token_hash,user_id,expires_at,created_at) VALUES(?,?,?,?)').run(hash(token), userId, expiresAt, timestamp());
  setCookie(res, token, req.secure || process.env.COOKIE_SECURE === 'true');
}
