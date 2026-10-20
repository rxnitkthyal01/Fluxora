import initSqlJs from 'sql.js';
import { createRequire } from 'node:module';
import fs from 'node:fs';
import path from 'node:path';
import { decryptStored, encryptStored } from './crypto.js';
import { redactPayload } from './security.js';

const configured=process.env.DATABASE_PATH??'./data/fluxora.sqlite';
const dbPath=configured===':memory:'?null:path.resolve(configured);
if(dbPath)fs.mkdirSync(path.dirname(dbPath),{recursive:true});
const require=createRequire(import.meta.url);
const SQL=await initSqlJs({locateFile:()=>require.resolve('sql.js/dist/sql-wasm.wasm')});
const raw=dbPath&&fs.existsSync(dbPath)?new SQL.Database(new Uint8Array(fs.readFileSync(dbPath))):new SQL.Database();
raw.create_function('history_search_body',(value:unknown)=>{
  try {
    const decrypted=decryptStored(typeof value==='string'?value:null);
    let parsed:unknown=decrypted;
    if(decrypted!==null){try{parsed=JSON.parse(decrypted);}catch{parsed=decrypted;}}
    return JSON.stringify(redactPayload(parsed)??parsed).toLowerCase();
  } catch { return ''; }
});
let transactionDepth=0;
function persist(){if(!dbPath||transactionDepth)return;const temp=`${dbPath}.tmp`;fs.writeFileSync(temp,Buffer.from(raw.export()));fs.renameSync(temp,dbPath);}
export const db={
  async exec(sql:string){return new Promise<void>((resolve,reject)=>{try{raw.exec(sql);persist();resolve();}catch(e){reject(e);}});},
  async transaction<T>(work:()=>Promise<T>|T):Promise<T>{
    return new Promise(async (resolve,reject)=>{
      raw.run('BEGIN TRANSACTION');
      transactionDepth++;
      try{
        const result=await work();
        raw.run('COMMIT');
        transactionDepth--;
        persist();
        resolve(result);
      }catch(error){
        raw.run('ROLLBACK');
        transactionDepth--;
        reject(error);
      }
    });
  },
  pragma(_sql:string){/* sql.js is an embedded single-connection SQLite database. */},
  prepare(sql:string){return {
    async all(...params:unknown[]){return new Promise<any[]>((resolve,reject)=>{try{const st=raw.prepare(sql);try{st.bind(params as any[]);const rows:any[]=[];while(st.step())rows.push(st.getAsObject());resolve(rows);}finally{st.free();}}catch(e){reject(e);}});},
    async get(...params:unknown[]){return new Promise<any>((resolve,reject)=>{try{const st=raw.prepare(sql);try{st.bind(params as any[]);resolve(st.step()?st.getAsObject():undefined);}finally{st.free();}}catch(e){reject(e);}});},
    async run(...params:unknown[]){return new Promise<{changes:number}>((resolve,reject)=>{try{const st=raw.prepare(sql);try{st.bind(params as any[]);while(st.step()){};}finally{st.free();}const changes=raw.getRowsModified();persist();resolve({changes});}catch(e){reject(e);}});}
  };}
};
await db.exec(`
CREATE TABLE IF NOT EXISTS endpoints (id TEXT PRIMARY KEY, name TEXT NOT NULL, method TEXT NOT NULL, route TEXT NOT NULL, status INTEGER NOT NULL, response TEXT NOT NULL, headers TEXT NOT NULL DEFAULT '{}', delay INTEGER NOT NULL DEFAULT 0, timeout_ms INTEGER, scenario TEXT, scenario_count INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS idx_endpoint_method_route ON endpoints(method, route);
CREATE TABLE IF NOT EXISTS history (id TEXT PRIMARY KEY, kind TEXT NOT NULL, method TEXT NOT NULL, url TEXT NOT NULL, status INTEGER, request_headers TEXT NOT NULL, request_body TEXT, response_headers TEXT, response_body TEXT, duration INTEGER, error TEXT, created_at TEXT NOT NULL, endpoint_id TEXT);
CREATE TABLE IF NOT EXISTS webhook_endpoints (id TEXT PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL, revoked_at TEXT);
CREATE TABLE IF NOT EXISTS webhooks (id TEXT PRIMARY KEY, receiver_id TEXT, method TEXT NOT NULL, headers TEXT NOT NULL, body TEXT, query TEXT NOT NULL, ip TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS auth_users (id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE, password_salt TEXT NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'admin', created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS auth_sessions (token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE, expires_at TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS auth_config (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_history_created ON history(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_history_filter ON history(method,status,kind);
CREATE INDEX IF NOT EXISTS idx_history_method_created ON history(method,created_at DESC);
CREATE INDEX IF NOT EXISTS idx_history_status_created ON history(status,created_at DESC);
CREATE INDEX IF NOT EXISTS idx_webhooks_created ON webhooks(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_expiry ON auth_sessions(expires_at);
`);
if(!((await db.prepare('PRAGMA table_info(auth_users)').all()) as Array<{name:string}>).some(column=>column.name==='role'))await db.exec("ALTER TABLE auth_users ADD COLUMN role TEXT NOT NULL DEFAULT 'admin'");
if(!((await db.prepare('PRAGMA table_info(webhooks)').all()) as Array<{name:string}>).some(column=>column.name==='receiver_id'))await db.exec('ALTER TABLE webhooks ADD COLUMN receiver_id TEXT');
await db.exec('CREATE INDEX IF NOT EXISTS idx_webhooks_receiver_created ON webhooks(receiver_id,created_at DESC)');

// Encrypt older plaintext records in one migration transaction at startup.
const encryptLegacy = (value:string|null) => value === null || value.startsWith('enc:v1:') ? value : encryptStored(value);
await db.transaction(async ()=>{
  for (const row of (await db.prepare('SELECT id,response,headers,scenario FROM endpoints').all()) as Array<{id:string;response:string;headers:string;scenario:string|null}>) {
    if ([row.response, row.headers, row.scenario].every(value => value === null || value.startsWith('enc:v1:'))) continue;
    await db.prepare('UPDATE endpoints SET response=?,headers=?,scenario=? WHERE id=?').run(
      encryptLegacy(row.response), encryptLegacy(row.headers), encryptLegacy(row.scenario), row.id,
    );
  }
  for (const row of (await db.prepare('SELECT id,headers,body,query FROM webhooks').all()) as Array<{id:string;headers:string;body:string|null;query:string}>) {
    if ([row.headers, row.body, row.query].every(value => value === null || value.startsWith('enc:v1:'))) continue;
    await db.prepare('UPDATE webhooks SET headers=?,body=?,query=? WHERE id=?').run(
      encryptLegacy(row.headers), encryptLegacy(row.body), encryptLegacy(row.query), row.id,
    );
  }
  for (const row of (await db.prepare('SELECT id,request_headers,request_body,response_headers,response_body FROM history').all()) as Array<{id:string;request_headers:string;request_body:string|null;response_headers:string|null;response_body:string|null}>) {
    const fields = [row.request_headers, row.request_body, row.response_headers, row.response_body];
    if (fields.every(value => value === null || value.startsWith('enc:v1:'))) continue;
    await db.prepare('UPDATE history SET request_headers=?,request_body=?,response_headers=?,response_body=? WHERE id=?').run(
      encryptLegacy(row.request_headers), encryptLegacy(row.request_body),
      encryptLegacy(row.response_headers), encryptLegacy(row.response_body), row.id,
    );
  }
});
