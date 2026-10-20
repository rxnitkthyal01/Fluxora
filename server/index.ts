import './env.js';
import { app } from './app.js';
import { seedConfiguredAdmin } from './auth.js';
const port=Number(process.env.PORT??3001);
const host=process.env.HOST??'127.0.0.1';
const isLoopback=['127.0.0.1','localhost','::1'].includes(host.toLowerCase());
if(!isLoopback){
  const missing=['FLUXORA_ENCRYPTION_KEY','FLUXORA_ADMIN_USERNAME','FLUXORA_ADMIN_PASSWORD','CLIENT_ORIGIN','ALLOWED_HOSTS'].filter(key=>!process.env[key]?.trim());
  if(missing.length)throw new Error(`Non-loopback deployment requires: ${missing.join(', ')}`);
  if(process.env.COOKIE_SECURE!=='true')throw new Error('Non-loopback deployment requires COOKIE_SECURE=true behind an HTTPS reverse proxy');
  if(process.env.TRUST_PROXY!=='1')throw new Error('Set TRUST_PROXY=1 only when a trusted HTTPS reverse proxy sanitizes forwarded headers');
}
if(process.env.TRUST_PROXY==='1')app.set('trust proxy',1);
await seedConfiguredAdmin();
app.listen(port,host,()=>console.log(`Fluxora API listening on ${host}:${port}`));
