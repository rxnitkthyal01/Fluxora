import dns from 'node:dns/promises';
import net from 'node:net';
import { z } from 'zod';

export const methods = ['GET', 'POST', 'PUT', 'DELETE'] as const;
export const statuses = [200, 201, 202, 400, 404, 429, 500] as const;
const safeHeaders=z.record(z.string().regex(/^[a-zA-Z0-9-]{1,100}$/),z.string().max(1000).refine(v=>!/[\r\n]/.test(v)));
const scenarioStatus=z.number().int().refine(x=>statuses.includes(x as any));
const scenarioStep=z.object({status:scenarioStatus.optional(),response:z.unknown().optional(),headers:safeHeaders.optional(),delay:z.number().int().min(0).max(Number(process.env.MAX_DELAY_MS??10000)).optional(),timeoutMs:z.number().int().min(0).max(15000).nullable().optional()}).strict();
const scenarioSchema=z.union([z.object({sequence:z.array(scenarioStep).min(1).max(100)}).strict(),z.object({conditions:z.array(z.object({when:z.object({method:z.enum(methods).optional(),query:z.record(z.string(),z.string()).optional(),header:z.record(z.string(),z.string()).optional(),body:z.record(z.string(),z.unknown()).optional()}).strict(),status:scenarioStatus.optional(),response:z.unknown().optional(),headers:safeHeaders.optional(),delay:z.number().int().min(0).max(Number(process.env.MAX_DELAY_MS??10000)).optional(),timeoutMs:z.number().int().min(0).max(15000).nullable().optional()}).strict()).max(100)}).strict()]);
export const endpointSchema = z.object({ name: z.string().trim().min(1).max(80), method: z.enum(methods), route: z.string().trim().regex(/^\/[a-zA-Z0-9_./:-]*$/).max(160).refine(x => !x.includes('..') && !x.includes('//')), status: scenarioStatus, response: z.unknown(), headers: safeHeaders.default({}), delay: z.number().int().min(0).max(Number(process.env.MAX_DELAY_MS??10000)).default(0), timeoutMs: z.number().int().min(0).max(15000).nullable().optional(), scenario: scenarioSchema.nullable().optional() });
const blockedV4 = (ip: string) => { const p=ip.split('.').map(Number); return p[0]===10 || p[0]===127 || p[0]===0 || (p[0]===169&&p[1]===254) || (p[0]===172&&p[1]>=16&&p[1]<=31) || (p[0]===192&&(p[1]===168||p[1]===0||p[1]===2)) || (p[0]===198&&(p[1]===18||p[1]===19||p[1]===51&&p[2]===100)) || (p[0]===203&&p[1]===0&&p[2]===113) || (p[0]===192&&p[1]===88&&p[2]===99) || p[0]>=224 || (p[0]===100&&p[1]>=64&&p[1]<=127); };
export function isPublicIp(ip: string) {
  const version=net.isIP(ip);
  if(version===4)return !blockedV4(ip);
  if(version!==6)return false;
  let lower=ip.toLowerCase();
  const mapped=lower.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/);
  if(mapped)return net.isIP(mapped[1])===4&&!blockedV4(mapped[1]);
  const dottedTail=lower.match(/(\d{1,3}(?:\.\d{1,3}){3})$/);
  if(dottedTail){const octets=dottedTail[1].split('.').map(Number);if(octets.some(x=>x<0||x>255))return false;const high=((octets[0]<<8)|octets[1]).toString(16),low=((octets[2]<<8)|octets[3]).toString(16);lower=lower.replace(dottedTail[1],`${high}:${low}`);}
  const [left,right='']=lower.split('::');
  const parseHalf=(half:string)=>half?half.split(':').map(part=>Number.parseInt(part,16)):[];
  const lhs=parseHalf(left),rhs=parseHalf(right);
  const missing=8-lhs.length-rhs.length;
  if(missing<0)return false;
  const words=[...lhs,...Array(missing).fill(0),...rhs];
  if(words.length!==8)return false;
  const first=words[0],second=words[1];
  // Only global unicast space is eligible for external replay. Exclude
  // transition and documentation blocks that can encapsulate private IPv4.
  if(first<0x2000||first>0x3fff||first===0x2002)return false;
  if(first===0x2001&&(second<=0x01ff||second===0x0db8))return false;
  if(first===0x3fff&&(second&0xfff0)===0)return false;
  return true;
}
export async function validateReplayUrl(raw: string) {
  let u: URL; try { u=new URL(raw); } catch { throw new Error('Enter a valid destination URL'); }
  if(!['http:','https:'].includes(u.protocol) || u.username || u.password) throw new Error('Only HTTP(S) destinations without embedded credentials are allowed');
  if(u.hostname==='localhost' || u.hostname.endsWith('.localhost') || u.hostname.endsWith('.local')) throw new Error('Private and local network destinations are blocked');
  const hostname=u.hostname.replace(/^\[|\]$/g,'');const literal=net.isIP(hostname);
  const addresses=literal ? [{address:hostname}] : await dns.lookup(hostname,{all:true,verbatim:true}).catch(()=>[]);
  if(!addresses.length || addresses.some(x=>!isPublicIp(x.address))) throw new Error('Destination must resolve only to public IP addresses');
  return u;
}
const sensitiveWords = new Set(['auth', 'authorization', 'password', 'passwd', 'passphrase', 'secret', 'token', 'credential', 'cookie', 'signature', 'key', 'privatekey', 'publickey', 'apikey', 'accesskey', 'session', 'jwt', 'bearer', 'clientsecret']);
const normalizedKey = (key: string) => key.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, '');
export function isSensitiveField(key: string) {
  const normalized = normalizedKey(key);
  const parts = normalized.split('_').filter(Boolean);
  return parts.some(part => sensitiveWords.has(part) || sensitiveWords.has(part.replace(/s$/, ''))) ||
    /(^|_)(api|access|refresh|private|public|client|proxy|set)_?(key|token|secret|cookie|authorization|credential|signature)(_|$)/.test(normalized) ||
    /(^|_)(pass(word|wd)?|secret|token|credential|authorization|cookie|signature|session|jwt)(_|$)/.test(normalized);
}

export function redactText(value: string) {
  return value
    .replace(/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/-]+=*/gi, '$1 [REDACTED]')
    .replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, '[REDACTED JWT]')
    .replace(/-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |)PRIVATE KEY-----/g, '[REDACTED PRIVATE KEY]')
    .replace(/((?:api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|password|passwd|secret|token|authorization|credential)\s*[=:]\s*)([^\s&,;]+)/gi, '$1[REDACTED]');
}

export function redactUrl(raw: string) {
  try {
    const relative = !/^[a-z][a-z\d+.-]*:\/\//i.test(raw);
    const url = new URL(raw, 'http://fluxora.invalid');
    for (const key of [...url.searchParams.keys()]) if (isSensitiveField(key)) url.searchParams.set(key, '[REDACTED]');
    const value = relative ? `${url.pathname}${url.search}${url.hash}` : url.toString();
    return redactText(value).replace(/%5B/gi, '[').replace(/%5D/gi, ']').replace(/%20/gi, ' ');
  } catch { return redactText(raw); }
}

export function redactHeaders(headers: Record<string, string | string[] | undefined>): Record<string, string | string[]> {
  const result: Record<string, string | string[]> = {};
  for (const [key, value] of Object.entries(headers)) {
    if (isSensitiveField(key)) result[key] = '[REDACTED]';
    else if (Array.isArray(value)) result[key] = value.map(v => typeof v === 'string' ? redactText(v) : '[REDACTED]');
    else if (typeof value === 'string') result[key] = redactText(value);
    else result[key] = '[REDACTED]';
  }
  return result;
}

export function redactPayload(data: any): any {
  if (typeof data === 'string') return redactText(data);
  if (data === null || typeof data !== 'object') return data;
  if (Array.isArray(data)) return data.map(redactPayload);
  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(data)) result[key] = isSensitiveField(key) ? '[REDACTED]' : redactPayload(value);
  return result;
}
