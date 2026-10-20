import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const configuredPath = process.env.DATABASE_PATH ?? './data/fluxora.sqlite';
const databasePath = configuredPath === ':memory:' ? null : path.resolve(configuredPath);
const profileDirectory = process.env.LOCALAPPDATA
  ? path.join(process.env.LOCALAPPDATA, 'Fluxora')
  : path.join(process.env.XDG_CONFIG_HOME ?? process.env.HOME ?? process.env.USERPROFILE ?? process.cwd(), '.fluxora');
const keyDirectory = process.env.FLUXORA_KEY_DIRECTORY ?? profileDirectory;
const keyFile = databasePath ? path.join(keyDirectory, 'encryption.key') : null;
const configuredKey = process.env.FLUXORA_ENCRYPTION_KEY;
const configuredHost = (process.env.HOST ?? '127.0.0.1').toLowerCase();
const loopbackHost = ['127.0.0.1', 'localhost', '::1'].includes(configuredHost);

function loadKey(): Buffer {
  if (configuredKey !== undefined) {
    if (!/^[a-f\d]{64}$/i.test(configuredKey)) {
      throw new Error('FLUXORA_ENCRYPTION_KEY must contain exactly 64 hexadecimal characters');
    }
    return Buffer.from(configuredKey, 'hex');
  }

  if (!loopbackHost) throw new Error('FLUXORA_ENCRYPTION_KEY is required when Fluxora binds outside loopback');

  if (!keyFile) return randomBytes(32);
  fs.mkdirSync(path.dirname(keyFile), { recursive: true });
  const readKeyFile = () => {
    const stored = fs.readFileSync(keyFile, 'utf8').trim();
    if (!/^[a-f\d]{64}$/i.test(stored)) throw new Error('Stored Fluxora encryption key is invalid');
    return Buffer.from(stored, 'hex');
  };
  try {
    return readKeyFile();
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }

  const key = randomBytes(32);
  try {
    fs.writeFileSync(keyFile, key.toString('hex'), { flag: 'wx', mode: 0o600 });
    if (process.platform !== 'win32') fs.chmodSync(keyFile, 0o600);
    return key;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
    return readKeyFile();
  }
}

const key = loadKey();
if (key.length !== 32) throw new Error('Stored Fluxora encryption key is invalid');
const prefix = 'enc:v1:';

export function encryptStored(value: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
  return `${prefix}${Buffer.concat([iv, cipher.getAuthTag(), ciphertext]).toString('base64')}`;
}

export function decryptStored(value: string | null): string | null {
  if (value === null || !value.startsWith(prefix)) return value;
  const packed = Buffer.from(value.slice(prefix.length), 'base64');
  if (packed.length < 28) throw new Error('Encrypted Fluxora data is corrupted');
  const decipher = createDecipheriv('aes-256-gcm', key, packed.subarray(0, 12));
  decipher.setAuthTag(packed.subarray(12, 28));
  return Buffer.concat([decipher.update(packed.subarray(28)), decipher.final()]).toString('utf8');
}
