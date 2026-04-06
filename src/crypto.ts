import { createHash, generateKeyPairSync, sign, verify, randomBytes } from 'node:crypto';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import type { KeyPair } from './types.ts';

// ── SHA-256 Hashing ──

export function sha256(data: string | Uint8Array): string {
  const hash = createHash('sha256');
  hash.update(data);
  return hash.digest('hex');
}

// ── Ed25519 Key Management ──

export function generateKeyPair(): KeyPair {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
  });

  const keyId = computeKeyId(publicKey);

  return {
    privateKey: new Uint8Array(privateKey),
    publicKey: new Uint8Array(publicKey),
    keyId,
  };
}

export function computeKeyId(publicKey: Uint8Array): string {
  return sha256(publicKey).slice(0, 16);
}

// ── Signing ──

export function signHash(hash: string, privateKeyDer: Uint8Array): string {
  const hashBytes = Buffer.from(hash, 'hex');
  const signature = sign(
    null, // Ed25519 doesn't use a separate hash algorithm
    hashBytes,
    { key: Buffer.from(privateKeyDer), format: 'der', type: 'pkcs8' },
  );
  return signature.toString('base64');
}

// ── Verification ──

export function verifySignature(
  hash: string,
  signature: string,
  publicKeyDer: Uint8Array,
): boolean {
  try {
    const hashBytes = Buffer.from(hash, 'hex');
    const sigBytes = Buffer.from(signature, 'base64');
    return verify(
      null,
      hashBytes,
      { key: Buffer.from(publicKeyDer), format: 'der', type: 'spki' },
      sigBytes,
    );
  } catch {
    return false;
  }
}

// ── Key Persistence ──

export async function saveKeyPair(keyDir: string, keyPair: KeyPair): Promise<void> {
  await mkdir(keyDir, { recursive: true });
  await writeFile(join(keyDir, 'agent.key'), keyPair.privateKey);
  await writeFile(join(keyDir, 'agent.pub'), keyPair.publicKey);
}

export async function loadKeyPair(keyDir: string): Promise<KeyPair | null> {
  try {
    const [privateKey, publicKey] = await Promise.all([
      readFile(join(keyDir, 'agent.key')),
      readFile(join(keyDir, 'agent.pub')),
    ]);
    const keyId = computeKeyId(new Uint8Array(publicKey));
    return {
      privateKey: new Uint8Array(privateKey),
      publicKey: new Uint8Array(publicKey),
      keyId,
    };
  } catch {
    return null;
  }
}

export async function loadOrCreateKeyPair(keyDir: string): Promise<KeyPair> {
  const existing = await loadKeyPair(keyDir);
  if (existing) return existing;

  const keyPair = generateKeyPair();
  await saveKeyPair(keyDir, keyPair);
  return keyPair;
}

// ── Public Key Display ──

export function formatPublicKey(publicKey: Uint8Array): string {
  return `ed25519:${Buffer.from(publicKey).toString('base64')}`;
}

// ── Unique ID Generation ──

export function generateProofId(): string {
  return `ap_${randomBytes(8).toString('hex')}`;
}

export function generateChainId(): string {
  return `ch_${randomBytes(8).toString('hex')}`;
}

export function generateSessionId(): string {
  return `sess_${randomBytes(8).toString('hex')}`;
}
