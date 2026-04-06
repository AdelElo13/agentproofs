import { readdir, rename, writeFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import {
  generateKeyPair,
  loadOrCreateKeyPair,
  saveKeyPair,
  computeKeyId,
  sha256,
  signHash,
} from './crypto.ts';
import type { KeyPair, ProofLogInput } from './types.ts';

/**
 * Key rotation protocol:
 * 1. Generate new Ed25519 keypair
 * 2. Log key_rotated proof (signed by OLD key, contains new public key)
 * 3. Archive old key
 * 4. Next proof signed by new key
 */

export interface KeyRotationResult {
  readonly oldKeyId: string;
  readonly newKeyId: string;
  readonly newPublicKey: Uint8Array;
  readonly rotationInput: ProofLogInput;
}

export async function rotateKey(
  keyDir: string,
  currentKeyPair: KeyPair,
  reason: string,
): Promise<KeyRotationResult> {
  // Generate new keypair
  const newKeyPair = generateKeyPair();

  // Archive old key
  const rotatedDir = join(keyDir, 'rotated');
  await mkdir(rotatedDir, { recursive: true });
  await writeFile(
    join(rotatedDir, `${currentKeyPair.keyId}.key`),
    currentKeyPair.privateKey,
  );
  await writeFile(
    join(rotatedDir, `${currentKeyPair.keyId}.pub`),
    currentKeyPair.publicKey,
  );

  // Save new key as current
  await saveKeyPair(keyDir, newKeyPair);

  // Create the rotation proof input (to be signed by OLD key)
  const rotationInput: ProofLogInput = {
    event_type: 'key_rotated',
    success: true,
    origin: 'daemon',
    input_summary: `Key rotation: ${currentKeyPair.keyId} -> ${newKeyPair.keyId}`,
    output_summary: `New public key: ${Buffer.from(newKeyPair.publicKey).toString('base64')}`,
    reason,
  };

  return {
    oldKeyId: currentKeyPair.keyId,
    newKeyId: newKeyPair.keyId,
    newPublicKey: newKeyPair.publicKey,
    rotationInput,
  };
}

/**
 * List all keys (current + rotated).
 */
export async function listKeys(
  keyDir: string,
): Promise<ReadonlyArray<{ keyId: string; isCurrent: boolean }>> {
  const current = await loadOrCreateKeyPair(keyDir);
  const keys: Array<{ keyId: string; isCurrent: boolean }> = [
    { keyId: current.keyId, isCurrent: true },
  ];

  // List rotated keys
  const rotatedDir = join(keyDir, 'rotated');
  try {
    const files = await readdir(rotatedDir);
    const pubFiles = files.filter((f) => f.endsWith('.pub'));
    for (const f of pubFiles) {
      const keyId = f.replace('.pub', '');
      keys.push({ keyId, isCurrent: false });
    }
  } catch {
    // No rotated keys
  }

  return keys;
}

/**
 * Load a specific key by ID (current or rotated).
 */
export async function loadKeyById(
  keyDir: string,
  keyId: string,
): Promise<KeyPair | null> {
  const current = await loadOrCreateKeyPair(keyDir);
  if (current.keyId === keyId) return current;

  // Check rotated
  try {
    const { readFile } = await import('node:fs/promises');
    const [priv, pub] = await Promise.all([
      readFile(join(keyDir, 'rotated', `${keyId}.key`)),
      readFile(join(keyDir, 'rotated', `${keyId}.pub`)),
    ]);
    return {
      privateKey: new Uint8Array(priv),
      publicKey: new Uint8Array(pub),
      keyId,
    };
  } catch {
    return null;
  }
}

/**
 * Build a map of all public keys (for verification across key rotations).
 */
export async function loadAllPublicKeys(
  keyDir: string,
): Promise<ReadonlyMap<string, Uint8Array>> {
  const keys = new Map<string, Uint8Array>();
  const current = await loadOrCreateKeyPair(keyDir);
  keys.set(current.keyId, current.publicKey);

  const rotatedDir = join(keyDir, 'rotated');
  try {
    const { readFile, readdir } = await import('node:fs/promises');
    const files = await readdir(rotatedDir);
    for (const f of files.filter((f) => f.endsWith('.pub'))) {
      const keyId = f.replace('.pub', '');
      const pub = await readFile(join(rotatedDir, f));
      keys.set(keyId, new Uint8Array(pub));
    }
  } catch {
    // No rotated keys
  }

  return keys;
}
