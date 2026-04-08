import { readdir, rename, writeFile, mkdir } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
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

// ── macOS Keychain Storage ──

export interface KeychainError {
  readonly code: 'KEYCHAIN_LOCKED' | 'KEY_NOT_FOUND' | 'KEYCHAIN_ERROR' | 'NOT_MACOS';
  readonly message: string;
}

function isKeychainAvailable(): boolean {
  return process.platform === 'darwin';
}

function keychainLabel(label: string): string {
  return `agentproofs:${label}`;
}

function runSecurity(args: readonly string[]): string {
  if (!isKeychainAvailable()) {
    throw Object.assign(new Error('macOS Keychain is only available on macOS'), {
      keychainErrorCode: 'NOT_MACOS' as const,
    });
  }

  try {
    // execFileSync is used intentionally (not exec) — arguments are passed as
    // an array so there is no shell interpretation and no injection risk.
    return execFileSync('security', args as string[], {
      encoding: 'utf-8',
      timeout: 10_000,
      stdio: ['pipe', 'pipe', 'pipe'],
    }).trim();
  } catch (err: unknown) {
    const error = err as { status?: number; stderr?: string; message?: string };
    const stderr = error.stderr ?? error.message ?? '';

    if (stderr.includes('errSecAuthFailed') || stderr.includes('User canceled')) {
      throw Object.assign(new Error('Keychain is locked or user denied access'), {
        keychainErrorCode: 'KEYCHAIN_LOCKED' as const,
      });
    }
    if (stderr.includes('could not be found') || error.status === 44) {
      throw Object.assign(new Error(`Key not found in keychain`), {
        keychainErrorCode: 'KEY_NOT_FOUND' as const,
      });
    }

    throw Object.assign(new Error(`Keychain operation failed: ${stderr}`), {
      keychainErrorCode: 'KEYCHAIN_ERROR' as const,
    });
  }
}

/**
 * Store a keypair in macOS Keychain.
 * Private key is stored as base64 under service "agentproofs:<label>".
 * Public key is stored under service "agentproofs:<label>:pub".
 */
export function storeKeyInKeychain(keyPair: KeyPair, label: string): void {
  const service = keychainLabel(label);
  const privB64 = Buffer.from(keyPair.privateKey).toString('base64');
  const pubB64 = Buffer.from(keyPair.publicKey).toString('base64');

  // Store private key (-U updates if exists)
  runSecurity([
    'add-generic-password',
    '-a', 'agentproofs',
    '-s', service,
    '-w', privB64,
    '-T', '',
    '-U',
  ]);

  // Store public key
  runSecurity([
    'add-generic-password',
    '-a', 'agentproofs',
    '-s', `${service}:pub`,
    '-w', pubB64,
    '-T', '',
    '-U',
  ]);
}

/**
 * Load a keypair from macOS Keychain by label.
 */
export function loadKeyFromKeychain(label: string): KeyPair {
  const service = keychainLabel(label);

  const privB64 = runSecurity([
    'find-generic-password',
    '-a', 'agentproofs',
    '-s', service,
    '-w',
  ]);

  const pubB64 = runSecurity([
    'find-generic-password',
    '-a', 'agentproofs',
    '-s', `${service}:pub`,
    '-w',
  ]);

  const privateKey = new Uint8Array(Buffer.from(privB64, 'base64'));
  const publicKey = new Uint8Array(Buffer.from(pubB64, 'base64'));
  const keyId = computeKeyId(publicKey);

  return { privateKey, publicKey, keyId };
}

/**
 * Delete a keypair from macOS Keychain by label.
 */
export function deleteKeyFromKeychain(label: string): void {
  const service = keychainLabel(label);

  // Delete private key
  try {
    runSecurity([
      'delete-generic-password',
      '-a', 'agentproofs',
      '-s', service,
    ]);
  } catch (err: unknown) {
    const error = err as { keychainErrorCode?: string };
    if (error.keychainErrorCode !== 'KEY_NOT_FOUND') throw err;
  }

  // Delete public key
  try {
    runSecurity([
      'delete-generic-password',
      '-a', 'agentproofs',
      '-s', `${service}:pub`,
    ]);
  } catch (err: unknown) {
    const error = err as { keychainErrorCode?: string };
    if (error.keychainErrorCode !== 'KEY_NOT_FOUND') throw err;
  }
}

/**
 * List all agentproofs keys stored in macOS Keychain.
 * Returns labels (without the "agentproofs:" prefix).
 */
export function listKeychainKeys(): readonly string[] {
  if (!isKeychainAvailable()) {
    return [];
  }

  try {
    const output = runSecurity([
      'dump-keychain',
    ]);

    const labels: string[] = [];
    const serviceRegex = /"svce"<blob>="agentproofs:([^"]+)"/g;
    let match: RegExpExecArray | null;

    while ((match = serviceRegex.exec(output)) !== null) {
      const label = match[1];
      // Skip the :pub entries — only return base labels
      if (!label.endsWith(':pub')) {
        labels.push(label);
      }
    }

    // Deduplicate
    return [...new Set(labels)];
  } catch {
    return [];
  }
}

/**
 * Load or create a keypair, respecting the configured key store.
 * When keyStore is 'keychain', uses macOS Keychain with label 'current'.
 * Falls back to file-based storage otherwise.
 */
export async function loadOrCreateKeyPairFromStore(
  keyDir: string,
  keyStore: 'file' | 'keychain' | 'hsm',
): Promise<KeyPair> {
  if (keyStore === 'keychain') {
    try {
      return loadKeyFromKeychain('current');
    } catch (err: unknown) {
      const error = err as { keychainErrorCode?: string };
      if (error.keychainErrorCode === 'KEY_NOT_FOUND') {
        // Generate new keypair and store in keychain
        const keyPair = generateKeyPair();
        storeKeyInKeychain(keyPair, 'current');
        return keyPair;
      }
      throw err;
    }
  }

  // Default: file-based
  return loadOrCreateKeyPair(keyDir);
}
