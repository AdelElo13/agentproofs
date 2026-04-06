import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { tmpdir } from 'node:os';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { rotateKey, listKeys, loadKeyById, loadAllPublicKeys } from '../src/keys.ts';
import { loadOrCreateKeyPair, verifySignature, signHash, sha256 } from '../src/crypto.ts';

let keyDir: string;

beforeEach(async () => {
  keyDir = await mkdtemp(join(tmpdir(), 'agentproofs-keys-'));
});

afterEach(async () => {
  await rm(keyDir, { recursive: true });
});

describe('Key Rotation', () => {
  it('rotates to a new key', async () => {
    const original = await loadOrCreateKeyPair(keyDir);
    const result = await rotateKey(keyDir, original, 'scheduled rotation');

    expect(result.oldKeyId).toBe(original.keyId);
    expect(result.newKeyId).not.toBe(original.keyId);
    expect(result.rotationInput.event_type).toBe('key_rotated');
  });

  it('archives the old key', async () => {
    const original = await loadOrCreateKeyPair(keyDir);
    await rotateKey(keyDir, original, 'test');

    const keys = await listKeys(keyDir);
    expect(keys).toHaveLength(2);
    expect(keys.find((k) => k.keyId === original.keyId)?.isCurrent).toBe(false);
  });

  it('new key becomes current', async () => {
    const original = await loadOrCreateKeyPair(keyDir);
    const result = await rotateKey(keyDir, original, 'test');

    const current = await loadOrCreateKeyPair(keyDir);
    expect(current.keyId).toBe(result.newKeyId);
  });

  it('old key can still verify old signatures', async () => {
    const original = await loadOrCreateKeyPair(keyDir);
    const hash = sha256('test data');
    const sig = signHash(hash, original.privateKey);

    await rotateKey(keyDir, original, 'test');

    // Load old key by ID
    const oldKey = await loadKeyById(keyDir, original.keyId);
    expect(oldKey).not.toBeNull();
    expect(verifySignature(hash, sig, oldKey!.publicKey)).toBe(true);
  });

  it('loadAllPublicKeys includes current and rotated', async () => {
    const original = await loadOrCreateKeyPair(keyDir);
    await rotateKey(keyDir, original, 'test');

    const allKeys = await loadAllPublicKeys(keyDir);
    expect(allKeys.size).toBe(2);
  });

  it('handles multiple rotations', async () => {
    let current = await loadOrCreateKeyPair(keyDir);
    await rotateKey(keyDir, current, 'first rotation');

    current = await loadOrCreateKeyPair(keyDir);
    await rotateKey(keyDir, current, 'second rotation');

    const keys = await listKeys(keyDir);
    expect(keys).toHaveLength(3);
    expect(keys.filter((k) => k.isCurrent)).toHaveLength(1);
    expect(keys.filter((k) => !k.isCurrent)).toHaveLength(2);
  });
});

describe('Key Loading', () => {
  it('returns null for unknown key ID', async () => {
    await loadOrCreateKeyPair(keyDir);
    const key = await loadKeyById(keyDir, 'nonexistent');
    expect(key).toBeNull();
  });

  it('lists only current key when no rotations', async () => {
    await loadOrCreateKeyPair(keyDir);
    const keys = await listKeys(keyDir);
    expect(keys).toHaveLength(1);
    expect(keys[0].isCurrent).toBe(true);
  });
});
