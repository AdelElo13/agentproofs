import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { tmpdir } from 'node:os';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import {
  sha256,
  generateKeyPair,
  computeKeyId,
  signHash,
  verifySignature,
  saveKeyPair,
  loadKeyPair,
  loadOrCreateKeyPair,
  formatPublicKey,
  generateProofId,
  generateChainId,
  generateSessionId,
} from '../src/crypto.ts';

describe('SHA-256', () => {
  it('produces consistent hashes for same input', () => {
    const hash1 = sha256('hello world');
    const hash2 = sha256('hello world');
    expect(hash1).toBe(hash2);
  });

  it('produces different hashes for different input', () => {
    const hash1 = sha256('hello');
    const hash2 = sha256('world');
    expect(hash1).not.toBe(hash2);
  });

  it('produces 64-char hex string', () => {
    const hash = sha256('test');
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('handles empty string', () => {
    const hash = sha256('');
    expect(hash).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  });
});

describe('Ed25519 Key Generation', () => {
  it('generates a valid keypair', () => {
    const kp = generateKeyPair();
    expect(kp.privateKey).toBeInstanceOf(Uint8Array);
    expect(kp.publicKey).toBeInstanceOf(Uint8Array);
    expect(kp.privateKey.length).toBeGreaterThan(0);
    expect(kp.publicKey.length).toBeGreaterThan(0);
  });

  it('generates unique keypairs', () => {
    const kp1 = generateKeyPair();
    const kp2 = generateKeyPair();
    expect(kp1.keyId).not.toBe(kp2.keyId);
  });

  it('computes deterministic key ID from public key', () => {
    const kp = generateKeyPair();
    const id1 = computeKeyId(kp.publicKey);
    const id2 = computeKeyId(kp.publicKey);
    expect(id1).toBe(id2);
    expect(id1).toMatch(/^[0-9a-f]{16}$/);
  });
});

describe('Signing and Verification', () => {
  it('signs and verifies a hash', () => {
    const kp = generateKeyPair();
    const hash = sha256('test data');
    const sig = signHash(hash, kp.privateKey);
    expect(verifySignature(hash, sig, kp.publicKey)).toBe(true);
  });

  it('rejects tampered hash', () => {
    const kp = generateKeyPair();
    const hash = sha256('original');
    const sig = signHash(hash, kp.privateKey);
    const tamperedHash = sha256('tampered');
    expect(verifySignature(tamperedHash, sig, kp.publicKey)).toBe(false);
  });

  it('rejects wrong public key', () => {
    const kp1 = generateKeyPair();
    const kp2 = generateKeyPair();
    const hash = sha256('test');
    const sig = signHash(hash, kp1.privateKey);
    expect(verifySignature(hash, sig, kp2.publicKey)).toBe(false);
  });

  it('rejects tampered signature', () => {
    const kp = generateKeyPair();
    const hash = sha256('test');
    const sig = signHash(hash, kp.privateKey);
    const tampered = Buffer.from(sig, 'base64');
    tampered[0] ^= 0xff;
    expect(verifySignature(hash, tampered.toString('base64'), kp.publicKey)).toBe(false);
  });
});

describe('Key Persistence', () => {
  let tmpDir: string;

  beforeEach(async () => {
    tmpDir = await mkdtemp(join(tmpdir(), 'agentproofs-test-'));
  });

  afterEach(async () => {
    await rm(tmpDir, { recursive: true });
  });

  it('saves and loads a keypair', async () => {
    const kp = generateKeyPair();
    await saveKeyPair(tmpDir, kp);
    const loaded = await loadKeyPair(tmpDir);

    expect(loaded).not.toBeNull();
    expect(loaded!.keyId).toBe(kp.keyId);
    expect(Buffer.from(loaded!.publicKey)).toEqual(Buffer.from(kp.publicKey));
    expect(Buffer.from(loaded!.privateKey)).toEqual(Buffer.from(kp.privateKey));
  });

  it('returns null for non-existent keys', async () => {
    const loaded = await loadKeyPair(join(tmpDir, 'nonexistent'));
    expect(loaded).toBeNull();
  });

  it('creates new keys if none exist', async () => {
    const keyDir = join(tmpDir, 'newkeys');
    const kp = await loadOrCreateKeyPair(keyDir);
    expect(kp.keyId).toMatch(/^[0-9a-f]{16}$/);

    // Loading again returns same keys
    const kp2 = await loadOrCreateKeyPair(keyDir);
    expect(kp2.keyId).toBe(kp.keyId);
  });
});

describe('ID Generation', () => {
  it('generates unique proof IDs with prefix', () => {
    const id1 = generateProofId();
    const id2 = generateProofId();
    expect(id1).toMatch(/^ap_[0-9a-f]{16}$/);
    expect(id1).not.toBe(id2);
  });

  it('generates unique chain IDs with prefix', () => {
    const id = generateChainId();
    expect(id).toMatch(/^ch_[0-9a-f]{16}$/);
  });

  it('generates unique session IDs with prefix', () => {
    const id = generateSessionId();
    expect(id).toMatch(/^sess_[0-9a-f]{16}$/);
  });
});

describe('Public Key Formatting', () => {
  it('formats public key as ed25519:base64', () => {
    const kp = generateKeyPair();
    const formatted = formatPublicKey(kp.publicKey);
    expect(formatted).toMatch(/^ed25519:.+$/);
  });
});
