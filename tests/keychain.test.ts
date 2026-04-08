import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { tmpdir } from 'node:os';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import {
  storeKeyInKeychain,
  loadKeyFromKeychain,
  deleteKeyFromKeychain,
  listKeychainKeys,
  loadOrCreateKeyPairFromStore,
} from '../src/keys.ts';
import { loadOrCreateKeyPair } from '../src/crypto.ts';
import { loadConfig } from '../src/config.ts';

let keyDir: string;

beforeEach(async () => {
  keyDir = await mkdtemp(join(tmpdir(), 'agentproofs-keychain-'));
});

afterEach(async () => {
  await rm(keyDir, { recursive: true });
});

describe('Keychain Functions — Exports', () => {
  it('storeKeyInKeychain is a function', () => {
    expect(typeof storeKeyInKeychain).toBe('function');
  });

  it('loadKeyFromKeychain is a function', () => {
    expect(typeof loadKeyFromKeychain).toBe('function');
  });

  it('deleteKeyFromKeychain is a function', () => {
    expect(typeof deleteKeyFromKeychain).toBe('function');
  });

  it('listKeychainKeys is a function', () => {
    expect(typeof listKeychainKeys).toBe('function');
  });

  it('loadOrCreateKeyPairFromStore is a function', () => {
    expect(typeof loadOrCreateKeyPairFromStore).toBe('function');
  });
});

describe('Config — keyStore option', () => {
  it('defaults keyStore to file', () => {
    // Clear any env override
    const prev = process.env.AGENTPROOFS_KEY_STORE;
    delete process.env.AGENTPROOFS_KEY_STORE;

    try {
      const config = loadConfig();
      expect(config.keyStore).toBe('file');
    } finally {
      if (prev !== undefined) {
        process.env.AGENTPROOFS_KEY_STORE = prev;
      }
    }
  });

  it('reads keyStore from AGENTPROOFS_KEY_STORE env', () => {
    const prev = process.env.AGENTPROOFS_KEY_STORE;
    process.env.AGENTPROOFS_KEY_STORE = 'keychain';

    try {
      const config = loadConfig();
      expect(config.keyStore).toBe('keychain');
    } finally {
      if (prev !== undefined) {
        process.env.AGENTPROOFS_KEY_STORE = prev;
      } else {
        delete process.env.AGENTPROOFS_KEY_STORE;
      }
    }
  });
});

describe('loadOrCreateKeyPairFromStore — file mode', () => {
  it('creates a keypair in file mode', async () => {
    const keyPair = await loadOrCreateKeyPairFromStore(keyDir, 'file');

    expect(keyPair.privateKey).toBeInstanceOf(Uint8Array);
    expect(keyPair.publicKey).toBeInstanceOf(Uint8Array);
    expect(keyPair.keyId).toBeDefined();
    expect(keyPair.keyId.length).toBe(16);
  });

  it('returns the same keypair on repeated calls in file mode', async () => {
    const first = await loadOrCreateKeyPairFromStore(keyDir, 'file');
    const second = await loadOrCreateKeyPairFromStore(keyDir, 'file');

    expect(first.keyId).toBe(second.keyId);
  });

  it('file mode matches loadOrCreateKeyPair behavior', async () => {
    const fromStore = await loadOrCreateKeyPairFromStore(keyDir, 'file');
    const fromDirect = await loadOrCreateKeyPair(keyDir);

    expect(fromStore.keyId).toBe(fromDirect.keyId);
  });
});
