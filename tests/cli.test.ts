import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { tmpdir } from 'node:os';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';

let tmpDir: string;

beforeEach(async () => {
  tmpDir = await mkdtemp(join(tmpdir(), 'agentproofs-cli-'));
});

afterEach(async () => {
  await rm(tmpDir, { recursive: true });
});

function run(...args: string[]): string {
  return execFileSync('node', ['bin/cli.mjs', ...args], {
    env: {
      ...process.env,
      AGENTPROOFS_DATA_DIR: tmpDir,
    },
    cwd: join(import.meta.dirname ?? '.', '..'),
    timeout: 10000,
  }).toString().trim();
}

describe('CLI', () => {
  it('shows help', () => {
    const output = run('--help');
    expect(output).toContain('agentproofs');
    expect(output).toContain('COMMANDS');
    expect(output).toContain('verify');
    expect(output).toContain('export');
  });

  it('initializes data directory', () => {
    const output = run('init');
    expect(output).toContain('agentproofs initialized');
    expect(output).toContain('Key ID');
    expect(output).toContain('Public key');
  });

  it('prints public key', () => {
    run('init');
    const output = run('pubkey');
    expect(output).toMatch(/^ed25519:/);
  });

  it('shows keys', () => {
    run('init');
    const output = run('keys');
    expect(output).toContain('Current key');
    expect(output).toContain('Key ID');
  });

  it('verifies empty chain', () => {
    run('init');
    const output = run('verify');
    expect(output).toContain('Chain valid');
    expect(output).toContain('proofs verified');
  });

  it('shows stats for empty chain', () => {
    run('init');
    const output = run('stats');
    expect(output).toContain('No proofs');
  });

  it('shows tail for empty chain', () => {
    run('init');
    const output = run('tail');
    expect(output).toContain('No proofs');
  });

  it('shows query with no results', () => {
    run('init');
    const output = run('query', '--tool', 'Nonexistent');
    expect(output).toContain('No matching');
  });

  it('exports empty chain', () => {
    run('init');
    const output = run('export');
    expect(output).toContain('Exported');
    expect(output).toContain('proofs');
  });

  it('shows segments', () => {
    run('init');
    const output = run('segments');
    expect(output).toContain('Segments');
  });

  it('errors on unknown command', () => {
    try {
      run('foobar');
      expect.fail('Should have thrown');
    } catch (err: any) {
      expect(err.stderr.toString()).toContain('Unknown command');
    }
  });
});
