#!/usr/bin/env node

/**
 * agentproofs Stop hook
 *
 * Logs session_ended event when Claude Code session ends.
 */

import { createConnection } from 'node:net';
import { createHash } from 'node:crypto';

const SOCKET_PATH = process.env.AGENTPROOFS_SOCKET_PATH
  || `${process.env.HOME}/.agentproofs/daemon.sock`;

function sha256(data) {
  return createHash('sha256').update(data).digest('hex');
}

function sendEvent(event) {
  return new Promise((resolve) => {
    try {
      const socket = createConnection(SOCKET_PATH, () => {
        socket.write(JSON.stringify({ type: 'log', input: event }) + '\n');
        socket.on('data', (data) => {
          socket.end();
          resolve(JSON.parse(data.toString()));
        });
        socket.on('error', () => {
          socket.end();
          resolve(null);
        });
      });
      socket.on('error', () => resolve(null));
      setTimeout(() => {
        socket.end();
        resolve(null);
      }, 2000);
    } catch {
      resolve(null);
    }
  });
}

let input = '';
process.stdin.on('data', (chunk) => { input += chunk; });
process.stdin.on('end', async () => {
  try {
    await sendEvent({
      event_type: 'session_ended',
      input_hash: sha256('session_ended'),
      output_hash: sha256(''),
      success: true,
      origin: 'hook',
      input_summary: 'Session ended',
    });
  } catch {
    // Never block
  }
  process.exit(0);
});
