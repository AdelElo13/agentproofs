#!/usr/bin/env node

/**
 * agentproofs PreToolUse hook
 *
 * Captures tool_started events before execution.
 * Sends events to the daemon via Unix socket, never writes directly.
 */

import { createConnection } from 'node:net';
import { createHash, randomBytes } from 'node:crypto';

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
    const hookData = JSON.parse(input);
    const toolName = hookData.tool_name || 'unknown';
    const toolInput = JSON.stringify(hookData.tool_input || '');

    await sendEvent({
      event_type: 'tool_started',
      tool: toolName,
      input_hash: sha256(toolInput),
      output_hash: sha256(''),
      success: true,
      origin: 'hook',
      working_dir: process.cwd(),
      tool_invocation_id: `inv_${randomBytes(8).toString('hex')}`,
    });
  } catch {
    // Never block the agent
  }
  process.exit(0);
});
