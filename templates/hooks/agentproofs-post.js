#!/usr/bin/env node

/**
 * agentproofs PostToolUse hook
 *
 * Captures every tool completion as a proof in the chain.
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
      // Timeout: don't block the agent
      setTimeout(() => {
        socket.end();
        resolve(null);
      }, 2000);
    } catch {
      resolve(null);
    }
  });
}

// Read hook input from stdin
let input = '';
process.stdin.on('data', (chunk) => { input += chunk; });
process.stdin.on('end', async () => {
  try {
    const hookData = JSON.parse(input);
    const toolName = hookData.tool_name || 'unknown';
    const toolInput = JSON.stringify(hookData.tool_input || '');
    const toolOutput = JSON.stringify(hookData.tool_output || '');

    await sendEvent({
      event_type: 'tool_completed',
      tool: toolName,
      input_hash: sha256(toolInput),
      output_hash: sha256(toolOutput),
      success: !hookData.error,
      error_message: hookData.error || undefined,
      origin: 'hook',
      working_dir: process.cwd(),
      tool_invocation_id: `inv_${randomBytes(8).toString('hex')}`,
    });
  } catch {
    // Never block the agent — silently fail
  }
  process.exit(0);
});
