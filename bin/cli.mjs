#!/usr/bin/env node

import { cli } from '../dist/cli.js';

cli(process.argv.slice(2)).catch((err) => {
  console.error('agentproofs error:', err.message);
  process.exit(1);
});
