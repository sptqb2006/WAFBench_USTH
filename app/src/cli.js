#!/usr/bin/env node
// app/src/cli.js
// Javascript / Node.js 20 / CLI / Terminal RBAC & HMAC-SHA256 Auth Tool

const { signToken, verifyToken } = require('./utils/hmac');

function printUsage() {
  console.log(`
WAFBench Terminal Auth & RBAC Manager (HMAC-SHA256)
Usage:
  node src/cli.js sign <username> <role>
  node src/cli.js verify <token>

Examples:
  node src/cli.js sign admin administrator
  node src/cli.js sign alice editor
  node src/cli.js verify eyJhbGciOiJIUzI1Ni...
`);
}

function run() {
  const args = process.argv.slice(2);
  const command = args[0];

  if (!command || command === '--help' || command === '-h') {
    printUsage();
    process.exit(0);
  }

  if (command === 'sign') {
    const username = args[1];
    const role = args[2] || 'viewer';

    if (!username) {
      console.error('[ERROR] Username is required. Usage: node src/cli.js sign <username> [role]');
      process.exit(1);
    }

    const payload = {
      username,
      role,
      issued_at: new Date().toISOString(),
    };

    const token = signToken(payload);
    console.log(JSON.stringify({
      status: 'SUCCESS',
      action: 'SIGN_TOKEN',
      algorithm: 'HMAC-SHA256',
      claims: payload,
      token: token,
    }, null, 2));
    process.exit(0);
  }

  if (command === 'verify') {
    const token = args[1];

    if (!token) {
      console.error('[ERROR] Token is required. Usage: node src/cli.js verify <token>');
      process.exit(1);
    }

    const result = verifyToken(token);
    if (result.valid) {
      console.log(JSON.stringify({
        status: 'AUTHORIZED',
        action: 'VERIFY_TOKEN',
        algorithm: 'HMAC-SHA256',
        is_tampered: false,
        user: result.payload.username,
        role: result.payload.role,
        claims: result.payload,
      }, null, 2));
      process.exit(0);
    } else {
      console.error(JSON.stringify({
        status: 'UNAUTHORIZED',
        action: 'VERIFY_TOKEN',
        is_tampered: true,
        reason: result.reason,
      }, null, 2));
      process.exit(1);
    }
  }

  console.error(`[ERROR] Unknown command: ${command}`);
  printUsage();
  process.exit(1);
}

run();
