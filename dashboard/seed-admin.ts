// Donna - Continuous AI Pentesting Platform
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Seed script — creates the initial admin user.
 *
 * Better-auth auto-migrates the SQLite schema on first import,
 * so this script only needs to call signUpEmail.
 *
 * Usage:
 *   npx tsx seed-admin.ts
 *   # or with custom values:
 *   ADMIN_EMAIL=me@example.com ADMIN_PASSWORD=secret npx tsx seed-admin.ts
 */

import { auth } from './src/lib/auth';

import crypto from 'node:crypto';

const email = process.env.ADMIN_EMAIL || 'admin@donna.local';
const name = process.env.ADMIN_NAME || 'Admin';

// Require explicit password or generate a secure random one
let password = process.env.ADMIN_PASSWORD;
let generatedPassword = false;
if (!password) {
  password = crypto.randomBytes(16).toString('base64url');
  generatedPassword = true;
}

async function main() {
  console.log(`\n🛡  Donna — Seeding admin user`);
  console.log(`   Email:    ${email}`);
  if (generatedPassword) {
    console.log(`   Password: ${password} (auto-generated — save this!)`);
  } else {
    console.log(`   Password: ${'*'.repeat(password.length)}`);
  }
  console.log();

  try {
    const result = await auth.api.signUpEmail({
      body: { email, password, name },
    });

    console.log(`✅ Admin user created successfully!`);
    console.log(`   User ID: ${result.user?.id || 'unknown'}\n`);
  } catch (err: any) {
    const msg = err?.message || err?.body?.message || String(err);
    if (msg.toLowerCase().includes('already') || msg.toLowerCase().includes('unique')) {
      console.log(`ℹ️  Admin user already exists (${email}). Skipping.\n`);
    } else {
      console.error(`❌ Failed to create admin user:`, msg);
      process.exit(1);
    }
  }
}

main();
