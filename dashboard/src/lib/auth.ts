// Donna - Continuous AI Pentesting Platform
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Better Auth — server-side configuration
 *
 * Uses SQLite for zero-dependency persistence.
 * Supports email/password + Google OAuth.
 */

import { betterAuth } from 'better-auth';
import Database from 'better-sqlite3';
import path from 'node:path';
import fs from 'node:fs';

// Store the DB in a persistent location (Docker volume or local)
const dataDir = process.env.AUTH_DB_DIR || path.join(process.cwd(), 'data');
fs.mkdirSync(dataDir, { recursive: true });
const dbPath = path.join(dataDir, 'auth.db');

// Tauri desktop mode — auto-login is enabled when this env var is set by the Tauri app
const isTauriMode = !!process.env.TAURI_AUTH_TOKEN;
const DESKTOP_EMAIL = 'desktop@donna.local';

// Allowed emails for Google OAuth sign-up (comma-separated env var or hardcoded defaults)
// Only these emails can create accounts via Google. Existing accounts can always sign in.
// In Tauri mode, the desktop user email is always allowed.
const ALLOWED_EMAILS = [
  ...(process.env.AUTH_ALLOWED_EMAILS
    ? process.env.AUTH_ALLOWED_EMAILS.split(',').map((e) => e.trim().toLowerCase())
    : []),
  ...(isTauriMode ? [DESKTOP_EMAIL] : []),
];

// Validate BETTER_AUTH_SECRET — sessions are insecure without it.
// Skip validation during build/prerender: Astro sets ASTRO_BUILD=true, or we detect
// the build via process.argv. The secret is only needed at runtime, not for static HTML.
const isBuild = !!process.env.ASTRO_BUILD || process.argv.some((a) => a.includes('astro') && process.argv.includes('build'));
const authSecret = process.env.BETTER_AUTH_SECRET || (isBuild ? 'build-placeholder-not-used-at-runtime' : '');
if (!isBuild && (!authSecret || authSecret.length < 32)) {
  const msg = !process.env.BETTER_AUTH_SECRET
    ? 'BETTER_AUTH_SECRET is not set. Session tokens cannot be signed securely.'
    : `BETTER_AUTH_SECRET is too short (${process.env.BETTER_AUTH_SECRET.length} chars, minimum 32). Use a strong random secret.`;
  console.error(`\n❌ SECURITY ERROR: ${msg}`);
  console.error('   Generate one with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"\n');
  process.exit(1);
}

export const auth = betterAuth({
  database: new Database(dbPath),

  // Secret for signing session tokens (HMAC). Validated above.
  secret: authSecret,

  // Base path prefix (for reverse proxy sub-path deployments like /donna)
  basePath: process.env.AUTH_BASE_PATH || '/api/auth',

  // Base URL for auth callbacks (must match your deployment domain)
  baseURL: process.env.AUTH_BASE_URL || 'http://localhost:4321',

  // Email + password authentication
  // Enabled in Tauri desktop mode for auto-login; disabled otherwise (Google OAuth only)
  emailAndPassword: {
    enabled: isTauriMode,
  },

  // Google OAuth (optional — only enabled when env vars are set)
  socialProviders: {
    ...(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET
      ? {
          google: {
            clientId: process.env.GOOGLE_CLIENT_ID,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET,
          },
        }
      : {}),
  },

  // Session configuration
  session: {
    expiresIn: 60 * 60 * 24 * 7, // 7 days
    updateAge: 60 * 60 * 24,      // refresh session every 24h
    cookieCache: {
      enabled: true,
      maxAge: 60 * 5, // 5 minutes
    },
  },

  // Trust proxy headers (behind Caddy/nginx)
  trustedOrigins: process.env.AUTH_TRUSTED_ORIGINS
    ? process.env.AUTH_TRUSTED_ORIGINS.split(',')
    : ['http://localhost:4321'],

  // Hook: restrict sign-ups to allowed emails only (skip if no allowlist configured)
  databaseHooks: {
    user: {
      create: {
        before: async (user) => {
          // If no allowlist is configured, allow all sign-ups
          if (ALLOWED_EMAILS.length === 0) return user;
          const email = (user.email || '').toLowerCase();
          if (!ALLOWED_EMAILS.includes(email)) {
            // Reject — this email is not in the allowlist
            return false;
          }
          return user;
        },
      },
    },
  },
});

export type Session = typeof auth.$Infer.Session;
