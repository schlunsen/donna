// Donna - Continuous AI Pentesting Platform
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Tauri Desktop Auto-Login Endpoint
 *
 * When running inside the Tauri desktop app, the dashboard runs on localhost
 * and is only accessible by the local user. This endpoint creates a session
 * automatically so the user doesn't need Google OAuth for local use.
 *
 * Security model:
 * - Only enabled when TAURI_AUTH_TOKEN env var is set (Tauri passes it at startup)
 * - Token is a cryptographically random 64-char hex string, unique per app launch
 * - Token must match the env var — prevents unauthorized access
 * - Dashboard only listens on 127.0.0.1 — not reachable from the network
 */

import type { APIRoute } from 'astro';
import { auth } from '../../../lib/auth';

const DESKTOP_EMAIL = 'desktop@donna.local';
const DESKTOP_NAME = 'Desktop User';
const DESKTOP_PASSWORD = 'donna-desktop-local-user-2024';

// Track whether auto-login has already completed this session
let loginComplete = false;
// Track whether migrations have been run
let migrationsRun = false;

async function ensureMigrations() {
  if (migrationsRun) return;
  try {
    const ctx = await auth.$context;
    if (ctx.runMigrations) {
      await ctx.runMigrations();
      console.log('[tauri-login] Database migrations completed');
    }
  } catch (err: any) {
    // Migrations may fail if tables already exist — that's fine
    if (!err?.message?.includes('already exists')) {
      console.warn('[tauri-login] Migration warning:', err?.message || err);
    }
  }
  migrationsRun = true;
}

export const GET: APIRoute = async ({ request, redirect }) => {
  const tauriToken = process.env.TAURI_AUTH_TOKEN;

  // Endpoint only exists in Tauri desktop mode
  if (!tauriToken) {
    return new Response(JSON.stringify({ error: 'Not available' }), {
      status: 404,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // Validate the token from query params
  const url = new URL(request.url);
  const providedToken = url.searchParams.get('token');

  if (!providedToken || providedToken !== tauriToken) {
    return new Response(JSON.stringify({ error: 'Invalid token' }), {
      status: 403,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // If already logged in this session, check for existing session
  if (loginComplete) {
    const existingSession = await auth.api.getSession({ headers: request.headers });
    if (existingSession) {
      return redirect('/');
    }
    loginComplete = false;
  }

  // Ensure database tables exist before attempting auth
  await ensureMigrations();

  try {
    // Attempt 1: Try to sign in (user exists from a previous run)
    try {
      const signInResponse = await auth.api.signInEmail({
        body: { email: DESKTOP_EMAIL, password: DESKTOP_PASSWORD },
        asResponse: true,
      });

      if (signInResponse.ok) {
        loginComplete = true;
        console.log('[tauri-login] Desktop user signed in successfully');
        return buildRedirectResponse(signInResponse);
      }
    } catch {
      // Sign-in failed — continue to sign-up
    }

    // Attempt 2: Create new user
    try {
      const signUpResponse = await auth.api.signUpEmail({
        body: {
          email: DESKTOP_EMAIL,
          password: DESKTOP_PASSWORD,
          name: DESKTOP_NAME,
        },
        asResponse: true,
      });

      if (signUpResponse.ok) {
        loginComplete = true;
        console.log('[tauri-login] Desktop user created and signed in');
        return buildRedirectResponse(signUpResponse);
      }
    } catch {
      // Sign-up failed — user exists with different password
    }

    // Attempt 3: User exists but password is wrong (BETTER_AUTH_SECRET changed between runs)
    // Delete the existing user via the internal adapter and recreate
    console.log('[tauri-login] Resetting desktop user (password mismatch)...');
    try {
      const ctx = await auth.$context;
      const adapter = ctx.adapter;

      const existingUser = await adapter.findOne<{ id: string }>({
        model: 'user',
        where: [{ field: 'email', value: DESKTOP_EMAIL }],
      });

      if (existingUser) {
        // Delete all related records (accounts, sessions) then the user
        await adapter.deleteMany({
          model: 'session',
          where: [{ field: 'userId', value: existingUser.id }],
        });
        await adapter.deleteMany({
          model: 'account',
          where: [{ field: 'userId', value: existingUser.id }],
        });
        await adapter.delete({
          model: 'user',
          where: [{ field: 'id', value: existingUser.id }],
        });
        console.log('[tauri-login] Deleted stale desktop user');
      }

      // Recreate with correct password
      const signUpResponse = await auth.api.signUpEmail({
        body: {
          email: DESKTOP_EMAIL,
          password: DESKTOP_PASSWORD,
          name: DESKTOP_NAME,
        },
        asResponse: true,
      });

      if (signUpResponse.ok) {
        loginComplete = true;
        console.log('[tauri-login] Desktop user recreated and signed in');
        return buildRedirectResponse(signUpResponse);
      }

      const errorText = await signUpResponse.text();
      console.error('[tauri-login] Recreate sign-up failed:', signUpResponse.status, errorText);
    } catch (err) {
      console.error('[tauri-login] Reset failed:', err);
    }

    return redirect('/login');
  } catch (err) {
    console.error('[tauri-login] Auto-login error:', err);
    return redirect('/login');
  }
};

/** Build a 302 redirect response with session cookies from an auth response */
function buildRedirectResponse(authResponse: Response): Response {
  const headers = new Headers();
  headers.set('Location', '/');
  const cookies = authResponse.headers.getSetCookie?.() || [];
  for (const cookie of cookies) {
    headers.append('Set-Cookie', cookie);
  }
  return new Response(null, { status: 302, headers });
}
