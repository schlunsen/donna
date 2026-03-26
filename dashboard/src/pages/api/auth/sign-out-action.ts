// Donna - Continuous AI Pentesting Platform
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Server-side sign-out — clears session cookies and redirects to login.
 * Uses POST to prevent CSRF via GET-based forced logout.
 */

import type { APIRoute } from 'astro';
import { auth } from '../../../lib/auth';

export const POST: APIRoute = async ({ request, redirect }) => {
  // Validate Origin header to prevent CSRF
  const origin = request.headers.get('origin');
  const host = request.headers.get('host');
  if (origin && host) {
    let originHost: string;
    try { originHost = new URL(origin).host; } catch { originHost = ''; }
    if (originHost !== host) {
      return new Response(JSON.stringify({ error: 'Invalid origin' }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' },
      });
    }
  }

  try {
    // Revoke the session server-side
    await auth.api.signOut({ headers: request.headers });
  } catch {
    // Even if revocation fails, we clear cookies below
  }

  // Clear all auth cookies by setting them expired
  const cookieNames = [
    'better-auth.session_token',
    'better-auth.session_data',
    '__Secure-better-auth.session_token',
    '__Secure-better-auth.session_data',
  ];

  const headers = new Headers();
  headers.set('Location', '/login');
  for (const name of cookieNames) {
    headers.append(
      'Set-Cookie',
      `${name}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax`
    );
  }

  return new Response(null, { status: 302, headers });
};

// Reject GET requests with a helpful message
export const GET: APIRoute = async () => {
  return new Response(JSON.stringify({ error: 'Use POST to sign out' }), {
    status: 405,
    headers: {
      'Content-Type': 'application/json',
      'Allow': 'POST',
    },
  });
};
