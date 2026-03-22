// Donna - Continuous AI Pentesting Platform
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Server-side sign-out — clears session cookies and redirects to login.
 * This avoids CSRF issues with client-side fetch POST to better-auth.
 */

import type { APIRoute } from 'astro';
import { auth } from '../../../lib/auth';

export const GET: APIRoute = async ({ request, redirect }) => {
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
