// Donna - Continuous AI Pentesting Platform
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Astro middleware — protects all routes behind authentication,
 * adds security headers, and provides basic rate limiting for API endpoints.
 *
 * Public routes: /login, /api/auth/*
 * Everything else requires a valid session.
 */

import { defineMiddleware } from 'astro:middleware';
import { auth } from './lib/auth';

const PUBLIC_PATHS = ['/login', '/api/auth'];

function isPublic(pathname: string): boolean {
  // Allow all presentation assets (/presentation, /presentation-script.js, /presentation-audio/*, etc.)
  if (pathname.startsWith('/presentation')) return true;
  return PUBLIC_PATHS.some((p) => pathname === p || pathname.startsWith(p + '/'));
}

// --- Simple in-memory rate limiter for API endpoints ---
const RATE_LIMIT_WINDOW_MS = 60_000; // 1 minute
const RATE_LIMIT_MAX_REQUESTS = 100;  // max requests per window per IP

const rateLimitStore = new Map<string, { count: number; resetAt: number }>();

// Clean up stale entries every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of rateLimitStore) {
    if (now > entry.resetAt) rateLimitStore.delete(key);
  }
}, 300_000);

function checkRateLimit(ip: string): { allowed: boolean; remaining: number; resetAt: number } {
  const now = Date.now();
  let entry = rateLimitStore.get(ip);

  if (!entry || now > entry.resetAt) {
    entry = { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS };
    rateLimitStore.set(ip, entry);
    return { allowed: true, remaining: RATE_LIMIT_MAX_REQUESTS - 1, resetAt: entry.resetAt };
  }

  entry.count++;
  const remaining = Math.max(0, RATE_LIMIT_MAX_REQUESTS - entry.count);
  return { allowed: entry.count <= RATE_LIMIT_MAX_REQUESTS, remaining, resetAt: entry.resetAt };
}

// --- Security headers ---
const SECURITY_HEADERS: Record<string, string> = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-XSS-Protection': '1; mode=block',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
};

function addSecurityHeaders(response: Response): Response {
  for (const [key, value] of Object.entries(SECURITY_HEADERS)) {
    response.headers.set(key, value);
  }
  return response;
}

export const onRequest = defineMiddleware(async ({ request, redirect, locals }, next) => {
  const url = new URL(request.url);

  // --- Rate limiting for API endpoints ---
  if (url.pathname.startsWith('/api/') && !url.pathname.startsWith('/api/auth')) {
    const clientIp = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim()
      || request.headers.get('x-real-ip')
      || 'unknown';
    const { allowed, remaining, resetAt } = checkRateLimit(clientIp);

    if (!allowed) {
      const retryAfter = Math.ceil((resetAt - Date.now()) / 1000);
      return addSecurityHeaders(new Response(JSON.stringify({ error: 'Too many requests' }), {
        status: 429,
        headers: {
          'Content-Type': 'application/json',
          'Retry-After': String(retryAfter),
          'X-RateLimit-Limit': String(RATE_LIMIT_MAX_REQUESTS),
          'X-RateLimit-Remaining': '0',
        },
      }));
    }
  }

  // Let public routes through
  if (isPublic(url.pathname)) {
    const response = await next();
    return addSecurityHeaders(response);
  }

  // Check session via better-auth
  const session = await auth.api.getSession({ headers: request.headers });

  if (!session) {
    // Redirect to login with return URL
    const returnTo = url.pathname + url.search;
    return redirect(`/login?returnTo=${encodeURIComponent(returnTo)}`);
  }

  // Attach session to locals for use in pages
  (locals as any).session = session;

  const response = await next();
  return addSecurityHeaders(response);
});
