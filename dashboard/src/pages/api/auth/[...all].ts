// Donna - Continuous AI Pentesting Platform
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Catch-all API route that delegates to better-auth.
 *
 * Handles:  /api/auth/sign-in/email
 *           /api/auth/sign-up/email
 *           /api/auth/sign-in/social  (Google OAuth)
 *           /api/auth/sign-out
 *           /api/auth/session
 *           /api/auth/change-password
 *           /api/auth/callback/*
 *           etc.
 */

import type { APIRoute } from 'astro';
import { auth } from '../../../lib/auth';

export const ALL: APIRoute = async ({ request }) => {
  return auth.handler(request);
};
