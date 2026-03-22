// Donna - Continuous AI Pentesting Platform
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Better Auth — client-side helper
 *
 * Used in <script> tags and client-side components for
 * sign-in, sign-out, and password updates.
 */

import { createAuthClient } from 'better-auth/client';

export const authClient = createAuthClient({
  baseURL: window.location.origin,
});
