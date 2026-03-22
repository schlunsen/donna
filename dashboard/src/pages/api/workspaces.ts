// Donna - Continuous AI Pentesting Platform
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * GET /api/workspaces
 *
 * Returns workspace data from audit-logs session.json files.
 * This provides historical cost and duration data.
 */

import type { APIRoute } from 'astro';
import { listWorkspaces } from '../../lib/audit-logs.js';

export const GET: APIRoute = async () => {
  try {
    const workspaces = await listWorkspaces();

    return new Response(JSON.stringify({ workspaces }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (error) {
    console.error('Workspaces GET error:', error instanceof Error ? error.message : error);
    return new Response(JSON.stringify({ error: 'Failed to list workspaces' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
};
