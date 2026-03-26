// Donna - Continuous AI Pentesting Platform
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * GET /api/workspaces
 *
 * Returns workspace data from audit-logs session.json files,
 * filtered to the current authenticated user's workspaces only.
 */

import type { APIRoute } from 'astro';
import { listWorkspaces } from '../../lib/audit-logs.js';
import { listUserWorkflowIds } from '../../lib/temporal.js';

export const GET: APIRoute = async ({ locals }) => {
  const session = (locals as any).session;

  if (!session?.user?.email) {
    return new Response(JSON.stringify({ error: 'Authentication required' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  try {
    // Get all workspaces from audit-logs
    const allWorkspaces = await listWorkspaces();

    // Get user's workflow IDs (lightweight — no progress enrichment)
    const userWorkflowIds = await listUserWorkflowIds(session.user.email);

    // Filter workspaces to only those belonging to the user's workflows
    // Workspace names correspond to workflow IDs
    const workspaces = allWorkspaces.filter(ws => userWorkflowIds.has(ws.name));

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
