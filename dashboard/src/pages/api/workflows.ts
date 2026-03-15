/**
 * GET  /api/workflows          — list workflows (with progress)
 * POST /api/workflows          — start a new scan workflow
 *
 * GET query params:
 *   ?status=running|completed|failed
 *   ?pageSize=100
 *
 * POST body (JSON):
 *   { "webUrl": "https://…", "repoPath": "/path/to/repo", "pipelineTestingMode"?: true }
 */

import type { APIRoute } from 'astro';
import { listWorkflowsWithProgress, startWorkflow } from '../../lib/temporal.js';

export const GET: APIRoute = async ({ url }) => {
  try {
    const status = url.searchParams.get('status') || undefined;
    const pageSize = parseInt(url.searchParams.get('pageSize') || '100', 10);

    const workflows = await listWorkflowsWithProgress({ status, pageSize });

    return new Response(JSON.stringify({ workflows }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    return new Response(JSON.stringify({ error: message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
};

export const POST: APIRoute = async ({ request }) => {
  try {
    const body = await request.json();
    const { webUrl, repoPath, pipelineTestingMode } = body as {
      webUrl?: string;
      repoPath?: string;
      pipelineTestingMode?: boolean;
    };

    if (!webUrl || !repoPath) {
      return new Response(
        JSON.stringify({ error: 'webUrl and repoPath are required' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } }
      );
    }

    // Basic URL validation
    try {
      new URL(webUrl);
    } catch {
      return new Response(
        JSON.stringify({ error: 'webUrl must be a valid URL (e.g. https://example.com)' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } }
      );
    }

    const result = await startWorkflow({ webUrl, repoPath, pipelineTestingMode });

    return new Response(JSON.stringify(result), {
      status: 201,
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    return new Response(JSON.stringify({ error: message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
};
