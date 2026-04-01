// Donna - Continuous AI Pentesting Platform
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * GET  /api/workflows          — list workflows (with progress) for the current user
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
import { validateWebUrl } from '../../lib/url-validation.js';
import { getModelProfileFromSettings } from '../../lib/llm-settings.js';

export const GET: APIRoute = async ({ url, locals }) => {
  const session = (locals as any).session;

  if (!session?.user?.email) {
    return new Response(JSON.stringify({ error: 'Authentication required' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  try {
    const status = url.searchParams.get('status') || undefined;
    const pageSize = parseInt(url.searchParams.get('pageSize') || '100', 10);

    // Pass user email for per-user filtering (AUTHZ-VULN-01 fix)
    const workflows = await listWorkflowsWithProgress({
      status,
      pageSize,
      userEmail: session.user.email,
    });

    return new Response(JSON.stringify({ workflows }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (error) {
    console.error('Workflows GET error:', error instanceof Error ? error.message : error);
    return new Response(JSON.stringify({ error: 'Failed to list workflows' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
};

export const POST: APIRoute = async ({ request, locals }) => {
  const session = (locals as any).session;

  if (!session?.user?.email) {
    return new Response(JSON.stringify({ error: 'Authentication required' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  try {
    const body = await request.json();
    const { webUrl, repoPath, gitUrl, pipelineTestingMode, modelProfile } = body as {
      webUrl?: string;
      repoPath?: string;
      gitUrl?: string;
      pipelineTestingMode?: boolean;
      modelProfile?: string;
    };

    if (!webUrl) {
      return new Response(
        JSON.stringify({ error: 'webUrl is required' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } }
      );
    }

    // Strict URL validation — blocks SSRF via private IPs and non-HTTP schemes (SSRF-VULN-01 fix)
    const urlError = validateWebUrl(webUrl);
    if (urlError) {
      return new Response(
        JSON.stringify({ error: `Invalid webUrl: ${urlError}` }),
        { status: 400, headers: { 'Content-Type': 'application/json' } }
      );
    }

    // Validate gitUrl if provided — only allow https:// and git:// schemes
    if (gitUrl) {
      try {
        const parsed = new URL(gitUrl);
        if (parsed.protocol !== 'https:' && parsed.protocol !== 'git:') {
          return new Response(
            JSON.stringify({ error: 'Git URL must use https:// or git:// scheme' }),
            { status: 400, headers: { 'Content-Type': 'application/json' } }
          );
        }
      } catch {
        return new Response(
          JSON.stringify({ error: 'Invalid Git Repository URL format' }),
          { status: 400, headers: { 'Content-Type': 'application/json' } }
        );
      }
    }

    // If a non-Claude profile is selected, load its inline config from LLM settings
    let modelProfileConfig: { base_url: string; api_key: string; tiers: { small: string; medium: string; large: string } } | undefined;
    if (modelProfile && modelProfile !== 'claude') {
      const profileConfig = await getModelProfileFromSettings(modelProfile);
      if (profileConfig) {
        modelProfileConfig = profileConfig;
      }
    }

    // Pass user email to associate workflow with creator
    const result = await startWorkflow({
      webUrl,
      ...(repoPath && { repoPath }),
      ...(gitUrl && { gitUrl }),
      pipelineTestingMode,
      createdByEmail: session.user.email,
      modelProfile,
      modelProfileConfig,
    });

    return new Response(JSON.stringify(result), {
      status: 201,
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (error) {
    console.error('Workflows POST error:', error instanceof Error ? error.message : error);
    return new Response(JSON.stringify({ error: 'Failed to start workflow' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
};
