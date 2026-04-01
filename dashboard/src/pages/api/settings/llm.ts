// Donna - Continuous AI Pentesting Platform
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * GET  /api/settings/llm  — load LLM provider settings
 * POST /api/settings/llm  — save LLM provider settings
 */

/**
 * GET  /api/settings/llm       — load LLM provider settings
 * POST /api/settings/llm       — save LLM provider settings
 * PUT  /api/settings/llm       — test connection to an LLM endpoint (server-side proxy)
 */

import type { APIRoute } from 'astro';
import { loadLlmSettings, saveLlmSettings, type LlmSettings } from '../../../lib/llm-settings.js';

export const GET: APIRoute = async ({ locals }) => {
  const session = (locals as any).session;
  if (!session?.user?.email) {
    return new Response(JSON.stringify({ error: 'Authentication required' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  try {
    const settings = await loadLlmSettings();
    return new Response(JSON.stringify(settings), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (error) {
    console.error('LLM settings GET error:', error instanceof Error ? error.message : error);
    return new Response(JSON.stringify({ error: 'Failed to load LLM settings' }), {
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
    const body = (await request.json()) as LlmSettings;

    // Basic validation
    const qwen = body?.providers?.['qwen-local'];
    if (!qwen || typeof qwen.enabled !== 'boolean') {
      return new Response(JSON.stringify({ error: 'Invalid settings format' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    if (qwen.enabled) {
      if (!qwen.baseUrl || typeof qwen.baseUrl !== 'string') {
        return new Response(JSON.stringify({ error: 'Base URL is required when provider is enabled' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      if (!qwen.model || typeof qwen.model !== 'string') {
        return new Response(JSON.stringify({ error: 'Model name is required when provider is enabled' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' },
        });
      }
    }

    await saveLlmSettings(body);

    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (error) {
    console.error('LLM settings POST error:', error instanceof Error ? error.message : error);
    return new Response(JSON.stringify({ error: 'Failed to save LLM settings' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
};

/**
 * PUT /api/settings/llm — test connection to an LLM endpoint.
 *
 * The browser can't reach server-local URLs (localhost, host.docker.internal),
 * so this endpoint proxies the test from the server side.
 *
 * Body: { baseUrl: string, apiKey?: string }
 */
export const PUT: APIRoute = async ({ request, locals }) => {
  const session = (locals as any).session;
  if (!session?.user?.email) {
    return new Response(JSON.stringify({ error: 'Authentication required' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  try {
    const body = await request.json() as { baseUrl?: string; apiKey?: string };
    const baseUrl = body.baseUrl?.replace(/\/+$/, '');

    if (!baseUrl) {
      return new Response(JSON.stringify({ error: 'baseUrl is required' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // Build the /v1/models URL
    const modelsUrl = baseUrl.includes('/v1') ? `${baseUrl}/models` : `${baseUrl}/v1/models`;

    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (body.apiKey) {
      headers['Authorization'] = `Bearer ${body.apiKey}`;
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);

    try {
      const res = await fetch(modelsUrl, { headers, signal: controller.signal });
      clearTimeout(timeout);

      if (res.ok) {
        const data = await res.json() as { data?: { id: string }[] };
        const models = data.data || [];
        const modelNames = models.map((m) => m.id).slice(0, 5);
        return new Response(JSON.stringify({
          ok: true,
          modelCount: models.length,
          models: modelNames,
        }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      } else {
        const text = await res.text().catch(() => '');
        return new Response(JSON.stringify({
          ok: false,
          error: `HTTP ${res.status}: ${text.slice(0, 200)}`,
        }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }
    } catch (fetchErr) {
      clearTimeout(timeout);
      const msg = fetchErr instanceof Error ? fetchErr.message : String(fetchErr);
      return new Response(JSON.stringify({
        ok: false,
        error: msg.includes('abort') ? 'Connection timed out (10s)' : msg,
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }
  } catch (error) {
    console.error('LLM test connection error:', error instanceof Error ? error.message : error);
    return new Response(JSON.stringify({ error: 'Failed to test connection' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
};
