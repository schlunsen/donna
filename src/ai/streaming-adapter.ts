// Donna - Continuous AI Pentesting Platform
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Streaming Adapter Proxy
 *
 * Solves a critical incompatibility: LiteLLM's streaming mode does NOT properly
 * convert OpenAI-format tool_calls to Anthropic streaming tool_use content blocks.
 * The Claude Agent SDK always uses streaming, so tool calls arrive as plain text
 * instead of structured tool_use blocks, causing agents to fail.
 *
 * This adapter sits between the Claude Agent SDK and LiteLLM:
 * 1. Receives streaming requests from the SDK (Anthropic format)
 * 2. Forwards them as NON-streaming to LiteLLM (where tool_use works correctly)
 * 3. Converts the non-streaming response to proper Anthropic SSE streaming events
 * 4. Returns the stream to the SDK
 *
 * Usage: Call `ensureStreamingAdapter(litellmBaseUrl)` before starting the agent.
 * It returns a local proxy URL to use as ANTHROPIC_BASE_URL.
 */

import { createServer, type IncomingMessage, type ServerResponse } from 'http';

let adapterServer: ReturnType<typeof createServer> | null = null;
let adapterPort: number | null = null;
let targetBaseUrl: string | null = null;

/**
 * Ensure the streaming adapter proxy is running and return its URL.
 * Idempotent — returns the existing proxy URL if already started.
 */
export async function ensureStreamingAdapter(litellmBaseUrl: string): Promise<string> {
  if (adapterServer && adapterPort && targetBaseUrl === litellmBaseUrl) {
    return `http://127.0.0.1:${adapterPort}`;
  }

  targetBaseUrl = litellmBaseUrl;

  return new Promise((resolve, reject) => {
    const server = createServer(handleRequest);

    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      if (typeof addr === 'object' && addr) {
        adapterPort = addr.port;
        adapterServer = server;
        const url = `http://127.0.0.1:${adapterPort}`;
        console.log(`[streaming-adapter] Proxy started on ${url} -> ${litellmBaseUrl}`);
        resolve(url);
      } else {
        reject(new Error('Failed to get adapter server address'));
      }
    });

    server.on('error', reject);
  });
}

async function handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
  // Only handle POST /v1/messages
  if (req.method !== 'POST' || !req.url?.startsWith('/v1/messages')) {
    // Pass through other requests
    await proxyPassthrough(req, res);
    return;
  }

  try {
    // Read request body
    const body = await readBody(req);
    const parsed = JSON.parse(body);
    const isStreaming = parsed.stream === true;

    if (!isStreaming) {
      // Non-streaming requests pass through directly
      await proxyPassthrough(req, res, body);
      return;
    }

    // Make a non-streaming request to LiteLLM
    const nonStreamBody = { ...parsed, stream: false };

    const upstreamUrl = `${targetBaseUrl}${req.url}`;
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };

    // Forward relevant headers
    for (const key of ['x-api-key', 'anthropic-version', 'authorization']) {
      const val = req.headers[key];
      if (val && typeof val === 'string') {
        headers[key] = val;
      }
    }

    const upstreamRes = await fetch(upstreamUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify(nonStreamBody),
    });

    if (!upstreamRes.ok) {
      const errorBody = await upstreamRes.text();
      res.writeHead(upstreamRes.status, { 'Content-Type': 'application/json' });
      res.end(errorBody);
      return;
    }

    const responseData = await upstreamRes.json() as AnthropicMessage;

    // Convert non-streaming response to proper Anthropic SSE events
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
    });

    emitAnthropicStream(res, responseData);

  } catch (error) {
    const errMsg = error instanceof Error ? error.message : String(error);
    console.error(`[streaming-adapter] Error: ${errMsg}`);

    if (!res.headersSent) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: { message: errMsg } }));
    }
  }
}

interface AnthropicContentBlock {
  type: string;
  text?: string;
  id?: string;
  name?: string;
  input?: Record<string, unknown>;
  thinking?: string;
}

interface AnthropicMessage {
  id: string;
  type: string;
  role: string;
  model: string;
  content: AnthropicContentBlock[];
  stop_reason: string | null;
  stop_sequence: string | null;
  usage: {
    input_tokens: number;
    output_tokens: number;
    cache_creation_input_tokens?: number;
    cache_read_input_tokens?: number;
  };
}

function sendSSE(res: ServerResponse, event: string, data: unknown): void {
  res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
}

/**
 * Convert a non-streaming Anthropic response to proper SSE events.
 * This ensures tool_use blocks are properly formatted as streaming events.
 */
function emitAnthropicStream(res: ServerResponse, msg: AnthropicMessage): void {
  // 1. message_start
  sendSSE(res, 'message_start', {
    type: 'message_start',
    message: {
      id: msg.id,
      type: 'message',
      role: 'assistant',
      content: [],
      model: msg.model,
      stop_reason: null,
      stop_sequence: null,
      usage: {
        input_tokens: msg.usage?.input_tokens ?? 0,
        output_tokens: 0,
        cache_creation_input_tokens: msg.usage?.cache_creation_input_tokens ?? 0,
        cache_read_input_tokens: msg.usage?.cache_read_input_tokens ?? 0,
      },
    },
  });

  // 2. Emit each content block
  for (let i = 0; i < msg.content.length; i++) {
    const block = msg.content[i]!;

    if (block.type === 'text') {
      // Text block
      sendSSE(res, 'content_block_start', {
        type: 'content_block_start',
        index: i,
        content_block: { type: 'text', text: '' },
      });

      if (block.text) {
        sendSSE(res, 'content_block_delta', {
          type: 'content_block_delta',
          index: i,
          delta: { type: 'text_delta', text: block.text },
        });
      }

      sendSSE(res, 'content_block_stop', {
        type: 'content_block_stop',
        index: i,
      });

    } else if (block.type === 'tool_use') {
      // Tool use block — properly formatted!
      sendSSE(res, 'content_block_start', {
        type: 'content_block_start',
        index: i,
        content_block: {
          type: 'tool_use',
          id: block.id ?? `tool_${i}`,
          name: block.name ?? '',
        },
      });

      // Send input as JSON delta
      const inputJson = JSON.stringify(block.input ?? {});
      sendSSE(res, 'content_block_delta', {
        type: 'content_block_delta',
        index: i,
        delta: { type: 'input_json_delta', partial_json: inputJson },
      });

      sendSSE(res, 'content_block_stop', {
        type: 'content_block_stop',
        index: i,
      });

    } else if (block.type === 'thinking') {
      // Thinking block
      sendSSE(res, 'content_block_start', {
        type: 'content_block_start',
        index: i,
        content_block: { type: 'thinking', thinking: '' },
      });

      if (block.thinking) {
        sendSSE(res, 'content_block_delta', {
          type: 'content_block_delta',
          index: i,
          delta: { type: 'thinking_delta', thinking: block.thinking },
        });
      }

      sendSSE(res, 'content_block_stop', {
        type: 'content_block_stop',
        index: i,
      });
    }
  }

  // 3. message_delta (final usage + stop_reason)
  sendSSE(res, 'message_delta', {
    type: 'message_delta',
    delta: {
      stop_reason: msg.stop_reason ?? 'end_turn',
      stop_sequence: msg.stop_sequence ?? null,
    },
    usage: {
      output_tokens: msg.usage?.output_tokens ?? 0,
    },
  });

  // 4. message_stop
  sendSSE(res, 'message_stop', { type: 'message_stop' });

  res.end();
}

async function proxyPassthrough(
  req: IncomingMessage,
  res: ServerResponse,
  existingBody?: string
): Promise<void> {
  const body = existingBody ?? await readBody(req);
  const upstreamUrl = `${targetBaseUrl}${req.url}`;

  const headers: Record<string, string> = {
    'Content-Type': req.headers['content-type'] ?? 'application/json',
  };

  for (const key of ['x-api-key', 'anthropic-version', 'authorization']) {
    const val = req.headers[key];
    if (val && typeof val === 'string') {
      headers[key] = val;
    }
  }

  const upstreamRes = await fetch(upstreamUrl, {
    method: req.method ?? 'POST',
    headers,
    ...(body ? { body } : {}),
  });

  const responseBody = await upstreamRes.text();
  const responseHeaders: Record<string, string> = {};
  upstreamRes.headers.forEach((value, key) => {
    responseHeaders[key] = value;
  });

  res.writeHead(upstreamRes.status, responseHeaders);
  res.end(responseBody);
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks).toString()));
    req.on('error', reject);
  });
}
