/**
 * API endpoints for workflow operations:
 * GET  /api/workflow/:runId          — returns workflow detail
 * GET  /api/workflow/:runId?query=X  — runs a query
 * POST /api/workflow/:runId?action=cancel    — request cancellation
 * POST /api/workflow/:runId?action=terminate — terminate workflow
 */

import type { APIRoute } from 'astro';
import { getTemporalClient } from '../../../lib/temporal.js';

async function findWorkflow(runId: string) {
  const client = await getTemporalClient();
  let workflowId: string | null = null;
  for await (const wf of client.workflow.list({ query: `RunId = "${runId}"` })) {
    workflowId = wf.workflowId;
    break;
  }
  if (!workflowId) return null;
  return { client, handle: client.workflow.getHandle(workflowId, runId), workflowId };
}

export const GET: APIRoute = async ({ params, url }) => {
  const { runId } = params;

  if (!runId) {
    return new Response(JSON.stringify({ error: 'runId required' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  try {
    const found = await findWorkflow(runId);
    if (!found) {
      return new Response(JSON.stringify({ error: 'Workflow not found' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    const { handle } = found;

    // Handle query parameter — run a specific query
    const queryType = url.searchParams.get('query');
    if (queryType) {
      try {
        const result = await handle.query(queryType);
        return new Response(JSON.stringify({ progress: result }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      } catch (err) {
        return new Response(JSON.stringify({
          error: `Query "${queryType}" failed: ${err instanceof Error ? err.message : 'unknown error'}`
        }), {
          status: 500,
          headers: { 'Content-Type': 'application/json' },
        });
      }
    }

    const description = await handle.describe();

    // Build detail object
    const detail: Record<string, unknown> = {
      workflowId: description.workflowId,
      runId: description.runId,
      type: description.type,
      status: description.status.name.toLowerCase(),
      taskQueue: description.taskQueue,
      startTime: description.startTime?.toISOString() || null,
      closeTime: description.closeTime?.toISOString() || null,
      executionTime: description.executionTime?.toISOString() || null,
      historyLength: description.historyLength,
      memo: description.memo,
      searchAttributes: description.searchAttributes,
      parentExecution: description.parentExecution || null,
    };

    // Get progress query for running workflows
    if (description.status.name === 'RUNNING') {
      try {
        const progress = await handle.query('getProgress');
        detail.progress = progress;
      } catch {
        // Query may not be available
      }

      // Fetch heartbeat details from pending activities for live turn data
      try {
        const fullDesc = await handle.describe();
        // The Temporal SDK WorkflowExecutionDescription has a `raw` property
        // containing the full gRPC DescribeWorkflowExecutionResponse,
        // which includes pendingActivities with heartbeatDetails.
        const raw = (fullDesc as unknown as { raw?: { pendingActivities?: Array<{ heartbeatDetails?: { payloads?: Array<{ data?: Uint8Array | Buffer }> } }> } }).raw;
        const pendingActivities = raw?.pendingActivities;
        if (Array.isArray(pendingActivities) && pendingActivities.length > 0) {
          const heartbeats: Array<Record<string, unknown>> = [];
          for (const pa of pendingActivities) {
            if (pa.heartbeatDetails) {
              const payloads = pa.heartbeatDetails?.payloads;
              if (Array.isArray(payloads) && payloads.length > 0) {
                for (const payload of payloads) {
                  if (payload.data) {
                    try {
                      const decoded = Buffer.from(payload.data).toString('utf-8');
                      heartbeats.push(JSON.parse(decoded));
                    } catch {
                      // skip malformed payloads
                    }
                  }
                }
              }
            }
          }
          if (heartbeats.length > 0) {
            detail.heartbeats = heartbeats;
          }
        }
      } catch {
        // Heartbeat data is best-effort
      }
    }

    // Fetch history events (last 50)
    try {
      const history: Array<Record<string, unknown>> = [];
      const fullHistory = await handle.fetchHistory();
      const events = fullHistory.events || [];

      for (const event of events.slice(-50)) {
        history.push({
          eventId: Number(event.eventId),
          eventType: event.eventType,
          eventTime: event.eventTime?.toISOString?.() || null,
          attributes: getEventAttributes(event),
        });
      }
      detail.history = history;
      detail.historySize = events.length;
    } catch {
      detail.history = [];
      detail.historySize = 0;
    }

    return new Response(JSON.stringify(detail), {
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

export const POST: APIRoute = async ({ params, url }) => {
  const { runId } = params;
  const action = url.searchParams.get('action');

  if (!runId) {
    return new Response(JSON.stringify({ error: 'runId required' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  if (!action || !['cancel', 'terminate'].includes(action)) {
    return new Response(JSON.stringify({ error: 'action must be "cancel" or "terminate"' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  try {
    const found = await findWorkflow(runId);
    if (!found) {
      return new Response(JSON.stringify({ error: 'Workflow not found' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    const { handle } = found;

    if (action === 'cancel') {
      await handle.cancel();
      return new Response(JSON.stringify({ success: true, message: 'Cancellation requested' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    if (action === 'terminate') {
      await handle.terminate('Terminated via Donna Dashboard');
      return new Response(JSON.stringify({ success: true, message: 'Workflow terminated' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    return new Response(JSON.stringify({ error: 'Unknown action' }), {
      status: 400,
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

function getEventAttributes(event: Record<string, unknown>): Record<string, unknown> {
  const attrKeys = Object.keys(event).filter(k =>
    k.endsWith('EventAttributes') || k.endsWith('Attributes')
  );

  for (const key of attrKeys) {
    const attrs = event[key];
    if (attrs && typeof attrs === 'object') {
      return attrs as Record<string, unknown>;
    }
  }

  return {};
}
