// Donna - Continuous AI Pentesting Platform
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Temporal client for the Donna dashboard.
 *
 * Connects to the same Temporal server as the worker and queries
 * workflow state via the getProgress query + list workflows API.
 */

import { Connection, Client } from '@temporalio/client';
import { computeFindingSummaryFromFiles } from './audit-logs.js';

// Types mirrored from src/temporal/shared.ts (kept in sync manually —
// dashboard is a separate package so we don't import from the main project)

export interface FindingSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  informational: number;
  deduplicated: number;
}

export interface PipelineSummary {
  totalCostUsd: number;
  totalDurationMs: number;
  totalTurns: number;
  agentCount: number;
}

export interface AgentMetrics {
  durationMs: number;
  inputTokens: number | null;
  outputTokens: number | null;
  costUsd: number | null;
  numTurns: number | null;
  model?: string | undefined;
}

export interface PipelineProgress {
  workflowId: string;
  status: 'running' | 'completed' | 'failed';
  currentPhase: string | null;
  currentAgent: string | null;
  completedAgents: string[];
  failedAgent: string | null;
  error: string | null;
  startTime: number;
  agentMetrics: Record<string, AgentMetrics>;
  summary: PipelineSummary | null;
  findingSummary: FindingSummary | null;
  elapsedMs: number;
}

export interface WorkflowInfo {
  workflowId: string;
  runId: string;
  status: string;
  type: string;
  startTime: string;
  closeTime: string | null;
  executionTime: string | null;
  // Enriched from getProgress query (only for running workflows)
  progress?: PipelineProgress;
  // Target URL extracted from workflow input
  webUrl?: string;
  // Model profile name from workflow input (e.g., "claude", "qwen-local", "hybrid")
  modelProfile?: string;
  // Owner email extracted from workflow input
  createdByEmail?: string;
}

// Singleton connection — reused across requests
let clientPromise: Promise<Client> | null = null;

function getTemporalAddress(): string {
  return process.env.TEMPORAL_ADDRESS || 'localhost:7233';
}

export function getTemporalClient(): Promise<Client> {
  if (!clientPromise) {
    clientPromise = (async () => {
      const address = getTemporalAddress();
      const connection = await Connection.connect({ address });
      return new Client({ connection });
    })();
  }
  return clientPromise;
}

/**
 * List all workflows from Temporal, optionally filtered by status.
 */
export async function listWorkflows(options?: {
  status?: string;
  pageSize?: number;
}): Promise<WorkflowInfo[]> {
  const client = await getTemporalClient();
  const pageSize = options?.pageSize || 100;

  // Build query string for workflow list
  let query = 'WorkflowType = "pentestPipelineWorkflow"';
  if (options?.status) {
    const statusMap: Record<string, string> = {
      running: 'Running',
      completed: 'Completed',
      failed: 'Failed',
      terminated: 'Terminated',
      cancelled: 'Canceled',
    };
    const mapped = statusMap[options.status.toLowerCase()];
    if (mapped) {
      query += ` AND ExecutionStatus = "${mapped}"`;
    }
  }

  const workflows: WorkflowInfo[] = [];
  let count = 0;

  for await (const workflow of client.workflow.list({ query })) {
    if (count >= pageSize) break;

    workflows.push({
      workflowId: workflow.workflowId,
      runId: workflow.runId,
      status: workflow.status.name.toLowerCase(),
      type: workflow.workflowType || 'unknown',
      startTime: workflow.startTime?.toISOString() || '',
      closeTime: workflow.closeTime?.toISOString() || null,
      executionTime: workflow.executionTime?.toISOString() || null,
    });

    count++;
  }

  return workflows;
}

/**
 * Query a running workflow's progress via the getProgress query.
 */
export async function getWorkflowProgress(
  workflowId: string
): Promise<PipelineProgress | null> {
  try {
    const client = await getTemporalClient();
    const handle = client.workflow.getHandle(workflowId);
    const progress = await handle.query<PipelineProgress>('getProgress');
    return progress;
  } catch {
    // Workflow may have completed or query not available
    return null;
  }
}

/**
 * Start a new pentest pipeline workflow.
 */
export async function startWorkflow(options: {
  webUrl: string;
  repoPath?: string;
  gitUrl?: string;
  pipelineTestingMode?: boolean;
  createdByEmail?: string;
  modelProfile?: string;
  modelProfileConfig?: {
    base_url: string;
    api_key?: string;
    tiers: { small: string; medium: string; large: string };
  };
}): Promise<{ workflowId: string; runId: string }> {
  const client = await getTemporalClient();

  // Build a workflow ID from the hostname + timestamp
  const hostname = new URL(options.webUrl).hostname.replace(/[^a-zA-Z0-9-]/g, '_');
  const workflowId = `${hostname}_donna-${Date.now()}`;

  const input = {
    webUrl: options.webUrl,
    ...(options.repoPath && { repoPath: options.repoPath }),
    ...(options.gitUrl && { gitUrl: options.gitUrl }),
    workflowId,
    sessionId: workflowId,
    ...(options.pipelineTestingMode && { pipelineTestingMode: true }),
    // Store creator email for per-user authorization (AUTHZ-VULN-01 fix)
    ...(options.createdByEmail && { createdByEmail: options.createdByEmail }),
    // Model profile for multi-provider LLM support
    ...(options.modelProfile && { modelProfile: options.modelProfile }),
    ...(options.modelProfileConfig && { modelProfileConfig: options.modelProfileConfig }),
  };

  const handle = await client.workflow.start('pentestPipelineWorkflow', {
    taskQueue: 'donna-pipeline',
    workflowId,
    args: [input],
  });

  return { workflowId, runId: handle.firstExecutionRunId };
}

/**
 * Extract workflow input from the first history event.
 * Returns the parsed input object or null.
 */
export async function extractWorkflowInput(client: Client, workflowId: string, runId: string): Promise<Record<string, unknown> | null> {
  try {
    const handle = client.workflow.getHandle(workflowId, runId);
    const history = handle.fetchHistory();
    for await (const event of (await history).events || []) {
      const attrs = (event as any).workflowExecutionStartedEventAttributes;
      if (attrs?.input?.payloads?.[0]?.data) {
        return JSON.parse(Buffer.from(attrs.input.payloads[0].data).toString('utf-8'));
      }
    }
  } catch { /* history unavailable */ }
  return null;
}

/**
 * List workflow IDs owned by a specific user (lightweight — no progress enrichment).
 * Used for authorization checks without the overhead of full progress/result fetching.
 */
export async function listUserWorkflowIds(userEmail: string): Promise<Set<string>> {
  const workflows = await listWorkflows();
  const client = await getTemporalClient();
  const ids = new Set<string>();

  await Promise.all(
    workflows.map(async (wf) => {
      const input = await extractWorkflowInput(client, wf.workflowId, wf.runId);
      const owner = input?.createdByEmail as string | undefined;
      // Include if owned by user, or legacy (no owner)
      if (!owner || owner.toLowerCase() === userEmail.toLowerCase()) {
        ids.add(wf.workflowId);
      }
    })
  );

  return ids;
}

/**
 * List workflows enriched with progress data for running ones.
 * When userEmail is provided, only returns workflows owned by that user
 * (or legacy workflows without owner info).
 */
export async function listWorkflowsWithProgress(options?: {
  status?: string;
  pageSize?: number;
  userEmail?: string;
}): Promise<WorkflowInfo[]> {
  const workflows = await listWorkflows(options);

  // Enrich workflows with progress/result data (in parallel)
  const client = await getTemporalClient();
  const enriched = await Promise.all(
    workflows.map(async (wf) => {
      let enriched: WorkflowInfo = { ...wf };

      // Extract webUrl and createdByEmail from workflow input (first history event)
      const input = await extractWorkflowInput(client, wf.workflowId, wf.runId);
      if (input) {
        if (input.webUrl) enriched.webUrl = input.webUrl as string;
        if (input.modelProfile) enriched.modelProfile = input.modelProfile as string;
        if (input.createdByEmail) enriched.createdByEmail = input.createdByEmail as string;
      }

      if (wf.status === 'running') {
        const progress = await getWorkflowProgress(wf.workflowId);
        if (progress) {
          return { ...enriched, progress };
        }
      } else if (wf.status === 'completed') {
        // Fetch result for completed workflows to get findingSummary
        try {
          const handle = client.workflow.getHandle(wf.workflowId);
          const result = await handle.result() as PipelineProgress;
          if (result) {
            // Backfill findingSummary from evidence files if not in workflow result
            if (!result.findingSummary) {
              const backfilled = await computeFindingSummaryFromFiles(wf.workflowId);
              if (backfilled) {
                result.findingSummary = backfilled;
              }
            }
            return { ...enriched, progress: { ...result, workflowId: wf.workflowId, elapsedMs: 0 } };
          }
        } catch { /* result unavailable */ }
      }
      return enriched;
    })
  );

  // Filter by user email if provided (AUTHZ-VULN-01 fix)
  if (options?.userEmail) {
    const userEmail = options.userEmail.toLowerCase();
    return enriched.filter(wf => {
      // Legacy workflows without owner are visible to all authenticated users
      if (!wf.createdByEmail) return true;
      return wf.createdByEmail.toLowerCase() === userEmail;
    });
  }

  return enriched;
}
