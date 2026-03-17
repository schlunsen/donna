// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Donna Sentinel — Continuous security monitoring workflow.
 *
 * Runs on a cron schedule via Temporal's cronSchedule option.
 * Each execution:
 *   1. Fetches latest git changes
 *   2. Determines what changed (incremental diff)
 *   3. Routes changes to relevant vuln categories
 *   4. Runs the pentest pipeline (full or incremental)
 *   5. Tracks findings across scans (new/confirmed/resolved)
 *   6. Sends notifications on new or resolved findings
 *
 * State between cron runs is persisted via baseline files in audit-logs/continuous/.
 *
 * Usage (via Temporal client):
 *   client.workflow.start('continuousPentestWorkflow', {
 *     taskQueue: 'donna-pipeline',
 *     workflowId: 'donna-continuous-myapp',
 *     cronSchedule: '0 *​/6 * * *',  // every 6 hours
 *     args: [input],
 *   });
 */

import {
  log,
  proxyActivities,
  setHandler,
  workflowInfo,
  executeChild,
} from '@temporalio/workflow';
import type * as continuousActivities from './continuous-activities.js';
import {
  getContinuousProgress,
  formatNotificationSummary,
  type ContinuousInput,
  type ContinuousState,
  type ContinuousProgress,
  type NotificationPayload,
} from './continuous-shared.js';
import type { PipelineInput, PipelineState } from './shared.js';

// ── Activity Proxies ────────────────────────────────────────────

// Continuous-specific activities (git sync, finding tracking, notifications)
const contActs = proxyActivities<typeof continuousActivities>({
  startToCloseTimeout: '10 minutes',
  heartbeatTimeout: '5 minutes',
  retry: {
    initialInterval: '30 seconds',
    maximumInterval: '5 minutes',
    backoffCoefficient: 2,
    maximumAttempts: 5,
    nonRetryableErrorTypes: ['ConfigurationError', 'InvalidTargetError'],
  },
});

// ── Workflow ─────────────────────────────────────────────────────

export async function continuousPentestWorkflow(
  input: ContinuousInput
): Promise<ContinuousState> {
  const { workflowId } = workflowInfo();
  const scanId = `scan-${Date.now()}`;

  const state: ContinuousState = {
    status: 'idle',
    currentScanId: scanId,
    lastScanId: null,
    lastScanTimestamp: null,
    lastGitCommit: null,
    totalScans: 0,
    totalFindings: 0,
    error: null,
    startTime: Date.now(),
  };

  setHandler(getContinuousProgress, (): ContinuousProgress => ({
    ...state,
    workflowId,
    elapsedMs: Date.now() - state.startTime,
  }));

  try {
    // ── Step 1: Git Sync & Change Routing ──────────────────────
    state.status = 'syncing';
    log.info('Starting continuous scan', { scanId });

    const { diff, routing } = await contActs.gitSyncAndRoute(
      input,
      state.lastGitCommit,
      state.lastScanTimestamp
    );

    state.lastGitCommit = diff.currentCommit;

    // ── Step 2: Early exit if no changes ───────────────────────
    if (!diff.hasChanges || routing.vulnCategories.length === 0) {
      log.info('No changes detected, skipping scan');

      // Record skip in history
      await contActs.recordScanHistory(input, {
        scanId,
        timestamp: new Date().toISOString(),
        gitCommit: diff.currentCommit,
        scanType: routing.fullScan ? 'full' : 'incremental',
        newFindings: 0,
        resolvedFindings: 0,
        totalActive: state.totalFindings,
        skipped: true,
        skipReason: routing.reason,
      });

      state.status = 'completed';
      state.totalScans += 1;
      return state;
    }

    // ── Step 3: Run Pentest Pipeline ───────────────────────────
    state.status = 'scanning';
    log.info(`Running ${routing.fullScan ? 'full' : 'incremental'} scan: ${routing.reason}`);

    // Build pipeline input for the child workflow
    const pipelineInput: PipelineInput = {
      webUrl: input.webUrl,
      repoPath: input.repoPath,
      workflowId: `${workflowId}-${scanId}`,
      sessionId: `continuous-${scanId}`,
      ...(input.configPath && { configPath: input.configPath }),
      ...(input.outputPath && { outputPath: input.outputPath }),
      ...(input.pipelineTestingMode && { pipelineTestingMode: input.pipelineTestingMode }),
      ...(input.pipelineConfig && { pipelineConfig: input.pipelineConfig }),
    };

    // Execute the existing pentest pipeline as a child workflow
    // This reuses ALL existing agent logic without modification
    const pipelineResult = await executeChild<(input: PipelineInput) => Promise<PipelineState>>(
      'pentestPipelineWorkflow',
      {
        workflowId: `${workflowId}-pipeline-${scanId}`,
        taskQueue: 'donna-pipeline',
        args: [pipelineInput],
      }
    );

    log.info('Pipeline completed', {
      status: pipelineResult.status,
      completedAgents: pipelineResult.completedAgents.length,
    });

    // ── Step 4: Track Findings ─────────────────────────────────
    state.status = 'reporting';

    const scanType = routing.fullScan ? 'full' : 'incremental';
    const { delta, baseline } = await contActs.trackFindings(
      input,
      scanId,
      diff.currentCommit,
      routing.vulnCategories,
      scanType
    );

    state.totalFindings = baseline.findings.filter((f) => f.status !== 'resolved').length;

    // ── Step 5: Record History ─────────────────────────────────
    await contActs.recordScanHistory(input, {
      scanId,
      timestamp: new Date().toISOString(),
      gitCommit: diff.currentCommit,
      scanType,
      newFindings: delta.newFindings.length,
      resolvedFindings: delta.resolvedFindings.length,
      totalActive: delta.totalActive,
      skipped: false,
    });

    // ── Step 6: Notify ─────────────────────────────────────────
    if (input.notificationWebhook) {
      const summary = formatNotificationSummary(
        delta,
        input.webUrl,
        diff.currentCommit,
        scanType
      );

      const payload: NotificationPayload = {
        scanId,
        timestamp: new Date().toISOString(),
        webUrl: input.webUrl,
        gitCommit: diff.currentCommit,
        scanType,
        delta,
        summary,
      };

      await contActs.sendNotification(input.notificationWebhook, payload);
    }

    // ── Done ───────────────────────────────────────────────────
    state.status = 'completed';
    state.lastScanId = scanId;
    state.lastScanTimestamp = new Date().toISOString();
    state.totalScans += 1;

    log.info('Continuous scan complete', {
      scanId,
      newFindings: delta.newFindings.length,
      resolvedFindings: delta.resolvedFindings.length,
      totalActive: delta.totalActive,
    });

    return state;
  } catch (error) {
    state.status = 'failed';
    state.error = error instanceof Error ? error.message : String(error);
    log.error('Continuous scan failed', { error: state.error });
    throw error;
  }
}
