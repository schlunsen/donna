// Donna - Continuous AI Pentesting Platform
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Temporal activities for the continuous scanning workflow.
 *
 * These activities handle:
 * - Git fetch and diff operations
 * - Change routing (mapping file changes to vuln categories)
 * - Finding tracking and baseline management
 * - Webhook notifications
 */

import { heartbeat } from '@temporalio/activity';
import path from 'path';
import fs from 'fs/promises';

import {
  gitFetchLatest,
  gitDiff,
  routeChanges,
} from '../services/git-monitor.js';
import {
  loadBaseline,
  saveBaseline,
  extractFindingsFromReport,
  computeDelta,
} from '../services/finding-tracker.js';
import { fileExists } from '../utils/file-io.js';
import { createActivityLogger } from './activity-logger.js';
import type { VulnType } from '../types/agents.js';
import type {
  ContinuousInput,
  GitDiffResult,
  ChangeRouting,
  ScanBaseline,
  DeltaReport,
  NotificationPayload,
  Finding,
} from './continuous-shared.js';

const HEARTBEAT_INTERVAL_MS = 5000;

// ── Git Sync Activity ───────────────────────────────────────────

export interface GitSyncResult {
  diff: GitDiffResult;
  routing: ChangeRouting;
}

/**
 * Fetch latest changes from git remote and determine what to scan.
 *
 * This is the first activity in the continuous workflow. It:
 * 1. Fetches the latest commits from the remote
 * 2. Diffs against the last scanned commit
 * 3. Routes changes to determine scan strategy
 */
export async function gitSyncAndRoute(
  input: ContinuousInput,
  lastScannedCommit: string | null,
  lastFullScanTimestamp: string | null
): Promise<GitSyncResult> {
  const logger = createActivityLogger();
  const startTime = Date.now();

  const heartbeatInterval = setInterval(() => {
    const elapsed = Math.floor((Date.now() - startTime) / 1000);
    heartbeat({ phase: 'git-sync', elapsedSeconds: elapsed });
  }, HEARTBEAT_INTERVAL_MS);

  try {
    const remote = input.gitRemote ?? 'origin';
    const branch = input.gitBranch ?? 'main';

    // 1. Fetch latest
    const fetchOptions: { deployKeyPath?: string; tokenEnvVar?: string } = {};
    if (input.gitDeployKey) fetchOptions.deployKeyPath = input.gitDeployKey;
    if (input.gitTokenEnv) fetchOptions.tokenEnvVar = input.gitTokenEnv;

    await gitFetchLatest(input.repoPath, remote, branch, logger, fetchOptions);

    // 2. Diff
    const diff = await gitDiff(input.repoPath, lastScannedCommit, remote, branch, logger);

    // 3. Determine if we need a forced full scan (periodic)
    const fullScanEveryDays = input.fullScanEveryDays ?? 7;
    const daysSinceFullScan = lastFullScanTimestamp
      ? (Date.now() - new Date(lastFullScanTimestamp).getTime()) / (1000 * 60 * 60 * 24)
      : Infinity;
    const forceFull = daysSinceFullScan >= fullScanEveryDays;

    // 4. Route changes
    const routing = routeChanges(diff, {
      strategy: input.strategy ?? 'incremental',
      forceFull,
      isFirstScan: lastScannedCommit === null,
    });

    logger.info(`Routing decision: ${routing.reason}`);
    logger.info(`Categories to scan: ${routing.vulnCategories.join(', ') || '(none — skipping)'}`);

    return { diff, routing };
  } finally {
    clearInterval(heartbeatInterval);
  }
}

// ── Finding Tracking Activity ───────────────────────────────────

export interface FindingTrackingResult {
  delta: DeltaReport;
  baseline: ScanBaseline;
}

/**
 * After a pipeline run completes, extract findings from the report,
 * compare against the previous baseline, and produce a delta report.
 */
export async function trackFindings(
  input: ContinuousInput,
  scanId: string,
  gitCommit: string,
  scannedCategories: VulnType[],
  scanType: 'full' | 'incremental'
): Promise<FindingTrackingResult> {
  const logger = createActivityLogger();
  const startTime = Date.now();

  const heartbeatInterval = setInterval(() => {
    const elapsed = Math.floor((Date.now() - startTime) / 1000);
    heartbeat({ phase: 'finding-tracking', elapsedSeconds: elapsed });
  }, HEARTBEAT_INTERVAL_MS);

  try {
    const auditDir = input.outputPath
      ? path.join(input.outputPath, 'continuous')
      : path.join('./audit-logs', 'continuous');
    const timestamp = new Date().toISOString();

    // 1. Load previous baseline
    const previousBaseline = await loadBaseline(auditDir, logger);

    // 2. Extract findings from each scanned category's evidence/report files
    const allNewFindings: Finding[] = [];

    for (const vulnType of scannedCategories) {
      // Try exploitation evidence first (more reliable — actual exploits)
      const evidenceFile = path.join(
        input.repoPath,
        'deliverables',
        `${vulnType}_exploitation_evidence.md`
      );

      if (await fileExists(evidenceFile)) {
        const content = await fs.readFile(evidenceFile, 'utf8');
        const findings = extractFindingsFromReport(content, vulnType, scanId, timestamp);
        allNewFindings.push(...findings);
        logger.info(`Extracted ${findings.length} finding(s) from ${vulnType} evidence`);
      }
    }

    // Also check the comprehensive report
    const reportFile = path.join(
      input.repoPath,
      'deliverables',
      'comprehensive_security_assessment_report.md'
    );

    if (await fileExists(reportFile)) {
      const content = await fs.readFile(reportFile, 'utf8');
      // Extract from report for any categories we might have missed
      for (const vulnType of scannedCategories) {
        const findings = extractFindingsFromReport(content, vulnType, scanId, timestamp);
        // Only add findings not already extracted from evidence files
        const existingIds = new Set(allNewFindings.map((f) => f.id));
        const newFromReport = findings.filter((f) => !existingIds.has(f.id));
        allNewFindings.push(...newFromReport);
      }
    }

    logger.info(`Total findings extracted: ${allNewFindings.length}`);

    // 3. Compute delta
    const { updatedFindings, delta } = computeDelta(
      previousBaseline,
      allNewFindings,
      scannedCategories,
      scanId,
      timestamp,
      logger
    );

    // 4. Save new baseline
    const newBaseline: ScanBaseline = {
      scanId,
      timestamp,
      gitCommit,
      findings: updatedFindings,
      scanType,
      scannedCategories,
    };

    await saveBaseline(auditDir, newBaseline, logger);

    return { delta, baseline: newBaseline };
  } finally {
    clearInterval(heartbeatInterval);
  }
}

// ── Notification Activity ───────────────────────────────────────

/**
 * Send a notification about scan results via webhook.
 *
 * Supports Slack and Discord webhook formats.
 * Only sends if there are new or resolved findings (skips "no changes" scans).
 */
export async function sendNotification(
  webhookUrl: string,
  payload: NotificationPayload
): Promise<void> {
  const logger = createActivityLogger();

  // Skip notification if no meaningful changes
  if (
    payload.delta.newFindings.length === 0 &&
    payload.delta.resolvedFindings.length === 0
  ) {
    logger.info('No new or resolved findings, skipping notification');
    return;
  }

  const summary = payload.summary;

  try {
    // Detect webhook type and format accordingly
    const isDiscord = webhookUrl.includes('discord.com');
    const body = isDiscord
      ? JSON.stringify({ content: summary })
      : JSON.stringify({ text: summary });

    const response = await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body,
    });

    if (!response.ok) {
      logger.warn(`Webhook returned ${response.status}: ${await response.text()}`);
    } else {
      logger.info('Notification sent successfully');
    }
  } catch (error) {
    const errMsg = error instanceof Error ? error.message : String(error);
    logger.warn(`Failed to send notification: ${errMsg}`);
    // Don't throw — notifications are best-effort
  }
}

// ── Scan History Activity ───────────────────────────────────────

export interface ScanHistoryEntry {
  scanId: string;
  timestamp: string;
  gitCommit: string;
  scanType: 'full' | 'incremental';
  newFindings: number;
  resolvedFindings: number;
  totalActive: number;
  skipped: boolean;
  skipReason?: string;
}

const SCAN_HISTORY_FILENAME = 'continuous_scan_history.json';

/**
 * Append a scan result to the scan history log.
 */
export async function recordScanHistory(
  input: ContinuousInput,
  entry: ScanHistoryEntry
): Promise<void> {
  const logger = createActivityLogger();
  const auditDir = input.outputPath
    ? path.join(input.outputPath, 'continuous')
    : path.join('./audit-logs', 'continuous');

  const historyPath = path.join(auditDir, SCAN_HISTORY_FILENAME);

  await fs.mkdir(auditDir, { recursive: true });

  let history: ScanHistoryEntry[] = [];
  if (await fileExists(historyPath)) {
    try {
      const content = await fs.readFile(historyPath, 'utf8');
      history = JSON.parse(content);
    } catch {
      logger.warn('Failed to parse scan history, starting fresh');
    }
  }

  history.push(entry);

  // Keep last 100 entries
  if (history.length > 100) {
    history = history.slice(-100);
  }

  await fs.writeFile(historyPath, JSON.stringify(history, null, 2));
  logger.info(`Recorded scan ${entry.scanId} to history (${history.length} total entries)`);
}
