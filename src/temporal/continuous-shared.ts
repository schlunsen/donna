// Donna - Continuous AI Pentesting Platform
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Types and queries for the continuous scanning workflow.
 *
 * The continuous workflow monitors git repos and web targets on a cron schedule,
 * detects changes, and triggers incremental or full pentest pipelines.
 */

import { defineQuery } from '@temporalio/workflow';
import type { VulnType } from '../types/agents.js';
import type { PipelineConfig } from '../types/config.js';

// ── Workflow Input ──────────────────────────────────────────────

export interface ContinuousInput {
  /** Web target URL */
  webUrl: string;
  /** Local path to the cloned repository */
  repoPath: string;
  /** Git remote to fetch from (default: "origin") */
  gitRemote?: string;
  /** Branch to track (default: "main") */
  gitBranch?: string;
  /** SSH deploy key path for git fetch (optional) */
  gitDeployKey?: string;
  /** Environment variable name holding a git token (optional) */
  gitTokenEnv?: string;
  /** Strategy: "incremental" skips unchanged vuln categories, "full" always runs all */
  strategy?: 'incremental' | 'full';
  /** Days between forced full scans (default: 7) */
  fullScanEveryDays?: number;
  /** Optional config path (auth, rules, etc.) */
  configPath?: string;
  /** Output directory for audit logs */
  outputPath?: string;
  /** Pipeline testing mode (fast, minimal prompts) */
  pipelineTestingMode?: boolean;
  /** Pipeline config (retry preset, concurrency) */
  pipelineConfig?: PipelineConfig;
  /** Notification webhook URL (Slack/Discord) */
  notificationWebhook?: string;
  /** Workflow ID for audit correlation */
  workflowId?: string;
}

// ── Git Diff ────────────────────────────────────────────────────

export interface GitDiffResult {
  /** Commit hash of the previous scan (null if first scan) */
  previousCommit: string | null;
  /** Current HEAD commit after fetch */
  currentCommit: string;
  /** Files changed since last scan */
  changedFiles: string[];
  /** Whether any changes were detected */
  hasChanges: boolean;
  /** Summary of changes by directory */
  changeSummary: Record<string, number>;
}

// ── Change Routing ──────────────────────────────────────────────

export interface ChangeRouting {
  /** Whether to run a full scan (vs incremental) */
  fullScan: boolean;
  /** Reason for the routing decision */
  reason: string;
  /** Vuln categories to scan (all 5 for full, subset for incremental) */
  vulnCategories: VulnType[];
  /** Number of changed files */
  changedFileCount: number;
}

// ── Scan Baseline ───────────────────────────────────────────────

export interface ScanBaseline {
  /** Unique scan identifier */
  scanId: string;
  /** ISO timestamp of the scan */
  timestamp: string;
  /** Git commit that was scanned */
  gitCommit: string;
  /** All known findings */
  findings: Finding[];
  /** Whether this was a full or incremental scan */
  scanType: 'full' | 'incremental';
  /** Vuln categories that were scanned */
  scannedCategories: VulnType[];
}

export type FindingStatus = 'new' | 'confirmed' | 'resolved';

export interface Finding {
  /** Stable ID (hash of vuln signature: type + location + description) */
  id: string;
  /** Vulnerability type */
  vulnType: VulnType;
  /** First seen ISO timestamp */
  firstSeen: string;
  /** Last seen ISO timestamp */
  lastSeen: string;
  /** Current lifecycle status */
  status: FindingStatus;
  /** Severity from report */
  severity: string;
  /** Short description */
  title: string;
  /** File/endpoint where the vulnerability was found */
  location: string;
  /** Scan ID when first discovered */
  discoveredInScan: string;
}

// ── Delta Report ────────────────────────────────────────────────

export interface DeltaReport {
  /** New findings in this scan */
  newFindings: Finding[];
  /** Findings confirmed again */
  confirmedFindings: Finding[];
  /** Findings no longer present */
  resolvedFindings: Finding[];
  /** Total active findings */
  totalActive: number;
}

// ── Notification ────────────────────────────────────────────────

export interface NotificationPayload {
  scanId: string;
  timestamp: string;
  webUrl: string;
  gitCommit: string;
  scanType: 'full' | 'incremental';
  delta: DeltaReport;
  /** Human-readable summary */
  summary: string;
}

// ── Workflow State ──────────────────────────────────────────────

export interface ContinuousState {
  status: 'idle' | 'syncing' | 'routing' | 'scanning' | 'reporting' | 'completed' | 'failed';
  currentScanId: string | null;
  lastScanId: string | null;
  lastScanTimestamp: string | null;
  lastGitCommit: string | null;
  totalScans: number;
  totalFindings: number;
  error: string | null;
  startTime: number;
}

export interface ContinuousProgress extends ContinuousState {
  workflowId: string;
  elapsedMs: number;
}

// ── Queries ─────────────────────────────────────────────────────

export const getContinuousProgress = defineQuery<ContinuousProgress>('getContinuousProgress');

// ── Notification Formatting ─────────────────────────────────────

/**
 * Format a human-readable notification summary from a DeltaReport.
 * Pure function — safe for workflow context (no crypto/fs/path).
 */
export function formatNotificationSummary(
  delta: DeltaReport,
  webUrl: string,
  gitCommit: string,
  scanType: 'full' | 'incremental'
): string {
  const lines: string[] = [];

  lines.push(`🛡️ Donna Sentinel — ${scanType} scan`);
  lines.push(`Target: ${webUrl}`);
  lines.push(`Commit: ${gitCommit.slice(0, 8)}`);
  lines.push('');

  if (delta.newFindings.length > 0) {
    lines.push(`🚨 ${delta.newFindings.length} NEW finding(s):`);
    for (const f of delta.newFindings.slice(0, 5)) {
      lines.push(`  • [${f.severity.toUpperCase()}] ${f.title}`);
    }
    if (delta.newFindings.length > 5) {
      lines.push(`  ... and ${delta.newFindings.length - 5} more`);
    }
    lines.push('');
  }

  if (delta.resolvedFindings.length > 0) {
    lines.push(`✅ ${delta.resolvedFindings.length} RESOLVED finding(s)`);
  }

  if (delta.confirmedFindings.length > 0) {
    lines.push(`⚠️  ${delta.confirmedFindings.length} still present`);
  }

  lines.push('');
  lines.push(`Total active: ${delta.totalActive}`);

  return lines.join('\n');
}
