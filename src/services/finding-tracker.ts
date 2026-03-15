// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Finding lifecycle tracker for continuous scanning.
 *
 * Tracks vulnerability findings across scans:
 * - NEW: first time seen
 * - CONFIRMED: seen again in subsequent scan
 * - RESOLVED: not seen in a scan that covered its vuln category
 *
 * Findings are identified by a stable hash of (vulnType + location + title),
 * so they persist across scans even as the report text changes.
 */

import { createHash } from 'crypto';
import fs from 'fs/promises';
import path from 'path';
import { fileExists, readJson } from '../utils/file-io.js';
import type { VulnType } from '../types/agents.js';
import type {
  Finding,
  ScanBaseline,
  DeltaReport,
} from '../temporal/continuous-shared.js';
import type { ActivityLogger } from '../types/activity-logger.js';

// ── Finding ID Generation ───────────────────────────────────────

/**
 * Generate a stable finding ID from its signature.
 * Same vuln in same location produces the same ID across scans.
 */
export function generateFindingId(
  vulnType: VulnType,
  location: string,
  title: string
): string {
  const signature = `${vulnType}:${location}:${title}`.toLowerCase().trim();
  return createHash('sha256').update(signature).digest('hex').slice(0, 16);
}

// ── Baseline Storage ────────────────────────────────────────────

const BASELINE_FILENAME = 'continuous_baseline.json';

/**
 * Get the path to the baseline file for a session.
 */
function baselinePath(auditDir: string): string {
  return path.join(auditDir, BASELINE_FILENAME);
}

/**
 * Load the most recent scan baseline.
 * Returns null if no baseline exists (first scan).
 */
export async function loadBaseline(
  auditDir: string,
  logger: ActivityLogger
): Promise<ScanBaseline | null> {
  const filePath = baselinePath(auditDir);

  if (!(await fileExists(filePath))) {
    logger.info('No existing baseline found (first scan)');
    return null;
  }

  try {
    const baseline = await readJson<ScanBaseline>(filePath);
    logger.info(`Loaded baseline: scan ${baseline.scanId} with ${baseline.findings.length} finding(s)`);
    return baseline;
  } catch (error) {
    const errMsg = error instanceof Error ? error.message : String(error);
    logger.warn(`Failed to load baseline, treating as first scan: ${errMsg}`);
    return null;
  }
}

/**
 * Save a new scan baseline.
 */
export async function saveBaseline(
  auditDir: string,
  baseline: ScanBaseline,
  logger: ActivityLogger
): Promise<void> {
  const filePath = baselinePath(auditDir);

  // Ensure directory exists
  await fs.mkdir(auditDir, { recursive: true });

  await fs.writeFile(filePath, JSON.stringify(baseline, null, 2));
  logger.info(`Saved baseline: scan ${baseline.scanId} with ${baseline.findings.length} finding(s)`);
}

// ── Finding Extraction ──────────────────────────────────────────

/**
 * Parse findings from a pentest report markdown.
 *
 * Looks for structured finding blocks in the report format:
 * - Severity headers (Critical/High/Medium/Low)
 * - Finding titles
 * - Location/file references
 *
 * This is intentionally loose — it parses whatever the report agent produces.
 */
export function extractFindingsFromReport(
  reportContent: string,
  vulnType: VulnType,
  scanId: string,
  timestamp: string
): Finding[] {
  const findings: Finding[] = [];

  // Match finding blocks: look for severity + title patterns
  // Common patterns in Donna reports:
  //   ### Critical: SQL Injection in /api/users
  //   ### [HIGH] XSS via user input in search.js
  //   **Severity:** Critical | **Location:** src/auth/login.ts
  const findingPattern = /###\s*(?:\[?(Critical|High|Medium|Low)\]?[:\s]*)?(.+?)(?:\n|$)/gi;
  const locationPattern = /(?:Location|File|Endpoint|Path)[:\s]*[`*]*([^\n`*]+)[`*]*/i;

  let match: RegExpExecArray | null;

  while ((match = findingPattern.exec(reportContent)) !== null) {
    const severity = match[1] ?? 'Medium';
    const title = (match[2] ?? '').trim();

    if (!title || title.length < 5) continue;

    // Skip non-finding headers (table of contents, summary sections, etc.)
    if (/^(table of contents|summary|overview|methodology|scope|appendix)/i.test(title)) {
      continue;
    }

    // Look for location in the next ~500 chars after the match
    const contextBlock = reportContent.slice(match.index, match.index + 500);
    const locMatch = locationPattern.exec(contextBlock);
    const location = locMatch?.[1]?.trim() ?? 'unknown';

    const id = generateFindingId(vulnType, location, title);

    // Deduplicate within this extraction
    if (findings.some((f) => f.id === id)) continue;

    findings.push({
      id,
      vulnType,
      firstSeen: timestamp,
      lastSeen: timestamp,
      status: 'new',
      severity: severity.toLowerCase(),
      title,
      location,
      discoveredInScan: scanId,
    });

  }

  return findings;
}

// ── Delta Computation ───────────────────────────────────────────

/**
 * Compute the delta between a previous baseline and new findings.
 *
 * Finding lifecycle:
 * - Finding in new but not in previous → NEW
 * - Finding in both → CONFIRMED (update lastSeen)
 * - Finding in previous but not in new, AND the category was scanned → RESOLVED
 * - Finding in previous but not in new, AND the category was NOT scanned → unchanged (carry forward)
 */
export function computeDelta(
  previousBaseline: ScanBaseline | null,
  newFindings: Finding[],
  scannedCategories: VulnType[],
  scanId: string,
  timestamp: string,
  logger: ActivityLogger
): { updatedFindings: Finding[]; delta: DeltaReport } {
  const previousFindings = previousBaseline?.findings ?? [];
  const previousById = new Map(previousFindings.map((f) => [f.id, f]));
  const newById = new Map(newFindings.map((f) => [f.id, f]));
  const scannedSet = new Set(scannedCategories);

  const updatedFindings: Finding[] = [];
  const newDelta: Finding[] = [];
  const confirmedDelta: Finding[] = [];
  const resolvedDelta: Finding[] = [];

  // 1. Process new findings
  for (const finding of newFindings) {
    const prev = previousById.get(finding.id);

    if (prev) {
      // Confirmed: seen before, still present
      const confirmed: Finding = {
        ...prev,
        lastSeen: timestamp,
        status: 'confirmed',
      };
      updatedFindings.push(confirmed);
      confirmedDelta.push(confirmed);
    } else {
      // New: first time seen
      const newFinding: Finding = {
        ...finding,
        status: 'new',
        discoveredInScan: scanId,
      };
      updatedFindings.push(newFinding);
      newDelta.push(newFinding);
    }
  }

  // 2. Process previous findings not in new results
  for (const prev of previousFindings) {
    if (newById.has(prev.id)) continue; // Already handled above

    if (scannedSet.has(prev.vulnType)) {
      // Category was scanned but finding not present → resolved
      const resolved: Finding = {
        ...prev,
        status: 'resolved',
      };
      updatedFindings.push(resolved);
      resolvedDelta.push(resolved);
    } else {
      // Category was NOT scanned → carry forward unchanged
      updatedFindings.push(prev);
    }
  }

  const delta: DeltaReport = {
    newFindings: newDelta,
    confirmedFindings: confirmedDelta,
    resolvedFindings: resolvedDelta,
    totalActive: updatedFindings.filter((f) => f.status !== 'resolved').length,
  };

  logger.info(
    `Delta: ${newDelta.length} new, ${confirmedDelta.length} confirmed, ${resolvedDelta.length} resolved ` +
    `(${delta.totalActive} total active)`
  );

  return { updatedFindings, delta };
}

// ── Notification Formatting ─────────────────────────────────────

/**
 * Format a delta report into a human-readable notification summary.
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
