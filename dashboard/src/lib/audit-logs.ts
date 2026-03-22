// Donna - Continuous AI Pentesting Platform
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Reads workspace data from audit-logs session.json files.
 *
 * This provides historical data (cost, duration, resume attempts) that
 * complements the live workflow data from Temporal.
 */

import fs from 'node:fs/promises';
import path from 'node:path';
import type { FindingSummary } from './temporal.js';

export interface AgentAttempt {
  attempt_number: number;
  duration_ms: number;
  cost_usd: number;
  success: boolean;
  timestamp: string;
  model?: string;
  error?: string;
  checkpoint?: string;
}

export interface SessionAgentData {
  status: string;
  final_duration_ms: number;
  total_cost_usd: number;
  model?: string;
  checkpoint?: string;
  attempts?: AgentAttempt[];
}

export interface SessionData {
  session: {
    id: string;
    webUrl: string;
    status: 'in-progress' | 'completed' | 'failed';
    createdAt: string;
    completedAt?: string;
    originalWorkflowId?: string;
    repoPath?: string;
    resumeAttempts?: Array<{
      workflowId: string;
      timestamp: string;
    }>;
  };
  metrics: {
    total_duration_ms: number;
    total_cost_usd: number;
    phases?: Record<string, {
      duration_ms: number;
      duration_percentage: number;
      cost_usd: number;
      agent_count: number;
    }>;
    agents?: Record<string, SessionAgentData>;
  };
}

export interface WorkspaceInfo {
  name: string;
  url: string;
  status: 'in-progress' | 'completed' | 'failed';
  createdAt: Date;
  completedAt: Date | null;
  costUsd: number;
  durationMs: number;
  resumeAttempts: number;
}

function getAuditLogsDir(): string {
  return process.env.AUDIT_LOGS_DIR || './audit-logs';
}

/**
 * List all workspaces from audit-logs directory.
 */
export async function listWorkspaces(): Promise<WorkspaceInfo[]> {
  const auditDir = getAuditLogsDir();

  let entries: string[];
  try {
    entries = await fs.readdir(auditDir);
  } catch {
    return [];
  }

  const workspaces: WorkspaceInfo[] = [];

  for (const entry of entries) {
    const sessionPath = path.join(auditDir, entry, 'session.json');
    try {
      const content = await fs.readFile(sessionPath, 'utf8');
      const data = JSON.parse(content) as SessionData;

      const createdAt = new Date(data.session.createdAt);
      const completedAt = data.session.completedAt ? new Date(data.session.completedAt) : null;
      const durationMs = completedAt
        ? completedAt.getTime() - createdAt.getTime()
        : Date.now() - createdAt.getTime();

      workspaces.push({
        name: entry,
        url: data.session.webUrl,
        status: data.session.status,
        createdAt,
        completedAt,
        costUsd: data.metrics.total_cost_usd,
        durationMs,
        resumeAttempts: data.session.resumeAttempts?.length || 0,
      });
    } catch {
      // Skip directories without valid session.json
    }
  }

  // Sort by creation date (most recent first)
  workspaces.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  return workspaces;
}

/**
 * Get detailed session data for a specific workspace.
 */
export async function getWorkspaceDetail(name: string): Promise<SessionData | null> {
  const auditDir = getAuditLogsDir();
  const sessionPath = path.join(auditDir, name, 'session.json');

  try {
    const content = await fs.readFile(sessionPath, 'utf8');
    return JSON.parse(content) as SessionData;
  } catch {
    return null;
  }
}

/**
 * Find session data by workflow ID.
 * Searches audit-logs directories for a session matching the given workflow ID.
 */
export async function getSessionByWorkflowId(workflowId: string): Promise<SessionData | null> {
  // The audit-log directory name usually matches the workflow ID
  const direct = await getWorkspaceDetail(workflowId);
  if (direct) return direct;

  // Fallback: scan all sessions for matching originalWorkflowId
  const auditDir = getAuditLogsDir();
  let entries: string[];
  try {
    entries = await fs.readdir(auditDir);
  } catch {
    return null;
  }

  for (const entry of entries) {
    const sessionPath = path.join(auditDir, entry, 'session.json');
    try {
      const content = await fs.readFile(sessionPath, 'utf8');
      const data = JSON.parse(content) as SessionData;
      if (data.session.id === workflowId || data.session.originalWorkflowId === workflowId) {
        return data;
      }
    } catch {
      // skip
    }
  }

  return null;
}

// ─── Finding Summary Backfill ─────────────────────────────────────────────────

/** CVSS 3.1 severity levels */
type CvssSeverity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';

/** Map severity strings to normalized CVSS 3.1 qualitative scale */
function normalizeSeverity(raw: string): CvssSeverity {
  const lower = raw.toLowerCase().trim();
  const numericMatch = lower.match(/(\d+\.?\d*)/);
  if (numericMatch?.[1]) {
    const score = parseFloat(numericMatch[1]);
    if (score >= 9.0) return 'Critical';
    if (score >= 7.0) return 'High';
    if (score >= 4.0) return 'Medium';
    if (score >= 0.1) return 'Low';
    return 'Informational';
  }
  if (lower.includes('critical') || lower.includes('crit')) return 'Critical';
  if (lower.includes('high') || lower.includes('severe')) return 'High';
  if (lower.includes('medium') || lower.includes('moderate') || lower.includes('med')) return 'Medium';
  if (lower.includes('low') || lower.includes('minor')) return 'Low';
  if (lower.includes('info') || lower.includes('note')) return 'Informational';
  return 'Medium';
}

/**
 * Parse evidence files from a workspace's deliverables directory to compute
 * a FindingSummary. Used as a backfill for workflows that completed before
 * findingSummary was added to PipelineState.
 */
export async function computeFindingSummaryFromFiles(workflowId: string): Promise<FindingSummary | null> {
  const auditDir = getAuditLogsDir();

  // Try direct match first, then scan for matching session
  const candidates = [workflowId];

  // Also try with hyphens replaced by underscores and vice versa
  try {
    const entries = await fs.readdir(auditDir);
    for (const entry of entries) {
      if (entry.startsWith(workflowId.split('_donna')[0]) && entry.includes('donna')) {
        candidates.push(entry);
      }
    }
  } catch {
    return null;
  }

  const evidenceFiles = [
    'injection_exploitation_evidence.md',
    'xss_exploitation_evidence.md',
    'auth_exploitation_evidence.md',
    'ssrf_exploitation_evidence.md',
    'authz_exploitation_evidence.md',
  ];

  for (const candidate of candidates) {
    const deliverablesDir = path.join(auditDir, candidate, 'deliverables');

    // Check if deliverables directory exists
    try {
      await fs.access(deliverablesDir);
    } catch {
      continue;
    }

    // Parse findings from evidence files
    const vulnPattern = /^###\s+(\w+-VULN-\d+):\s*(.+)$/gm;
    let totalParsed = 0;
    const severityCounts: Record<CvssSeverity, number> = {
      Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0,
    };

    // Track dedup keys to count unique findings
    const seenKeys = new Set<string>();
    let uniqueCount = 0;

    for (const fileName of evidenceFiles) {
      const filePath = path.join(deliverablesDir, fileName);
      let content: string;
      try {
        content = await fs.readFile(filePath, 'utf8');
      } catch {
        continue;
      }

      const matches = [...content.matchAll(vulnPattern)];
      for (const match of matches) {
        totalParsed++;
        const title = match[2] ?? '';
        const startIdx = match.index ?? 0;
        const rawContent = content.slice(startIdx, startIdx + 500);

        // Extract severity
        const sevMatch = rawContent.match(/\*\*Severity[:\s]*\*\*\s*(.+)/i);
        const severity = normalizeSeverity(sevMatch?.[1]?.trim() ?? 'Medium');

        // Extract endpoint for dedup key
        const epMatch = rawContent.match(/\*\*Endpoint[:\s]*\*\*\s*(.+)/i);
        const endpoint = (epMatch?.[1]?.trim() ?? title).toLowerCase();
        const dedupKey = `${endpoint}||${fileName}`;

        if (!seenKeys.has(dedupKey)) {
          seenKeys.add(dedupKey);
          severityCounts[severity]++;
          uniqueCount++;
        }
      }
    }

    if (totalParsed > 0) {
      return {
        total: uniqueCount,
        critical: severityCounts.Critical,
        high: severityCounts.High,
        medium: severityCounts.Medium,
        low: severityCounts.Low,
        informational: severityCounts.Informational,
        deduplicated: totalParsed - uniqueCount,
      };
    }
  }

  return null;
}

// ─── Detailed Finding Extraction ──────────────────────────────────────────────

export interface DetailedFinding {
  id: string;
  category: string;        // 'auth' | 'xss' | 'ssrf' | 'authz' | 'injection'
  severity: CvssSeverity;
  title: string;
  location: string;
  summary: string;
  evidenceSnippet: string;  // first ~500 chars of the finding block
}

/**
 * Extract detailed findings from a workflow's evidence files.
 * Returns individual findings with enough context for display and copy-to-agent.
 */
export async function getDetailedFindings(workflowId: string): Promise<DetailedFinding[]> {
  const auditDir = getAuditLogsDir();

  // Build candidate directory names
  const candidates = [workflowId];
  try {
    const entries = await fs.readdir(auditDir);
    for (const entry of entries) {
      if (entry.startsWith(workflowId.split('_donna')[0]) && entry.includes('donna')) {
        candidates.push(entry);
      }
    }
  } catch {
    return [];
  }

  const evidenceFiles: Array<{ file: string; category: string }> = [
    { file: 'auth_exploitation_evidence.md', category: 'auth' },
    { file: 'xss_exploitation_evidence.md', category: 'xss' },
    { file: 'ssrf_exploitation_evidence.md', category: 'ssrf' },
    { file: 'authz_exploitation_evidence.md', category: 'authz' },
    { file: 'injection_exploitation_evidence.md', category: 'injection' },
  ];

  for (const candidate of candidates) {
    const deliverablesDir = path.join(auditDir, candidate, 'deliverables');

    try {
      await fs.access(deliverablesDir);
    } catch {
      continue;
    }

    const findings: DetailedFinding[] = [];
    const seenKeys = new Set<string>();
    const vulnPattern = /^###\s+(\w+-VULN-\d+[\w\s+]*?):\s*(.+)$/gm;

    for (const { file: fileName, category } of evidenceFiles) {
      const filePath = path.join(deliverablesDir, fileName);
      let content: string;
      try {
        content = await fs.readFile(filePath, 'utf8');
      } catch {
        continue;
      }

      const matches = [...content.matchAll(vulnPattern)];
      for (const match of matches) {
        const vulnId = match[1]?.trim() ?? '';
        const title = match[2]?.trim() ?? '';
        const startIdx = match.index ?? 0;

        // Find the end of this finding block (next ### or end of file)
        const nextHeadingIdx = content.indexOf('\n### ', startIdx + 1);
        const blockEnd = nextHeadingIdx > 0 ? nextHeadingIdx : startIdx + 3000;
        const rawBlock = content.slice(startIdx, Math.min(blockEnd, startIdx + 3000));

        // Extract severity
        const sevMatch = rawBlock.match(/\*\*Severity[:\s]*\*\*\s*(.+)/i);
        const severity = normalizeSeverity(sevMatch?.[1]?.trim() ?? 'Medium');

        // Extract location/endpoint
        const epMatch = rawBlock.match(/\*\*(?:Endpoint|Vulnerable location|Location)[:\s]*\*\*\s*(.+)/i);
        const location = epMatch?.[1]?.trim() ?? '';

        // Extract summary
        const sumMatch = rawBlock.match(/\*\*(?:Summary|Overview)[:\s]*\*\*\s*(.+)/i);
        const summary = sumMatch?.[1]?.trim() ?? '';

        // Dedup
        const dedupKey = `${(location || title).toLowerCase()}||${fileName}`;
        if (seenKeys.has(dedupKey)) continue;
        seenKeys.add(dedupKey);

        // Build evidence snippet (first meaningful lines after the header)
        const snippetLines = rawBlock.split('\n').slice(1, 12).join('\n').trim();

        findings.push({
          id: vulnId,
          category,
          severity,
          title,
          location,
          summary,
          evidenceSnippet: snippetLines.slice(0, 800),
        });
      }
    }

    if (findings.length > 0) {
      // Sort by severity: Critical > High > Medium > Low > Informational
      const severityOrder: Record<CvssSeverity, number> = {
        Critical: 0, High: 1, Medium: 2, Low: 3, Informational: 4,
      };
      findings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
      return findings;
    }
  }

  return [];
}

// ─── Full Finding Extraction (for Report) ─────────────────────────────────────

export interface FullFinding extends DetailedFinding {
  fullEvidence: string;       // complete markdown block for this finding
  impact: string;
  prerequisites: string;
  exploitationSteps: string;
  remediation: string;
}

/**
 * Extract full findings with complete evidence blocks from evidence files.
 * Unlike getDetailedFindings(), this returns the entire evidence markdown
 * for each finding — suitable for the full security report page.
 */
export async function getFullFindings(workflowId: string): Promise<FullFinding[]> {
  const auditDir = getAuditLogsDir();

  const candidates = [workflowId];
  try {
    const entries = await fs.readdir(auditDir);
    for (const entry of entries) {
      if (entry.startsWith(workflowId.split('_donna')[0]) && entry.includes('donna')) {
        candidates.push(entry);
      }
    }
  } catch {
    return [];
  }

  const evidenceFiles: Array<{ file: string; category: string }> = [
    { file: 'auth_exploitation_evidence.md', category: 'auth' },
    { file: 'xss_exploitation_evidence.md', category: 'xss' },
    { file: 'ssrf_exploitation_evidence.md', category: 'ssrf' },
    { file: 'authz_exploitation_evidence.md', category: 'authz' },
    { file: 'injection_exploitation_evidence.md', category: 'injection' },
  ];

  for (const candidate of candidates) {
    const deliverablesDir = path.join(auditDir, candidate, 'deliverables');

    try {
      await fs.access(deliverablesDir);
    } catch {
      continue;
    }

    const findings: FullFinding[] = [];
    const seenKeys = new Set<string>();
    const vulnPattern = /^###\s+(\w+-VULN-\d+[\w\s+]*?):\s*(.+)$/gm;

    for (const { file: fileName, category } of evidenceFiles) {
      const filePath = path.join(deliverablesDir, fileName);
      let content: string;
      try {
        content = await fs.readFile(filePath, 'utf8');
      } catch {
        continue;
      }

      const matches = [...content.matchAll(vulnPattern)];
      for (const match of matches) {
        const vulnId = match[1]?.trim() ?? '';
        const title = match[2]?.trim() ?? '';
        const startIdx = match.index ?? 0;

        // Get the FULL block (not truncated)
        const nextHeadingIdx = content.indexOf('\n### ', startIdx + 1);
        const blockEnd = nextHeadingIdx > 0 ? nextHeadingIdx : content.length;
        const rawBlock = content.slice(startIdx, blockEnd);

        // Extract severity
        const sevMatch = rawBlock.match(/\*\*Severity[:\s]*\*\*\s*(.+)/i);
        const severity = normalizeSeverity(sevMatch?.[1]?.trim() ?? 'Medium');

        // Extract location/endpoint
        const epMatch = rawBlock.match(/\*\*(?:Endpoint|Vulnerable location|Location)[:\s]*\*\*\s*(.+)/i);
        const location = epMatch?.[1]?.trim() ?? '';

        // Extract summary
        const sumMatch = rawBlock.match(/\*\*(?:Summary|Overview)[:\s]*\*\*\s*(.+)/i);
        const summary = sumMatch?.[1]?.trim() ?? '';

        // Extract impact
        const impMatch = rawBlock.match(/\*\*(?:Impact|Potential Impact)[:\s]*\*\*\s*(.+)/i);
        const impact = impMatch?.[1]?.trim() ?? '';

        // Extract prerequisites
        const preMatch = rawBlock.match(/\*\*Prerequisites[:\s]*\*\*\s*([\s\S]*?)(?=\n\*\*[A-Z]|\n---)/i);
        const prerequisites = preMatch?.[1]?.trim() ?? '';

        // Extract exploitation steps section
        const expMatch = rawBlock.match(/\*\*Exploitation Steps[:\s]*\*\*\s*([\s\S]*?)(?=\n\*\*(?:Live Proof|Proof|Notes|Remediation|Impact)|$)/i);
        const exploitationSteps = expMatch?.[1]?.trim() ?? '';

        // Extract remediation
        const remMatch = rawBlock.match(/\*\*Remediation[:\s]*\*\*\s*([\s\S]*?)(?=\n---|\n###|$)/i);
        const remediation = remMatch?.[1]?.trim() ?? '';

        // Dedup
        const dedupKey = `${(location || title).toLowerCase()}||${fileName}`;
        if (seenKeys.has(dedupKey)) continue;
        seenKeys.add(dedupKey);

        const snippetLines = rawBlock.split('\n').slice(1, 12).join('\n').trim();

        findings.push({
          id: vulnId,
          category,
          severity,
          title,
          location,
          summary,
          evidenceSnippet: snippetLines.slice(0, 800),
          fullEvidence: rawBlock,
          impact,
          prerequisites,
          exploitationSteps,
          remediation,
        });
      }
    }

    if (findings.length > 0) {
      const severityOrder: Record<CvssSeverity, number> = {
        Critical: 0, High: 1, Medium: 2, Low: 3, Informational: 4,
      };
      findings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
      return findings;
    }
  }

  return [];
}

// ─── Comprehensive Report ─────────────────────────────────────────────────────

export interface RootCauseCorrelation {
  rootCause: string;
  endpoint: string;
  mergedIds: string[];
  sources: string[];
  severity: string;
}

export interface ComprehensiveReport {
  rawMarkdown: string;
  rootCauses: RootCauseCorrelation[];
  deduplicatedCount: number;
}

/**
 * Read and parse the comprehensive security assessment report.
 */
export async function getComprehensiveReport(workflowId: string): Promise<ComprehensiveReport | null> {
  const auditDir = getAuditLogsDir();

  const candidates = [workflowId];
  try {
    const entries = await fs.readdir(auditDir);
    for (const entry of entries) {
      if (entry.startsWith(workflowId.split('_donna')[0]) && entry.includes('donna')) {
        candidates.push(entry);
      }
    }
  } catch {
    return null;
  }

  for (const candidate of candidates) {
    const reportPath = path.join(auditDir, candidate, 'deliverables', 'comprehensive_security_assessment_report.md');
    let content: string;
    try {
      content = await fs.readFile(reportPath, 'utf8');
    } catch {
      continue;
    }

    // Parse root-cause correlations
    const rootCauses: RootCauseCorrelation[] = [];
    const rcPattern = /- \*\*(.+?)\*\*\s*\((.+?)\)\s*\n\s*- Merged:\s*(.+)\n\s*- Sources:\s*(.+)\n\s*- Severity:\s*(.+)/g;
    for (const match of content.matchAll(rcPattern)) {
      rootCauses.push({
        rootCause: match[1].trim(),
        endpoint: match[2].trim(),
        mergedIds: match[3].split(',').map(s => s.trim()),
        sources: match[4].split(',').map(s => s.trim()),
        severity: match[5].trim(),
      });
    }

    // Extract deduplicated count
    const dedupMatch = content.match(/(\d+)\s+duplicate\s+finding/i);
    const deduplicatedCount = dedupMatch ? parseInt(dedupMatch[1], 10) : 0;

    return {
      rawMarkdown: content,
      rootCauses,
      deduplicatedCount,
    };
  }

  return null;
}
