// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Finding deduplication and root-cause correlation for security reports.
 *
 * When multiple exploit agents independently discover the same underlying
 * vulnerability, this module merges them into a single finding with all
 * related evidence, provides consistent CVSS 3.1 severity, and generates
 * summary statistics.
 */

import type { ActivityLogger } from '../types/activity-logger.js';

// ─── Types ───────────────────────────────────────────────────────────────────

/** Normalized severity using CVSS 3.1 qualitative scale */
export type CvssSeverity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';

/** CWE-based vulnerability classification */
export type VulnerabilityClass =
  | 'sql-injection'
  | 'command-injection'
  | 'xss-reflected'
  | 'xss-stored'
  | 'xss-dom'
  | 'auth-bypass'
  | 'broken-auth'
  | 'ssrf'
  | 'idor'
  | 'privilege-escalation'
  | 'path-traversal'
  | 'open-redirect'
  | 'csrf'
  | 'unknown';

/** A single parsed finding from an evidence file */
export interface ParsedFinding {
  /** Original vulnerability ID, e.g. "INJ-VULN-001" */
  id: string;
  /** Raw title from the evidence section */
  title: string;
  /** Which agent/source produced this finding */
  source: string;
  /** Original severity string before normalization */
  rawSeverity: string;
  /** Normalized CVSS 3.1 severity */
  severity: CvssSeverity;
  /** Canonical endpoint path */
  endpoint: string;
  /** Affected parameter name (if identified) */
  parameter: string | null;
  /** Vulnerability classification */
  vulnClass: VulnerabilityClass;
  /** CWE ID if identified */
  cweId: string | null;
  /** Full original markdown content of this finding */
  rawContent: string;
}

/** A deduplicated finding that may merge multiple parsed findings */
export interface MergedFinding {
  /** Primary ID (first discovered) */
  primaryId: string;
  /** All original IDs that were merged */
  mergedIds: string[];
  /** Unified title */
  title: string;
  /** Highest severity across merged findings */
  severity: CvssSeverity;
  /** Canonical endpoint */
  endpoint: string;
  /** Affected parameter */
  parameter: string | null;
  /** Vulnerability class */
  vulnClass: VulnerabilityClass;
  /** CWE ID */
  cweId: string | null;
  /** All sources that discovered this */
  sources: string[];
  /** Root-cause description */
  rootCause: string;
  /** Unified remediation guidance */
  remediation: string;
  /** All original evidence content blocks */
  evidenceBlocks: Array<{ source: string; content: string }>;
}

/** Summary statistics for the report */
export interface FindingSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  informational: number;
  deduplicated: number; // how many findings were merged
}

// ─── Severity Mapping ────────────────────────────────────────────────────────

const SEVERITY_ORDER: Record<CvssSeverity, number> = {
  Critical: 5,
  High: 4,
  Medium: 3,
  Low: 2,
  Informational: 1,
};

/** Map various agent severity strings to CVSS 3.1 qualitative scale */
export function normalizeSeverity(raw: string): CvssSeverity {
  const lower = raw.toLowerCase().trim();

  // CVSS numeric score ranges
  const numericMatch = lower.match(/(\d+\.?\d*)/);
  if (numericMatch && numericMatch[1]) {
    const score = parseFloat(numericMatch[1]);
    if (score >= 9.0) return 'Critical';
    if (score >= 7.0) return 'High';
    if (score >= 4.0) return 'Medium';
    if (score >= 0.1) return 'Low';
    return 'Informational';
  }

  // Text-based severity
  if (lower.includes('critical') || lower.includes('crit')) return 'Critical';
  if (lower.includes('high') || lower.includes('severe')) return 'High';
  if (lower.includes('medium') || lower.includes('moderate') || lower.includes('med')) return 'Medium';
  if (lower.includes('low') || lower.includes('minor')) return 'Low';
  if (lower.includes('info') || lower.includes('note')) return 'Informational';

  return 'Medium'; // default when unclear
}

/** Return the higher of two severities */
function maxSeverity(a: CvssSeverity, b: CvssSeverity): CvssSeverity {
  return SEVERITY_ORDER[a] >= SEVERITY_ORDER[b] ? a : b;
}

// ─── Endpoint Normalization ──────────────────────────────────────────────────

/** Canonicalize an endpoint path for comparison */
export function canonicalizeEndpoint(endpoint: string): string {
  let canonical = endpoint.trim();

  // Strip protocol + host if present
  try {
    const url = new URL(canonical);
    canonical = url.pathname + url.search;
  } catch {
    // Already a path, continue
  }

  // Strip trailing slashes
  canonical = canonical.replace(/\/+$/, '') || '/';

  // Normalize path parameters: :id, {id}, <id> → {param}
  canonical = canonical.replace(/:[a-zA-Z_][a-zA-Z0-9_]*/g, '{param}');
  canonical = canonical.replace(/\{[a-zA-Z_][a-zA-Z0-9_]*\}/g, '{param}');
  canonical = canonical.replace(/<[a-zA-Z_][a-zA-Z0-9_]*>/g, '{param}');

  // Normalize numeric path segments that look like IDs (e.g., /users/123)
  canonical = canonical.replace(/\/\d+(?=\/|$)/g, '/{param}');

  // Lowercase for comparison
  canonical = canonical.toLowerCase();

  return canonical;
}

// ─── Vulnerability Classification ────────────────────────────────────────────

/** Classify a finding by its vulnerability type based on title, content, and source */
export function classifyVulnerability(
  title: string,
  content: string,
  source: string
): { vulnClass: VulnerabilityClass; cweId: string | null } {
  const combined = `${title} ${content} ${source}`.toLowerCase();

  // CWE extraction
  const cweMatch = combined.match(/cwe-(\d+)/i);
  const cweId = cweMatch ? `CWE-${cweMatch[1]}` : null;

  // Classification by patterns
  if (/sql\s*injection|sqli|sql\s*i(?:nj)?/i.test(combined)) {
    return { vulnClass: 'sql-injection', cweId: cweId || 'CWE-89' };
  }
  if (/command\s*injection|os\s*command|rce|remote\s*code/i.test(combined)) {
    return { vulnClass: 'command-injection', cweId: cweId || 'CWE-78' };
  }
  if (/stored\s*xss|persistent\s*xss/i.test(combined)) {
    return { vulnClass: 'xss-stored', cweId: cweId || 'CWE-79' };
  }
  if (/dom[\s-]*(?:based\s*)?xss/i.test(combined)) {
    return { vulnClass: 'xss-dom', cweId: cweId || 'CWE-79' };
  }
  if (/xss|cross[\s-]*site[\s-]*script/i.test(combined)) {
    return { vulnClass: 'xss-reflected', cweId: cweId || 'CWE-79' };
  }
  if (/auth(?:entication)?\s*bypass|login\s*bypass/i.test(combined)) {
    return { vulnClass: 'auth-bypass', cweId: cweId || 'CWE-287' };
  }
  if (/broken\s*auth|weak\s*auth|credential|session/i.test(combined)) {
    return { vulnClass: 'broken-auth', cweId: cweId || 'CWE-287' };
  }
  if (/ssrf|server[\s-]*side[\s-]*request/i.test(combined)) {
    return { vulnClass: 'ssrf', cweId: cweId || 'CWE-918' };
  }
  if (/idor|insecure\s*direct\s*object/i.test(combined)) {
    return { vulnClass: 'idor', cweId: cweId || 'CWE-639' };
  }
  if (/privilege[\s-]*escalat|authz|authorization/i.test(combined)) {
    return { vulnClass: 'privilege-escalation', cweId: cweId || 'CWE-269' };
  }
  if (/path[\s-]*traversal|directory[\s-]*traversal|\.\.[\\/]/i.test(combined)) {
    return { vulnClass: 'path-traversal', cweId: cweId || 'CWE-22' };
  }
  if (/open[\s-]*redirect/i.test(combined)) {
    return { vulnClass: 'open-redirect', cweId: cweId || 'CWE-601' };
  }
  if (/csrf|cross[\s-]*site[\s-]*request[\s-]*forg/i.test(combined)) {
    return { vulnClass: 'csrf', cweId: cweId || 'CWE-352' };
  }

  // Source-based fallback
  if (source.includes('injection')) return { vulnClass: 'sql-injection', cweId: cweId || 'CWE-89' };
  if (source.includes('xss')) return { vulnClass: 'xss-reflected', cweId: cweId || 'CWE-79' };
  if (source.includes('auth')) return { vulnClass: 'broken-auth', cweId: cweId || 'CWE-287' };
  if (source.includes('ssrf')) return { vulnClass: 'ssrf', cweId: cweId || 'CWE-918' };
  if (source.includes('authz')) return { vulnClass: 'privilege-escalation', cweId: cweId || 'CWE-269' };

  return { vulnClass: 'unknown', cweId };
}

// ─── Finding Parser ──────────────────────────────────────────────────────────

/**
 * Parse a single evidence markdown file into structured findings.
 *
 * Expects headings like:
 *   ### INJ-VULN-001: SQL Injection in /api/users
 *   **Severity:** High
 *   **Endpoint:** /api/users?id=
 *   **Parameter:** id
 */
export function parseFindings(content: string, source: string): ParsedFinding[] {
  const findings: ParsedFinding[] = [];

  // Split on vulnerability ID headings: ### TYPE-VULN-NNN: Title
  const vulnPattern = /^###\s+(\w+-VULN-\d+):\s*(.+)$/gm;
  const matches = [...content.matchAll(vulnPattern)];

  for (let i = 0; i < matches.length; i++) {
    const match = matches[i]!;
    const id = match[1] ?? 'UNKNOWN';
    const title = (match[2] ?? 'Unknown Finding').trim();
    const startIdx = match.index ?? 0;
    const nextMatch = i + 1 < matches.length ? matches[i + 1] : undefined;
    const endIdx = nextMatch?.index ?? content.length;
    const rawContent = content.slice(startIdx, endIdx).trim();

    // Extract severity
    const severityMatch = rawContent.match(/\*\*Severity[:\s]*\*\*\s*(.+)/i);
    const rawSeverity = severityMatch?.[1]?.trim() ?? 'Medium';
    const severity = normalizeSeverity(rawSeverity);

    // Extract endpoint
    const endpointMatch = rawContent.match(/\*\*Endpoint[:\s]*\*\*\s*(.+)/i)
      || rawContent.match(/\*\*URL[:\s]*\*\*\s*(.+)/i)
      || rawContent.match(/\*\*Path[:\s]*\*\*\s*(.+)/i);
    const rawEndpoint = endpointMatch?.[1]?.trim() ?? extractEndpointFromTitle(title);
    const endpoint = canonicalizeEndpoint(rawEndpoint);

    // Extract parameter
    const paramMatch = rawContent.match(/\*\*Parameter[:\s]*\*\*\s*(.+)/i)
      || rawContent.match(/\*\*Param[:\s]*\*\*\s*(.+)/i);
    const parameter = paramMatch?.[1]?.trim() ?? null;

    // Classify vulnerability
    const { vulnClass, cweId } = classifyVulnerability(title, rawContent, source);

    findings.push({
      id,
      title,
      source,
      rawSeverity,
      severity,
      endpoint,
      parameter,
      vulnClass,
      cweId,
      rawContent,
    });
  }

  return findings;
}

/** Try to extract an endpoint from a finding title */
function extractEndpointFromTitle(title: string): string {
  const pathMatch = title.match(/(\/[a-zA-Z0-9/_\-{}:?&=.]+)/);
  return pathMatch?.[1] ?? '/unknown';
}

// ─── Deduplication Engine ────────────────────────────────────────────────────

/** Generate a dedup key from a finding's normalized attributes */
function dedupKey(finding: ParsedFinding): string {
  return `${finding.endpoint}||${finding.vulnClass}||${finding.parameter || '*'}`;
}

/** Root cause descriptions by vulnerability class */
const ROOT_CAUSE_MAP: Record<VulnerabilityClass, string> = {
  'sql-injection': 'Missing parameterized queries / prepared statements',
  'command-injection': 'Unsanitized user input passed to OS command execution',
  'xss-reflected': 'Missing output encoding / input sanitization on reflected content',
  'xss-stored': 'Missing output encoding on stored user-controlled content',
  'xss-dom': 'Unsafe DOM manipulation with user-controlled data',
  'auth-bypass': 'Broken authentication logic allowing credential bypass',
  'broken-auth': 'Weak authentication mechanisms or session management',
  'ssrf': 'Unvalidated user-supplied URLs in server-side requests',
  'idor': 'Missing authorization checks on direct object references',
  'privilege-escalation': 'Insufficient authorization enforcement between privilege levels',
  'path-traversal': 'Missing path canonicalization / directory traversal protection',
  'open-redirect': 'Unvalidated redirect targets accepting user-controlled URLs',
  'csrf': 'Missing or improperly validated anti-CSRF tokens',
  'unknown': 'Unclassified vulnerability requiring manual review',
};

/** Remediation guidance by vulnerability class */
const REMEDIATION_MAP: Record<VulnerabilityClass, string> = {
  'sql-injection': 'Use parameterized queries or prepared statements for all database interactions. Apply input validation as defense-in-depth.',
  'command-injection': 'Avoid shell command execution with user input. Use language-native APIs and strict input validation.',
  'xss-reflected': 'Apply context-aware output encoding. Implement Content-Security-Policy headers. Validate and sanitize input.',
  'xss-stored': 'Apply output encoding when rendering stored content. Sanitize HTML input with a proven library (e.g., DOMPurify).',
  'xss-dom': 'Avoid innerHTML/document.write with user data. Use safe DOM APIs (textContent, setAttribute) and CSP.',
  'auth-bypass': 'Review authentication flow for logic flaws. Enforce server-side validation of all authentication steps.',
  'broken-auth': 'Implement strong session management, enforce password complexity, use MFA, and secure credential storage.',
  'ssrf': 'Validate and whitelist URLs server-side. Block internal/private IP ranges. Use network-level egress controls.',
  'idor': 'Implement object-level authorization checks. Use indirect references (UUIDs) rather than sequential IDs.',
  'privilege-escalation': 'Enforce role-based access control at the API layer. Validate permissions on every privileged operation.',
  'path-traversal': 'Canonicalize file paths and validate against an allowed base directory. Reject ".." sequences.',
  'open-redirect': 'Validate redirect URLs against a whitelist of allowed domains. Use relative paths for internal redirects.',
  'csrf': 'Implement anti-CSRF tokens (synchronizer or double-submit pattern). Use SameSite cookie attribute.',
  'unknown': 'Conduct manual review to determine appropriate remediation.',
};

/**
 * Deduplicate and merge findings that share the same root cause.
 *
 * Findings are grouped by (canonical endpoint, vulnerability class, parameter).
 * Within each group, findings are merged with the highest severity preserved.
 */
export function deduplicateFindings(
  findings: ParsedFinding[],
  logger: ActivityLogger
): MergedFinding[] {
  const groups = new Map<string, ParsedFinding[]>();

  for (const finding of findings) {
    const key = dedupKey(finding);
    const existing = groups.get(key);
    if (existing) {
      existing.push(finding);
    } else {
      groups.set(key, [finding]);
    }
  }

  const merged: MergedFinding[] = [];

  for (const [, group] of groups) {
    if (group.length === 0) continue;

    const primary = group[0]!;

    if (group.length > 1) {
      logger.info(
        `Merging ${group.length} findings for ${primary.endpoint} (${primary.vulnClass}): ${group.map((f) => f.id).join(', ')}`
      );
    }

    let highestSeverity = primary.severity;
    for (const f of group) {
      highestSeverity = maxSeverity(highestSeverity, f.severity);
    }

    merged.push({
      primaryId: primary.id,
      mergedIds: group.map((f) => f.id),
      title: primary.title,
      severity: highestSeverity,
      endpoint: primary.endpoint,
      parameter: primary.parameter,
      vulnClass: primary.vulnClass,
      cweId: primary.cweId,
      sources: [...new Set(group.map((f) => f.source))],
      rootCause: ROOT_CAUSE_MAP[primary.vulnClass],
      remediation: REMEDIATION_MAP[primary.vulnClass],
      evidenceBlocks: group.map((f) => ({ source: f.source, content: f.rawContent })),
    });
  }

  // Sort by severity (highest first)
  merged.sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity]);

  return merged;
}

// ─── Summary Statistics ──────────────────────────────────────────────────────

/** Compute summary statistics from merged findings */
export function computeFindingSummary(
  mergedFindings: MergedFinding[],
  totalParsed: number
): FindingSummary {
  const summary: FindingSummary = {
    total: mergedFindings.length,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    informational: 0,
    deduplicated: totalParsed - mergedFindings.length,
  };

  for (const finding of mergedFindings) {
    switch (finding.severity) {
      case 'Critical': summary.critical++; break;
      case 'High': summary.high++; break;
      case 'Medium': summary.medium++; break;
      case 'Low': summary.low++; break;
      case 'Informational': summary.informational++; break;
    }
  }

  return summary;
}

// ─── Report Rendering ────────────────────────────────────────────────────────

/** Render the severity summary table as markdown */
export function renderSeveritySummaryTable(summary: FindingSummary): string {
  const lines = [
    '## Finding Summary',
    '',
    '| Severity | Count |',
    '|----------|-------|',
    `| 🔴 Critical | ${summary.critical} |`,
    `| 🟠 High | ${summary.high} |`,
    `| 🟡 Medium | ${summary.medium} |`,
    `| 🔵 Low | ${summary.low} |`,
    `| ⚪ Informational | ${summary.informational} |`,
    `| **Total** | **${summary.total}** |`,
    '',
  ];

  if (summary.deduplicated > 0) {
    lines.push(`> ${summary.deduplicated} duplicate finding(s) were merged based on root-cause correlation.`);
    lines.push('');
  }

  return lines.join('\n');
}

/** Render a merged finding as markdown */
function renderMergedFinding(finding: MergedFinding): string {
  const lines: string[] = [];

  lines.push(`### ${finding.primaryId}: ${finding.title}`);
  lines.push(`**Severity:** ${finding.severity}`);
  lines.push(`**Endpoint:** ${finding.endpoint}`);
  if (finding.parameter) {
    lines.push(`**Parameter:** ${finding.parameter}`);
  }
  if (finding.cweId) {
    lines.push(`**Classification:** ${finding.cweId} (${formatVulnClass(finding.vulnClass)})`);
  }

  if (finding.mergedIds.length > 1) {
    lines.push('');
    lines.push(`> **Root Cause:** ${finding.rootCause}`);
    lines.push(`> **Related findings:** ${finding.mergedIds.join(', ')} (from ${finding.sources.join(', ')})`);
  }

  lines.push('');
  lines.push(`**Remediation:** ${finding.remediation}`);
  lines.push('');

  // Include all evidence blocks
  for (const block of finding.evidenceBlocks) {
    if (finding.evidenceBlocks.length > 1) {
      lines.push(`<details><summary>Evidence from ${block.source}</summary>`);
      lines.push('');
    }
    // Strip the heading from the evidence (we already rendered it)
    const contentWithoutHeading = block.content.replace(/^###\s+\w+-VULN-\d+:.*\n/, '');
    lines.push(contentWithoutHeading.trim());
    if (finding.evidenceBlocks.length > 1) {
      lines.push('');
      lines.push('</details>');
    }
    lines.push('');
  }

  return lines.join('\n');
}

/** Format a VulnerabilityClass as a human-readable string */
function formatVulnClass(vulnClass: VulnerabilityClass): string {
  const map: Record<VulnerabilityClass, string> = {
    'sql-injection': 'SQL Injection',
    'command-injection': 'Command Injection',
    'xss-reflected': 'Reflected XSS',
    'xss-stored': 'Stored XSS',
    'xss-dom': 'DOM-based XSS',
    'auth-bypass': 'Authentication Bypass',
    'broken-auth': 'Broken Authentication',
    'ssrf': 'Server-Side Request Forgery',
    'idor': 'Insecure Direct Object Reference',
    'privilege-escalation': 'Privilege Escalation',
    'path-traversal': 'Path Traversal',
    'open-redirect': 'Open Redirect',
    'csrf': 'Cross-Site Request Forgery',
    'unknown': 'Unknown',
  };
  return map[vulnClass];
}

/** Render the root-cause correlation metadata section */
function renderCorrelationMetadata(mergedFindings: MergedFinding[]): string {
  const correlated = mergedFindings.filter((f) => f.mergedIds.length > 1);
  if (correlated.length === 0) return '';

  const lines = [
    '## Root-Cause Correlation',
    '',
    'The following findings were identified independently by multiple agents but share the same underlying root cause:',
    '',
  ];

  for (const finding of correlated) {
    lines.push(`- **${finding.rootCause}** (${finding.endpoint})`);
    lines.push(`  - Merged: ${finding.mergedIds.join(', ')}`);
    lines.push(`  - Sources: ${finding.sources.join(', ')}`);
    lines.push(`  - Severity: ${finding.severity}`);
    lines.push('');
  }

  return lines.join('\n');
}

// ─── Main Pipeline ───────────────────────────────────────────────────────────

/**
 * Process evidence files through the deduplication pipeline.
 *
 * Takes raw evidence content from each agent, parses findings,
 * deduplicates, and returns the deduplicated content ready for
 * insertion into the final report.
 *
 * Returns:
 * - deduplicatedContent: markdown string with merged findings
 * - summary: finding count statistics
 * - correlationSection: root-cause correlation metadata
 * - mergedFindings: structured merged finding data
 */
export function processAndDeduplicateFindings(
  evidenceSections: Array<{ source: string; content: string }>,
  logger: ActivityLogger
): {
  deduplicatedContent: string;
  summaryTable: string;
  correlationSection: string;
  summary: FindingSummary;
  mergedFindings: MergedFinding[];
} {
  // 1. Parse all findings from all sources
  const allFindings: ParsedFinding[] = [];
  for (const section of evidenceSections) {
    const findings = parseFindings(section.content, section.source);
    logger.info(`Parsed ${findings.length} findings from ${section.source}`);
    allFindings.push(...findings);
  }

  if (allFindings.length === 0) {
    logger.info('No structured findings found to deduplicate');
    return {
      deduplicatedContent: '',
      summaryTable: '',
      correlationSection: '',
      summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, informational: 0, deduplicated: 0 },
      mergedFindings: [],
    };
  }

  // 2. Deduplicate and merge
  const mergedFindings = deduplicateFindings(allFindings, logger);
  logger.info(`Deduplicated ${allFindings.length} findings into ${mergedFindings.length} unique findings`);

  // 3. Compute summary
  const summary = computeFindingSummary(mergedFindings, allFindings.length);

  // 4. Render outputs
  const summaryTable = renderSeveritySummaryTable(summary);
  const correlationSection = renderCorrelationMetadata(mergedFindings);

  // 5. Render deduplicated findings grouped by severity
  const contentParts: string[] = [];
  contentParts.push('## Deduplicated Findings\n');

  for (const finding of mergedFindings) {
    contentParts.push(renderMergedFinding(finding));
  }

  const deduplicatedContent = contentParts.join('\n');

  return {
    deduplicatedContent,
    summaryTable,
    correlationSection,
    summary,
    mergedFindings,
  };
}
