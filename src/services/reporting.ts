// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { fs, path } from 'zx';
import { PentestError } from './error-handling.js';
import { ErrorCode } from '../types/errors.js';
import type { ActivityLogger } from '../types/activity-logger.js';
import { processAndDeduplicateFindings, type FindingSummary } from './finding-deduplication.js';

interface DeliverableFile {
  name: string;
  path: string;
  required: boolean;
}

/**
 * Assemble final report from specialist deliverables with deduplication.
 *
 * This function:
 * 1. Reads all exploitation evidence files
 * 2. Parses individual findings from each file
 * 3. Deduplicates findings that share the same root cause
 * 4. Normalizes severity ratings to CVSS 3.1
 * 5. Generates a summary table with finding counts by severity
 * 6. Writes both the deduplicated report and the raw concatenated report
 */
export async function assembleFinalReport(sourceDir: string, logger: ActivityLogger): Promise<{ content: string; findingSummary: FindingSummary }> {
  const deliverableFiles: DeliverableFile[] = [
    { name: 'Injection', path: 'injection_exploitation_evidence.md', required: false },
    { name: 'XSS', path: 'xss_exploitation_evidence.md', required: false },
    { name: 'Authentication', path: 'auth_exploitation_evidence.md', required: false },
    { name: 'SSRF', path: 'ssrf_exploitation_evidence.md', required: false },
    { name: 'Authorization', path: 'authz_exploitation_evidence.md', required: false }
  ];

  const sections: string[] = [];
  const evidenceSections: Array<{ source: string; content: string }> = [];

  for (const file of deliverableFiles) {
    const filePath = path.join(sourceDir, 'deliverables', file.path);
    try {
      if (await fs.pathExists(filePath)) {
        const content = await fs.readFile(filePath, 'utf8');
        sections.push(content);
        evidenceSections.push({ source: file.name, content });
        logger.info(`Added ${file.name} findings`);
      } else if (file.required) {
        throw new PentestError(
          `Required deliverable file not found: ${file.path}`,
          'filesystem',
          false,
          { deliverableFile: file.path, sourceDir },
          ErrorCode.DELIVERABLE_NOT_FOUND
        );
      } else {
        logger.info(`No ${file.name} deliverable found`);
      }
    } catch (error) {
      if (file.required) {
        throw error;
      }
      const err = error as Error;
      logger.warn(`Could not read ${file.path}: ${err.message}`);
    }
  }

  const deliverablesDir = path.join(sourceDir, 'deliverables');
  const finalReportPath = path.join(deliverablesDir, 'comprehensive_security_assessment_report.md');

  try {
    // Ensure deliverables directory exists
    await fs.ensureDir(deliverablesDir);

    // Run deduplication pipeline on parsed findings
    const {
      deduplicatedContent,
      summaryTable,
      correlationSection,
      summary,
      mergedFindings,
    } = processAndDeduplicateFindings(evidenceSections, logger);

    let finalContent: string;

    if (mergedFindings.length > 0) {
      // Build report with deduplication metadata
      const reportParts: string[] = [];

      // Severity summary table
      reportParts.push(summaryTable);

      // Root-cause correlation section (if any findings were merged)
      if (correlationSection) {
        reportParts.push(correlationSection);
      }

      // Deduplicated findings
      reportParts.push(deduplicatedContent);

      // Original evidence sections (preserved for the report agent)
      reportParts.push('---\n');
      reportParts.push('## Original Evidence Sections\n');
      reportParts.push('> The following sections contain the raw evidence from each exploitation agent.\n');
      reportParts.push(sections.join('\n\n'));

      finalContent = reportParts.join('\n\n');

      logger.info(
        `Deduplication complete: ${summary.total} unique findings ` +
        `(${summary.deduplicated} duplicates merged). ` +
        `Critical: ${summary.critical}, High: ${summary.high}, ` +
        `Medium: ${summary.medium}, Low: ${summary.low}`
      );
    } else {
      // No structured findings found — fall back to simple concatenation
      finalContent = sections.join('\n\n');
      logger.info('No structured findings found; using raw concatenation');
    }

    await fs.writeFile(finalReportPath, finalContent);
    logger.info(`Final report assembled at ${finalReportPath}`);

    const findingSummary: FindingSummary = mergedFindings.length > 0
      ? summary
      : { total: 0, critical: 0, high: 0, medium: 0, low: 0, informational: 0, deduplicated: 0 };

    return { content: finalContent, findingSummary };
  } catch (error) {
    const err = error as Error;
    throw new PentestError(
      `Failed to write final report: ${err.message}`,
      'filesystem',
      false,
      { finalReportPath, originalError: err.message }
    );
  }
}

/**
 * Inject model information into the final security report.
 * Reads session.json to get the model(s) used, then injects a "Model:" line
 * into the Executive Summary section of the report.
 */
export async function injectModelIntoReport(
  repoPath: string,
  outputPath: string,
  logger: ActivityLogger
): Promise<void> {
  // 1. Read session.json to get model information
  const sessionJsonPath = path.join(outputPath, 'session.json');

  if (!(await fs.pathExists(sessionJsonPath))) {
    logger.warn('session.json not found, skipping model injection');
    return;
  }

  interface SessionData {
    metrics: {
      agents: Record<string, { model?: string }>;
    };
  }

  const sessionData: SessionData = await fs.readJson(sessionJsonPath);

  // 2. Extract unique models from all agents
  const models = new Set<string>();
  for (const agent of Object.values(sessionData.metrics.agents)) {
    if (agent.model) {
      models.add(agent.model);
    }
  }

  if (models.size === 0) {
    logger.warn('No model information found in session.json');
    return;
  }

  const modelStr = Array.from(models).join(', ');
  logger.info(`Injecting model info into report: ${modelStr}`);

  // 3. Read the final report
  const reportPath = path.join(repoPath, 'deliverables', 'comprehensive_security_assessment_report.md');

  if (!(await fs.pathExists(reportPath))) {
    logger.warn('Final report not found, skipping model injection');
    return;
  }

  let reportContent = await fs.readFile(reportPath, 'utf8');

  // 4. Find and inject model line after "Assessment Date" in Executive Summary
  // Pattern: "- Assessment Date: <date>" followed by a newline
  const assessmentDatePattern = /^(- Assessment Date: .+)$/m;
  const match = reportContent.match(assessmentDatePattern);

  if (match) {
    // Inject model line after Assessment Date
    const modelLine = `- Model: ${modelStr}`;
    reportContent = reportContent.replace(
      assessmentDatePattern,
      `$1\n${modelLine}`
    );
    logger.info('Model info injected into Executive Summary');
  } else {
    // If no Assessment Date line found, try to add after Executive Summary header
    const execSummaryPattern = /^## Executive Summary$/m;
    if (reportContent.match(execSummaryPattern)) {
      // Add model as first item in Executive Summary
      reportContent = reportContent.replace(
        execSummaryPattern,
        `## Executive Summary\n- Model: ${modelStr}`
      );
      logger.info('Model info added to Executive Summary header');
    } else {
      logger.warn('Could not find Executive Summary section');
      return;
    }
  }

  // 5. Write modified report back
  await fs.writeFile(reportPath, reportContent);
}
