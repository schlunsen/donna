// Donna - Continuous AI Pentesting Platform
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * File Operations Utilities
 *
 * Handles file system operations for deliverable saving.
 * Ported from tools/save_deliverable.js (lines 117-130).
 */

import { writeFileSync, mkdirSync, existsSync } from 'fs';
import { writeFile, mkdir } from 'fs/promises';
import { join } from 'path';
import lockfile from 'proper-lockfile';

/**
 * Save deliverable file to deliverables/ directory
 *
 * @param targetDir - Target directory for deliverables (passed explicitly to avoid race conditions)
 * @param filename - Name of the deliverable file
 * @param content - File content to save
 */
export function saveDeliverableFile(targetDir: string, filename: string, content: string): string {
  const deliverablesDir = join(targetDir, 'deliverables');
  const filepath = join(deliverablesDir, filename);

  // Ensure deliverables directory exists
  try {
    mkdirSync(deliverablesDir, { recursive: true });
  } catch {
    throw new Error(`Cannot create deliverables directory at ${deliverablesDir}`);
  }

  // Write file (atomic write - single operation)
  writeFileSync(filepath, content, 'utf8');

  return filepath;
}

/**
 * Save deliverable file with cross-process file locking.
 *
 * Uses proper-lockfile with configurable retries and exponential backoff
 * to prevent race conditions when multiple agents write concurrently.
 *
 * @param targetDir - Target directory for deliverables
 * @param filename - Name of the deliverable file
 * @param content - File content to save
 * @returns Path to the saved file
 */
export async function saveDeliverableFileLocked(
  targetDir: string,
  filename: string,
  content: string
): Promise<string> {
  const deliverablesDir = join(targetDir, 'deliverables');
  const filepath = join(deliverablesDir, filename);

  // Ensure deliverables directory exists
  await mkdir(deliverablesDir, { recursive: true });

  // Ensure the file exists before locking (proper-lockfile requirement)
  if (!existsSync(filepath)) {
    writeFileSync(filepath, '', 'utf8');
  }

  // Acquire file lock with retries and exponential backoff
  const release = await lockfile.lock(filepath, {
    retries: {
      retries: 5,
      minTimeout: 100,
      maxTimeout: 5000,
      factor: 2,
    },
    stale: 10000,
  });

  try {
    // Write via temp file + rename for atomicity
    const tempPath = `${filepath}.tmp`;
    await writeFile(tempPath, content, 'utf8');
    const { rename } = await import('fs/promises');
    await rename(tempPath, filepath);
  } finally {
    await release();
  }

  return filepath;
}
