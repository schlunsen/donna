// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * File I/O Utilities
 *
 * Core utility functions for file operations including atomic writes,
 * directory creation, and JSON file handling.
 */

import fs from 'fs/promises';
import { lockedAtomicWrite, type FileLockOptions } from '../services/file-lock.js';

/**
 * Ensure directory exists (idempotent, race-safe)
 */
export async function ensureDirectory(dirPath: string): Promise<void> {
  try {
    await fs.mkdir(dirPath, { recursive: true });
  } catch (error) {
    // Ignore EEXIST errors (race condition safe)
    if ((error as NodeJS.ErrnoException).code !== 'EEXIST') {
      throw error;
    }
  }
}

/**
 * Atomic write using temp file + rename pattern
 * Guarantees no partial writes or corruption on crash
 */
export async function atomicWrite(filePath: string, data: object | string): Promise<void> {
  const tempPath = `${filePath}.tmp`;
  const content = typeof data === 'string' ? data : JSON.stringify(data, null, 2);

  try {
    // Write to temp file
    await fs.writeFile(tempPath, content, 'utf8');

    // Atomic rename (POSIX guarantee: atomic on same filesystem)
    await fs.rename(tempPath, filePath);
  } catch (error) {
    // Clean up temp file on failure
    try {
      await fs.unlink(tempPath);
    } catch {
      // Ignore cleanup errors
    }
    throw error;
  }
}

/**
 * Read and parse JSON file
 */
export async function readJson<T = unknown>(filePath: string): Promise<T> {
  const content = await fs.readFile(filePath, 'utf8');
  return JSON.parse(content) as T;
}

/**
 * Locked atomic write using file lock + temp file + rename pattern.
 * Provides cross-process safety for concurrent file access.
 *
 * @param filePath - File to write to
 * @param data - Data to write (objects are JSON-serialized)
 * @param lockOptions - Optional lock retry/backoff configuration
 */
export async function atomicWriteLocked(
  filePath: string,
  data: object | string,
  lockOptions?: FileLockOptions
): Promise<void> {
  await lockedAtomicWrite(filePath, data, lockOptions);
}

/**
 * Check if file exists
 */
export async function fileExists(filePath: string): Promise<boolean> {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}
