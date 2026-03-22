// Donna - Continuous AI Pentesting Platform
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * File Locking Service
 *
 * Provides cross-process file locking using proper-lockfile for safe concurrent
 * access to shared files (session.json, queue files, deliverables).
 *
 * Features:
 * - Configurable retry count and exponential backoff
 * - Stale lock detection and recovery
 * - Wrapper for lock-protected read/write operations
 */

import lockfile from 'proper-lockfile';
import fs from 'fs/promises';
import path from 'path';

export interface FileLockOptions {
  /** Number of retries on lock contention (default: 5) */
  retries?: number;
  /** Minimum delay between retries in ms (default: 100) */
  minTimeout?: number;
  /** Maximum delay between retries in ms (default: 5000) */
  maxTimeout?: number;
  /** Stale lock threshold in ms (default: 10000) */
  stale?: number;
}

const DEFAULT_LOCK_OPTIONS: Required<FileLockOptions> = {
  retries: 5,
  minTimeout: 100,
  maxTimeout: 5000,
  stale: 10000,
};

/**
 * Ensure a file exists before locking (proper-lockfile requires the file to exist).
 */
async function ensureFileExists(filePath: string): Promise<void> {
  try {
    await fs.access(filePath);
  } catch {
    // Create parent directory and empty file
    await fs.mkdir(path.dirname(filePath), { recursive: true });
    await fs.writeFile(filePath, '', 'utf8');
  }
}

/**
 * Execute a function while holding a file lock.
 *
 * Uses proper-lockfile for cross-process safety with configurable
 * retry count and exponential backoff on contention.
 *
 * @param filePath - Path to the file to lock
 * @param fn - Function to execute while lock is held
 * @param options - Lock configuration options
 * @returns The return value of fn
 */
export async function withFileLock<T>(
  filePath: string,
  fn: () => Promise<T>,
  options?: FileLockOptions
): Promise<T> {
  const opts = { ...DEFAULT_LOCK_OPTIONS, ...options };

  await ensureFileExists(filePath);

  const release = await lockfile.lock(filePath, {
    retries: {
      retries: opts.retries,
      minTimeout: opts.minTimeout,
      maxTimeout: opts.maxTimeout,
      factor: 2, // Exponential backoff
    },
    stale: opts.stale,
  });

  try {
    return await fn();
  } finally {
    await release();
  }
}

/**
 * Atomically write to a file while holding a lock.
 *
 * Combines file locking with atomic write (temp file + rename) for
 * maximum safety against corruption and race conditions.
 *
 * @param filePath - Path to write to
 * @param data - Data to write (object will be JSON-serialized)
 * @param options - Lock configuration options
 */
export async function lockedAtomicWrite(
  filePath: string,
  data: object | string,
  options?: FileLockOptions
): Promise<void> {
  await withFileLock(
    filePath,
    async () => {
      const tempPath = `${filePath}.tmp`;
      const content = typeof data === 'string' ? data : JSON.stringify(data, null, 2);

      try {
        await fs.writeFile(tempPath, content, 'utf8');
        await fs.rename(tempPath, filePath);
      } catch (error) {
        try {
          await fs.unlink(tempPath);
        } catch {
          // Ignore cleanup errors
        }
        throw error;
      }
    },
    options
  );
}

/**
 * Read a file while holding a lock.
 *
 * Prevents reading partial writes from concurrent writers.
 *
 * @param filePath - Path to read
 * @param options - Lock configuration options
 * @returns File contents as string
 */
export async function lockedRead(
  filePath: string,
  options?: FileLockOptions
): Promise<string> {
  return withFileLock(
    filePath,
    async () => {
      return fs.readFile(filePath, 'utf8');
    },
    options
  );
}
