// Donna - Continuous AI Pentesting Platform
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Browser Pool Manager
 *
 * Manages Playwright browser/MCP subprocess lifecycle:
 * - Configurable max concurrent instances (default: 3, respects ConcurrencyConfig.max_browsers)
 * - Acquire/release semantics with queue and timeout
 * - Process cleanup on SIGINT, SIGTERM, and uncaught exceptions
 * - Idle browser detection and cleanup (>5 min idle)
 * - Resource usage stats for pipeline completion reporting
 *
 * NOTE: Playwright MCP servers are spawned by the Claude Agent SDK as stdio
 * subprocesses. This pool tracks allocations at the logical level (agent slots)
 * rather than managing raw browser PIDs. The SDK handles actual process
 * lifecycle. This pool enforces concurrency limits and cleanup coordination.
 */

import { rmSync, existsSync } from 'fs';

export interface BrowserPoolConfig {
  /** Max concurrent browser instances (default: 3) */
  maxInstances: number;
  /** Timeout in ms when waiting for a free slot (default: 300000 = 5 min) */
  acquireTimeoutMs: number;
  /** Idle threshold in ms before releasing (default: 300000 = 5 min) */
  idleTimeoutMs: number;
}

export interface BrowserSlot {
  agentId: string;
  acquiredAt: number;
  lastActivityAt: number;
}

export interface BrowserPoolStats {
  active: number;
  queued: number;
  totalAcquired: number;
  totalReleased: number;
  peakConcurrent: number;
}

const DEFAULT_CONFIG: BrowserPoolConfig = {
  maxInstances: 3,
  acquireTimeoutMs: 300_000,
  idleTimeoutMs: 300_000,
};

/**
 * BrowserPool manages concurrent Playwright browser instance slots.
 *
 * Usage:
 * ```ts
 * const pool = new BrowserPool({ maxInstances: 3 });
 * pool.registerCleanupHandlers();
 *
 * const slot = await pool.acquire('injection-exploit');
 * try {
 *   // ... agent execution with browser
 * } finally {
 *   pool.release('injection-exploit');
 * }
 *
 * pool.getStats(); // { active: 0, queued: 0, totalAcquired: 1, ... }
 * ```
 */
export class BrowserPool {
  private config: BrowserPoolConfig;
  private activeSlots: Map<string, BrowserSlot> = new Map();
  private waitQueue: Array<{
    agentId: string;
    resolve: () => void;
    reject: (err: Error) => void;
    timer: ReturnType<typeof setTimeout>;
  }> = [];

  private totalAcquired: number = 0;
  private totalReleased: number = 0;
  private peakConcurrent: number = 0;
  private idleCheckInterval: ReturnType<typeof setInterval> | null = null;
  private cleanupRegistered: boolean = false;

  constructor(config?: Partial<BrowserPoolConfig>) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /**
   * Acquire a browser slot for an agent.
   * If the pool is full, waits in a queue with timeout.
   *
   * @param agentId - Unique identifier for the requesting agent
   * @throws Error if acquire times out
   */
  async acquire(agentId: string): Promise<void> {
    // If this agent already has a slot, just update activity time
    if (this.activeSlots.has(agentId)) {
      const slot = this.activeSlots.get(agentId)!;
      slot.lastActivityAt = Date.now();
      return;
    }

    // If there's room, acquire immediately
    if (this.activeSlots.size < this.config.maxInstances) {
      this.addSlot(agentId);
      return;
    }

    // Otherwise, queue and wait
    return new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        // Remove from queue on timeout
        this.waitQueue = this.waitQueue.filter((w) => w.agentId !== agentId);
        reject(
          new Error(
            `Browser pool acquire timeout after ${this.config.acquireTimeoutMs}ms for agent ${agentId}. ` +
            `Pool: ${this.activeSlots.size}/${this.config.maxInstances} active, ${this.waitQueue.length} queued.`
          )
        );
      }, this.config.acquireTimeoutMs);

      this.waitQueue.push({ agentId, resolve, reject, timer });
    });
  }

  /**
   * Release a browser slot, allowing queued agents to proceed.
   *
   * @param agentId - Agent releasing the browser slot
   */
  release(agentId: string): void {
    if (!this.activeSlots.has(agentId)) {
      return; // Already released or never acquired
    }

    this.activeSlots.delete(agentId);
    this.totalReleased++;

    // Clean up the agent's user data directory
    this.cleanupUserDataDir(agentId);

    // Process next in queue
    this.processQueue();
  }

  /**
   * Get current pool statistics.
   */
  getStats(): BrowserPoolStats {
    return {
      active: this.activeSlots.size,
      queued: this.waitQueue.length,
      totalAcquired: this.totalAcquired,
      totalReleased: this.totalReleased,
      peakConcurrent: this.peakConcurrent,
    };
  }

  /**
   * Register process signal handlers for cleanup on exit.
   * Call once during worker startup.
   */
  registerCleanupHandlers(): void {
    if (this.cleanupRegistered) return;
    this.cleanupRegistered = true;

    const cleanup = (): void => {
      this.cleanup();
    };

    process.on('SIGINT', cleanup);
    process.on('SIGTERM', cleanup);
    process.on('uncaughtException', (err) => {
      console.error('Uncaught exception, cleaning up browser pool:', err.message);
      cleanup();
    });

    // Start idle browser check (every 60s)
    this.idleCheckInterval = setInterval(() => {
      this.evictIdleSlots();
    }, 60_000);

    // Don't let the interval prevent process exit
    if (this.idleCheckInterval.unref) {
      this.idleCheckInterval.unref();
    }
  }

  /**
   * Clean up all browser slots and reject all queued requests.
   * Called on process exit.
   */
  cleanup(): void {
    // Clear idle check
    if (this.idleCheckInterval) {
      clearInterval(this.idleCheckInterval);
      this.idleCheckInterval = null;
    }

    // Clean up all active slots' user data directories
    for (const [agentId] of this.activeSlots) {
      this.cleanupUserDataDir(agentId);
    }
    this.activeSlots.clear();

    // Reject all queued requests
    for (const waiter of this.waitQueue) {
      clearTimeout(waiter.timer);
      waiter.reject(new Error('Browser pool shutting down'));
    }
    this.waitQueue = [];
  }

  /**
   * Evict browser slots that have been idle beyond the threshold.
   */
  private evictIdleSlots(): void {
    const now = Date.now();
    const evicted: string[] = [];

    for (const [agentId, slot] of this.activeSlots) {
      if (now - slot.lastActivityAt > this.config.idleTimeoutMs) {
        evicted.push(agentId);
      }
    }

    for (const agentId of evicted) {
      console.log(`[BrowserPool] Evicting idle browser for agent: ${agentId}`);
      this.release(agentId);
    }
  }

  private addSlot(agentId: string): void {
    this.activeSlots.set(agentId, {
      agentId,
      acquiredAt: Date.now(),
      lastActivityAt: Date.now(),
    });
    this.totalAcquired++;

    if (this.activeSlots.size > this.peakConcurrent) {
      this.peakConcurrent = this.activeSlots.size;
    }
  }

  private processQueue(): void {
    while (this.waitQueue.length > 0 && this.activeSlots.size < this.config.maxInstances) {
      const next = this.waitQueue.shift()!;
      clearTimeout(next.timer);
      this.addSlot(next.agentId);
      next.resolve();
    }
  }

  /**
   * Clean up Playwright user data directory for an agent.
   */
  private cleanupUserDataDir(agentId: string): void {
    // Map agent IDs to MCP server names used in claude-executor.ts
    const userDataDir = `/tmp/${agentId}`;
    try {
      if (existsSync(userDataDir)) {
        rmSync(userDataDir, { recursive: true, force: true });
      }
    } catch {
      // Best-effort cleanup
    }
  }
}

/**
 * Global browser pool instance.
 * Shared across all activities in the worker process.
 */
let globalPool: BrowserPool | null = null;

/**
 * Get or create the global browser pool.
 *
 * @param maxBrowsers - Max concurrent browser instances (from ConcurrencyConfig)
 */
export function getBrowserPool(maxBrowsers?: number): BrowserPool {
  if (!globalPool) {
    globalPool = new BrowserPool({
      maxInstances: maxBrowsers ?? 3,
    });
    globalPool.registerCleanupHandlers();
  }
  return globalPool;
}

/**
 * Validate that Playwright/Chromium is available.
 * Used during preflight checks.
 *
 * @returns true if Chromium can be found, false otherwise
 */
export function validateChromiumAvailability(): { available: boolean; message: string } {
  const isDocker = process.env.DONNA_DOCKER === 'true';

  if (isDocker) {
    // In Docker, check for the expected Chromium binary
    if (existsSync('/usr/bin/chromium-browser')) {
      return { available: true, message: 'Chromium found at /usr/bin/chromium-browser' };
    }
    return {
      available: false,
      message: 'Chromium not found at /usr/bin/chromium-browser. Ensure the Docker image includes Chromium.',
    };
  }

  // For local mode, npx @playwright/mcp handles browser download
  // Check if playwright is accessible via npx
  return {
    available: true,
    message: 'Playwright MCP will be launched via npx (auto-downloads Chromium if needed)',
  };
}
