// Donna - Continuous AI Pentesting Platform
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Budget Monitor Service
 *
 * Tracks token usage and cost during agent execution, emitting warnings
 * at configurable thresholds (75%, 90%, 99%) and enabling graceful
 * shutdown when budgets are exhausted.
 *
 * Works alongside the existing cost tracking in metrics-tracker.ts
 * to provide real-time budget awareness during execution.
 */

import type { ActivityLogger } from '../types/activity-logger.js';

export interface BudgetThresholds {
  /** Warn at this percentage of budget (default: 75) */
  warn: number;
  /** Urgent warning at this percentage (default: 90) */
  urgent: number;
  /** Force stop at this percentage (default: 99) */
  critical: number;
}

export interface BudgetConfig {
  /** Maximum cost in USD for this agent (0 = unlimited) */
  maxCostUsd: number;
  /** Maximum output tokens for this agent (0 = unlimited) */
  maxOutputTokens: number;
  /** Threshold percentages for warnings */
  thresholds: BudgetThresholds;
}

export interface BudgetStatus {
  /** Current cost in USD */
  currentCostUsd: number;
  /** Current turn count */
  currentTurns: number;
  /** Whether the warn threshold has been reached */
  warnReached: boolean;
  /** Whether the urgent threshold has been reached */
  urgentReached: boolean;
  /** Whether the critical threshold has been reached */
  criticalReached: boolean;
  /** Suggested action message (if any) */
  actionMessage: string | null;
}

const DEFAULT_THRESHOLDS: BudgetThresholds = {
  warn: 75,
  urgent: 90,
  critical: 99,
};

/**
 * Default budget configs per model tier.
 * Larger models get higher cost budgets since they're more expensive per token.
 */
export const DEFAULT_BUDGET_BY_TIER: Record<string, BudgetConfig> = {
  small: {
    maxCostUsd: 0.50,
    maxOutputTokens: 32000,
    thresholds: DEFAULT_THRESHOLDS,
  },
  medium: {
    maxCostUsd: 2.00,
    maxOutputTokens: 64000,
    thresholds: DEFAULT_THRESHOLDS,
  },
  large: {
    maxCostUsd: 5.00,
    maxOutputTokens: 64000,
    thresholds: DEFAULT_THRESHOLDS,
  },
};

/**
 * BudgetMonitor tracks real-time cost/token usage during agent execution
 * and emits warnings at threshold crossings.
 */
export class BudgetMonitor {
  private config: BudgetConfig;
  private agentName: string;
  private logger: ActivityLogger;

  private currentCostUsd: number = 0;
  private currentTurns: number = 0;

  // Track which thresholds we've already fired (avoid spamming)
  private warnFired: boolean = false;
  private urgentFired: boolean = false;
  private criticalFired: boolean = false;

  constructor(agentName: string, config: BudgetConfig, logger: ActivityLogger) {
    this.agentName = agentName;
    this.config = config;
    this.logger = logger;
  }

  /**
   * Create a BudgetMonitor with defaults for the given model tier.
   */
  static forTier(
    agentName: string,
    tier: string,
    logger: ActivityLogger,
    overrides?: Partial<BudgetConfig>
  ): BudgetMonitor {
    const base = DEFAULT_BUDGET_BY_TIER[tier] ?? DEFAULT_BUDGET_BY_TIER['medium']!;
    const config: BudgetConfig = {
      ...base,
      ...overrides,
      thresholds: { ...base.thresholds, ...overrides?.thresholds },
    };
    return new BudgetMonitor(agentName, config, logger);
  }

  /**
   * Update the monitor with new cost data from a message/turn.
   * Call this after each assistant message or cost update.
   *
   * @returns BudgetStatus with current state and any action messages
   */
  update(costUsd: number, turns: number): BudgetStatus {
    this.currentCostUsd = costUsd;
    this.currentTurns = turns;

    const status: BudgetStatus = {
      currentCostUsd: this.currentCostUsd,
      currentTurns: this.currentTurns,
      warnReached: false,
      urgentReached: false,
      criticalReached: false,
      actionMessage: null,
    };

    // Skip budget checks if no budget configured
    if (this.config.maxCostUsd <= 0) {
      return status;
    }

    const costPct = (this.currentCostUsd / this.config.maxCostUsd) * 100;

    // Check thresholds in order (critical > urgent > warn)
    if (costPct >= this.config.thresholds.critical) {
      status.criticalReached = true;
      if (!this.criticalFired) {
        this.criticalFired = true;
        this.logger.warn(
          `[BUDGET CRITICAL] ${this.agentName}: $${this.currentCostUsd.toFixed(4)} / $${this.config.maxCostUsd.toFixed(2)} (${costPct.toFixed(1)}%) — forcing graceful stop`
        );
        status.actionMessage =
          'BUDGET LIMIT REACHED. Output your current findings immediately and stop. Focus on highest-priority items only.';
      }
    } else if (costPct >= this.config.thresholds.urgent) {
      status.urgentReached = true;
      if (!this.urgentFired) {
        this.urgentFired = true;
        this.logger.warn(
          `[BUDGET URGENT] ${this.agentName}: $${this.currentCostUsd.toFixed(4)} / $${this.config.maxCostUsd.toFixed(2)} (${costPct.toFixed(1)}%) — focus on highest-priority remaining items`
        );
        status.actionMessage =
          'Approaching budget limit. Focus on highest-priority remaining items and prepare to output findings.';
      }
    } else if (costPct >= this.config.thresholds.warn) {
      status.warnReached = true;
      if (!this.warnFired) {
        this.warnFired = true;
        this.logger.info(
          `[BUDGET WARN] ${this.agentName}: $${this.currentCostUsd.toFixed(4)} / $${this.config.maxCostUsd.toFixed(2)} (${costPct.toFixed(1)}%)`
        );
      }
    }

    return status;
  }

  /**
   * Get a summary of budget usage for pipeline completion reporting.
   */
  getSummary(): { agentName: string; costUsd: number; budgetUsd: number; turns: number; utilizationPct: number } {
    return {
      agentName: this.agentName,
      costUsd: this.currentCostUsd,
      budgetUsd: this.config.maxCostUsd,
      turns: this.currentTurns,
      utilizationPct: this.config.maxCostUsd > 0
        ? Math.round((this.currentCostUsd / this.config.maxCostUsd) * 100)
        : 0,
    };
  }
}

/**
 * Calculate dynamic output token budget based on input characteristics.
 *
 * Scaling:
 * - Base: 16K tokens
 * - Per 10 source files: +4K tokens
 * - Per queue entry to exploit: +2K tokens
 * - Cap: 64K tokens (or env override)
 *
 * @param fileCount - Number of source files in the project
 * @param queueEntryCount - Number of queue entries to process
 * @returns Computed max output tokens
 */
export function computeDynamicTokenBudget(
  fileCount: number = 0,
  queueEntryCount: number = 0
): number {
  const BASE_TOKENS = 16_000;
  const PER_10_FILES = 4_000;
  const PER_QUEUE_ENTRY = 2_000;
  const MAX_TOKENS = parseInt(process.env.CLAUDE_CODE_MAX_OUTPUT_TOKENS || '64000', 10);

  const fileBonus = Math.floor(fileCount / 10) * PER_10_FILES;
  const queueBonus = queueEntryCount * PER_QUEUE_ENTRY;
  const computed = BASE_TOKENS + fileBonus + queueBonus;

  return Math.min(computed, MAX_TOKENS);
}
