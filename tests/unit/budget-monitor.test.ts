import { describe, it, expect, vi } from 'vitest';
import { BudgetMonitor, computeDynamicTokenBudget } from '../../src/services/budget-monitor.js';
import type { ActivityLogger } from '../../src/types/activity-logger.js';

function createMockLogger(): ActivityLogger {
  return {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  } as unknown as ActivityLogger;
}

describe('BudgetMonitor', () => {
  it('creates monitor with default tier budgets', () => {
    const logger = createMockLogger();
    const monitor = BudgetMonitor.forTier('test-agent', 'medium', logger);
    const summary = monitor.getSummary();
    expect(summary.agentName).toBe('test-agent');
    expect(summary.budgetUsd).toBe(2.00);
    expect(summary.costUsd).toBe(0);
  });

  it('does not fire warnings below 75%', () => {
    const logger = createMockLogger();
    const monitor = BudgetMonitor.forTier('test-agent', 'medium', logger);
    const status = monitor.update(1.00, 50); // 50% of $2.00
    expect(status.warnReached).toBe(false);
    expect(status.urgentReached).toBe(false);
    expect(status.criticalReached).toBe(false);
    expect(status.actionMessage).toBeNull();
  });

  it('fires warn at 75% threshold', () => {
    const logger = createMockLogger();
    const monitor = BudgetMonitor.forTier('test-agent', 'medium', logger);
    const status = monitor.update(1.50, 75); // 75% of $2.00
    expect(status.warnReached).toBe(true);
    expect(status.urgentReached).toBe(false);
    expect(logger.info).toHaveBeenCalledWith(expect.stringContaining('[BUDGET WARN]'));
  });

  it('fires urgent at 90% threshold', () => {
    const logger = createMockLogger();
    const monitor = BudgetMonitor.forTier('test-agent', 'medium', logger);
    const status = monitor.update(1.80, 90); // 90% of $2.00
    expect(status.urgentReached).toBe(true);
    expect(status.actionMessage).toContain('highest-priority');
    expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('[BUDGET URGENT]'));
  });

  it('fires critical at 99% threshold', () => {
    const logger = createMockLogger();
    const monitor = BudgetMonitor.forTier('test-agent', 'medium', logger);
    const status = monitor.update(1.98, 99); // 99% of $2.00
    expect(status.criticalReached).toBe(true);
    expect(status.actionMessage).toContain('BUDGET LIMIT REACHED');
    expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('[BUDGET CRITICAL]'));
  });

  it('only fires each threshold once', () => {
    const logger = createMockLogger();
    const monitor = BudgetMonitor.forTier('test-agent', 'medium', logger);

    monitor.update(1.50, 75);
    monitor.update(1.55, 80);
    // warn should only have fired once
    expect((logger.info as ReturnType<typeof vi.fn>).mock.calls.filter(
      (c: unknown[]) => typeof c[0] === 'string' && (c[0] as string).includes('[BUDGET WARN]')
    )).toHaveLength(1);
  });

  it('returns correct summary', () => {
    const logger = createMockLogger();
    const monitor = BudgetMonitor.forTier('test-agent', 'large', logger);
    monitor.update(2.50, 100);
    const summary = monitor.getSummary();
    expect(summary.agentName).toBe('test-agent');
    expect(summary.costUsd).toBe(2.50);
    expect(summary.budgetUsd).toBe(5.00);
    expect(summary.turns).toBe(100);
    expect(summary.utilizationPct).toBe(50);
  });

  it('skips budget checks when maxCostUsd is 0 (unlimited)', () => {
    const logger = createMockLogger();
    const monitor = BudgetMonitor.forTier('test-agent', 'medium', logger, { maxCostUsd: 0 });
    const status = monitor.update(100.00, 500); // Way over any budget
    expect(status.warnReached).toBe(false);
    expect(status.criticalReached).toBe(false);
    expect(status.actionMessage).toBeNull();
  });

  it('uses small tier defaults', () => {
    const logger = createMockLogger();
    const monitor = BudgetMonitor.forTier('report', 'small', logger);
    expect(monitor.getSummary().budgetUsd).toBe(0.50);
  });
});

describe('computeDynamicTokenBudget', () => {
  it('returns base tokens with no files or queue entries', () => {
    expect(computeDynamicTokenBudget(0, 0)).toBe(16_000);
  });

  it('adds 4K per 10 files', () => {
    expect(computeDynamicTokenBudget(30, 0)).toBe(16_000 + 12_000); // 28K
  });

  it('adds 2K per queue entry', () => {
    expect(computeDynamicTokenBudget(0, 5)).toBe(16_000 + 10_000); // 26K
  });

  it('combines file and queue bonuses', () => {
    expect(computeDynamicTokenBudget(20, 3)).toBe(16_000 + 8_000 + 6_000); // 30K
  });

  it('caps at 64K tokens', () => {
    expect(computeDynamicTokenBudget(1000, 100)).toBe(64_000);
  });

  it('handles partial file groups (floors)', () => {
    expect(computeDynamicTokenBudget(15, 0)).toBe(16_000 + 4_000); // 15/10 = 1 group
  });
});
