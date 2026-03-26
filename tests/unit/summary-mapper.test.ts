import { describe, it, expect } from 'vitest';
import { toWorkflowSummary } from '../../src/temporal/summary-mapper.js';
import type { PipelineState } from '../../src/temporal/shared.js';

function makeState(overrides: Partial<PipelineState> = {}): PipelineState {
  return {
    phase: 'complete',
    completedAgents: ['recon', 'injection-vuln', 'report'],
    agentMetrics: {
      recon: { durationMs: 5000, costUsd: 0.10 },
      'injection-vuln': { durationMs: 8000, costUsd: 0.25 },
      report: { durationMs: 3000, costUsd: 0.05 },
    },
    summary: {
      totalDurationMs: 16000,
      totalCostUsd: 0.40,
    },
    error: undefined,
    ...overrides,
  } as unknown as PipelineState;
}

describe('toWorkflowSummary', () => {
  it('maps a completed pipeline state to WorkflowSummary', () => {
    const state = makeState();
    const result = toWorkflowSummary(state, 'completed');

    expect(result.status).toBe('completed');
    expect(result.totalDurationMs).toBe(16000);
    expect(result.totalCostUsd).toBe(0.40);
    expect(result.completedAgents).toEqual(['recon', 'injection-vuln', 'report']);
    expect(result.agentMetrics).toEqual({
      recon: { durationMs: 5000, costUsd: 0.10 },
      'injection-vuln': { durationMs: 8000, costUsd: 0.25 },
      report: { durationMs: 3000, costUsd: 0.05 },
    });
    expect(result.error).toBeUndefined();
  });

  it('maps a failed pipeline state with error', () => {
    const state = makeState({
      error: 'Agent injection-exploit timed out',
    });
    const result = toWorkflowSummary(state, 'failed');

    expect(result.status).toBe('failed');
    expect(result.error).toBe('Agent injection-exploit timed out');
  });

  it('throws if state.summary is not set', () => {
    const state = makeState({ summary: undefined } as any);

    expect(() => toWorkflowSummary(state, 'completed')).toThrow(
      'state.summary must be set before calling'
    );
  });

  it('strips extra fields from agentMetrics (only durationMs + costUsd)', () => {
    const state = makeState({
      agentMetrics: {
        recon: { durationMs: 1000, costUsd: 0.01, turns: 5, model: 'claude-4' } as any,
      },
    });

    const result = toWorkflowSummary(state, 'completed');
    expect(result.agentMetrics.recon).toEqual({
      durationMs: 1000,
      costUsd: 0.01,
    });
    expect((result.agentMetrics.recon as any).turns).toBeUndefined();
    expect((result.agentMetrics.recon as any).model).toBeUndefined();
  });

  it('handles empty completedAgents and agentMetrics', () => {
    const state = makeState({
      completedAgents: [],
      agentMetrics: {},
    });

    const result = toWorkflowSummary(state, 'failed');
    expect(result.completedAgents).toEqual([]);
    expect(result.agentMetrics).toEqual({});
  });
});
