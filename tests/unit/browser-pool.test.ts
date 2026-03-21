import { describe, it, expect } from 'vitest';
import { BrowserPool } from '../../src/services/browser-pool.js';

describe('BrowserPool', () => {
  it('acquires and releases slots', async () => {
    const pool = new BrowserPool({ maxInstances: 2 });
    await pool.acquire('agent-1');
    expect(pool.getStats().active).toBe(1);
    pool.release('agent-1');
    expect(pool.getStats().active).toBe(0);
  });

  it('tracks peak concurrent usage', async () => {
    const pool = new BrowserPool({ maxInstances: 3 });
    await pool.acquire('agent-1');
    await pool.acquire('agent-2');
    expect(pool.getStats().peakConcurrent).toBe(2);
    pool.release('agent-1');
    expect(pool.getStats().peakConcurrent).toBe(2); // Peak doesn't decrease
    pool.release('agent-2');
  });

  it('queues when pool is full', async () => {
    const pool = new BrowserPool({ maxInstances: 1, acquireTimeoutMs: 5000 });
    await pool.acquire('agent-1');

    let acquired = false;
    const acquirePromise = pool.acquire('agent-2').then(() => {
      acquired = true;
    });

    // agent-2 should be queued
    expect(pool.getStats().queued).toBe(1);
    expect(acquired).toBe(false);

    // Release agent-1, agent-2 should get the slot
    pool.release('agent-1');
    await acquirePromise;
    expect(acquired).toBe(true);
    expect(pool.getStats().active).toBe(1);
    pool.release('agent-2');
  });

  it('times out when pool is exhausted', async () => {
    const pool = new BrowserPool({ maxInstances: 1, acquireTimeoutMs: 100 });
    await pool.acquire('agent-1');

    await expect(pool.acquire('agent-2')).rejects.toThrow('Browser pool acquire timeout');

    pool.release('agent-1');
  });

  it('allows re-acquisition by same agent (idempotent)', async () => {
    const pool = new BrowserPool({ maxInstances: 1 });
    await pool.acquire('agent-1');
    await pool.acquire('agent-1'); // Should not block
    expect(pool.getStats().active).toBe(1);
    pool.release('agent-1');
  });

  it('cleanup releases all slots and rejects queued', async () => {
    const pool = new BrowserPool({ maxInstances: 1, acquireTimeoutMs: 5000 });
    await pool.acquire('agent-1');

    const acquirePromise = pool.acquire('agent-2');
    pool.cleanup();

    await expect(acquirePromise).rejects.toThrow('Browser pool shutting down');
    expect(pool.getStats().active).toBe(0);
    expect(pool.getStats().queued).toBe(0);
  });

  it('release is idempotent', () => {
    const pool = new BrowserPool({ maxInstances: 2 });
    pool.release('nonexistent'); // Should not throw
    expect(pool.getStats().active).toBe(0);
  });

  it('reports totalAcquired and totalReleased', async () => {
    const pool = new BrowserPool({ maxInstances: 2 });
    await pool.acquire('a');
    await pool.acquire('b');
    pool.release('a');
    pool.release('b');
    const stats = pool.getStats();
    expect(stats.totalAcquired).toBe(2);
    expect(stats.totalReleased).toBe(2);
  });
});
