import { describe, it, expect } from 'vitest';
import { SessionMutex } from '../../src/utils/concurrency.js';

describe('SessionMutex', () => {
  it('acquires and releases lock', async () => {
    const mutex = new SessionMutex();
    const unlock = await mutex.lock('session-1');
    expect(typeof unlock).toBe('function');
    unlock();
  });

  it('serializes concurrent access to same session', async () => {
    const mutex = new SessionMutex();
    const order: number[] = [];

    const p1 = mutex.lock('session-1').then(async (unlock) => {
      order.push(1);
      // Simulate work
      await new Promise((r) => setTimeout(r, 50));
      order.push(2);
      unlock();
    });

    const p2 = mutex.lock('session-1').then(async (unlock) => {
      order.push(3);
      unlock();
    });

    await Promise.all([p1, p2]);
    // p2 should start after p1 completes
    expect(order).toEqual([1, 2, 3]);
  });

  it('allows parallel access to different sessions', async () => {
    const mutex = new SessionMutex();
    const started: string[] = [];

    const p1 = mutex.lock('session-a').then(async (unlock) => {
      started.push('a');
      await new Promise((r) => setTimeout(r, 50));
      unlock();
    });

    const p2 = mutex.lock('session-b').then(async (unlock) => {
      started.push('b');
      await new Promise((r) => setTimeout(r, 10));
      unlock();
    });

    await Promise.all([p1, p2]);
    // Both should start without waiting for each other
    expect(started).toContain('a');
    expect(started).toContain('b');
  });
});
