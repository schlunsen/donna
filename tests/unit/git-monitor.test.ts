import { describe, it, expect } from 'vitest';
import {
  categorizeChanges,
  hasInfrastructureChanges,
  routeChanges,
} from '../../src/services/git-monitor.js';
import type { VulnType } from '../../src/types/agents.js';
import type { GitDiffResult } from '../../src/temporal/continuous-shared.js';

// ─── categorizeChanges ───────────────────────────────────────────

describe('categorizeChanges', () => {
  it('maps SQL/database files to injection', () => {
    const categories = categorizeChanges(['src/models/user.sql', 'src/db/query.ts']);
    expect(categories).toContain('injection');
  });

  it('maps template/HTML files to xss', () => {
    const categories = categorizeChanges(['src/views/home.html', 'src/components/Card.tsx']);
    expect(categories).toContain('xss');
  });

  it('maps auth-related files to auth', () => {
    const categories = categorizeChanges(['src/auth/login.ts', 'src/middleware/session.ts']);
    expect(categories).toContain('auth');
  });

  it('maps HTTP/URL files to ssrf', () => {
    const categories = categorizeChanges(['src/utils/fetch.ts', 'src/services/webhook.ts']);
    expect(categories).toContain('ssrf');
  });

  it('maps permission/role files to authz', () => {
    const categories = categorizeChanges(['src/middleware/rbac.ts', 'src/guards/admin.ts']);
    expect(categories).toContain('authz');
  });

  it('maps ORM-related files to injection', () => {
    const categories = categorizeChanges(['src/models/prisma.ts']);
    expect(categories).toContain('injection');
  });

  it('maps Vue/Svelte files to xss', () => {
    const categories = categorizeChanges(['src/components/App.vue', 'src/pages/Home.svelte']);
    expect(categories).toContain('xss');
  });

  it('maps JWT/OAuth files to auth', () => {
    const categories = categorizeChanges(['src/auth/jwt.ts', 'src/auth/oauth.ts']);
    expect(categories).toContain('auth');
  });

  it('returns empty array when no patterns match', () => {
    const categories = categorizeChanges(['README.md', 'docs/guide.txt', 'assets/logo.png']);
    expect(categories).toEqual([]);
  });

  it('returns unique categories (no duplicates)', () => {
    const categories = categorizeChanges([
      'src/db/users.sql',
      'src/db/posts.sql',
      'src/models/query.ts',
    ]);
    const injectionCount = categories.filter(c => c === 'injection').length;
    expect(injectionCount).toBe(1);
  });

  it('can match multiple categories from a single file set', () => {
    const categories = categorizeChanges([
      'src/auth/login.ts',     // auth
      'src/views/form.html',   // xss
      'src/db/query.sql',      // injection
    ]);
    expect(categories).toContain('auth');
    expect(categories).toContain('xss');
    expect(categories).toContain('injection');
  });

  it('maps controller/router files to authz', () => {
    const categories = categorizeChanges(['src/routes/api.ts', 'src/controllers/userController.ts']);
    expect(categories).toContain('authz');
  });
});

// ─── hasInfrastructureChanges ────────────────────────────────────

describe('hasInfrastructureChanges', () => {
  it('detects package.json changes', () => {
    expect(hasInfrastructureChanges(['package.json'])).toBe(true);
  });

  it('detects package-lock.json changes', () => {
    expect(hasInfrastructureChanges(['package-lock.json'])).toBe(true);
  });

  it('detects yarn.lock changes', () => {
    expect(hasInfrastructureChanges(['yarn.lock'])).toBe(true);
  });

  it('detects pnpm-lock.yaml changes', () => {
    expect(hasInfrastructureChanges(['pnpm-lock.yaml'])).toBe(true);
  });

  it('detects Gemfile changes', () => {
    expect(hasInfrastructureChanges(['Gemfile'])).toBe(true);
    expect(hasInfrastructureChanges(['Gemfile.lock'])).toBe(true);
  });

  it('detects requirements.txt changes', () => {
    expect(hasInfrastructureChanges(['requirements.txt'])).toBe(true);
    expect(hasInfrastructureChanges(['requirements-dev.txt'])).toBe(true);
  });

  it('detects go.mod/go.sum changes', () => {
    expect(hasInfrastructureChanges(['go.mod'])).toBe(true);
    expect(hasInfrastructureChanges(['go.sum'])).toBe(true);
  });

  it('detects Cargo.toml/Cargo.lock changes', () => {
    expect(hasInfrastructureChanges(['Cargo.toml'])).toBe(true);
    expect(hasInfrastructureChanges(['Cargo.lock'])).toBe(true);
  });

  it('detects docker-compose changes', () => {
    expect(hasInfrastructureChanges(['docker-compose.yml'])).toBe(true);
    expect(hasInfrastructureChanges(['docker-compose.prod.yaml'])).toBe(true);
  });

  it('detects Dockerfile changes', () => {
    expect(hasInfrastructureChanges(['Dockerfile'])).toBe(true);
  });

  it('detects .env changes', () => {
    expect(hasInfrastructureChanges(['.env'])).toBe(true);
    expect(hasInfrastructureChanges(['.env.production'])).toBe(true);
  });

  it('detects nginx/apache config changes', () => {
    expect(hasInfrastructureChanges(['nginx.conf'])).toBe(true);
  });

  it('returns false for normal source files', () => {
    expect(hasInfrastructureChanges(['src/app.ts', 'src/utils/helper.ts'])).toBe(false);
  });

  it('returns false for empty file list', () => {
    expect(hasInfrastructureChanges([])).toBe(false);
  });
});

// ─── routeChanges ────────────────────────────────────────────────

describe('routeChanges', () => {
  const allCategories: VulnType[] = ['injection', 'xss', 'auth', 'ssrf', 'authz'];

  function makeDiff(overrides: Partial<GitDiffResult> = {}): GitDiffResult {
    return {
      previousCommit: 'abc123',
      currentCommit: 'def456',
      changedFiles: ['src/app.ts'],
      hasChanges: true,
      changeSummary: { src: 1 },
      ...overrides,
    };
  }

  it('returns no categories when there are no changes', () => {
    const routing = routeChanges(
      makeDiff({ hasChanges: false, changedFiles: [] }),
      { strategy: 'incremental', forceFull: false, isFirstScan: false }
    );
    expect(routing.fullScan).toBe(false);
    expect(routing.vulnCategories).toEqual([]);
    expect(routing.reason).toContain('No changes');
  });

  it('runs full scan on first scan', () => {
    const routing = routeChanges(
      makeDiff(),
      { strategy: 'incremental', forceFull: false, isFirstScan: true }
    );
    expect(routing.fullScan).toBe(true);
    expect(routing.vulnCategories).toEqual(allCategories);
    expect(routing.reason).toContain('First scan');
  });

  it('runs full scan when strategy is "full"', () => {
    const routing = routeChanges(
      makeDiff(),
      { strategy: 'full', forceFull: false, isFirstScan: false }
    );
    expect(routing.fullScan).toBe(true);
    expect(routing.vulnCategories).toEqual(allCategories);
  });

  it('runs full scan when forceFull is true', () => {
    const routing = routeChanges(
      makeDiff(),
      { strategy: 'incremental', forceFull: true, isFirstScan: false }
    );
    expect(routing.fullScan).toBe(true);
    expect(routing.reason).toContain('Periodic full scan');
  });

  it('runs full scan on infrastructure changes', () => {
    const routing = routeChanges(
      makeDiff({ changedFiles: ['package.json', 'src/app.ts'] }),
      { strategy: 'incremental', forceFull: false, isFirstScan: false }
    );
    expect(routing.fullScan).toBe(true);
    expect(routing.reason).toContain('Infrastructure');
  });

  it('runs incremental scan for categorized changes', () => {
    const routing = routeChanges(
      makeDiff({ changedFiles: ['src/auth/login.ts'] }),
      { strategy: 'incremental', forceFull: false, isFirstScan: false }
    );
    expect(routing.fullScan).toBe(false);
    expect(routing.vulnCategories).toContain('auth');
    expect(routing.reason).toContain('Incremental');
  });

  it('falls back to full scan when no categories match changed files', () => {
    const routing = routeChanges(
      makeDiff({ changedFiles: ['README.md'] }),
      { strategy: 'incremental', forceFull: false, isFirstScan: false }
    );
    // Conservative: unmatched changes → full scan
    expect(routing.fullScan).toBe(true);
    expect(routing.vulnCategories).toEqual(allCategories);
    expect(routing.reason).toContain('no vuln category matched');
  });

  it('includes correct changedFileCount', () => {
    const routing = routeChanges(
      makeDiff({ changedFiles: ['a.ts', 'b.ts', 'c.ts'] }),
      { strategy: 'incremental', forceFull: false, isFirstScan: true }
    );
    expect(routing.changedFileCount).toBe(3);
  });

  it('returns multiple categories for mixed changes', () => {
    const routing = routeChanges(
      makeDiff({
        changedFiles: [
          'src/auth/login.ts',       // auth
          'src/views/dashboard.html', // xss
          'src/models/user.sql',      // injection
        ],
      }),
      { strategy: 'incremental', forceFull: false, isFirstScan: false }
    );
    expect(routing.fullScan).toBe(false);
    expect(routing.vulnCategories).toContain('auth');
    expect(routing.vulnCategories).toContain('xss');
    expect(routing.vulnCategories).toContain('injection');
  });
});
