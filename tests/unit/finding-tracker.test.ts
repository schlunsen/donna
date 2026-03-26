import { describe, it, expect } from 'vitest';
import {
  generateFindingId,
  extractFindingsFromReport,
  computeDelta,
} from '../../src/services/finding-tracker.js';
import type { VulnType } from '../../src/types/agents.js';
import type { Finding, ScanBaseline } from '../../src/temporal/continuous-shared.js';
import type { ActivityLogger } from '../../src/types/activity-logger.js';

function createMockLogger(): ActivityLogger {
  return {
    info: () => {},
    warn: () => {},
    error: () => {},
    debug: () => {},
  } as unknown as ActivityLogger;
}

// ─── generateFindingId ───────────────────────────────────────────

describe('generateFindingId', () => {
  it('generates a 16-char hex string', () => {
    const id = generateFindingId('injection', '/api/users', 'SQL Injection');
    expect(id).toMatch(/^[a-f0-9]{16}$/);
  });

  it('is deterministic (same inputs → same output)', () => {
    const id1 = generateFindingId('xss', '/search', 'Reflected XSS');
    const id2 = generateFindingId('xss', '/search', 'Reflected XSS');
    expect(id1).toBe(id2);
  });

  it('is case-insensitive', () => {
    const id1 = generateFindingId('injection', '/API/Users', 'SQL INJECTION');
    const id2 = generateFindingId('injection', '/api/users', 'sql injection');
    expect(id1).toBe(id2);
  });

  it('produces different IDs for different inputs', () => {
    const id1 = generateFindingId('injection', '/api/users', 'SQL Injection');
    const id2 = generateFindingId('xss', '/api/users', 'XSS');
    const id3 = generateFindingId('injection', '/api/posts', 'SQL Injection');
    expect(id1).not.toBe(id2);
    expect(id1).not.toBe(id3);
  });
});

// ─── extractFindingsFromReport ───────────────────────────────────

describe('extractFindingsFromReport', () => {
  const scanId = 'scan-001';
  const timestamp = '2025-01-15T10:00:00Z';

  it('extracts findings with severity and title from markdown', () => {
    const report = `
# Pentest Report

### Critical: SQL Injection in /api/users
**Location:** src/routes/users.ts

Detailed description of the vulnerability...

### High: Command Injection in /api/exec
**Location:** src/routes/exec.ts

Another detailed description...
`;
    const findings = extractFindingsFromReport(report, 'injection', scanId, timestamp);

    expect(findings).toHaveLength(2);
    expect(findings[0]!.severity).toBe('critical');
    expect(findings[0]!.title).toBe('SQL Injection in /api/users');
    expect(findings[0]!.location).toBe('src/routes/users.ts');
    expect(findings[0]!.vulnType).toBe('injection');
    expect(findings[0]!.status).toBe('new');
    expect(findings[0]!.discoveredInScan).toBe(scanId);

    expect(findings[1]!.severity).toBe('high');
    expect(findings[1]!.title).toBe('Command Injection in /api/exec');
  });

  it('skips non-finding headers (summary, methodology, etc.)', () => {
    const report = `
### Summary
Overview of the scan...

### Methodology
How we scanned...

### Critical: Real Finding Here
**Location:** src/app.ts

Description...
`;
    const findings = extractFindingsFromReport(report, 'injection', scanId, timestamp);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.title).toBe('Real Finding Here');
  });

  it('skips titles shorter than 5 characters', () => {
    const report = `
### Critical: XSS
Some details...

### High: SQL Injection in Login Form
**Location:** src/auth.ts
`;
    const findings = extractFindingsFromReport(report, 'xss', scanId, timestamp);
    // "XSS" is only 3 chars, should be skipped
    expect(findings).toHaveLength(1);
    expect(findings[0]!.title).toBe('SQL Injection in Login Form');
  });

  it('defaults severity to Medium when not in heading', () => {
    const report = `
### Weak Password Policy Detected
**Location:** src/auth/config.ts

Details...
`;
    const findings = extractFindingsFromReport(report, 'auth', scanId, timestamp);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('medium');
  });

  it('defaults location to "unknown" when not found', () => {
    const report = `
### High: Open Redirect via Return URL

A simple description with no structured markers.
`;
    const findings = extractFindingsFromReport(report, 'ssrf', scanId, timestamp);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.location).toBe('unknown');
  });

  it('deduplicates findings within the same extraction', () => {
    const report = `
### Critical: SQL Injection in /api/users
**Location:** src/routes/users.ts

First mention...

### Critical: SQL Injection in /api/users
**Location:** src/routes/users.ts

Second mention (duplicate)...
`;
    const findings = extractFindingsFromReport(report, 'injection', scanId, timestamp);
    // Same vulnType + location + title → same ID → deduplicated
    expect(findings).toHaveLength(1);
  });

  it('returns empty array for reports with no findings', () => {
    const report = 'No vulnerabilities were found during this scan.';
    const findings = extractFindingsFromReport(report, 'injection', scanId, timestamp);
    expect(findings).toEqual([]);
  });

  it('sets firstSeen and lastSeen to the provided timestamp', () => {
    const report = `
### High: SSRF via webhook URL
**Location:** src/webhooks.ts
`;
    const findings = extractFindingsFromReport(report, 'ssrf', scanId, timestamp);
    expect(findings[0]!.firstSeen).toBe(timestamp);
    expect(findings[0]!.lastSeen).toBe(timestamp);
  });
});

// ─── computeDelta ────────────────────────────────────────────────

describe('computeDelta', () => {
  const logger = createMockLogger();
  const scanId = 'scan-002';
  const timestamp = '2025-01-16T10:00:00Z';

  function makeFinding(overrides: Partial<Finding>): Finding {
    return {
      id: 'finding-1',
      vulnType: 'injection' as VulnType,
      firstSeen: '2025-01-15T10:00:00Z',
      lastSeen: '2025-01-15T10:00:00Z',
      status: 'new',
      severity: 'high',
      title: 'Test Finding',
      location: 'src/test.ts',
      discoveredInScan: 'scan-001',
      ...overrides,
    };
  }

  it('marks all findings as NEW when no previous baseline', () => {
    const newFindings = [
      makeFinding({ id: 'f1' }),
      makeFinding({ id: 'f2' }),
    ];

    const { updatedFindings, delta } = computeDelta(
      null, newFindings, ['injection'], scanId, timestamp, logger
    );

    expect(delta.newFindings).toHaveLength(2);
    expect(delta.confirmedFindings).toHaveLength(0);
    expect(delta.resolvedFindings).toHaveLength(0);
    expect(delta.totalActive).toBe(2);
    expect(updatedFindings.every(f => f.status === 'new')).toBe(true);
  });

  it('marks findings as CONFIRMED when seen again', () => {
    const previousBaseline: ScanBaseline = {
      scanId: 'scan-001',
      timestamp: '2025-01-15T10:00:00Z',
      findings: [makeFinding({ id: 'f1', status: 'new' })],
      scannedCategories: ['injection'],
    };

    const newFindings = [makeFinding({ id: 'f1' })];

    const { updatedFindings, delta } = computeDelta(
      previousBaseline, newFindings, ['injection'], scanId, timestamp, logger
    );

    expect(delta.confirmedFindings).toHaveLength(1);
    expect(delta.confirmedFindings[0]!.status).toBe('confirmed');
    expect(delta.confirmedFindings[0]!.lastSeen).toBe(timestamp);
    expect(delta.newFindings).toHaveLength(0);
    expect(delta.resolvedFindings).toHaveLength(0);
  });

  it('marks findings as RESOLVED when not present and category was scanned', () => {
    const previousBaseline: ScanBaseline = {
      scanId: 'scan-001',
      timestamp: '2025-01-15T10:00:00Z',
      findings: [makeFinding({ id: 'f1', vulnType: 'injection' })],
      scannedCategories: ['injection'],
    };

    const newFindings: Finding[] = []; // Finding gone

    const { updatedFindings, delta } = computeDelta(
      previousBaseline, newFindings, ['injection'], scanId, timestamp, logger
    );

    expect(delta.resolvedFindings).toHaveLength(1);
    expect(delta.resolvedFindings[0]!.status).toBe('resolved');
    expect(delta.totalActive).toBe(0);
  });

  it('carries forward findings when their category was NOT scanned', () => {
    const previousBaseline: ScanBaseline = {
      scanId: 'scan-001',
      timestamp: '2025-01-15T10:00:00Z',
      findings: [makeFinding({ id: 'f1', vulnType: 'xss' as VulnType })],
      scannedCategories: ['xss'],
    };

    const newFindings: Finding[] = []; // XSS finding gone

    // But we only scanned injection this time, not xss
    const { updatedFindings, delta } = computeDelta(
      previousBaseline, newFindings, ['injection'], scanId, timestamp, logger
    );

    // Finding should be carried forward (not resolved)
    expect(delta.resolvedFindings).toHaveLength(0);
    expect(updatedFindings).toHaveLength(1);
    expect(updatedFindings[0]!.id).toBe('f1');
    expect(updatedFindings[0]!.status).toBe('new'); // unchanged original status
  });

  it('handles mixed scenario: new + confirmed + resolved', () => {
    const previousBaseline: ScanBaseline = {
      scanId: 'scan-001',
      timestamp: '2025-01-15T10:00:00Z',
      findings: [
        makeFinding({ id: 'f1', vulnType: 'injection' }), // will be confirmed
        makeFinding({ id: 'f2', vulnType: 'injection' }), // will be resolved
      ],
      scannedCategories: ['injection'],
    };

    const newFindings = [
      makeFinding({ id: 'f1' }),                           // confirmed
      makeFinding({ id: 'f3', title: 'Brand New' }),       // new
    ];

    const { delta } = computeDelta(
      previousBaseline, newFindings, ['injection'], scanId, timestamp, logger
    );

    expect(delta.confirmedFindings).toHaveLength(1);
    expect(delta.confirmedFindings[0]!.id).toBe('f1');

    expect(delta.newFindings).toHaveLength(1);
    expect(delta.newFindings[0]!.id).toBe('f3');

    expect(delta.resolvedFindings).toHaveLength(1);
    expect(delta.resolvedFindings[0]!.id).toBe('f2');

    expect(delta.totalActive).toBe(2); // f1 (confirmed) + f3 (new)
  });

  it('totalActive excludes resolved findings', () => {
    const previousBaseline: ScanBaseline = {
      scanId: 'scan-001',
      timestamp: '2025-01-15T10:00:00Z',
      findings: [
        makeFinding({ id: 'f1', vulnType: 'injection' }),
        makeFinding({ id: 'f2', vulnType: 'injection' }),
        makeFinding({ id: 'f3', vulnType: 'injection' }),
      ],
      scannedCategories: ['injection'],
    };

    // All 3 gone → all resolved
    const { delta } = computeDelta(
      previousBaseline, [], ['injection'], scanId, timestamp, logger
    );

    expect(delta.resolvedFindings).toHaveLength(3);
    expect(delta.totalActive).toBe(0);
  });
});
