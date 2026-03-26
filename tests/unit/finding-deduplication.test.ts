import { describe, it, expect } from 'vitest';
import {
  normalizeSeverity,
  canonicalizeEndpoint,
  classifyVulnerability,
  parseFindings,
  deduplicateFindings,
  computeFindingSummary,
  renderSeveritySummaryTable,
  processAndDeduplicateFindings,
  type ParsedFinding,
  type CvssSeverity,
} from '../../src/services/finding-deduplication.js';
import type { ActivityLogger } from '../../src/types/activity-logger.js';

// Minimal mock logger (no LLM calls, just collects log lines)
function createMockLogger(): ActivityLogger {
  return {
    info: () => {},
    warn: () => {},
    error: () => {},
    debug: () => {},
  } as unknown as ActivityLogger;
}

// ─── normalizeSeverity ───────────────────────────────────────────

describe('normalizeSeverity', () => {
  describe('CVSS numeric scores', () => {
    it('maps 9.0+ to Critical', () => {
      expect(normalizeSeverity('9.0')).toBe('Critical');
      expect(normalizeSeverity('10.0')).toBe('Critical');
      expect(normalizeSeverity('CVSS 9.8')).toBe('Critical');
    });

    it('maps 7.0-8.9 to High', () => {
      expect(normalizeSeverity('7.0')).toBe('High');
      expect(normalizeSeverity('8.9')).toBe('High');
    });

    it('maps 4.0-6.9 to Medium', () => {
      expect(normalizeSeverity('4.0')).toBe('Medium');
      expect(normalizeSeverity('6.9')).toBe('Medium');
    });

    it('maps 0.1-3.9 to Low', () => {
      expect(normalizeSeverity('0.1')).toBe('Low');
      expect(normalizeSeverity('3.9')).toBe('Low');
    });

    it('maps 0 to Informational', () => {
      // Note: 0 doesn't match >= 0.1 so falls through
      expect(normalizeSeverity('0')).toBe('Informational');
    });
  });

  describe('text-based severity', () => {
    it('maps critical/crit', () => {
      expect(normalizeSeverity('Critical')).toBe('Critical');
      expect(normalizeSeverity('CRITICAL')).toBe('Critical');
      expect(normalizeSeverity('crit')).toBe('Critical');
    });

    it('maps high/severe', () => {
      expect(normalizeSeverity('High')).toBe('High');
      expect(normalizeSeverity('severe')).toBe('High');
    });

    it('maps medium/moderate/med', () => {
      expect(normalizeSeverity('Medium')).toBe('Medium');
      expect(normalizeSeverity('moderate')).toBe('Medium');
      expect(normalizeSeverity('med')).toBe('Medium');
    });

    it('maps low/minor', () => {
      expect(normalizeSeverity('Low')).toBe('Low');
      expect(normalizeSeverity('minor')).toBe('Low');
    });

    it('maps info/note to Informational', () => {
      expect(normalizeSeverity('Informational')).toBe('Informational');
      expect(normalizeSeverity('info')).toBe('Informational');
      expect(normalizeSeverity('note')).toBe('Informational');
    });

    it('defaults unknown to Medium', () => {
      expect(normalizeSeverity('unknown')).toBe('Medium');
      expect(normalizeSeverity('')).toBe('Medium');
    });
  });
});

// ─── canonicalizeEndpoint ────────────────────────────────────────

describe('canonicalizeEndpoint', () => {
  it('strips trailing slashes', () => {
    expect(canonicalizeEndpoint('/api/users/')).toBe('/api/users');
  });

  it('preserves root path', () => {
    expect(canonicalizeEndpoint('/')).toBe('/');
  });

  it('strips protocol and host from full URLs', () => {
    expect(canonicalizeEndpoint('https://example.com/api/users')).toBe('/api/users');
  });

  it('normalizes :param style parameters', () => {
    expect(canonicalizeEndpoint('/api/users/:userId')).toBe('/api/users/{param}');
  });

  it('normalizes {param} style parameters', () => {
    expect(canonicalizeEndpoint('/api/users/{userId}')).toBe('/api/users/{param}');
  });

  it('normalizes <param> style parameters', () => {
    expect(canonicalizeEndpoint('/api/users/<userId>')).toBe('/api/users/{param}');
  });

  it('normalizes numeric path segments (IDs)', () => {
    expect(canonicalizeEndpoint('/api/users/123')).toBe('/api/users/{param}');
    expect(canonicalizeEndpoint('/api/users/123/posts/456')).toBe('/api/users/{param}/posts/{param}');
  });

  it('lowercases the path', () => {
    expect(canonicalizeEndpoint('/API/Users')).toBe('/api/users');
  });

  it('handles query strings in URLs', () => {
    expect(canonicalizeEndpoint('https://example.com/api/search?q=test')).toBe('/api/search?q=test');
  });

  it('trims whitespace', () => {
    expect(canonicalizeEndpoint('  /api/users  ')).toBe('/api/users');
  });
});

// ─── classifyVulnerability ───────────────────────────────────────

describe('classifyVulnerability', () => {
  it('classifies SQL injection', () => {
    const result = classifyVulnerability('SQL Injection in login', '', '');
    expect(result.vulnClass).toBe('sql-injection');
    expect(result.cweId).toBe('CWE-89');
  });

  it('classifies command injection', () => {
    const result = classifyVulnerability('Remote Code Execution', '', '');
    expect(result.vulnClass).toBe('command-injection');
    expect(result.cweId).toBe('CWE-78');
  });

  it('classifies stored XSS', () => {
    const result = classifyVulnerability('Stored XSS in comments', '', '');
    expect(result.vulnClass).toBe('xss-stored');
    expect(result.cweId).toBe('CWE-79');
  });

  it('classifies DOM-based XSS', () => {
    const result = classifyVulnerability('DOM-based XSS', '', '');
    expect(result.vulnClass).toBe('xss-dom');
    expect(result.cweId).toBe('CWE-79');
  });

  it('classifies reflected XSS (generic)', () => {
    const result = classifyVulnerability('Cross-Site Scripting in search', '', '');
    expect(result.vulnClass).toBe('xss-reflected');
    expect(result.cweId).toBe('CWE-79');
  });

  it('classifies authentication bypass', () => {
    const result = classifyVulnerability('Authentication Bypass via token', '', '');
    expect(result.vulnClass).toBe('auth-bypass');
    expect(result.cweId).toBe('CWE-287');
  });

  it('classifies broken authentication', () => {
    const result = classifyVulnerability('Weak session management', '', '');
    expect(result.vulnClass).toBe('broken-auth');
    expect(result.cweId).toBe('CWE-287');
  });

  it('classifies SSRF', () => {
    const result = classifyVulnerability('Server-Side Request Forgery', '', '');
    expect(result.vulnClass).toBe('ssrf');
    expect(result.cweId).toBe('CWE-918');
  });

  it('classifies IDOR', () => {
    const result = classifyVulnerability('Insecure Direct Object Reference', '', '');
    expect(result.vulnClass).toBe('idor');
    expect(result.cweId).toBe('CWE-639');
  });

  it('classifies privilege escalation', () => {
    const result = classifyVulnerability('Privilege Escalation to admin', '', '');
    expect(result.vulnClass).toBe('privilege-escalation');
    expect(result.cweId).toBe('CWE-269');
  });

  it('classifies path traversal', () => {
    const result = classifyVulnerability('Path Traversal in file upload', '', '');
    expect(result.vulnClass).toBe('path-traversal');
    expect(result.cweId).toBe('CWE-22');
  });

  it('classifies open redirect', () => {
    const result = classifyVulnerability('Open Redirect in login', '', '');
    expect(result.vulnClass).toBe('open-redirect');
    expect(result.cweId).toBe('CWE-601');
  });

  it('classifies CSRF', () => {
    const result = classifyVulnerability('Cross-Site Request Forgery', '', '');
    expect(result.vulnClass).toBe('csrf');
    expect(result.cweId).toBe('CWE-352');
  });

  it('extracts explicit CWE IDs from content', () => {
    const result = classifyVulnerability('XSS', 'Related to CWE-79', '');
    expect(result.cweId).toBe('CWE-79');
  });

  it('falls back to source-based classification', () => {
    const result = classifyVulnerability('Unknown finding', '', 'injection-exploit');
    expect(result.vulnClass).toBe('sql-injection');
  });

  it('returns unknown for unclassifiable findings', () => {
    const result = classifyVulnerability('Something weird', 'no patterns here', 'mystery-agent');
    expect(result.vulnClass).toBe('unknown');
    expect(result.cweId).toBeNull();
  });
});

// ─── parseFindings ───────────────────────────────────────────────

describe('parseFindings', () => {
  it('parses a standard evidence file', () => {
    const content = `
### INJ-VULN-001: SQL Injection in /api/users
**Severity:** High
**Endpoint:** /api/users?id=
**Parameter:** id

Evidence details here...

### INJ-VULN-002: Command Injection in /api/exec
**Severity:** Critical
**Endpoint:** /api/exec
**Parameter:** cmd

More evidence...
`;
    const findings = parseFindings(content, 'injection-exploit');

    expect(findings).toHaveLength(2);

    expect(findings[0]!.id).toBe('INJ-VULN-001');
    expect(findings[0]!.title).toBe('SQL Injection in /api/users');
    expect(findings[0]!.severity).toBe('High');
    expect(findings[0]!.parameter).toBe('id');
    expect(findings[0]!.vulnClass).toBe('sql-injection');

    expect(findings[1]!.id).toBe('INJ-VULN-002');
    expect(findings[1]!.severity).toBe('Critical');
    expect(findings[1]!.vulnClass).toBe('command-injection');
  });

  it('returns empty array for content with no findings', () => {
    const findings = parseFindings('No vulnerabilities found.', 'test');
    expect(findings).toEqual([]);
  });

  it('extracts endpoint from title when not explicitly specified', () => {
    const content = `
### XSS-VULN-001: Reflected XSS in /search
**Severity:** Medium

Some evidence...
`;
    const findings = parseFindings(content, 'xss-exploit');
    expect(findings).toHaveLength(1);
    expect(findings[0]!.endpoint).toContain('/search');
  });

  it('defaults severity to Medium when not specified', () => {
    const content = `
### AUTH-VULN-001: Weak Password Policy
**Endpoint:** /api/auth

Evidence...
`;
    const findings = parseFindings(content, 'auth-exploit');
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('Medium');
  });
});

// ─── deduplicateFindings ─────────────────────────────────────────

describe('deduplicateFindings', () => {
  const logger = createMockLogger();

  function makeFinding(overrides: Partial<ParsedFinding>): ParsedFinding {
    return {
      id: 'TEST-VULN-001',
      title: 'Test Finding',
      source: 'test-agent',
      rawSeverity: 'High',
      severity: 'High' as CvssSeverity,
      endpoint: '/api/test',
      parameter: null,
      vulnClass: 'sql-injection',
      cweId: 'CWE-89',
      rawContent: 'test content',
      ...overrides,
    };
  }

  it('returns findings as-is when no duplicates', () => {
    const findings = [
      makeFinding({ id: 'F1', endpoint: '/api/a' }),
      makeFinding({ id: 'F2', endpoint: '/api/b' }),
    ];

    const merged = deduplicateFindings(findings, logger);
    expect(merged).toHaveLength(2);
  });

  it('merges findings with same endpoint + vulnClass + parameter', () => {
    const findings = [
      makeFinding({ id: 'F1', source: 'agent-a', severity: 'High' }),
      makeFinding({ id: 'F2', source: 'agent-b', severity: 'Critical' }),
    ];

    const merged = deduplicateFindings(findings, logger);
    expect(merged).toHaveLength(1);
    expect(merged[0]!.mergedIds).toEqual(['F1', 'F2']);
    expect(merged[0]!.sources).toContain('agent-a');
    expect(merged[0]!.sources).toContain('agent-b');
  });

  it('preserves highest severity when merging', () => {
    const findings = [
      makeFinding({ id: 'F1', severity: 'Medium' }),
      makeFinding({ id: 'F2', severity: 'Critical' }),
      makeFinding({ id: 'F3', severity: 'High' }),
    ];

    const merged = deduplicateFindings(findings, logger);
    expect(merged).toHaveLength(1);
    expect(merged[0]!.severity).toBe('Critical');
  });

  it('does not merge findings with different parameters', () => {
    const findings = [
      makeFinding({ id: 'F1', parameter: 'id' }),
      makeFinding({ id: 'F2', parameter: 'name' }),
    ];

    const merged = deduplicateFindings(findings, logger);
    expect(merged).toHaveLength(2);
  });

  it('sorts results by severity (highest first)', () => {
    const findings = [
      makeFinding({ id: 'F1', endpoint: '/a', severity: 'Low' }),
      makeFinding({ id: 'F2', endpoint: '/b', severity: 'Critical' }),
      makeFinding({ id: 'F3', endpoint: '/c', severity: 'Medium' }),
    ];

    const merged = deduplicateFindings(findings, logger);
    expect(merged[0]!.severity).toBe('Critical');
    expect(merged[1]!.severity).toBe('Medium');
    expect(merged[2]!.severity).toBe('Low');
  });

  it('includes root cause and remediation from the vuln class', () => {
    const findings = [makeFinding({ vulnClass: 'sql-injection' })];
    const merged = deduplicateFindings(findings, logger);
    expect(merged[0]!.rootCause).toContain('parameterized queries');
    expect(merged[0]!.remediation).toContain('parameterized queries');
  });
});

// ─── computeFindingSummary ───────────────────────────────────────

describe('computeFindingSummary', () => {
  it('counts findings by severity', () => {
    const merged = [
      { severity: 'Critical' as CvssSeverity },
      { severity: 'Critical' as CvssSeverity },
      { severity: 'High' as CvssSeverity },
      { severity: 'Medium' as CvssSeverity },
      { severity: 'Low' as CvssSeverity },
      { severity: 'Informational' as CvssSeverity },
    ] as any;

    const summary = computeFindingSummary(merged, 10);
    expect(summary.total).toBe(6);
    expect(summary.critical).toBe(2);
    expect(summary.high).toBe(1);
    expect(summary.medium).toBe(1);
    expect(summary.low).toBe(1);
    expect(summary.informational).toBe(1);
    expect(summary.deduplicated).toBe(4); // 10 parsed - 6 merged
  });

  it('handles empty findings', () => {
    const summary = computeFindingSummary([], 0);
    expect(summary.total).toBe(0);
    expect(summary.deduplicated).toBe(0);
  });
});

// ─── renderSeveritySummaryTable ──────────────────────────────────

describe('renderSeveritySummaryTable', () => {
  it('renders a markdown table', () => {
    const summary = {
      total: 5,
      critical: 1,
      high: 2,
      medium: 1,
      low: 1,
      informational: 0,
      deduplicated: 3,
    };

    const table = renderSeveritySummaryTable(summary);
    expect(table).toContain('## Finding Summary');
    expect(table).toContain('| Severity | Count |');
    expect(table).toContain('Critical | 1');
    expect(table).toContain('High | 2');
    expect(table).toContain('**Total** | **5**');
    expect(table).toContain('3 duplicate finding(s) were merged');
  });

  it('omits dedup message when no duplicates', () => {
    const summary = {
      total: 2,
      critical: 1,
      high: 1,
      medium: 0,
      low: 0,
      informational: 0,
      deduplicated: 0,
    };

    const table = renderSeveritySummaryTable(summary);
    expect(table).not.toContain('duplicate');
  });
});

// ─── processAndDeduplicateFindings (integration) ─────────────────

describe('processAndDeduplicateFindings', () => {
  const logger = createMockLogger();

  it('returns empty results for empty input', () => {
    const result = processAndDeduplicateFindings([], logger);
    expect(result.mergedFindings).toEqual([]);
    expect(result.summary.total).toBe(0);
    expect(result.deduplicatedContent).toBe('');
  });

  it('processes multiple evidence sections end-to-end', () => {
    const sections = [
      {
        source: 'injection-exploit',
        content: `
### INJ-VULN-001: SQL Injection in /api/users
**Severity:** Critical
**Endpoint:** /api/users?id=
**Parameter:** id

Evidence from injection agent...
`,
      },
      {
        source: 'xss-exploit',
        content: `
### XSS-VULN-001: Reflected XSS in /api/search
**Severity:** High
**Endpoint:** /api/search?q=
**Parameter:** q

Evidence from XSS agent...
`,
      },
    ];

    const result = processAndDeduplicateFindings(sections, logger);
    expect(result.mergedFindings).toHaveLength(2);
    expect(result.summary.total).toBe(2);
    expect(result.summary.critical).toBe(1);
    expect(result.summary.high).toBe(1);
    expect(result.deduplicatedContent).toContain('INJ-VULN-001');
    expect(result.deduplicatedContent).toContain('XSS-VULN-001');
    expect(result.summaryTable).toContain('## Finding Summary');
  });

  it('deduplicates cross-agent findings for same endpoint', () => {
    const sections = [
      {
        source: 'injection-exploit',
        content: `
### INJ-VULN-001: SQL Injection in /api/users
**Severity:** High
**Endpoint:** /api/users
**Parameter:** id

Evidence A...
`,
      },
      {
        source: 'authz-exploit',
        content: `
### AUTHZ-VULN-001: SQL Injection in /api/users
**Severity:** Critical
**Endpoint:** /api/users
**Parameter:** id

Evidence B...
`,
      },
    ];

    const result = processAndDeduplicateFindings(sections, logger);
    // Should be merged into 1 finding
    expect(result.mergedFindings).toHaveLength(1);
    expect(result.mergedFindings[0]!.severity).toBe('Critical'); // highest wins
    expect(result.mergedFindings[0]!.mergedIds).toHaveLength(2);
    expect(result.summary.deduplicated).toBe(1);
  });
});
