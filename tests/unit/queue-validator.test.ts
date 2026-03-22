import { describe, it, expect } from 'vitest';
import { validateQueueJson } from '../../mcp-server/src/validation/queue-validator.js';
import { readFileSync } from 'fs';
import { join } from 'path';

const fixturesDir = join(import.meta.dirname, '..', 'fixtures');

function readFixture(name: string): string {
  return readFileSync(join(fixturesDir, name), 'utf8');
}

describe('QueueValidator', () => {
  // ── Structure Validation ────────────────────────────────────

  it('accepts valid queue with vulnerabilities', () => {
    const result = validateQueueJson(readFixture('valid-queue.json'));
    expect(result.valid).toBe(true);
    expect(result.data).toBeDefined();
    expect(result.data!.vulnerabilities).toHaveLength(2);
  });

  it('accepts empty vulnerabilities array', () => {
    const result = validateQueueJson(readFixture('empty-queue.json'));
    expect(result.valid).toBe(true);
    expect(result.data!.vulnerabilities).toHaveLength(0);
  });

  it('rejects queue with missing vulnerabilities property', () => {
    const result = validateQueueJson(readFixture('invalid-queue-missing-vulns.json'));
    expect(result.valid).toBe(false);
    expect(result.message).toContain("Missing 'vulnerabilities' property");
  });

  it('rejects non-JSON input', () => {
    const result = validateQueueJson('not valid json {{{');
    expect(result.valid).toBe(false);
    expect(result.message).toContain('Invalid JSON');
  });

  it('rejects null input', () => {
    const result = validateQueueJson('null');
    expect(result.valid).toBe(false);
    expect(result.message).toContain('Expected an object');
  });

  it('rejects array input (missing vulnerabilities property)', () => {
    const result = validateQueueJson('[]');
    expect(result.valid).toBe(false);
    expect(result.message).toContain("Missing 'vulnerabilities' property");
  });

  it('rejects non-array vulnerabilities', () => {
    const result = validateQueueJson('{"vulnerabilities": "not-array"}');
    expect(result.valid).toBe(false);
    expect(result.message).toContain("'vulnerabilities' must be an array");
  });

  // ── Field-Level Validation (Warnings) ───────────────────────

  it('warns on missing recommended fields', () => {
    const result = validateQueueJson(JSON.stringify({
      vulnerabilities: [{ some_field: 'value' }],
    }));
    expect(result.valid).toBe(true); // Backward compatible — still valid
    expect(result.warnings).toBeDefined();
    expect(result.warnings!.some(w => w.includes("Missing recommended field 'id'"))).toBe(true);
    expect(result.warnings!.some(w => w.includes("Missing recommended field 'endpoint'"))).toBe(true);
  });

  it('warns on invalid confidence values', () => {
    const result = validateQueueJson(JSON.stringify({
      vulnerabilities: [{
        id: 'TEST-001',
        vulnerability_type: 'SQLi',
        endpoint: '/api/test',
        method: 'GET',
        confidence: 'very_high', // invalid
        source_file: 'test.js',
        externally_exploitable: true,
      }],
    }));
    expect(result.valid).toBe(true);
    expect(result.warnings).toBeDefined();
    expect(result.warnings!.some(w => w.includes("Invalid confidence 'very_high'"))).toBe(true);
  });

  it('warns on duplicate IDs', () => {
    const result = validateQueueJson(JSON.stringify({
      vulnerabilities: [
        { id: 'DUP-001', vulnerability_type: 'SQLi', endpoint: '/a', method: 'GET', confidence: 'high', source_file: 'a.js', externally_exploitable: true },
        { id: 'DUP-001', vulnerability_type: 'SQLi', endpoint: '/b', method: 'POST', confidence: 'medium', source_file: 'b.js', externally_exploitable: true },
      ],
    }));
    expect(result.valid).toBe(true);
    expect(result.warnings).toBeDefined();
    expect(result.warnings!.some(w => w.includes("Duplicate ID 'DUP-001'"))).toBe(true);
  });

  it('no warnings for fully compliant queue', () => {
    const result = validateQueueJson(readFixture('valid-queue.json'));
    expect(result.valid).toBe(true);
    expect(result.warnings).toBeUndefined();
  });

  it('validates prerequisite_findings must be array', () => {
    const result = validateQueueJson(JSON.stringify({
      vulnerabilities: [{
        id: 'CHAIN-001',
        vulnerability_type: 'SQLi',
        endpoint: '/api/test',
        method: 'GET',
        confidence: 'high',
        source_file: 'test.js',
        externally_exploitable: true,
        prerequisite_findings: 'AUTH-001', // should be array
      }],
    }));
    expect(result.valid).toBe(true);
    expect(result.warnings).toBeDefined();
    expect(result.warnings!.some(w => w.includes("'prerequisite_findings' must be an array"))).toBe(true);
  });

  it('accepts valid prerequisite_findings array', () => {
    const result = validateQueueJson(JSON.stringify({
      vulnerabilities: [{
        id: 'CHAIN-001',
        vulnerability_type: 'SQLi',
        endpoint: '/api/test',
        method: 'GET',
        confidence: 'high',
        source_file: 'test.js',
        externally_exploitable: true,
        prerequisite_findings: ['AUTH-001', 'IDOR-002'],
      }],
    }));
    expect(result.valid).toBe(true);
    expect(result.warnings).toBeUndefined();
  });
});
