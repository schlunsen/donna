// Donna - Continuous AI Pentesting Platform
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Deliverable Type Definitions
 *
 * Maps deliverable types to their filenames and defines validation requirements.
 * Must match the exact mappings from tools/save_deliverable.js.
 */

export enum DeliverableType {
  // Pre-recon agent
  CODE_ANALYSIS = 'CODE_ANALYSIS',

  // Recon agent
  RECON = 'RECON',

  // Vulnerability analysis agents
  INJECTION_ANALYSIS = 'INJECTION_ANALYSIS',
  INJECTION_QUEUE = 'INJECTION_QUEUE',

  XSS_ANALYSIS = 'XSS_ANALYSIS',
  XSS_QUEUE = 'XSS_QUEUE',

  AUTH_ANALYSIS = 'AUTH_ANALYSIS',
  AUTH_QUEUE = 'AUTH_QUEUE',

  AUTHZ_ANALYSIS = 'AUTHZ_ANALYSIS',
  AUTHZ_QUEUE = 'AUTHZ_QUEUE',

  SSRF_ANALYSIS = 'SSRF_ANALYSIS',
  SSRF_QUEUE = 'SSRF_QUEUE',

  // Exploitation agents
  INJECTION_EVIDENCE = 'INJECTION_EVIDENCE',
  XSS_EVIDENCE = 'XSS_EVIDENCE',
  AUTH_EVIDENCE = 'AUTH_EVIDENCE',
  AUTHZ_EVIDENCE = 'AUTHZ_EVIDENCE',
  SSRF_EVIDENCE = 'SSRF_EVIDENCE',
}

/**
 * Hard-coded filename mappings from agent prompts
 * Must match tools/save_deliverable.js exactly
 */
export const DELIVERABLE_FILENAMES: Record<DeliverableType, string> = {
  [DeliverableType.CODE_ANALYSIS]: 'code_analysis_deliverable.md',
  [DeliverableType.RECON]: 'recon_deliverable.md',
  [DeliverableType.INJECTION_ANALYSIS]: 'injection_analysis_deliverable.md',
  [DeliverableType.INJECTION_QUEUE]: 'injection_exploitation_queue.json',
  [DeliverableType.XSS_ANALYSIS]: 'xss_analysis_deliverable.md',
  [DeliverableType.XSS_QUEUE]: 'xss_exploitation_queue.json',
  [DeliverableType.AUTH_ANALYSIS]: 'auth_analysis_deliverable.md',
  [DeliverableType.AUTH_QUEUE]: 'auth_exploitation_queue.json',
  [DeliverableType.AUTHZ_ANALYSIS]: 'authz_analysis_deliverable.md',
  [DeliverableType.AUTHZ_QUEUE]: 'authz_exploitation_queue.json',
  [DeliverableType.SSRF_ANALYSIS]: 'ssrf_analysis_deliverable.md',
  [DeliverableType.SSRF_QUEUE]: 'ssrf_exploitation_queue.json',
  [DeliverableType.INJECTION_EVIDENCE]: 'injection_exploitation_evidence.md',
  [DeliverableType.XSS_EVIDENCE]: 'xss_exploitation_evidence.md',
  [DeliverableType.AUTH_EVIDENCE]: 'auth_exploitation_evidence.md',
  [DeliverableType.AUTHZ_EVIDENCE]: 'authz_exploitation_evidence.md',
  [DeliverableType.SSRF_EVIDENCE]: 'ssrf_exploitation_evidence.md',
};

/**
 * Queue types that require JSON validation
 */
export const QUEUE_TYPES: DeliverableType[] = [
  DeliverableType.INJECTION_QUEUE,
  DeliverableType.XSS_QUEUE,
  DeliverableType.AUTH_QUEUE,
  DeliverableType.AUTHZ_QUEUE,
  DeliverableType.SSRF_QUEUE,
];

/**
 * Type guard to check if a deliverable type is a queue
 */
export function isQueueType(type: string): boolean {
  return QUEUE_TYPES.includes(type as DeliverableType);
}

/**
 * Vulnerability queue structure
 */
export interface VulnerabilityQueue {
  vulnerabilities: VulnerabilityItem[];
}

export interface VulnerabilityItem {
  [key: string]: unknown;
}

// ── Typed Queue Schemas (Issue #3) ──────────────────────────────

/**
 * Base fields required for ALL queue entries regardless of vulnerability type.
 * Provides consistent structure for exploitation agents.
 */
export interface BaseQueueEntry {
  /** Unique ID within the queue (e.g., "SQLI-001", "XSS-003") */
  id: string;
  /** Vulnerability class */
  vulnerability_type: string;
  /** Target endpoint URL or path */
  endpoint: string;
  /** HTTP method */
  method: string;
  /** Confidence level */
  confidence: 'high' | 'medium' | 'low';
  /** Source file where the vulnerability was found */
  source_file: string;
  /** Whether the vulnerability is externally exploitable */
  externally_exploitable: boolean;
  /** Optional prerequisite finding IDs for vulnerability chaining */
  prerequisite_findings?: string[];
  /** Optional chain description explaining the dependency */
  chain_description?: string;
  /** Optional severity multiplier when chained (default: 1.0) */
  chain_severity_multiplier?: number;
}

/**
 * Injection-specific queue entry (SQLi, CMDi, SSTI, XXE)
 */
export interface InjectionQueueEntry extends BaseQueueEntry {
  injection_type: 'sqli' | 'cmdi' | 'ssti' | 'xxe' | 'path_traversal' | 'deserialization';
  /** Sink function where injection occurs */
  sink_function: string;
  /** Vulnerable parameter name */
  vulnerable_parameter: string;
  /** Whether sanitization is present */
  sanitization_present: boolean;
  /** Bypass technique if sanitization exists */
  sanitization_bypass: string | null;
}

/**
 * XSS-specific queue entry
 */
export interface XssQueueEntry extends BaseQueueEntry {
  xss_type: 'reflected' | 'stored' | 'dom';
  /** Where the payload renders */
  output_context: 'html_body' | 'html_attribute' | 'javascript' | 'url' | 'css';
  /** Source input parameter */
  source: string;
  /** Additional source detail */
  source_detail?: string;
}

/**
 * Auth-specific queue entry
 */
export interface AuthQueueEntry extends BaseQueueEntry {
  auth_weakness: string;
  /** Endpoint requiring authentication */
  source_endpoint: string;
}

/**
 * SSRF-specific queue entry
 */
export interface SsrfQueueEntry extends BaseQueueEntry {
  /** Vulnerable parameter accepting URLs */
  vulnerable_parameter: string;
  /** Endpoint accepting the URL */
  source_endpoint: string;
  /** URL schemes that may be accepted */
  url_schemes?: string[];
}

/**
 * Authz-specific queue entry
 */
export interface AuthzQueueEntry extends BaseQueueEntry {
  authz_weakness: string;
  /** Resource or endpoint with broken access control */
  target_resource: string;
  /** Required privilege level to access */
  required_privilege: string;
}

/**
 * Payload execution scope for exploitation context.
 */
export interface PayloadExecutionScope {
  /** Required encoding (e.g., "double-url-encode", "base64") */
  encoding_required?: string[];
  /** Ordered request sequence for multi-step exploitation */
  request_sequence?: string[];
  /** Required HTTP headers */
  required_headers?: Record<string, string>;
  /** Authentication context needed */
  authentication_context?: string;
}

/**
 * Required fields for BaseQueueEntry validation.
 * Used by queue-validator.ts for save-time field checks.
 */
export const BASE_QUEUE_REQUIRED_FIELDS = [
  'id',
  'vulnerability_type',
  'endpoint',
  'method',
  'confidence',
  'source_file',
  'externally_exploitable',
] as const;

export const VALID_CONFIDENCE_VALUES = ['high', 'medium', 'low'] as const;
