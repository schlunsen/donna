// Donna - Continuous AI Pentesting Platform
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Queue Validator
 *
 * Validates JSON structure for vulnerability queue files.
 * Ported from tools/save_deliverable.js (lines 56-75).
 */

import type { VulnerabilityQueue } from '../types/deliverables.js';
import { BASE_QUEUE_REQUIRED_FIELDS, VALID_CONFIDENCE_VALUES } from '../types/deliverables.js';

export interface ValidationResult {
  valid: boolean;
  message?: string | undefined;
  warnings?: string[] | undefined;
  data?: VulnerabilityQueue | undefined;
}

/**
 * Validate JSON structure for queue files.
 *
 * Two-level validation:
 * 1. Structure: must have `{"vulnerabilities": [...]}` (hard fail)
 * 2. Fields: each item should have base required fields (warnings, not failures)
 *
 * Field validation is lenient (warnings) to maintain backward compatibility
 * while guiding agents toward the standardized schema.
 */
export function validateQueueJson(content: string): ValidationResult {
  try {
    const parsed = JSON.parse(content) as unknown;

    // Type guard for the parsed result
    if (typeof parsed !== 'object' || parsed === null) {
      return {
        valid: false,
        message: `Invalid queue structure: Expected an object. Got: ${typeof parsed}`,
      };
    }

    const obj = parsed as Record<string, unknown>;

    // Queue files must have a 'vulnerabilities' array
    if (!('vulnerabilities' in obj)) {
      return {
        valid: false,
        message: `Invalid queue structure: Missing 'vulnerabilities' property. Expected: {"vulnerabilities": [...]}`,
      };
    }

    if (!Array.isArray(obj.vulnerabilities)) {
      return {
        valid: false,
        message: `Invalid queue structure: 'vulnerabilities' must be an array. Expected: {"vulnerabilities": [...]}`,
      };
    }

    // Field-level validation (warnings, not failures — backward compatible)
    const warnings: string[] = [];
    const seenIds = new Set<string>();

    for (let i = 0; i < obj.vulnerabilities.length; i++) {
      const item = obj.vulnerabilities[i] as Record<string, unknown>;
      if (typeof item !== 'object' || item === null) {
        warnings.push(`vulnerabilities[${i}]: Expected an object, got ${typeof item}`);
        continue;
      }

      // Check required base fields
      for (const field of BASE_QUEUE_REQUIRED_FIELDS) {
        if (!(field in item)) {
          warnings.push(`vulnerabilities[${i}]: Missing recommended field '${field}'`);
        }
      }

      // Validate confidence values
      if ('confidence' in item && typeof item.confidence === 'string') {
        if (!(VALID_CONFIDENCE_VALUES as readonly string[]).includes(item.confidence)) {
          warnings.push(
            `vulnerabilities[${i}]: Invalid confidence '${item.confidence}', expected: ${VALID_CONFIDENCE_VALUES.join(', ')}`
          );
        }
      }

      // Check for duplicate IDs
      if ('id' in item && typeof item.id === 'string') {
        if (seenIds.has(item.id)) {
          warnings.push(`vulnerabilities[${i}]: Duplicate ID '${item.id}'`);
        }
        seenIds.add(item.id);
      }

      // Validate prerequisite_findings references (if present)
      if ('prerequisite_findings' in item) {
        if (!Array.isArray(item.prerequisite_findings)) {
          warnings.push(`vulnerabilities[${i}]: 'prerequisite_findings' must be an array`);
        }
      }
    }

    return {
      valid: true,
      warnings: warnings.length > 0 ? warnings : undefined,
      data: parsed as VulnerabilityQueue,
    };
  } catch (error) {
    return {
      valid: false,
      message: `Invalid JSON: ${error instanceof Error ? error.message : String(error)}`,
    };
  }
}
