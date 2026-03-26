import { describe, it, expect } from 'vitest';
import {
  matchesBillingTextPattern,
  matchesBillingApiPattern,
  isSpendingCapBehavior,
  BILLING_TEXT_PATTERNS,
  BILLING_API_PATTERNS,
} from '../../src/utils/billing-detection.js';

describe('matchesBillingTextPattern', () => {
  it('detects spending cap messages', () => {
    expect(matchesBillingTextPattern('Your spending cap has been reached')).toBe(true);
  });

  it('detects spending limit messages', () => {
    expect(matchesBillingTextPattern('You have hit your spending limit')).toBe(true);
  });

  it('detects cap reached messages', () => {
    expect(matchesBillingTextPattern('The cap reached for your account')).toBe(true);
  });

  it('detects budget exceeded messages', () => {
    expect(matchesBillingTextPattern('Your budget exceeded the threshold')).toBe(true);
  });

  it('detects usage limit messages', () => {
    expect(matchesBillingTextPattern('usage limit reached')).toBe(true);
  });

  it('detects resets messages', () => {
    expect(matchesBillingTextPattern('Your limit resets tomorrow')).toBe(true);
  });

  it('is case-insensitive', () => {
    expect(matchesBillingTextPattern('SPENDING CAP reached')).toBe(true);
  });

  it('returns false for non-billing text', () => {
    expect(matchesBillingTextPattern('SQL injection found in /api/users')).toBe(false);
  });

  it('returns false for empty string', () => {
    expect(matchesBillingTextPattern('')).toBe(false);
  });

  // Ensure all defined patterns are actually matchable
  for (const pattern of BILLING_TEXT_PATTERNS) {
    it(`matches the defined pattern: "${pattern}"`, () => {
      expect(matchesBillingTextPattern(pattern)).toBe(true);
    });
  }
});

describe('matchesBillingApiPattern', () => {
  it('detects billing_error', () => {
    expect(matchesBillingApiPattern('billing_error: account suspended')).toBe(true);
  });

  it('detects credit balance too low', () => {
    expect(matchesBillingApiPattern('credit balance is too low')).toBe(true);
  });

  it('detects insufficient credits', () => {
    expect(matchesBillingApiPattern('insufficient credits on your account')).toBe(true);
  });

  it('detects plans & billing prompt', () => {
    expect(matchesBillingApiPattern('please visit plans & billing')).toBe(true);
    expect(matchesBillingApiPattern('please visit plans and billing')).toBe(true);
  });

  it('detects quota exceeded', () => {
    expect(matchesBillingApiPattern('quota exceeded for this month')).toBe(true);
  });

  it('is case-insensitive', () => {
    expect(matchesBillingApiPattern('BILLING_ERROR')).toBe(true);
  });

  it('returns false for non-billing API errors', () => {
    expect(matchesBillingApiPattern('invalid_request_error: prompt too long')).toBe(false);
  });

  // Ensure all defined patterns are actually matchable
  for (const pattern of BILLING_API_PATTERNS) {
    it(`matches the defined pattern: "${pattern}"`, () => {
      expect(matchesBillingApiPattern(pattern)).toBe(true);
    });
  }
});

describe('isSpendingCapBehavior', () => {
  it('detects spending cap: low turns + zero cost + billing text', () => {
    expect(isSpendingCapBehavior(1, 0, 'Your spending cap has been reached')).toBe(true);
  });

  it('detects with exactly 2 turns', () => {
    expect(isSpendingCapBehavior(2, 0, 'Your spending limit resets tomorrow')).toBe(true);
  });

  it('returns false if turns > 2 (legitimate work)', () => {
    expect(isSpendingCapBehavior(3, 0, 'spending cap')).toBe(false);
  });

  it('returns false if cost > 0 (legitimate work)', () => {
    expect(isSpendingCapBehavior(1, 0.01, 'spending cap')).toBe(false);
  });

  it('returns false if text does not match billing patterns', () => {
    expect(isSpendingCapBehavior(1, 0, 'Agent completed successfully')).toBe(false);
  });

  it('returns false for normal short results', () => {
    expect(isSpendingCapBehavior(1, 0, 'No vulnerabilities found')).toBe(false);
  });

  it('requires all three signals to be present', () => {
    // Only turns + cost match, text doesn't
    expect(isSpendingCapBehavior(1, 0, 'normal result')).toBe(false);
    // Only turns + text match, cost doesn't
    expect(isSpendingCapBehavior(1, 0.05, 'spending cap reached')).toBe(false);
    // Only cost + text match, turns don't
    expect(isSpendingCapBehavior(5, 0, 'spending cap reached')).toBe(false);
  });
});
