import { describe, it, expect } from 'vitest';
import { ok, err, isOk, isErr, type Result } from '../../src/types/result.js';

describe('Result type', () => {
  describe('ok()', () => {
    it('creates a success result with a value', () => {
      const result = ok(42);
      expect(result.ok).toBe(true);
      expect(result.value).toBe(42);
    });

    it('works with string values', () => {
      const result = ok('hello');
      expect(result.ok).toBe(true);
      expect(result.value).toBe('hello');
    });

    it('works with object values', () => {
      const data = { name: 'test', count: 5 };
      const result = ok(data);
      expect(result.ok).toBe(true);
      expect(result.value).toEqual(data);
    });

    it('works with null value', () => {
      const result = ok(null);
      expect(result.ok).toBe(true);
      expect(result.value).toBeNull();
    });

    it('works with undefined value', () => {
      const result = ok(undefined);
      expect(result.ok).toBe(true);
      expect(result.value).toBeUndefined();
    });
  });

  describe('err()', () => {
    it('creates an error result', () => {
      const result = err('something went wrong');
      expect(result.ok).toBe(false);
      expect(result.error).toBe('something went wrong');
    });

    it('works with Error objects', () => {
      const error = new Error('fail');
      const result = err(error);
      expect(result.ok).toBe(false);
      expect(result.error).toBe(error);
      expect(result.error.message).toBe('fail');
    });

    it('works with structured error objects', () => {
      const error = { code: 'NOT_FOUND', message: 'Item not found' };
      const result = err(error);
      expect(result.ok).toBe(false);
      expect(result.error).toEqual(error);
    });
  });

  describe('isOk()', () => {
    it('returns true for ok results', () => {
      const result: Result<number, string> = ok(42);
      expect(isOk(result)).toBe(true);
    });

    it('returns false for err results', () => {
      const result: Result<number, string> = err('bad');
      expect(isOk(result)).toBe(false);
    });
  });

  describe('isErr()', () => {
    it('returns true for err results', () => {
      const result: Result<number, string> = err('bad');
      expect(isErr(result)).toBe(true);
    });

    it('returns false for ok results', () => {
      const result: Result<number, string> = ok(42);
      expect(isErr(result)).toBe(false);
    });
  });

  describe('type narrowing', () => {
    it('narrows to Ok type after isOk check', () => {
      const result: Result<number, string> = ok(42);
      if (isOk(result)) {
        // TypeScript should allow accessing .value here
        expect(result.value).toBe(42);
      } else {
        throw new Error('Should not reach here');
      }
    });

    it('narrows to Err type after isErr check', () => {
      const result: Result<number, string> = err('bad');
      if (isErr(result)) {
        // TypeScript should allow accessing .error here
        expect(result.error).toBe('bad');
      } else {
        throw new Error('Should not reach here');
      }
    });
  });
});
