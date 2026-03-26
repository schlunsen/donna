import { describe, it, expect } from 'vitest';
import {
  PentestError,
  isRetryableError,
  classifyErrorForTemporal,
} from '../../src/services/error-handling.js';
import { ErrorCode } from '../../src/types/errors.js';

describe('PentestError', () => {
  it('creates error with required fields', () => {
    const error = new PentestError('something broke', 'network', true);
    expect(error.message).toBe('something broke');
    expect(error.type).toBe('network');
    expect(error.retryable).toBe(true);
    expect(error.name).toBe('PentestError');
    expect(error.timestamp).toBeDefined();
    expect(error).toBeInstanceOf(Error);
  });

  it('defaults retryable to false', () => {
    const error = new PentestError('bad config', 'config');
    expect(error.retryable).toBe(false);
  });

  it('includes context and error code', () => {
    const error = new PentestError(
      'config not found',
      'config',
      false,
      { configPath: '/etc/donna.yaml' },
      ErrorCode.CONFIG_NOT_FOUND
    );
    expect(error.context).toEqual({ configPath: '/etc/donna.yaml' });
    expect(error.code).toBe(ErrorCode.CONFIG_NOT_FOUND);
  });

  it('has an ISO timestamp', () => {
    const error = new PentestError('test', 'unknown');
    // Should be a valid ISO date string
    expect(() => new Date(error.timestamp)).not.toThrow();
    expect(new Date(error.timestamp).toISOString()).toBe(error.timestamp);
  });
});

describe('isRetryableError', () => {
  describe('retryable errors', () => {
    const retryableCases = [
      'network error occurred',
      'connection refused',
      'request timeout',
      'ECONNRESET',
      'ENOTFOUND',
      'ECONNREFUSED',
      'rate limit exceeded',
      '429 Too Many Requests',
      'too many requests',
      'server error',
      'internal server error',
      'service unavailable',
      'bad gateway',
      'mcp server disconnected',
      'model unavailable',
      'service temporarily unavailable',
      'api error encountered',
      'agent terminated',
      'max turns reached',
      'maximum turns exceeded',
    ];

    for (const msg of retryableCases) {
      it(`considers "${msg}" retryable`, () => {
        expect(isRetryableError(new Error(msg))).toBe(true);
      });
    }
  });

  describe('non-retryable errors', () => {
    const nonRetryableCases = [
      'authentication failed',
      'invalid prompt format',
      'out of memory',
      'permission denied',
      'session limit reached',
      'invalid api key',
    ];

    for (const msg of nonRetryableCases) {
      it(`considers "${msg}" non-retryable`, () => {
        expect(isRetryableError(new Error(msg))).toBe(false);
      });
    }
  });

  it('defaults to non-retryable for unknown errors', () => {
    expect(isRetryableError(new Error('some random error'))).toBe(false);
  });

  it('non-retryable patterns take priority over retryable', () => {
    // "authentication" is non-retryable even though "network" substring isn't present
    expect(isRetryableError(new Error('authentication timeout'))).toBe(false);
  });
});

describe('classifyErrorForTemporal', () => {
  describe('code-based classification (PentestError with ErrorCode)', () => {
    it('classifies SPENDING_CAP_REACHED as BillingError (retryable)', () => {
      const error = new PentestError('cap hit', 'billing', false, {}, ErrorCode.SPENDING_CAP_REACHED);
      const result = classifyErrorForTemporal(error);
      expect(result.type).toBe('BillingError');
      expect(result.retryable).toBe(true);
    });

    it('classifies INSUFFICIENT_CREDITS as BillingError (retryable)', () => {
      const error = new PentestError('no credits', 'billing', false, {}, ErrorCode.INSUFFICIENT_CREDITS);
      const result = classifyErrorForTemporal(error);
      expect(result.type).toBe('BillingError');
      expect(result.retryable).toBe(true);
    });

    it('classifies API_RATE_LIMITED as RateLimitError (retryable)', () => {
      const error = new PentestError('rate limited', 'billing', false, {}, ErrorCode.API_RATE_LIMITED);
      const result = classifyErrorForTemporal(error);
      expect(result.type).toBe('RateLimitError');
      expect(result.retryable).toBe(true);
    });

    it('classifies CONFIG_NOT_FOUND as ConfigurationError (non-retryable)', () => {
      const error = new PentestError('missing', 'config', false, {}, ErrorCode.CONFIG_NOT_FOUND);
      const result = classifyErrorForTemporal(error);
      expect(result.type).toBe('ConfigurationError');
      expect(result.retryable).toBe(false);
    });

    it('classifies CONFIG_VALIDATION_FAILED as ConfigurationError (non-retryable)', () => {
      const error = new PentestError('invalid', 'config', false, {}, ErrorCode.CONFIG_VALIDATION_FAILED);
      const result = classifyErrorForTemporal(error);
      expect(result.type).toBe('ConfigurationError');
      expect(result.retryable).toBe(false);
    });

    it('classifies GIT_CHECKPOINT_FAILED as GitError (non-retryable)', () => {
      const error = new PentestError('git fail', 'filesystem', false, {}, ErrorCode.GIT_CHECKPOINT_FAILED);
      const result = classifyErrorForTemporal(error);
      expect(result.type).toBe('GitError');
      expect(result.retryable).toBe(false);
    });

    it('classifies OUTPUT_VALIDATION_FAILED as retryable', () => {
      const error = new PentestError('no output', 'validation', false, {}, ErrorCode.OUTPUT_VALIDATION_FAILED);
      const result = classifyErrorForTemporal(error);
      expect(result.type).toBe('OutputValidationError');
      expect(result.retryable).toBe(true);
    });

    it('classifies AGENT_EXECUTION_FAILED using the error retryable flag', () => {
      const retryable = new PentestError('fail', 'validation', true, {}, ErrorCode.AGENT_EXECUTION_FAILED);
      expect(classifyErrorForTemporal(retryable).retryable).toBe(true);

      const nonRetryable = new PentestError('fail', 'validation', false, {}, ErrorCode.AGENT_EXECUTION_FAILED);
      expect(classifyErrorForTemporal(nonRetryable).retryable).toBe(false);
    });

    it('classifies REPO_NOT_FOUND as ConfigurationError (non-retryable)', () => {
      const error = new PentestError('no repo', 'config', false, {}, ErrorCode.REPO_NOT_FOUND);
      const result = classifyErrorForTemporal(error);
      expect(result.type).toBe('ConfigurationError');
      expect(result.retryable).toBe(false);
    });

    it('classifies AUTH_FAILED as AuthenticationError (non-retryable)', () => {
      const error = new PentestError('auth bad', 'config', false, {}, ErrorCode.AUTH_FAILED);
      const result = classifyErrorForTemporal(error);
      expect(result.type).toBe('AuthenticationError');
      expect(result.retryable).toBe(false);
    });
  });

  describe('string-based classification (fallback for external errors)', () => {
    it('classifies billing errors as retryable', () => {
      const result = classifyErrorForTemporal(new Error('billing_error: credit balance is too low'));
      expect(result.type).toBe('BillingError');
      expect(result.retryable).toBe(true);
    });

    it('classifies spending cap messages as billing errors', () => {
      const result = classifyErrorForTemporal(new Error('Your spending limit has been reached'));
      expect(result.type).toBe('BillingError');
      expect(result.retryable).toBe(true);
    });

    it('classifies authentication errors as non-retryable', () => {
      const result = classifyErrorForTemporal(new Error('authentication_error: invalid API key'));
      expect(result.type).toBe('AuthenticationError');
      expect(result.retryable).toBe(false);
    });

    it('classifies 401 as authentication error', () => {
      const result = classifyErrorForTemporal(new Error('HTTP 401 Unauthorized'));
      expect(result.type).toBe('AuthenticationError');
      expect(result.retryable).toBe(false);
    });

    it('classifies permission/403 as non-retryable', () => {
      const result = classifyErrorForTemporal(new Error('403 Forbidden'));
      expect(result.type).toBe('PermissionError');
      expect(result.retryable).toBe(false);
    });

    it('classifies output validation as retryable', () => {
      const result = classifyErrorForTemporal(new Error('Agent failed output validation'));
      expect(result.type).toBe('OutputValidationError');
      expect(result.retryable).toBe(true);
    });

    it('classifies generic validation as non-retryable (after output validation check)', () => {
      const result = classifyErrorForTemporal(new Error('validation error in request'));
      expect(result.type).toBe('InvalidRequestError');
      expect(result.retryable).toBe(false);
    });

    it('classifies request too large as non-retryable', () => {
      const result = classifyErrorForTemporal(new Error('request_too_large'));
      expect(result.type).toBe('RequestTooLargeError');
      expect(result.retryable).toBe(false);
    });

    it('classifies ENOENT as configuration error', () => {
      const result = classifyErrorForTemporal(new Error('ENOENT: no such file'));
      expect(result.type).toBe('ConfigurationError');
      expect(result.retryable).toBe(false);
    });

    it('classifies max turns as execution limit error', () => {
      const result = classifyErrorForTemporal(new Error('error_max_turns reached'));
      expect(result.type).toBe('ExecutionLimitError');
      expect(result.retryable).toBe(false);
    });

    it('classifies invalid URL as non-retryable', () => {
      const result = classifyErrorForTemporal(new Error('invalid url provided'));
      expect(result.type).toBe('InvalidTargetError');
      expect(result.retryable).toBe(false);
    });

    it('defaults unknown errors to TransientError (retryable)', () => {
      const result = classifyErrorForTemporal(new Error('something completely unexpected'));
      expect(result.type).toBe('TransientError');
      expect(result.retryable).toBe(true);
    });

    it('handles non-Error objects', () => {
      const result = classifyErrorForTemporal('a plain string error');
      expect(result.type).toBe('TransientError');
      expect(result.retryable).toBe(true);
    });
  });
});
