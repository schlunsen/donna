// Donna - Continuous AI Pentesting Platform
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Config Loader Service
 *
 * Wraps parseConfig + distributeConfig with Result type for explicit error handling.
 * Pure service with no Temporal dependencies.
 */

import { parseConfig, distributeConfig, resolveActiveProfile } from '../config-parser.js';
import { PentestError } from './error-handling.js';
import { Result, ok, err } from '../types/result.js';
import { ErrorCode } from '../types/errors.js';
import type { DistributedConfig, ModelProfile } from '../types/config.js';

/** Inline model profile config from dashboard LLM settings. */
export interface InlineModelProfileConfig {
  base_url: string;
  api_key?: string;
  tiers: { small: string; medium: string; large: string };
}

/**
 * Service for loading and distributing configuration files.
 *
 * Provides a Result-based API for explicit error handling,
 * allowing callers to decide how to handle failures.
 */
export class ConfigLoaderService {
  /** Optional model profile override from CLI (--model-profile). */
  private profileOverride: string | undefined;

  /** Inline model profile config from dashboard LLM settings. */
  private inlineProfileConfig: InlineModelProfileConfig | undefined;

  constructor(profileOverride?: string, inlineProfileConfig?: InlineModelProfileConfig) {
    this.profileOverride = profileOverride;
    this.inlineProfileConfig = inlineProfileConfig;
  }

  /**
   * Load and distribute a configuration file.
   *
   * @param configPath - Path to the YAML configuration file
   * @returns Result containing DistributedConfig on success, PentestError on failure
   */
  async load(configPath: string): Promise<Result<DistributedConfig, PentestError>> {
    try {
      const config = await parseConfig(configPath);
      const distributed = distributeConfig(config, this.profileOverride);
      return ok(distributed);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);

      // Determine appropriate error code based on error message
      let errorCode = ErrorCode.CONFIG_PARSE_ERROR;
      if (errorMessage.includes('not found') || errorMessage.includes('ENOENT')) {
        errorCode = ErrorCode.CONFIG_NOT_FOUND;
      } else if (errorMessage.includes('validation failed')) {
        errorCode = ErrorCode.CONFIG_VALIDATION_FAILED;
      }

      return err(
        new PentestError(
          `Failed to load config ${configPath}: ${errorMessage}`,
          'config',
          false,
          { configPath, originalError: errorMessage },
          errorCode
        )
      );
    }
  }

  /**
   * Load config if path is provided, otherwise return null config.
   *
   * @param configPath - Optional path to the YAML configuration file
   * @returns Result containing DistributedConfig (or null) on success, PentestError on failure
   */
  async loadOptional(
    configPath: string | undefined
  ): Promise<Result<DistributedConfig | null, PentestError>> {
    if (!configPath) {
      // Inline profile config from dashboard LLM settings takes priority
      if (this.inlineProfileConfig) {
        const modelProfile: ModelProfile = {
          base_url: this.inlineProfileConfig.base_url,
          ...(this.inlineProfileConfig.api_key ? { api_key: this.inlineProfileConfig.api_key } : {}),
          tiers: this.inlineProfileConfig.tiers,
        };
        return ok({
          avoid: [],
          focus: [],
          authentication: null,
          modelProfile,
        });
      }

      // No config file, but if there's a model profile override, resolve built-in profiles
      if (this.profileOverride) {
        const modelProfile = resolveActiveProfile(null, this.profileOverride);
        if (modelProfile) {
          return ok({
            avoid: [],
            focus: [],
            authentication: null,
            modelProfile,
          });
        }
      }
      return ok(null);
    }
    return this.load(configPath);
  }
}
