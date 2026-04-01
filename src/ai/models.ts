// Donna - Continuous AI Pentesting Platform
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Model tier definitions and resolution.
 *
 * Three tiers mapped to capability levels:
 * - "small"  (Haiku — summarization, structured extraction)
 * - "medium" (Sonnet — tool use, general analysis)
 * - "large"  (Opus — deep reasoning, complex analysis)
 *
 * Users override via ANTHROPIC_SMALL_MODEL / ANTHROPIC_MEDIUM_MODEL / ANTHROPIC_LARGE_MODEL,
 * which works across all providers (direct, Bedrock, Vertex).
 *
 * Model profiles (Phase 1-3) allow per-scan and per-agent provider/model selection
 * via the `models` section in YAML config.
 */

import type { ModelProfile, ResolvedModelEndpoint } from '../types/config.js';

export type ModelTier = 'small' | 'medium' | 'large';

const DEFAULT_MODELS: Readonly<Record<ModelTier, string>> = {
  small: 'claude-haiku-4-5-20251001',
  medium: 'claude-sonnet-4-6',
  large: 'claude-opus-4-6',
};

/** Built-in Claude profile used when no custom profile is configured. */
export const BUILTIN_CLAUDE_PROFILE: ModelProfile = {
  tiers: {
    small: DEFAULT_MODELS.small,
    medium: DEFAULT_MODELS.medium,
    large: DEFAULT_MODELS.large,
  },
};

/** Built-in Qwen profile — routes all tiers directly to local vLLM (bypasses LiteLLM). */
export const BUILTIN_QWEN_LOCAL_PROFILE: ModelProfile = {
  base_url: process.env.VLLM_BASE_URL || 'http://host.docker.internal:8000',
  api_key_env: 'VLLM_API_KEY',
  tiers: {
    small: 'Qwen/Qwen3.5-35B-A3B-FP8',
    medium: 'Qwen/Qwen3.5-35B-A3B-FP8',
    large: 'Qwen/Qwen3.5-35B-A3B-FP8',
  },
};

/** Map of built-in profile names to their definitions. */
export const BUILTIN_PROFILES: Readonly<Record<string, ModelProfile>> = {
  claude: BUILTIN_CLAUDE_PROFILE,
  'qwen-local': BUILTIN_QWEN_LOCAL_PROFILE,
};

/** Resolve a model tier to a concrete model ID (legacy path, env-var based). */
export function resolveModel(tier: ModelTier = 'medium'): string {
  switch (tier) {
    case 'small':
      return process.env.ANTHROPIC_SMALL_MODEL || DEFAULT_MODELS.small;
    case 'large':
      return process.env.ANTHROPIC_LARGE_MODEL || DEFAULT_MODELS.large;
    default:
      return process.env.ANTHROPIC_MEDIUM_MODEL || DEFAULT_MODELS.medium;
  }
}

/**
 * Resolve a model tier using a profile, returning full endpoint info.
 *
 * Resolution priority:
 * 1. Profile tier_endpoints override (Phase 2 — hybrid profiles)
 * 2. Profile tiers + base_url (Phase 1 — single provider)
 * 3. Env var override (ANTHROPIC_SMALL_MODEL etc.)
 * 4. Built-in defaults
 */
export function resolveModelFromProfile(
  tier: ModelTier = 'medium',
  profile?: ModelProfile
): ResolvedModelEndpoint {
  // No profile — fall back to legacy env-var resolution
  if (!profile) {
    return { model: resolveModel(tier) };
  }

  // Phase 2: Check for per-tier endpoint override
  const tierEndpoint = profile.tier_endpoints?.[tier];
  if (tierEndpoint) {
    return {
      model: profile.tiers[tier],
      base_url: tierEndpoint.base_url,
      api_key_env: tierEndpoint.api_key_env ?? profile.api_key_env,
    };
  }

  // Phase 1: Use profile's tiers and base_url
  return {
    model: profile.tiers[tier],
    base_url: profile.base_url,
    api_key_env: profile.api_key_env,
    api_key: profile.api_key,
  };
}
