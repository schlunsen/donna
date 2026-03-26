// Donna - Continuous AI Pentesting Platform
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Configuration type definitions
 */

export type RuleType =
  | 'path'
  | 'subdomain'
  | 'domain'
  | 'method'
  | 'header'
  | 'parameter';

export interface Rule {
  description: string;
  type: RuleType;
  url_path: string;
}

export interface Rules {
  avoid?: Rule[];
  focus?: Rule[];
}

export type LoginType = 'form' | 'sso' | 'api' | 'basic';

export interface SuccessCondition {
  type: 'url' | 'cookie' | 'element' | 'redirect';
  value: string;
}

export interface Credentials {
  username: string;
  password: string;
  totp_secret?: string;
}

export interface Authentication {
  login_type: LoginType;
  login_url: string;
  credentials: Credentials;
  login_flow: string[];
  success_condition: SuccessCondition;
}

export interface Config {
  rules?: Rules;
  authentication?: Authentication;
  pipeline?: PipelineConfig;
  continuous?: ContinuousConfig;
  /** Model profiles for multi-provider support. */
  models?: ModelsConfig;
}

export type RetryPreset = 'default' | 'subscription';

export interface ConcurrencyConfig {
  /** Max concurrent vuln→exploit pipeline pairs (default: 5) */
  pipelines?: number;
  /** Max concurrent browsers for exploitation agents (default: 3) */
  max_browsers?: number;
}

/** Per-agent model tier overrides. Keys are AgentName values. */
export type ModelTierOverrides = Record<string, 'small' | 'medium' | 'large'>;

// ── Model Profiles ──────────────────────────────────────────────

/** Per-tier endpoint override (Phase 2: hybrid profiles). */
export interface TierEndpoint {
  base_url: string;
  api_key_env?: string;
}

/**
 * A named model profile that defines which models and endpoint to use.
 *
 * Phase 1: Single provider per profile (base_url + tiers).
 * Phase 2: Per-tier endpoint overrides via tier_endpoints (hybrid profiles).
 * Phase 3: Per-agent profile references via model_tiers agent-level overrides.
 */
export interface ModelProfile {
  /** API base URL. Omit for default Anthropic API. */
  base_url?: string;
  /** Environment variable name holding the API key (default: ANTHROPIC_API_KEY). */
  api_key_env?: string;
  /** Model ID for each tier. */
  tiers: {
    small: string;
    medium: string;
    large: string;
  };
  /** Per-tier endpoint overrides for hybrid profiles (Phase 2). */
  tier_endpoints?: Partial<Record<'small' | 'medium' | 'large', TierEndpoint>>;
}

/** Top-level models configuration section. */
export interface ModelsConfig {
  profiles: Record<string, ModelProfile>;
  /** Default profile name. Falls back to 'claude' if not specified. */
  default_profile?: string;
}

/** Resolved endpoint info for a single model execution. */
export interface ResolvedModelEndpoint {
  model: string;
  base_url?: string | undefined;
  api_key_env?: string | undefined;
}

export interface PipelineConfig {
  retry_preset?: RetryPreset;
  max_concurrent_pipelines?: number;
  /** Number of exploitation feedback loop iterations (0 = no retry, 1 = recommended, N = thorough). Default: 0 */
  feedback_iterations?: number;
  /** Fine-grained concurrency limits per resource type */
  concurrency?: ConcurrencyConfig;
  /** Override default model tiers for specific agents */
  model_tiers?: ModelTierOverrides;
  /** Model profile to use for this scan (overrides models.default_profile) */
  model_profile?: string;
}

// ── Continuous Scanning Config ──────────────────────────────────

export interface ContinuousConfig {
  /** Cron expression for scan schedule (e.g. "0 0/6 * * *" for every 6 hours) */
  schedule: string;
  /** Git remote to fetch from (default: "origin") */
  git_remote?: string;
  /** Branch to track (default: "main") */
  git_branch?: string;
  /** SSH deploy key path for read-only git access */
  git_deploy_key?: string;
  /** Environment variable name holding a git PAT (alternative to deploy key) */
  git_token_env?: string;
  /** Scan strategy: "incremental" (only changed categories) or "full" (all categories) */
  strategy?: 'incremental' | 'full';
  /** Days between forced full scans even in incremental mode (default: 7) */
  full_scan_every_days?: number;
  /** Notification settings */
  notifications?: {
    /** Slack or Discord webhook URL */
    webhook_url?: string;
    /** Send notification on new findings (default: true) */
    on_new_finding?: boolean;
    /** Send notification on resolved findings (default: true) */
    on_resolved?: boolean;
  };
}

export interface DistributedConfig {
  avoid: Rule[];
  focus: Rule[];
  authentication: Authentication | null;
  /** Active model profile (resolved from config + CLI override). */
  modelProfile?: ModelProfile;
  /** Per-agent model tier overrides from config. */
  modelTiers?: ModelTierOverrides;
}
