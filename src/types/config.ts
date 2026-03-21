// Copyright (C) 2025 Keygraph, Inc.
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
}

export type RetryPreset = 'default' | 'subscription';

export interface ConcurrencyConfig {
  /** Max concurrent vuln→exploit pipeline pairs (default: 5) */
  pipelines?: number;
  /** Max concurrent browsers for exploitation agents (default: 3) */
  max_browsers?: number;
}

export interface PipelineConfig {
  retry_preset?: RetryPreset;
  max_concurrent_pipelines?: number;
  /** Number of exploitation feedback loop iterations (0 = no retry, 1 = recommended, N = thorough). Default: 0 */
  feedback_iterations?: number;
  /** Fine-grained concurrency limits per resource type */
  concurrency?: ConcurrencyConfig;
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
}
