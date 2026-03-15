// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Git monitoring service for continuous scanning.
 *
 * Handles:
 * - Fetching latest changes from a remote
 * - Diffing against the last scanned commit
 * - Categorizing changed files into vulnerability categories
 *
 * Designed for minimal git permissions (read-only clone/fetch access).
 */

import { $ } from 'zx';
import type { VulnType } from '../types/agents.js';
import type { GitDiffResult, ChangeRouting } from '../temporal/continuous-shared.js';
import { executeGitCommandWithRetry, isGitRepository } from './git-manager.js';
import type { ActivityLogger } from '../types/activity-logger.js';

// ── File Pattern → Vuln Category Mapping ────────────────────────

/**
 * Heuristic mapping of file path patterns to vulnerability categories.
 *
 * When a file changes, we check which patterns match to determine which
 * vuln categories need re-scanning. This avoids running all 5 pipelines
 * when only auth code changed.
 */
const VULN_CATEGORY_PATTERNS: Record<VulnType, RegExp[]> = {
  injection: [
    /\b(sql|query|database|db|orm|model|migration|knex|prisma|sequelize|typeorm)\b/i,
    /\b(exec|spawn|shell|command|system|eval|child_process)\b/i,
    /\b(ldap|xpath|nosql|mongo|redis)\b/i,
    /\.(sql|graphql|gql)$/i,
  ],
  xss: [
    /\b(template|view|render|component|html|jsx|tsx|vue|svelte|handlebars|ejs|pug)\b/i,
    /\b(sanitize|escape|encode|decode|innerHTML|dangerouslySetInnerHTML)\b/i,
    /\b(dom|parser|markdown|rich[-_]?text)\b/i,
    /\.(html|htm|ejs|hbs|pug|jade|vue|svelte)$/i,
  ],
  auth: [
    /\b(auth|login|logout|session|token|jwt|oauth|password|credential|sign[-_]?in|sign[-_]?up)\b/i,
    /\b(bcrypt|argon|scrypt|hash|salt|encrypt|decrypt|crypto)\b/i,
    /\b(cookie|bearer|api[-_]?key|secret|2fa|totp|mfa|otp)\b/i,
    /\b(passport|next[-_]?auth|clerk|lucia|iron[-_]?session)\b/i,
  ],
  ssrf: [
    /\b(fetch|request|http|https|axios|got|node[-_]?fetch|urllib|curl)\b/i,
    /\b(url|uri|endpoint|proxy|redirect|forward|webhook|callback)\b/i,
    /\b(dns|resolve|lookup|socket|net)\b/i,
    /\b(s3|cloud|storage|upload|download|remote)\b/i,
  ],
  authz: [
    /\b(role|permission|acl|rbac|abac|policy|guard|middleware|interceptor)\b/i,
    /\b(admin|owner|member|user|moderator|superuser|privilege)\b/i,
    /\b(authorize|can|ability|casl|casbin)\b/i,
    /\b(route|router|controller|handler|endpoint|api)\b/i,
    /\b(tenant|organization|workspace|team)\b/i,
  ],
};

/**
 * Files/patterns that should trigger a full scan regardless of content.
 * These are infrastructure-level changes that could affect any vuln category.
 */
const FULL_SCAN_TRIGGERS: RegExp[] = [
  /^package\.json$/,
  /^package-lock\.json$/,
  /^yarn\.lock$/,
  /^pnpm-lock\.yaml$/,
  /^Gemfile(\.lock)?$/,
  /^requirements.*\.txt$/,
  /^go\.(mod|sum)$/,
  /^Cargo\.(toml|lock)$/,
  /^docker-compose.*\.ya?ml$/,
  /^Dockerfile/,
  /^\.env/,
  /^(nginx|apache|caddy|traefik)/i,
];

// ── Git Operations ──────────────────────────────────────────────

/**
 * Build the GIT_SSH_COMMAND environment for deploy key authentication.
 */
function buildSshEnv(deployKeyPath: string): Record<string, string> {
  return {
    GIT_SSH_COMMAND: `ssh -i ${deployKeyPath} -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new`,
  };
}

/**
 * Fetch latest changes from the remote.
 *
 * Supports authentication via:
 * - SSH deploy key (gitDeployKey path)
 * - Token from environment variable (gitTokenEnv)
 * - Default SSH/credential config (no explicit auth)
 */
export async function gitFetchLatest(
  repoPath: string,
  remote: string,
  branch: string,
  logger: ActivityLogger,
  options?: {
    deployKeyPath?: string;
    tokenEnvVar?: string;
  }
): Promise<void> {
  if (!(await isGitRepository(repoPath))) {
    throw new Error(`Not a git repository: ${repoPath}`);
  }

  logger.info(`Fetching ${remote}/${branch}...`);

  const env: Record<string, string> = {};

  // Configure SSH deploy key if provided
  if (options?.deployKeyPath) {
    Object.assign(env, buildSshEnv(options.deployKeyPath));
    logger.info(`Using deploy key: ${options.deployKeyPath}`);
  }

  // Configure token-based auth if provided
  if (options?.tokenEnvVar) {
    const token = process.env[options.tokenEnvVar];
    if (!token) {
      throw new Error(
        `Git token environment variable "${options.tokenEnvVar}" is not set.\n` +
        `Set it in your .env file or export it before running.`
      );
    }
    // For HTTPS remotes, configure credential helper
    env.GIT_ASKPASS = 'echo';
    env.GIT_TOKEN = token;
    logger.info(`Using token from env: ${options.tokenEnvVar}`);
  }

  try {
    await $({
      cwd: repoPath,
      env: { ...process.env, ...env },
    })`git fetch ${remote} ${branch}`;

    logger.info(`Fetch complete`);
  } catch (error) {
    const errMsg = error instanceof Error ? error.message : String(error);
    throw new Error(
      `Git fetch failed for ${remote}/${branch}: ${errMsg}\n\n` +
      `Troubleshooting:\n` +
      `  1. Verify the remote exists: git remote -v\n` +
      `  2. Check authentication:\n` +
      `     - Deploy key: ensure the key file exists and is added to the repo's deploy keys\n` +
      `     - Token: ensure the env var is set and the token has read access\n` +
      `  3. For GitHub deploy keys (recommended, read-only):\n` +
      `     ssh-keygen -t ed25519 -f ~/.ssh/donna-deploy -N "" -C "donna-scanner"\n` +
      `     Then add the public key at: Repo → Settings → Deploy keys\n` +
      `  4. For fine-grained PAT:\n` +
      `     GitHub → Settings → Developer settings → Fine-grained tokens\n` +
      `     Permission needed: Contents → Read-only\n`
    );
  }
}

/**
 * Get the current HEAD commit hash.
 */
export async function getCurrentCommit(repoPath: string): Promise<string> {
  const result = await executeGitCommandWithRetry(
    ['git', 'rev-parse', 'HEAD'],
    repoPath,
    'get current commit'
  );
  return result.stdout.trim();
}

/**
 * Diff the repo against a previous commit to find changed files.
 *
 * If previousCommit is null (first scan), returns all tracked files.
 */
export async function gitDiff(
  repoPath: string,
  previousCommit: string | null,
  remote: string,
  branch: string,
  logger: ActivityLogger
): Promise<GitDiffResult> {
  // Merge remote changes into local branch
  logger.info(`Merging ${remote}/${branch} into local...`);
  try {
    await executeGitCommandWithRetry(
      ['git', 'merge', `${remote}/${branch}`, '--ff-only'],
      repoPath,
      'fast-forward merge'
    );
  } catch {
    // If fast-forward fails, reset to remote (we're read-only consumers)
    logger.warn('Fast-forward merge failed, resetting to remote HEAD');
    await executeGitCommandWithRetry(
      ['git', 'reset', '--hard', `${remote}/${branch}`],
      repoPath,
      'reset to remote HEAD'
    );
  }

  const newCommit = await getCurrentCommit(repoPath);

  if (!previousCommit) {
    // First scan — list all tracked files
    logger.info('First scan — listing all tracked files');
    const result = await executeGitCommandWithRetry(
      ['git', 'ls-files'],
      repoPath,
      'list all tracked files'
    );
    const files = result.stdout.trim().split('\n').filter(Boolean);
    return {
      previousCommit: null,
      currentCommit: newCommit,
      changedFiles: files,
      hasChanges: true,
      changeSummary: buildChangeSummary(files),
    };
  }

  if (previousCommit === newCommit) {
    logger.info(`No changes since last scan (commit: ${newCommit.slice(0, 8)})`);
    return {
      previousCommit,
      currentCommit: newCommit,
      changedFiles: [],
      hasChanges: false,
      changeSummary: {},
    };
  }

  // Diff between last scan and current
  logger.info(`Diffing ${previousCommit.slice(0, 8)}..${newCommit.slice(0, 8)}`);
  const result = await executeGitCommandWithRetry(
    ['git', 'diff', '--name-only', previousCommit, newCommit],
    repoPath,
    'diff changed files'
  );

  const changedFiles = result.stdout.trim().split('\n').filter(Boolean);
  logger.info(`Found ${changedFiles.length} changed file(s)`);

  return {
    previousCommit,
    currentCommit: newCommit,
    changedFiles,
    hasChanges: changedFiles.length > 0,
    changeSummary: buildChangeSummary(changedFiles),
  };
}

// ── Change Categorization ───────────────────────────────────────

/**
 * Build a summary of changes by top-level directory.
 */
function buildChangeSummary(files: string[]): Record<string, number> {
  const summary: Record<string, number> = {};
  for (const file of files) {
    const topDir = file.includes('/') ? file.split('/')[0]! : '(root)';
    summary[topDir] = (summary[topDir] ?? 0) + 1;
  }
  return summary;
}

/**
 * Categorize changed files into vulnerability types.
 *
 * Returns the subset of VulnType categories that have at least one
 * matching changed file.
 */
export function categorizeChanges(changedFiles: string[]): VulnType[] {
  const matchedCategories = new Set<VulnType>();

  for (const file of changedFiles) {
    for (const [vulnType, patterns] of Object.entries(VULN_CATEGORY_PATTERNS) as [VulnType, RegExp[]][]) {
      if (patterns.some((pattern) => pattern.test(file))) {
        matchedCategories.add(vulnType);
      }
    }
  }

  return [...matchedCategories];
}

/**
 * Check if any changed files are infrastructure-level changes
 * that should trigger a full scan.
 */
export function hasInfrastructureChanges(changedFiles: string[]): boolean {
  return changedFiles.some((file) =>
    FULL_SCAN_TRIGGERS.some((pattern) => pattern.test(file))
  );
}

/**
 * Route changes to determine scan strategy.
 *
 * Decision logic:
 * 1. First scan (no previousCommit) → full scan
 * 2. Infrastructure changes (deps, Dockerfile, etc.) → full scan
 * 3. Force full scan (strategy=full or days since last full exceeded) → full scan
 * 4. Otherwise → incremental, scanning only matched vuln categories
 * 5. If no categories matched but files changed → full scan (conservative)
 */
export function routeChanges(
  diff: GitDiffResult,
  options: {
    strategy: 'incremental' | 'full';
    forceFull: boolean;
    isFirstScan: boolean;
  }
): ChangeRouting {
  const allCategories: VulnType[] = ['injection', 'xss', 'auth', 'ssrf', 'authz'];

  // No changes → nothing to do
  if (!diff.hasChanges) {
    return {
      fullScan: false,
      reason: 'No changes detected since last scan',
      vulnCategories: [],
      changedFileCount: 0,
    };
  }

  // First scan → always full
  if (options.isFirstScan) {
    return {
      fullScan: true,
      reason: 'First scan — running full pipeline',
      vulnCategories: allCategories,
      changedFileCount: diff.changedFiles.length,
    };
  }

  // Force full scan (strategy=full or periodic full scan due)
  if (options.strategy === 'full' || options.forceFull) {
    return {
      fullScan: true,
      reason: options.forceFull
        ? 'Periodic full scan interval reached'
        : 'Full scan strategy configured',
      vulnCategories: allCategories,
      changedFileCount: diff.changedFiles.length,
    };
  }

  // Infrastructure changes → full scan
  if (hasInfrastructureChanges(diff.changedFiles)) {
    return {
      fullScan: true,
      reason: 'Infrastructure files changed (dependencies, config, Docker)',
      vulnCategories: allCategories,
      changedFileCount: diff.changedFiles.length,
    };
  }

  // Incremental: categorize changes
  const matched = categorizeChanges(diff.changedFiles);

  if (matched.length === 0) {
    // Changed files don't match any pattern — be conservative
    return {
      fullScan: true,
      reason: `${diff.changedFiles.length} file(s) changed but no vuln category matched — running full scan`,
      vulnCategories: allCategories,
      changedFileCount: diff.changedFiles.length,
    };
  }

  return {
    fullScan: false,
    reason: `Incremental scan: ${matched.length} category/ies affected (${matched.join(', ')})`,
    vulnCategories: matched,
    changedFileCount: diff.changedFiles.length,
  };
}
