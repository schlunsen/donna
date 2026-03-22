# Changelog

All notable changes to Donna will be documented in this file.

## [2.1.0] - 2026-03-21

### Added

#### Pipeline Concurrency Hardening (#7)
- Cross-process file locking via `proper-lockfile` with configurable retries and exponential backoff
- `atomicWriteLocked()` for crash-safe concurrent file writes
- `saveDeliverableFileLocked()` for concurrent deliverable saves in MCP server
- Fine-grained concurrency config: `concurrency.pipelines` and `concurrency.max_browsers`

#### Per-Agent Model Tier Optimization (#6)
- Explicit model tiers for all 13 agents (Opus for exploitation, Sonnet for analysis, Haiku for reporting)
- Config-driven model tier overrides via `pipeline.model_tiers`
- `BudgetMonitor` service with warnings at 75%, 90%, and 99% cost thresholds
- `computeDynamicTokenBudget()` for input-size-aware token allocation

#### Browser Resource Management (#5)
- `BrowserPool` with acquire/release semantics, FIFO queue, and configurable max instances
- Idle browser eviction (>5 min) with periodic health checks
- User data directory cleanup on release
- Process cleanup handlers for SIGINT, SIGTERM, and uncaught exceptions
- Chromium availability check during preflight validation

#### Expanded Prompt Coverage (#4)
- XXE detection in injection analysis (DocumentBuilder, SAXParser, lxml.etree, xml2js)
- OAuth/OIDC edge cases in auth analysis (PKCE downgrade, hybrid flow leakage, cross-tenant confusion, JWT algorithm confusion, redirect URI bypass, state parameter entropy, token binding)
- DNS rebinding detection in SSRF analysis with TOCTOU code patterns
- Polyglot and context-switching payloads in injection and XSS exploitation prompts

#### Standardized Queue Schemas (#3)
- Typed interfaces: `BaseQueueEntry`, `InjectionQueueEntry`, `XssQueueEntry`, `AuthQueueEntry`, `SsrfQueueEntry`, `AuthzQueueEntry`
- Vulnerability chaining: `prerequisite_findings`, `chain_description`, `chain_severity_multiplier`
- `PayloadExecutionScope` for encoding, request sequencing, and auth context
- Enhanced save-time validation with field checks, duplicate ID detection, and confidence validation

#### Test Coverage Foundation (#8)
- Vitest framework with `npm test` and `npm run test:watch`
- 39 unit tests across 4 suites (queue validation, budget monitoring, concurrency, browser pool)
- Test fixtures for valid, invalid, and empty queue files

## [1.0.0] - 2025-12-01

### Added
- Initial release of Donna autonomous pentesting pipeline
- Temporal-based workflow orchestration with 13 specialized agents
- Claude Agent SDK integration with MCP tool servers
- Git-based checkpointing and granular resume
- Continuous scanning mode (Sentinel)
- Exploitation feedback loops
- Comprehensive audit logging and session tracking
