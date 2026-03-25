# Changelog

All notable changes to Donna will be documented in this file.

## [1.1.0] - 2026-03-25

### Added

#### Tauri Desktop App
- Native macOS and Windows desktop application built with Tauri v2
- Auto-login flow with embedded dashboard authentication
- Dark/light theme toggle synced across the app
- Loading screen with startup status and Temporal readiness detection
- DMG packaging for macOS distribution
- Cross-platform CI pipeline with sidecar builds for mcp-server and dashboard

#### Dashboard Enhancements
- Redesigned report cover page with improved visual hierarchy
- "Start New" workflow action for quick scan initiation
- DONNA acronym branding across the UI
- Workflow API response improvements for better status tracking
- Parent run comparison in workflow detail views

#### Infrastructure & Deployment
- Production deployment to Hetzner dedicated server with Justfile automation
- Docker Compose with bind-mounted SQLite databases (Temporal + Dashboard) for safe restarts
- Google OAuth (better-auth) with email allowlist for access control
- Automated Temporal DB backups via cron
- Server credential management for Claude Code OAuth tokens
- Nginx reverse proxy with SSL termination

#### Landing Site & Presentation
- GitHub Pages landing site with interactive Three.js synthwave background
- Animated SVG presentation deck with slide transitions
- Retro 70s aesthetic with custom graphics

### Fixed
- Windows build: proper ICO file generation for Tauri
- CI pipeline: Apple signing removal, Windows .exe support, cross-compilation target triples
- Dashboard startup: TCP health checks, project node_modules resolution, sidecar logging
- Tauri v2 API compatibility and permission discovery issues
- Three.js background z-index conflicts on landing page

---

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
