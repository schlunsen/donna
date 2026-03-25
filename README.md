<div align="center">

<img src="./assets/github-banner.png" alt="Donna — Continuous AI Pentesting Platform" width="100%">

# DONNA — Continuous AI Pentesting

> **D**eviant **O**rchestration of **N**on-compliant **N**eural **A**gents

### *Grab 'em by the balls.*

**Continuous AI-powered security scanning with a real-time web dashboard.**

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)

</div>

---

## What is Donna?

Donna is an autonomous AI pentester that analyzes source code, identifies attack vectors, and executes real exploits against running applications. It continuously monitors your repositories for changes, automatically runs incremental pentests on what changed, tracks findings across scans, and gives you a web dashboard to monitor everything remotely.

### Features

| Feature | Description |
|---------|-------------|
| **Donna Sentinel** | Continuous scanning via Temporal cron workflows — watches git repos, detects changes, runs incremental pentests automatically |
| **Web Dashboard** | Astro-based dashboard replacing Temporal's built-in UI — workflow list, live logs, findings panel, severity tracking |
| **Finding Lifecycle** | Tracks findings across scans (new → confirmed → resolved) with persistent baselines |
| **Finding Deduplication** | Normalizes, classifies, and merges duplicate findings using CVSS 3.1, CWE classification, and endpoint canonicalization |
| **Exploitation Feedback** | Iterative refinement loop — failed exploits feed context back into retry attempts |
| **Live Streaming** | Real-time agent turn streaming via heartbeat-based TurnBuffer, viewable in the dashboard |
| **Slack/Discord Alerts** | Webhook notifications on new or resolved findings |
| **Copy for Agent** | One-click "Copy All for Agent" to hand findings to a coding agent for remediation |
| **Security Hardening** | CSRF protection, rate limiting, security headers, input validation, scoped Docker permissions |

### Why Donna?

Donna isn't just a one-shot scanner — it's a full pentesting **platform**:

- **Continuous monitoring** with cron scheduling, not manual one-off scans
- **Real-time web dashboard** with live streaming, not just terminal output
- **Finding lifecycle tracking** (new → confirmed → resolved) across scans
- **Automatic change detection** — watches git repos, scans only what changed
- **Smart deduplication** — CVSS normalization, CWE classification, endpoint canonicalization
- **Slack/Discord notifications** on new or resolved findings
- **Iterative exploit refinement** — failed exploits feed context into retries
- **Durable workflows** — Temporal-backed, survives crashes, auto-retries on failure
- **Authenticated dashboard** with session management, CSRF protection, rate limiting

**Donna runs while you sleep.**

---

## Quick Start

### Prerequisites

- **Docker** ([Install Docker](https://docs.docker.com/get-docker/))
- **Node.js 20+** (for local development)
- **Anthropic API key** — [Get one here](https://console.anthropic.com)

### One-shot scan

```bash
# 1. Clone and configure
git clone https://github.com/schlunsen/donna.git
cd donna
cp .env.example .env   # Add your ANTHROPIC_API_KEY

# 2. Place your target repo
git clone https://github.com/your-org/your-app.git ./repos/your-app

# 3. Run a pentest
./donna start URL=https://your-app.com REPO=your-app
```

### Continuous scanning (Sentinel mode)

```bash
# 1. Start infrastructure
docker compose up -d

# 2. Build the project
just build

# 3. Start Sentinel — scans every 6 hours by default
just sentinel https://your-app.com ./repos/your-app

# Or set a custom schedule (every 12 hours)
just sentinel-cron "0 */12 * * *" https://your-app.com ./repos/your-app
```

Sentinel watches your repo for git changes. When it detects a diff, it routes the changed files to the relevant vulnerability categories and runs only the affected pipelines. When nothing changed, it exits at zero cost.

### Open the dashboard

```bash
just dashboard-ui    # Opens http://localhost:4321
```

The dashboard shows all workflows, live agent logs, per-finding severity badges, and detailed evidence for each finding.

---

## Architecture

Donna's multi-agent pentest pipeline with a continuous orchestration layer on top:

```
┌─────────────────────────────────────────────────────────────────┐
│                     Donna Sentinel (Cron)                       │
│                                                                 │
│  Git Fetch → Diff → Route Changes → Run Pipeline → Track       │
│                                         │            Findings   │
│                                         ▼                       │
│                              ┌──────────────────┐               │
│                              │  Pentest Pipeline │  (child wf)  │
│                              │                   │               │
│                              │  Recon → Analysis │               │
│                              │    → Exploit →    │               │
│                              │      Report       │               │
│                              └──────────────────┘               │
│                                         │                       │
│                    ┌────────────────────┴────────────┐          │
│                    ▼                                 ▼          │
│             Finding Tracker                   Notifications     │
│          (new/confirmed/resolved)          (Slack/Discord)      │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
                    ┌──────────────────┐
                    │    Dashboard     │  (Astro SSR)
                    │                  │
                    │  Workflows List  │
                    │  Live Logs       │
                    │  Findings Panel  │
                    │  Severity Badges │
                    └──────────────────┘
```

### Key components

| Component | Location | What it does |
|-----------|----------|-------------|
| **Continuous Workflow** | `src/temporal/continuous-workflow.ts` | Temporal cron workflow — git sync, change routing, child pipeline execution, finding tracking, notifications |
| **Git Monitor** | `src/services/git-monitor.ts` | Fetches latest changes, diffs since last scan, routes files to vulnerability categories |
| **Finding Tracker** | `src/services/finding-tracker.ts` | Manages finding lifecycle (new → confirmed → resolved) with persistent baselines |
| **Finding Deduplication** | `src/services/finding-deduplication.ts` | Merges duplicate findings — CVSS normalization, CWE classification, endpoint canonicalization |
| **Exploitation Feedback** | `src/services/exploitation-feedback.ts` | Parses exploit results, injects prior attempts into retries, generates calibration stats |
| **Dashboard** | `dashboard/` | Astro SSR app — queries Temporal API and reads audit-logs for real-time monitoring |
| **Pentest Pipeline** | `src/temporal/workflows.ts` | Core pipeline (recon → analysis → exploitation → reporting) |

### Tech stack

- **Temporal** — Durable workflow orchestration with cron scheduling
- **Claude Agent SDK** (`@anthropic-ai/claude-agent-sdk`) — AI agent execution
- **Astro** — Dashboard SSR framework
- **Docker Compose** — Temporal server + worker + dashboard + optional router
- **TypeScript** — All application code

---

## Dashboard

The dashboard runs at `http://localhost:4321` and provides:

- **Workflow list** — All scans with status, target, phase, cost, and severity badges (e.g., `3C 8H 3M`)
- **Workflow detail** — Per-agent progress, turn counts, metrics
- **Live logs** — Real-time streaming of agent turns with auto-scroll and pulse indicator
- **Findings panel** — List/grid view of all findings with severity, evidence, and detail modals
- **Copy for Agent** — Copies all findings as structured text for handing off to a coding agent
- **Workspaces** — Browse and manage scan workspaces
- **Audit logs** — Historical scan data and reports

### Running the dashboard

```bash
# Production (via Docker Compose)
docker compose up -d dashboard

# Development (hot reload)
just dashboard-dev
```

---

## Sentinel: Continuous Scanning

Sentinel is a Temporal cron workflow that automates the scan-on-change loop:

1. **Git Fetch** — Pulls the latest changes from the configured remote/branch
2. **Diff & Route** — Compares against the last scanned commit, maps changed files to vulnerability categories
3. **Smart Execution** — Runs a full scan or incremental scan (only affected categories), with forced full scans every N days
4. **Finding Tracking** — Compares new results against the persistent baseline to classify findings as new, confirmed, or resolved
5. **Notifications** — Sends a summary to Slack/Discord webhooks when findings change
6. **Zero-cost skip** — If nothing changed since the last scan, the workflow exits immediately

### Configuration

```bash
# Basic — scans every 6 hours
just sentinel https://app.example.com ./repos/my-app

# Custom schedule — every day at midnight
just sentinel-cron "0 0 * * *" https://app.example.com ./repos/my-app

# With deploy key for private repos
just sentinel https://app.example.com ./repos/my-app --deploy-key ~/.ssh/donna-deploy

# With Slack notifications
just sentinel https://app.example.com ./repos/my-app --webhook https://hooks.slack.com/...

# Stop a Sentinel workflow
just sentinel-stop donna-continuous-myapp

# View scan history
just sentinel-history

# View current finding baseline
just sentinel-baseline
```

### Incremental vs full scans

Sentinel routes changed files to vulnerability categories based on file patterns:

| File pattern | Vuln categories triggered |
|-------------|--------------------------|
| `*.sql`, `*query*`, `*db*` | Injection |
| `*.html`, `*.jsx`, `*template*` | XSS |
| `*auth*`, `*login*`, `*session*` | Authentication, Authorization |
| `*url*`, `*fetch*`, `*request*` | SSRF |
| Config files, large refactors | Full scan (all categories) |

A forced full scan runs every 7 days by default (configurable via `fullScanEveryDays`).

---

## Finding Deduplication

The reporting pipeline deduplicates findings before generating the final report:

- **Endpoint canonicalization** — Normalizes URLs, methods, and parameters
- **CWE classification** — Maps findings to CWE identifiers via pattern matching
- **CVSS 3.1 normalization** — Standardizes severity scores
- **Fuzzy matching** — Merges findings sharing the same endpoint + vulnerability class + parameter
- **Highest-severity wins** — Merged findings retain the most severe rating
- **Root-cause correlation** — Groups related findings and generates a severity summary table

---

## Exploitation Feedback Loop

When enabled (`feedback_iterations > 0` in config), exploitation results feed back into the pipeline:

1. Parse exploitation outcomes (success, failure, partial) with structured evidence
2. Inject prior attempt context into retry queue files
3. Generate calibration stats (success rate by vulnerability type, confidence levels)
4. Re-run exploitation with refined context
5. Append feedback metadata to the final report

```yaml
# In your config file
pipeline:
  feedback_iterations: 2    # Number of feedback rounds (default: 0, disabled)
```

---

## CLI Reference

```bash
# ── Scanning ──────────────────────────────────────────────
./donna start URL=<url> REPO=<name>              # Start a pentest
./donna start URL=<url> REPO=<name> WORKSPACE=q1 # Named workspace (resumable)
./donna logs ID=<workflow-id>                     # Tail workflow logs
./donna workspaces                                # List all workspaces
./donna stop                                      # Stop containers
./donna stop CLEAN=true                           # Stop + remove all data

# ── Sentinel ──────────────────────────────────────────────
just sentinel <url> <repo>                        # Start continuous scanning
just sentinel-cron "<cron>" <url> <repo>          # Custom schedule
just sentinel-stop <workflow-id>                  # Stop a Sentinel workflow
just sentinel-history                             # View scan history
just sentinel-baseline                            # View current findings

# ── Infrastructure ────────────────────────────────────────
just up                                           # Start all containers
just up-temporal                                  # Start Temporal only
just up-dashboard                                 # Start dashboard only
just ps                                           # Show container status

# ── Development ───────────────────────────────────────────
just build                                        # Build TypeScript
just watch                                        # Watch mode
just typecheck                                    # Type check
just dashboard-dev                                # Dashboard dev server

# ── Utilities ─────────────────────────────────────────────
just doctor                                       # Check dependencies
just repos                                        # List target repos
just import ~/path/to/repo                        # Import a local repo
just clone-repo <git-url> <name>                  # Clone a target repo
just audit-logs                                   # List audit log dirs
```

---

## Project Structure

```
.
├── src/
│   ├── temporal/
│   │   ├── continuous-workflow.ts    # Sentinel cron workflow
│   │   ├── continuous-activities.ts  # Git sync, finding tracking, notifications
│   │   ├── continuous-client.ts      # CLI to start/stop Sentinel
│   │   ├── continuous-shared.ts      # Types, queries, notification formatting
│   │   ├── workflows.ts             # Core pentest pipeline workflow
│   │   ├── activities.ts            # Pipeline activities
│   │   ├── worker.ts                # Temporal worker
│   │   └── client.ts               # One-shot scan client
│   ├── services/
│   │   ├── finding-tracker.ts       # Finding lifecycle management
│   │   ├── finding-deduplication.ts # Dedup engine (CVSS, CWE, fuzzy match)
│   │   ├── exploitation-feedback.ts # Feedback loop between exploit rounds
│   │   ├── git-monitor.ts           # Git diff and change routing
│   │   ├── reporting.ts             # Report generation with dedup
│   │   └── ...
│   └── ai/
│       ├── claude-executor.ts       # Claude Agent SDK integration
│       └── ...
├── dashboard/                       # Astro SSR dashboard
│   ├── src/pages/                   # Workflow list, detail, schedules, docs
│   ├── src/lib/temporal.ts          # Temporal client for dashboard
│   └── src/lib/audit-logs.ts        # Audit log parsing for findings
├── configs/                         # Scan configuration files
├── prompts/                         # Agent system prompts
├── audit-logs/                      # Scan output (auto-created)
├── repos/                           # Target repositories (you add these)
├── docker-compose.yml               # Temporal + worker + dashboard
├── donna                            # CLI entrypoint (bash)
├── justfile                         # Task runner recipes
└── package.json
```

---

## Provider Configuration

Donna supports multiple AI providers:

| Provider | Setup |
|----------|-------|
| **Anthropic API** (default) | Set `ANTHROPIC_API_KEY` in `.env` |
| **Claude Code OAuth** | Set `CLAUDE_CODE_OAUTH_TOKEN` in `.env` |
| **AWS Bedrock** | Set `CLAUDE_CODE_USE_BEDROCK=1` + AWS credentials |
| **Google Vertex AI** | Set `CLAUDE_CODE_USE_VERTEX=1` + GCP credentials |
| **Router Mode** (experimental) | `ROUTER=true` with OpenAI or OpenRouter keys |

See `.env.example` for all configuration options.

---

## Disclaimers

This tool **actively executes attacks** against target applications.

> **DO NOT run on production environments.** Use sandboxed, staging, or local development environments only.

> **You must have explicit, written authorization** from the system owner before running scans.

> **Human oversight is essential.** LLMs can generate hallucinated findings. Validate all reported vulnerabilities.

---

## Acknowledgments

Donna was originally inspired by and forked from [Shannon](https://github.com/keygraph/shannon) by [Keygraph](https://github.com/keygraph). Thank you to the Shannon team for the foundational work on AI-powered penetration testing.

---

## License

AGPL-3.0 — See [LICENSE](LICENSE) for details.
