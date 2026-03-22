# CLAUDE.md

AI-powered penetration testing agent for defensive security analysis. Automates vulnerability assessment by combining reconnaissance tools with AI-powered code analysis.

## Commands

**Prerequisites:** Docker, Anthropic API key in `.env`

```bash
# Setup
cp .env.example .env && edit .env  # Set ANTHROPIC_API_KEY

# Prepare repo (REPO is a folder name inside ./repos/, not an absolute path)
git clone https://github.com/org/repo.git ./repos/my-repo
# or symlink: ln -s /path/to/existing/repo ./repos/my-repo

# Run
./donna start URL=<url> REPO=my-repo
./donna start URL=<url> REPO=my-repo CONFIG=./configs/my-config.yaml

# Workspaces & Resume
./donna start URL=<url> REPO=my-repo WORKSPACE=my-audit    # New named workspace
./donna start URL=<url> REPO=my-repo WORKSPACE=my-audit    # Resume (same command)
./donna start URL=<url> REPO=my-repo WORKSPACE=<auto-name> # Resume auto-named run
./donna workspaces                                          # List all workspaces

# Monitor
./donna logs                      # Real-time worker logs
# Temporal Web UI: http://localhost:8233

# Stop
./donna stop                      # Preserves workflow data
./donna stop CLEAN=true           # Full cleanup including volumes

# Build
npm run build
```

**Options:** `CONFIG=<file>` (YAML config), `OUTPUT=<path>` (default: `./audit-logs/`), `WORKSPACE=<name>` (named workspace; auto-resumes if exists), `PIPELINE_TESTING=true` (minimal prompts, 10s retries), `REBUILD=true` (force Docker rebuild), `ROUTER=true` (multi-model routing via [claude-code-router](https://github.com/musistudio/claude-code-router))

## Justfile Commands

The project includes a `justfile` for common tasks. Run `just` to see all available commands.

```bash
# ── Build ──
just build              # Build TypeScript (mcp-server + main project)
just build-mcp          # Build only the MCP server
just build-main         # Build only the main project
just build-docker       # Build the Docker worker image
just build-docker-fresh # Build Docker image without cache
just install            # Install all npm dependencies
just clean              # Remove build artifacts (dist/)
just rebuild            # Clean + install + build

# ── Run ──
just start <url> <repo>                    # Start a pentest workflow
just start-ws <url> <repo> <workspace>     # Start with a named workspace
just start-test <url> <repo>               # Start in pipeline testing mode
just workspaces                            # List all workspaces
just logs <id>                             # Tail logs for a workflow
just stop                                  # Stop all containers
just stop-clean                            # Stop and remove all data

# ── Docker / Infrastructure ──
just up                 # Start all containers (build + detach)
just up-temporal        # Start only Temporal server
just up-dashboard       # Start only the dashboard
just up-router          # Start with multi-model router
just ps                 # Show running containers
just worker-logs        # Tail worker logs
just temporal-logs      # Tail Temporal logs
just dashboard-logs     # Tail dashboard logs
just restart-worker     # Rebuild and restart the worker

# ── Deploy (production) ──
just deploy             # Deploy dashboard only to production
just deploy-full        # Deploy everything (dashboard + worker + configs)
just deploy-logs        # View production dashboard logs
just deploy-ssh         # SSH into the production server

# ── Dashboard Dev ──
just dashboard-dev      # Run dashboard with hot reload
just dashboard-build    # Build dashboard for production

# ── Development ──
just typecheck          # TypeScript type check (no emit)
just watch              # Watch mode — rebuild on changes

# ── Audit Logs & Reports ──
just audit-logs         # List audit log directories
just latest-log         # Show the latest workflow log
just tail-latest        # Tail the latest log in real-time
just session <workspace># Show session summary JSON

# ── Repo Management ──
just import <path> [name]     # Import a local directory into ./repos/
just clone-repo <url> <name>  # Clone a repo into ./repos/
just repos                    # List available repos

# ── Utilities ──
just setup              # Create .env from template
just doctor             # Check if required tools are installed
just temporal-ui        # Open Temporal Web UI in browser
just dashboard-ui       # Open Donna Dashboard in browser
```

## Architecture

### Core Modules
- `src/session-manager.ts` — Agent definitions (`AGENTS` record). Agent types in `src/types/agents.ts`
- `src/config-parser.ts` — YAML config parsing with JSON Schema validation
- `src/ai/claude-executor.ts` — Claude Agent SDK integration with retry logic
- `src/services/` — Business logic layer (Temporal-agnostic). Activities delegate here. Key: `agent-execution.ts`, `error-handling.ts`, `container.ts`
- `src/types/` — Consolidated types: `Result<T,E>`, `ErrorCode`, `AgentName`, `ActivityLogger`, etc.
- `src/utils/` — Shared utilities (file I/O, formatting, concurrency)

### Temporal Orchestration
Durable workflow orchestration with crash recovery, queryable progress, intelligent retry, and parallel execution (5 concurrent agents in vuln/exploit phases).

- `src/temporal/workflows.ts` — Main workflow (`pentestPipelineWorkflow`)
- `src/temporal/activities.ts` — Thin wrappers — heartbeat loop, error classification, container lifecycle. Business logic delegated to `src/services/`
- `src/temporal/activity-logger.ts` — `TemporalActivityLogger` implementation of `ActivityLogger` interface
- `src/temporal/summary-mapper.ts` — Maps `PipelineSummary` to `WorkflowSummary`
- `src/temporal/worker.ts` — Worker entry point
- `src/temporal/client.ts` — CLI client for starting workflows
- `src/temporal/shared.ts` — Types, interfaces, query definitions
### Five-Phase Pipeline

1. **Pre-Recon** (`pre-recon`) — External scans (nmap, subfinder, whatweb) + source code analysis
2. **Recon** (`recon`) — Attack surface mapping from initial findings
3. **Vulnerability Analysis** (5 parallel agents) — injection, xss, auth, authz, ssrf
4. **Exploitation** (5 parallel agents, conditional) — Exploits confirmed vulnerabilities
5. **Reporting** (`report`) — Executive-level security report

### Supporting Systems
- **Configuration** — YAML configs in `configs/` with JSON Schema validation (`config-schema.json`). Supports auth settings, MFA/TOTP, and per-app testing parameters
- **Prompts** — Per-phase templates in `prompts/` with variable substitution (`{{TARGET_URL}}`, `{{CONFIG_CONTEXT}}`). Shared partials in `prompts/shared/` via `src/services/prompt-manager.ts`
- **SDK Integration** — Uses `@anthropic-ai/claude-agent-sdk` with `maxTurns: 10_000` and `bypassPermissions` mode. Playwright MCP for browser automation, TOTP generation via MCP tool. Login flow template at `prompts/shared/login-instructions.txt` supports form, SSO, API, and basic auth
- **Audit System** — Crash-safe append-only logging in `audit-logs/{hostname}_{sessionId}/`. Tracks session metrics, per-agent logs, prompts, and deliverables. WorkflowLogger (`audit/workflow-logger.ts`) provides unified human-readable per-workflow logs, backed by LogStream (`audit/log-stream.ts`) shared stream primitive
- **Deliverables** — Saved to `deliverables/` in the target repo via the `save_deliverable` MCP tool
- **Workspaces & Resume** — Named workspaces via `WORKSPACE=<name>` or auto-named from URL+timestamp. Resume passes `--workspace` to the Temporal client (`src/temporal/client.ts`), which loads `session.json` to detect completed agents. `loadResumeState()` in `src/temporal/activities.ts` validates deliverable existence, restores git checkpoints, and cleans up incomplete deliverables. Workspace listing via `src/temporal/workspaces.ts`

## Development Notes

### Adding a New Agent
1. Define agent in `src/session-manager.ts` (add to `AGENTS` record). `ALL_AGENTS`/`AgentName` types live in `src/types/agents.ts`
2. Create prompt template in `prompts/` (e.g., `vuln-newtype.txt`)
3. Two-layer pattern: add a thin activity wrapper in `src/temporal/activities.ts` (heartbeat + error classification). `AgentExecutionService` in `src/services/agent-execution.ts` handles the agent lifecycle automatically via the `AGENTS` registry
4. Register activity in `src/temporal/workflows.ts` within the appropriate phase

### Modifying Prompts
- Variable substitution: `{{TARGET_URL}}`, `{{CONFIG_CONTEXT}}`, `{{LOGIN_INSTRUCTIONS}}`
- Shared partials in `prompts/shared/` included via `src/services/prompt-manager.ts`
- Test with `PIPELINE_TESTING=true` for fast iteration

### Key Design Patterns
- **Configuration-Driven** — YAML configs with JSON Schema validation
- **Progressive Analysis** — Each phase builds on previous results
- **SDK-First** — Claude Agent SDK handles autonomous analysis
- **Modular Error Handling** — `ErrorCode` enum, `Result<T,E>` for explicit error propagation, automatic retry (3 attempts per agent)
- **Services Boundary** — Activities are thin Temporal wrappers; `src/services/` owns business logic, accepts `ActivityLogger`, returns `Result<T,E>`. No Temporal imports in services
- **DI Container** — Per-workflow in `src/services/container.ts`. `AuditSession` excluded (parallel safety)

### Security
Defensive security tool only. Use only on systems you own or have explicit permission to test.

## Code Style Guidelines

### Clarity Over Brevity
- Optimize for readability, not line count — three clear lines beat one dense expression
- Use descriptive names that convey intent
- Prefer explicit logic over clever one-liners

### Structure
- Keep functions focused on a single responsibility
- Use early returns and guard clauses instead of deep nesting
- Never use nested ternary operators — use if/else or switch
- Extract complex conditions into well-named boolean variables

### TypeScript Conventions
- Use `function` keyword for top-level functions (not arrow functions)
- Explicit return type annotations on exported/top-level functions
- Prefer `readonly` for data that shouldn't be mutated
- `exactOptionalPropertyTypes` is enabled — use spread for optional props, not direct `undefined` assignment

### Avoid
- Combining multiple concerns into a single function to "save lines"
- Dense callback chains when sequential logic is clearer
- Sacrificing readability for DRY — some repetition is fine if clearer
- Abstractions for one-time operations
- Backwards-compatibility shims, deprecated wrappers, or re-exports for removed code — delete the old code, don't preserve it

### Comments
Comments must be **timeless** — no references to this conversation, refactoring history, or the AI.

**Patterns used in this codebase:**
- `/** JSDoc */` — file headers (after license) and exported functions/interfaces
- `// N. Description` — numbered sequential steps inside function bodies. Use when a
  function has 3+ distinct phases where at least one isn't immediately obvious from the
  code. Each step marks the start of a logical phase. Reference: `AgentExecutionService.execute`
  (steps 1-9) and `injectModelIntoReport` (steps 1-5)
- `// === Section ===` — high-level dividers between groups of functions in long files,
  or to label major branching/classification blocks (e.g., `// === SPENDING CAP SAFEGUARD ===`).
  Not for sequential steps inside function bodies — use numbered steps for that
- `// NOTE:` / `// WARNING:` / `// IMPORTANT:` — gotchas and constraints

**Never:** obvious comments, conversation references ("as discussed"), history ("moved from X")

## Key Files

**Entry Points:** `src/temporal/workflows.ts`, `src/temporal/activities.ts`, `src/temporal/worker.ts`, `src/temporal/client.ts`

**Core Logic:** `src/session-manager.ts`, `src/ai/claude-executor.ts`, `src/config-parser.ts`, `src/services/`, `src/audit/`

**Config:** `donna` (CLI), `docker-compose.yml`, `configs/`, `prompts/`

**Version:** `version.json` (root) — single source of truth for the Donna version, propagated to dashboard and sub-services

## Troubleshooting

- **"Repository not found"** — `REPO` must be a folder name inside `./repos/`, not an absolute path. Clone or symlink your repo there first: `ln -s /path/to/repo ./repos/my-repo`
- **"Temporal not ready"** — Wait for health check or `docker compose logs temporal`
- **Worker not processing** — Check `docker compose ps`
- **Reset state** — `./donna stop CLEAN=true`
- **Local apps unreachable** — Use `host.docker.internal` instead of `localhost`
- **Missing tools** — Use `PIPELINE_TESTING=true` to skip nmap/subfinder/whatweb (graceful degradation)
- **Container permissions** — On Linux, may need `sudo` for docker commands
