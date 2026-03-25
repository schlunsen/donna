# Donna — AI Penetration Testing Framework
# Run `just` to see all available commands

# Default: show available commands
default:
    @just --list --unsorted

# ─── Build ──────────────────────────────────────────────────────────────────────

# Build TypeScript (mcp-server first, then main project)
build:
    cd mcp-server && npm run build
    npm run build

# Build only the MCP server
build-mcp:
    cd mcp-server && npm run build

# Build only the main project (assumes mcp-server already built)
build-main:
    npm run build

# Build the Docker worker image
build-docker:
    docker compose build worker

# Build Docker image without cache (for when code changes aren't picked up)
build-docker-fresh:
    docker compose build --no-cache worker

# Install all dependencies
install:
    npm ci
    cd mcp-server && npm ci

# Clean build artifacts
clean:
    rm -rf dist
    cd mcp-server && rm -rf dist

# Clean and rebuild everything
rebuild: clean install build

# ─── Run ────────────────────────────────────────────────────────────────────────

# Start a pentest workflow (e.g., just start https://example.com my-repo)
start url repo *args:
    ./donna start URL={{url}} REPO={{repo}} {{args}}

# Start with a named workspace (e.g., just start-ws https://example.com my-repo q1-audit)
start-ws url repo workspace *args:
    ./donna start URL={{url}} REPO={{repo}} WORKSPACE={{workspace}} {{args}}

# Start in pipeline testing mode (fast iteration with minimal prompts)
start-test url repo *args:
    ./donna start URL={{url}} REPO={{repo}} PIPELINE_TESTING=true {{args}}

# List all workspaces
workspaces:
    ./donna workspaces

# Tail logs for a specific workflow
logs id:
    ./donna logs ID={{id}}

# Stop all containers (preserves data)
stop:
    ./donna stop

# Stop and remove all data including volumes
stop-clean:
    ./donna stop CLEAN=true

# ─── Sentinel (Continuous Monitoring) ──────────────────────────────────────────

# Start Sentinel continuous scanning (e.g., just sentinel https://example.com ./repos/app --deploy-key ~/.ssh/donna-deploy)
sentinel url repo *args:
    node dist/temporal/continuous-client.js {{url}} {{repo}} {{args}}

# Start Sentinel with a custom schedule (e.g., just sentinel-cron "0 */12 * * *" https://example.com ./repos/app)
sentinel-cron schedule url repo *args:
    node dist/temporal/continuous-client.js {{url}} {{repo}} --schedule "{{schedule}}" {{args}}

# Stop a Sentinel workflow by ID
sentinel-stop id:
    node dist/temporal/continuous-client.js --stop --workflow-id {{id}}

# Show Sentinel scan history
sentinel-history:
    @cat audit-logs/continuous/continuous_scan_history.json 2>/dev/null | python3 -m json.tool || echo "No scan history found"

# Show current Sentinel baseline (tracked findings)
sentinel-baseline:
    @cat audit-logs/continuous/continuous_baseline.json 2>/dev/null | python3 -m json.tool || echo "No baseline found (no scans yet)"

# ─── Docker / Infrastructure ────────────────────────────────────────────────────

# Start all containers in the background
up:
    docker compose up -d --build

# Start only Temporal server
up-temporal:
    docker compose up -d temporal

# Start the dashboard
up-dashboard:
    docker compose up -d dashboard

# Start with router for multi-model support
up-router:
    docker compose --profile router up -d

# View running containers and their status
ps:
    docker compose ps

# Tail worker container logs
worker-logs:
    docker compose logs -f worker

# Tail Temporal server logs
temporal-logs:
    docker compose logs -f temporal

# Tail dashboard logs
dashboard-logs:
    docker compose logs -f dashboard

# Restart the worker (picks up new code after rebuild)
restart-worker:
    docker compose up -d --build worker

# ─── Deploy (production) ───────────────────────────────────────────────────
# DBs are bind-mounted to ./data/ on disk — safe to docker compose down/up.
# Temporal DB: ./data/temporal/temporal.db (owned by UID 1000)
# Dashboard auth DB: ./data/dashboard/auth.db

SERVER := env_var_or_default("DONNA_DEPLOY_SERVER", "root@78.46.219.157")
REMOTE_DIR := "/opt/donna"

RSYNC_EXCLUDES := "--exclude='node_modules' --exclude='.git' --exclude='data' --exclude='dashboard/data' --exclude='audit-logs' --exclude='repos' --exclude='dashboard/node_modules' --exclude='.worktrees' --exclude='.playwright-mcp' --exclude='.env' --exclude='src-tauri' --exclude='site'"

# Deploy dashboard only to production
deploy:
    @echo "🚀 Deploying dashboard to production..."
    rsync -avz {{RSYNC_EXCLUDES}} \
        ./dashboard/ {{SERVER}}:{{REMOTE_DIR}}/dashboard/
    ssh {{SERVER}} "cd {{REMOTE_DIR}} && docker compose build dashboard && docker compose up -d --no-deps dashboard"
    @echo "⏳ Waiting for dashboard to be healthy..."
    ssh {{SERVER}} "cd {{REMOTE_DIR}} && sleep 3 && docker compose ps dashboard"
    @echo "✅ Dashboard deployed!"

# Deploy worker only to production
deploy-worker:
    @echo "🚀 Deploying worker to production..."
    rsync -avz {{RSYNC_EXCLUDES}} \
        --exclude='dashboard' \
        ./ {{SERVER}}:{{REMOTE_DIR}}/
    ssh {{SERVER}} "cd {{REMOTE_DIR}} && docker compose build worker && docker compose up -d --no-deps worker"
    @echo "⏳ Waiting for worker to start..."
    ssh {{SERVER}} "cd {{REMOTE_DIR}} && sleep 3 && docker compose ps worker"
    @echo "✅ Worker deployed!"

# Deploy everything EXCEPT Temporal (safe — preserves DB)
deploy-full:
    @echo "🚀 Full deploy to production (Temporal untouched)..."
    rsync -avz {{RSYNC_EXCLUDES}} \
        ./ {{SERVER}}:{{REMOTE_DIR}}/
    @echo "📦 Building worker + dashboard images..."
    ssh {{SERVER}} "cd {{REMOTE_DIR}} && docker compose build worker dashboard"
    @echo "♻️  Restarting worker + dashboard (Temporal stays running)..."
    ssh {{SERVER}} "cd {{REMOTE_DIR}} && docker compose up -d --no-deps worker dashboard"
    @echo "⏳ Checking service status..."
    ssh {{SERVER}} "cd {{REMOTE_DIR}} && sleep 5 && docker compose ps"
    @echo "✅ Full deploy complete! Temporal DB untouched."

# Show production service status
deploy-status:
    ssh {{SERVER}} "cd {{REMOTE_DIR}} && docker compose ps && echo '---' && docker compose top temporal 2>/dev/null | head -5 && echo '--- Volumes:' && docker volume ls --filter name=donna"

# View production logs (all services)
deploy-logs *args="dashboard":
    ssh {{SERVER}} "cd {{REMOTE_DIR}} && docker compose logs -f {{args}}"

# SSH into the production server
deploy-ssh:
    ssh {{SERVER}}

# Backup production database volumes before risky operations
deploy-backup:
    @echo "💾 Backing up production database volumes..."
    ssh {{SERVER}} "mkdir -p /opt/donna-backups/$(date +%Y%m%d-%H%M%S) && \
        cd {{REMOTE_DIR}} && \
        docker compose exec -T temporal cp /home/temporal/temporal.db /tmp/temporal-backup.db && \
        docker compose cp temporal:/tmp/temporal-backup.db /opt/donna-backups/$(date +%Y%m%d-%H%M%S)/temporal.db && \
        docker compose cp dashboard:/app/data /opt/donna-backups/$(date +%Y%m%d-%H%M%S)/dashboard-data/ 2>/dev/null || true"
    @echo "✅ Backup complete at /opt/donna-backups/ on server"

# Migrate production DB from Docker volumes to disk bind mounts
deploy-migrate-volumes:
    @echo "🔄 Migrating Docker volumes to disk bind mounts..."
    ssh {{SERVER}} "cd {{REMOTE_DIR}} && mkdir -p data/temporal data/dashboard"
    @echo "📦 Copying Temporal DB from volume to disk..."
    ssh {{SERVER}} "cd {{REMOTE_DIR}} && docker compose cp temporal:/home/temporal/. data/temporal/"
    @echo "📦 Copying Dashboard DB from volume to disk..."
    ssh {{SERVER}} "cd {{REMOTE_DIR}} && docker compose cp dashboard:/app/data/. data/dashboard/ 2>/dev/null || echo '  (no dashboard data to migrate)'"
    @echo "🔒 Fixing permissions (Temporal runs as UID 1000)..."
    ssh {{SERVER}} "chown -R 1000:1000 {{REMOTE_DIR}}/data/temporal"
    @echo "🔄 Syncing new docker-compose.yml..."
    rsync -avz ./docker-compose.yml {{SERVER}}:{{REMOTE_DIR}}/docker-compose.yml
    @echo "♻️  Restarting all services with bind mounts..."
    ssh {{SERVER}} "cd {{REMOTE_DIR}} && docker compose down && docker compose up -d"
    @echo "⏳ Waiting for services..."
    ssh {{SERVER}} "cd {{REMOTE_DIR}} && sleep 12 && docker compose ps"
    @echo "✅ Migration complete! DBs now live at {{REMOTE_DIR}}/data/ on disk."
    @echo "   You can safely 'docker compose down && up' without losing data."
    @echo "   Old Docker volumes can be removed with: docker volume rm donna_temporal-data donna_dashboard-data"

# DANGEROUS: Restart Temporal (will briefly interrupt running workflows)
deploy-restart-temporal:
    @echo "⚠️  WARNING: This will restart Temporal. Running workflows will be interrupted."
    @echo "Press Ctrl+C to cancel, or wait 5 seconds to continue..."
    @sleep 5
    ssh {{SERVER}} "cd {{REMOTE_DIR}} && docker compose restart temporal"
    @echo "⏳ Waiting for Temporal to be healthy..."
    ssh {{SERVER}} "cd {{REMOTE_DIR}} && sleep 10 && docker compose ps temporal"

# ─── Dashboard Dev ──────────────────────────────────────────────────────────────

# Run the dashboard in dev mode (hot reload)
dashboard-dev:
    cd dashboard && npm run dev

# Build the dashboard for production
dashboard-build:
    cd dashboard && npm run build

# ─── Development ────────────────────────────────────────────────────────────────

# TypeScript type check without emitting
typecheck:
    npx tsc --noEmit
    cd mcp-server && npx tsc --noEmit

# Watch mode — rebuild on file changes
watch:
    npx tsc --watch

# ─── Audit Logs & Reports ──────────────────────────────────────────────────────

# List audit log directories with sizes
audit-logs:
    @ls -lhd audit-logs/*/ 2>/dev/null || echo "No audit logs found"

# Show the latest workflow log
latest-log:
    @LATEST=$(ls -td audit-logs/*/workflow.log 2>/dev/null | head -1); \
    if [ -n "$LATEST" ]; then tail -100 "$LATEST"; else echo "No workflow logs found"; fi

# Tail the latest workflow log in real-time
tail-latest:
    @LATEST=$(ls -td audit-logs/*/workflow.log 2>/dev/null | head -1); \
    if [ -n "$LATEST" ]; then echo "Tailing $LATEST"; tail -f "$LATEST"; else echo "No workflow logs found"; fi

# Show session summary for a workspace
session workspace:
    @cat audit-logs/{{workspace}}/session.json 2>/dev/null | python3 -m json.tool || echo "Session not found: {{workspace}}"

# ─── Repo Management ───────────────────────────────────────────────────────────

# Import a local directory into ./repos/ for scanning (e.g., just import ~/projects/my-app)
import path name="":
    #!/usr/bin/env bash
    src="{{path}}"
    # Expand ~ manually
    src="${src/#\~/$HOME}"
    if [ ! -d "$src" ]; then echo "Error: $src does not exist"; exit 1; fi
    # Use provided name or derive from directory name
    dest="{{name}}"
    if [ -z "$dest" ]; then dest=$(basename "$src" | tr '.' '-'); fi
    target="./repos/$dest"
    if [ -d "$target" ]; then
        echo "Updating $target ..."
        rsync -a --delete --exclude='.git' --exclude='node_modules' --exclude='.env' "$src/" "$target/"
    else
        echo "Importing $src → $target ..."
        rsync -a --exclude='.git' --exclude='node_modules' --exclude='.env' "$src/" "$target/"
    fi
    echo "✓ Imported to $target (use /repos/$dest in the dashboard)"

# Clone a target repo into ./repos/ (e.g., just clone-repo https://github.com/org/app.git my-app)
clone-repo url name:
    git clone {{url}} ./repos/{{name}}

# List available repos
repos:
    @ls -1 repos/ 2>/dev/null || echo "No repos found. Clone one with: just clone-repo <url> <name>"

# ─── Desktop App (Tauri) ──────────────────────────────────────────────────────

# Setup Tauri development environment (installs Rust, Tauri CLI, dependencies)
tauri-setup:
    bash src-tauri/scripts/setup.sh

# Run the desktop app in development mode
tauri-dev:
    PATH="$HOME/.cargo/bin:$PATH" cargo tauri dev

# Build the desktop app for distribution
tauri-build:
    node src-tauri/scripts/build-sidecars.mjs
    PATH="$HOME/.cargo/bin:$PATH" cargo tauri build

# Build only sidecar binaries (dashboard + worker)
tauri-sidecars:
    node src-tauri/scripts/build-sidecars.mjs

# Generate app icons from a source PNG (e.g., just tauri-icons assets/logo.png)
tauri-icons source:
    bash src-tauri/scripts/generate-icons.sh {{source}}

# ─── Utilities ──────────────────────────────────────────────────────────────────

# Create .env from example template
setup:
    @if [ -f .env ]; then echo ".env already exists"; else cp .env.example .env && echo "Created .env — edit it with your API key"; fi

# Open the Temporal Web UI in the browser
temporal-ui:
    open http://localhost:8233 2>/dev/null || xdg-open http://localhost:8233 2>/dev/null || echo "Open http://localhost:8233"

# Open the Donna Dashboard in the browser
dashboard-ui:
    open http://localhost:4321 2>/dev/null || xdg-open http://localhost:4321 2>/dev/null || echo "Open http://localhost:4321"

# Check if required tools are installed
doctor:
    @echo "Checking dependencies..."
    @command -v docker >/dev/null 2>&1 && echo "✓ docker $(docker --version 2>/dev/null | head -1)" || echo "✗ docker not found"
    @command -v node >/dev/null 2>&1 && echo "✓ node $(node --version)" || echo "✗ node not found"
    @command -v npm >/dev/null 2>&1 && echo "✓ npm $(npm --version)" || echo "✗ npm not found"
    @command -v just >/dev/null 2>&1 && echo "✓ just $(just --version)" || echo "✗ just not found"
    @command -v rustc >/dev/null 2>&1 && echo "✓ rustc $(rustc --version)" || echo "○ rustc not found (optional — needed for desktop app)"
    @command -v cargo >/dev/null 2>&1 && cargo install --list 2>/dev/null | grep -q "tauri-cli" && echo "✓ tauri-cli installed" || echo "○ tauri-cli not found (optional — run: just tauri-setup)"
    @[ -f .env ] && echo "✓ .env file exists" || echo "✗ .env file missing (run: just setup)"
    @docker compose ps --format '{{{{.Name}} {{{{.Status}}' 2>/dev/null | head -5 || echo "  (no containers running)"
