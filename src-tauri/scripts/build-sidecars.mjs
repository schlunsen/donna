#!/usr/bin/env node

/**
 * Build Donna sidecars for Tauri.
 *
 * This script packages the Astro SSR dashboard and the Temporal worker
 * as standalone Node.js executables using Node.js SEA (Single Executable
 * Application) or @yao-pkg/pkg as a fallback.
 *
 * The resulting binaries are placed in src-tauri/sidecars/ with the
 * platform-specific suffix that Tauri expects.
 */

import { execSync } from "node:child_process";
import { existsSync, mkdirSync, copyFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { platform, arch } from "node:os";

const ROOT = resolve(import.meta.dirname, "../..");
const TAURI_DIR = resolve(import.meta.dirname, "..");
const SIDECARS_DIR = join(TAURI_DIR, "sidecars");

// Tauri expects sidecar binaries named with a platform triple suffix.
// Allow override via TAURI_TARGET env var (set by CI for cross-compilation).
function getPlatformTriple() {
  if (process.env.TAURI_TARGET) {
    return process.env.TAURI_TARGET;
  }

  const p = platform();
  const a = arch();

  const archMap = {
    x64: "x86_64",
    arm64: "aarch64",
    ia32: "i686",
  };

  const osMap = {
    darwin: "apple-darwin",
    linux: "unknown-linux-gnu",
    win32: "pc-windows-msvc",
  };

  const mappedArch = archMap[a] || a;
  const mappedOs = osMap[p] || p;

  return `${mappedArch}-${mappedOs}`;
}

function run(cmd, opts = {}) {
  console.log(`  $ ${cmd}`);
  execSync(cmd, { stdio: "inherit", ...opts });
}

// Environment variables needed for the dashboard build.
// BETTER_AUTH_SECRET is validated at import time by auth.ts — we provide a
// build-time placeholder so the Astro SSR build succeeds. The real secret
// is injected at runtime via Tauri's Stronghold plugin or env vars.
const dashboardBuildEnv = {
  ...process.env,
  BETTER_AUTH_SECRET:
    process.env.BETTER_AUTH_SECRET ||
    "tauri-build-placeholder-secret-not-used-at-runtime-0000",
};

function buildDashboardSidecar() {
  console.log("\n📦 Building Dashboard sidecar...\n");

  const dashboardDir = join(ROOT, "dashboard");

  // Step 1: Build the Astro SSR app
  // Provide BETTER_AUTH_SECRET so auth.ts doesn't process.exit(1) during build
  console.log("  Building Astro SSR...");
  run("npm run build", { cwd: dashboardDir, env: dashboardBuildEnv });

  const entryPoint = join(dashboardDir, "dist", "server", "entry.mjs");

  if (!existsSync(entryPoint)) {
    throw new Error(
      `Dashboard entry point not found: ${entryPoint}\n` +
        "Make sure the Astro build completed successfully with the Node adapter.",
    );
  }

  // Instead of pkg (which can't handle Astro's dynamic ESM chunk imports),
  // create a shell script wrapper that runs the Astro SSR server via Node.js.
  // The dashboard dist/ folder is bundled as a Tauri resource.
  const triple = getPlatformTriple();
  const outputName = `donna-dashboard-${triple}`;
  const outputPath = join(SIDECARS_DIR, outputName);

  console.log("  Creating dashboard launcher script...");

  // Create a shell script that finds node and runs the Astro entry point
  const scriptContent = `#!/bin/bash
# Donna Dashboard Launcher — runs the Astro SSR server
# This script is invoked by Tauri as a sidecar

# Find node binary (macOS GUI apps don't inherit shell PATH)
find_node() {
  for candidate in \\
    "$HOME/.nvm/versions/node/"*/bin/node \\
    /usr/local/bin/node \\
    /opt/homebrew/bin/node \\
    /usr/bin/node \\
    node; do
    if [ -x "$candidate" ] 2>/dev/null; then
      echo "$candidate"
      return
    fi
  done
  # Last resort: try to source nvm
  if [ -s "$HOME/.nvm/nvm.sh" ]; then
    . "$HOME/.nvm/nvm.sh" 2>/dev/null
    command -v node 2>/dev/null && return
  fi
  echo "node"
}

NODE=$(find_node)

# Resolve the dashboard dist directory relative to this script
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# In Tauri bundle: Contents/MacOS/donna-dashboard → Contents/Resources/dashboard-dist/
DASHBOARD_DIR="$SCRIPT_DIR/../Resources/dashboard-dist"

if [ ! -d "$DASHBOARD_DIR" ]; then
  # Development fallback: script is at src-tauri/sidecars/donna-dashboard
  DASHBOARD_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)/dashboard/dist"
fi

if [ ! -d "$DASHBOARD_DIR" ]; then
  # Also try the bundled copy next to sidecars
  DASHBOARD_DIR="$SCRIPT_DIR/../dashboard-dist"
fi

if [ ! -f "$DASHBOARD_DIR/server/entry.mjs" ]; then
  echo "ERROR: Dashboard dist not found at $DASHBOARD_DIR" >&2
  exit 1
fi

exec "$NODE" "$DASHBOARD_DIR/server/entry.mjs"
`;

  writeFileSync(outputPath, scriptContent, { mode: 0o755 });

  // Also copy the dashboard dist folder to the sidecars area for bundling
  const dashboardDistSrc = join(dashboardDir, "dist");
  const dashboardDistDest = join(TAURI_DIR, "dashboard-dist");

  // Remove old copy
  if (existsSync(dashboardDistDest)) {
    run(`rm -rf "${dashboardDistDest}"`);
  }

  console.log("  Copying dashboard dist for bundling...");
  run(`cp -R "${dashboardDistSrc}" "${dashboardDistDest}"`);

  console.log(`  ✅ Dashboard sidecar: ${outputPath} (+ dashboard-dist/)`);
}

function buildWorkerSidecar() {
  console.log("\n📦 Building Worker sidecar...\n");

  // Step 1: Build the TypeScript project
  console.log("  Building TypeScript...");
  run("npm run build", { cwd: ROOT });

  // Step 2: Package the worker entry point
  const entryPoint = join(ROOT, "dist", "temporal", "worker.js");

  if (!existsSync(entryPoint)) {
    throw new Error(
      `Worker entry point not found: ${entryPoint}\n` +
        "Make sure the TypeScript build completed successfully.",
    );
  }

  const triple = getPlatformTriple();
  const outputName = `donna-worker-${triple}`;
  const outputPath = join(SIDECARS_DIR, outputName);

  // Use pkg to create a standalone binary
  // Map the target triple back to pkg's platform/arch format
  const pkgPlatform = platform() === "win32" ? "win" : platform() === "darwin" ? "macos" : "linux";
  const pkgArch = arch() === "arm64" ? "arm64" : "x64";
  console.log("  Packaging with pkg...");
  run(
    `npx --yes @yao-pkg/pkg "${entryPoint}" ` +
      `--target node22-${pkgPlatform}-${pkgArch} ` +
      `--output "${outputPath}" ` +
      `--compress GZip`,
  );

  console.log(`  ✅ Worker sidecar: ${outputPath}`);
}

// --- Main ---
console.log("🔨 Building Donna sidecars for Tauri");
console.log(`   Platform: ${getPlatformTriple()}`);

// Ensure sidecars directory exists
mkdirSync(SIDECARS_DIR, { recursive: true });

try {
  buildDashboardSidecar();
  buildWorkerSidecar();
  console.log("\n✅ All sidecars built successfully!\n");
} catch (error) {
  console.error(`\n❌ Sidecar build failed: ${error.message}\n`);
  process.exit(1);
}
