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
import { existsSync, mkdirSync, copyFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { platform, arch } from "node:os";

const ROOT = resolve(import.meta.dirname, "../..");
const TAURI_DIR = resolve(import.meta.dirname, "..");
const SIDECARS_DIR = join(TAURI_DIR, "sidecars");

// Tauri expects sidecar binaries named with a platform triple suffix
function getPlatformTriple() {
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

  // Step 2: Package with @yao-pkg/pkg
  // The Astro standalone adapter outputs to dist/server/entry.mjs
  const entryPoint = join(dashboardDir, "dist", "server", "entry.mjs");

  if (!existsSync(entryPoint)) {
    throw new Error(
      `Dashboard entry point not found: ${entryPoint}\n` +
        "Make sure the Astro build completed successfully with the Node adapter.",
    );
  }

  const triple = getPlatformTriple();
  const outputName = `donna-dashboard-${triple}`;
  const outputPath = join(SIDECARS_DIR, outputName);

  // Use pkg to create a standalone binary
  console.log("  Packaging with pkg...");
  run(
    `npx --yes @yao-pkg/pkg "${entryPoint}" ` +
      `--target node22-${platform()}-${arch()} ` +
      `--output "${outputPath}" ` +
      `--compress GZip`,
  );

  console.log(`  ✅ Dashboard sidecar: ${outputPath}`);
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
  console.log("  Packaging with pkg...");
  run(
    `npx --yes @yao-pkg/pkg "${entryPoint}" ` +
      `--target node22-${platform()}-${arch()} ` +
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
