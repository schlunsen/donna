// @ts-check
import { defineConfig } from 'astro/config';
import node from '@astrojs/node';

// https://astro.build/config
export default defineConfig({
  output: 'server',
  adapter: node({
    mode: 'standalone',
  }),
  // Base path (default: root — use a subdomain instead of sub-path)
  base: '/',
  server: {
    port: 4321,
    host: '0.0.0.0',
  },
  // Disable Astro's built-in CSRF origin check — reverse proxy
  // forwards requests causing origin mismatch.
  // Auth is handled by Better Auth (Google OAuth).
  security: {
    checkOrigin: false,
  },
});
