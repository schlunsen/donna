// Donna - Continuous AI Pentesting Platform
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * URL validation utilities — prevents SSRF by restricting webUrl to safe
 * schemes and blocking internal/private IP addresses.
 */

// Private/internal IP ranges that should never be targeted
const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'temporal',       // Docker internal service
  'worker',
  'dashboard',
  'metadata.google.internal',
]);

/**
 * Check if an IP address is in a private/internal range.
 */
function isPrivateIP(hostname: string): boolean {
  // IPv4 private ranges
  if (/^127\./.test(hostname)) return true;                          // Loopback
  if (/^10\./.test(hostname)) return true;                           // Class A private
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(hostname)) return true;     // Class B private
  if (/^192\.168\./.test(hostname)) return true;                     // Class C private
  if (/^169\.254\./.test(hostname)) return true;                     // Link-local / AWS metadata
  if (/^0\./.test(hostname)) return true;                            // "This" network
  if (hostname === '0.0.0.0') return true;

  // IPv6 private ranges
  if (hostname === '::1' || hostname === '[::1]') return true;       // Loopback
  if (/^f[cd]/i.test(hostname)) return true;                         // Unique local
  if (/^fe80/i.test(hostname)) return true;                          // Link-local

  return false;
}

/**
 * Validate a webUrl for safety. Returns null if valid, or an error message.
 *
 * Security checks:
 * - Only http:// and https:// schemes allowed (blocks file://, gopher://, etc.)
 * - Blocks private/internal IP addresses (prevents SSRF to cloud metadata, Docker services)
 * - Blocks known internal Docker service hostnames
 */
export function validateWebUrl(webUrl: string): string | null {
  let parsed: URL;
  try {
    parsed = new URL(webUrl);
  } catch {
    return 'Invalid URL format';
  }

  // Only allow http and https schemes
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return `Scheme "${parsed.protocol}" is not allowed. Use http:// or https://`;
  }

  // Block internal/private hostnames
  const hostname = parsed.hostname.toLowerCase();

  if (BLOCKED_HOSTNAMES.has(hostname)) {
    return `Hostname "${hostname}" is not allowed`;
  }

  if (isPrivateIP(hostname)) {
    return `Private/internal IP addresses are not allowed`;
  }

  // Block URLs with credentials
  if (parsed.username || parsed.password) {
    return 'URLs with embedded credentials are not allowed';
  }

  return null;
}
