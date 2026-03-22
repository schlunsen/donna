// Donna - Continuous AI Pentesting Platform
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { readFileSync } from 'fs';
import { resolve } from 'path';

/**
 * Reads the project version from the central version.json file.
 * This is the single source of truth for the Donna version across all sub-services.
 *
 * Searches multiple candidate paths to work in both local dev and Docker containers.
 */
export function getVersion(): string {
    const candidates = [
        // Docker container: version.json copied to /app/version.json
        '/app/version.json',
        // Local dev: relative to project root (dashboard/../version.json)
        resolve(import.meta.dirname, '../../../../version.json'),
        // Alt local dev path
        resolve(import.meta.dirname, '../../../version.json'),
    ];

    for (const candidate of candidates) {
        try {
            const data = JSON.parse(readFileSync(candidate, 'utf-8'));
            if (data.version) {
                return data.version;
            }
        } catch {
            // Try next candidate
        }
    }

    return '0.0.0';
}
