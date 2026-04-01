// Donna - Continuous AI Pentesting Platform
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * LLM provider settings — persisted in data/llm-settings.json.
 *
 * These settings configure local/custom LLM providers (e.g. Qwen via vLLM)
 * and are editable from the Settings page in the web UI.
 */

import fs from 'node:fs/promises';
import path from 'node:path';

const DATA_DIR = process.env.AUTH_DB_DIR || path.join(process.cwd(), 'data');
const SETTINGS_FILE = path.join(DATA_DIR, 'llm-settings.json');

/** Configuration for a single LLM provider. */
export interface LlmProviderSettings {
  /** Whether this provider is enabled and available in the scan dialog. */
  enabled: boolean;
  /** Base URL for the OpenAI-compatible API (e.g. http://host.docker.internal:8000). */
  baseUrl: string;
  /** API key (stored directly — for local models this is often a dummy value). */
  apiKey: string;
  /** Model ID for all tiers (e.g. Qwen/Qwen3.5-35B-A3B-FP8). */
  model: string;
}

/** Top-level LLM settings object. */
export interface LlmSettings {
  providers: {
    'qwen-local': LlmProviderSettings;
  };
}

const DEFAULT_SETTINGS: LlmSettings = {
  providers: {
    'qwen-local': {
      enabled: false,
      baseUrl: 'http://host.docker.internal:8000',
      apiKey: '',
      model: 'Qwen/Qwen3.5-35B-A3B-FP8',
    },
  },
};

/** Load LLM settings from disk, returning defaults if the file doesn't exist. */
export async function loadLlmSettings(): Promise<LlmSettings> {
  try {
    const raw = await fs.readFile(SETTINGS_FILE, 'utf-8');
    const parsed = JSON.parse(raw) as Partial<LlmSettings>;
    // Merge with defaults so new fields are always present
    return {
      providers: {
        'qwen-local': {
          ...DEFAULT_SETTINGS.providers['qwen-local'],
          ...parsed.providers?.['qwen-local'],
        },
      },
    };
  } catch {
    return { ...DEFAULT_SETTINGS };
  }
}

/** Save LLM settings to disk. */
export async function saveLlmSettings(settings: LlmSettings): Promise<void> {
  await fs.mkdir(DATA_DIR, { recursive: true });
  await fs.writeFile(SETTINGS_FILE, JSON.stringify(settings, null, 2), 'utf-8');
}

/**
 * Build a ModelProfile object from saved LLM settings for a given provider.
 * Returns undefined if the provider is not enabled or not configured.
 */
export async function getModelProfileFromSettings(
  providerName: string
): Promise<{ base_url: string; api_key: string; tiers: { small: string; medium: string; large: string } } | undefined> {
  const settings = await loadLlmSettings();
  const provider = (settings.providers as Record<string, LlmProviderSettings | undefined>)[providerName];

  if (!provider?.enabled || !provider.baseUrl || !provider.model) {
    return undefined;
  }

  return {
    base_url: provider.baseUrl,
    api_key: provider.apiKey,
    tiers: {
      small: provider.model,
      medium: provider.model,
      large: provider.model,
    },
  };
}
