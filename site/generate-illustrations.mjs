#!/usr/bin/env node
/**
 * Generate illustrations for Donna landing page using Hugging Face Inference API
 */
import { writeFile } from 'fs/promises';
import { join } from 'path';

const HF_TOKEN = process.env.HF_TOKEN;
if (!HF_TOKEN) {
  console.error('ERROR: HF_TOKEN environment variable not set');
  process.exit(1);
}

const MODEL = 'black-forest-labs/FLUX.1-schnell';
const OUTPUT_DIR = join(import.meta.dirname, 'public', 'illustrations');

async function generateImage(prompt, filename) {
  console.log(`Generating: ${filename}...`);
  console.log(`  Prompt: "${prompt}"`);

  const response = await fetch(
    `https://router.huggingface.co/hf-inference/models/${MODEL}`,
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${HF_TOKEN}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        inputs: prompt,
        parameters: {
          width: 1024,
          height: 576,
          num_inference_steps: 4,
        },
      }),
    }
  );

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`HF API error (${response.status}): ${errorText}`);
  }

  const buffer = Buffer.from(await response.arrayBuffer());
  const outputPath = join(OUTPUT_DIR, filename);
  await writeFile(outputPath, buffer);
  console.log(`  Saved: ${outputPath} (${(buffer.length / 1024).toFixed(0)} KB)`);
  return outputPath;
}

const illustrations = [
  {
    prompt: 'A futuristic cybersecurity command center with holographic displays showing network maps and vulnerability scans, dark purple and blue neon lighting, cinematic wide angle, digital art, highly detailed, no text',
    filename: 'hero-illustration.png',
  },
  {
    prompt: 'An army of sleek autonomous AI robots patrolling a digital fortress, scanning for vulnerabilities with laser beams, dark cyberpunk aesthetic with purple and teal glow, digital art, wide angle cinematic, no text',
    filename: 'agents-illustration.png',
  },
  {
    prompt: 'A stylized four-stage pipeline flowing left to right: reconnaissance radar, analysis magnifying glass, exploitation lightning bolt, report document, connected by glowing purple energy streams, dark background, digital art, icon style, no text',
    filename: 'pipeline-illustration.png',
  },
  {
    prompt: 'A futuristic AI shield protecting a server room from incoming cyber attacks, glowing purple force field, dramatic lighting, cyberpunk digital art style, wide cinematic shot, no text',
    filename: 'cta-illustration.png',
  },
];

// Create output directory
import { mkdir } from 'fs/promises';
await mkdir(OUTPUT_DIR, { recursive: true });

console.log(`\nGenerating ${illustrations.length} illustrations using ${MODEL}...\n`);

// Generate sequentially to avoid rate limits
for (const img of illustrations) {
  try {
    await generateImage(img.prompt, img.filename);
  } catch (err) {
    console.error(`  FAILED: ${err.message}`);
  }
}

console.log('\nDone!');
