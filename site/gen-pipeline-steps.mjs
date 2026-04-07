#!/usr/bin/env node
import { writeFile, mkdir } from 'fs/promises';
import { join } from 'path';

const HF_TOKEN = process.env.HF_TOKEN;
const MODEL = 'black-forest-labs/FLUX.1-schnell';
const OUTPUT_DIR = join(import.meta.dirname, 'public', 'illustrations');

async function generateImage(prompt, filename) {
  console.log(`Generating: ${filename}...`);
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
        parameters: { width: 512, height: 512, num_inference_steps: 4 },
      }),
    }
  );
  if (!response.ok) throw new Error(`HF API error (${response.status}): ${await response.text()}`);
  const buffer = Buffer.from(await response.arrayBuffer());
  const outputPath = join(OUTPUT_DIR, filename);
  await writeFile(outputPath, buffer);
  console.log(`  Saved: ${outputPath} (${(buffer.length / 1024).toFixed(0)} KB)`);
}

await mkdir(OUTPUT_DIR, { recursive: true });

const steps = [
  {
    prompt: 'A glowing blue radar dish scanning the horizon in a dark cyberpunk environment, digital waves emanating outward, neon blue and purple tones, dark background, centered composition, digital art icon style, no text no words',
    filename: 'step-recon.png',
  },
  {
    prompt: 'A glowing magnifying glass hovering over lines of code revealing hidden vulnerabilities highlighted in red, dark cyberpunk environment, neon green and purple tones, dark background, centered composition, digital art, no text no words',
    filename: 'step-analysis.png',
  },
  {
    prompt: 'A dramatic red lightning bolt striking through a digital firewall shield, shattered fragments flying, dark cyberpunk environment, neon red and orange tones on dark background, centered composition, digital art, no text no words',
    filename: 'step-exploit.png',
  },
  {
    prompt: 'A holographic floating document report with charts and security findings, glowing data visualizations, dark cyberpunk environment, neon teal and purple tones, dark background, centered composition, digital art, no text no words',
    filename: 'step-report.png',
  },
];

for (const step of steps) {
  await generateImage(step.prompt, step.filename);
}
console.log('\nDone!');
