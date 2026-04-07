#!/usr/bin/env node
import { writeFile } from 'fs/promises';
import { join } from 'path';

const HF_TOKEN = process.env.HF_TOKEN;
const MODEL = 'black-forest-labs/FLUX.1-schnell';
const OUTPUT = join(import.meta.dirname, 'public', 'illustrations', 'pipeline-illustration.png');

const prompt = 'A cinematic wide digital art illustration of a cybersecurity attack chain, four glowing stages connected by purple energy beams on a dark background: a radar dish scanning with blue waves, a magnifying glass analyzing code with green highlights, a red lightning bolt striking a firewall with sparks, and a holographic report floating with data charts. Dark cyberpunk aesthetic, neon purple and blue tones, no text no words no letters, highly detailed, wide aspect ratio';

console.log('Generating improved pipeline illustration...');

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
      parameters: { width: 1024, height: 576, num_inference_steps: 4 },
    }),
  }
);

if (!response.ok) {
  const err = await response.text();
  throw new Error(`HF API error (${response.status}): ${err}`);
}

const buffer = Buffer.from(await response.arrayBuffer());
await writeFile(OUTPUT, buffer);
console.log(`Saved: ${OUTPUT} (${(buffer.length / 1024).toFixed(0)} KB)`);
