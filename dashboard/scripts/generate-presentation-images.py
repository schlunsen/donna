#!/usr/bin/env python3
"""
Generate illustrations for the Donna presentation slides using HF Inference API.
Uses FLUX.1-schnell (free tier, no token needed) via HuggingFace Spaces.

Output: public/presentation-images/slide-*.png
"""

import requests
import time
import json
import base64
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIR = BASE_DIR / "public" / "presentation-images"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# Use the free black-forest-labs FLUX Spaces API
FLUX_API = "https://black-forest-labs-flux-1-schnell.hf.space/gradio_api"

# Common style suffix for all prompts — classy, dark, presentation-ready
STYLE = (
    "dark moody background, deep purple and dark blue tones, "
    "subtle neon glow accents, cinematic lighting, ultra clean, "
    "minimalist professional illustration, no text, no words, no letters, "
    "4k, sharp focus, dark theme matching #0a0a14 background"
)

# Slide illustrations to generate
SLIDES = {
    "slide-01-title": (
        "A sleek futuristic shield icon floating in dark space, "
        "glowing purple energy circuits running through it, "
        "AI neural network patterns emanating from the shield, "
        "cybersecurity concept art, abstract and elegant, " + STYLE
    ),
    "slide-02-problem": (
        "A cracked and broken digital shield shattering into fragments, "
        "red warning glitches and error symbols floating around it, "
        "digital decay and vulnerability concept, "
        "sense of urgency and danger, " + STYLE
    ),
    "slide-03-agents": (
        "13 glowing AI orbs connected by purple light beams in a constellation pattern, "
        "each orb pulsing with different colored energy — blue, gold, red, green, "
        "orchestrated swarm intelligence concept, "
        "floating in dark cyberspace, " + STYLE
    ),
    "slide-04-pipeline": (
        "A horizontal flow of 4 connected glowing nodes forming a pipeline, "
        "data streams flowing between them like liquid light, "
        "from reconnaissance to analysis to exploitation to reporting, "
        "abstract tech pipeline visualization, " + STYLE
    ),
    "slide-05-docker": (
        "Multiple transparent glass cubes stacked in a grid, each containing "
        "a glowing AI brain or circuit board, sandboxed containers concept, "
        "observe-plan-execute-verify cycle shown as orbital rings, "
        "isolated computing environments, " + STYLE
    ),
    "slide-06-temporal": (
        "An elegant timeline visualization with glowing checkpoints, "
        "workflow orchestration concept with branching paths that reconverge, "
        "durable execution metaphor — a river of data that flows around obstacles, "
        "abstract and architectural, " + STYLE
    ),
    "slide-07-dashboard": (
        "A futuristic holographic dashboard floating in space, "
        "showing security metrics and threat indicators, "
        "glowing purple and blue interface elements, real-time monitoring concept, "
        "sci-fi command center aesthetic, " + STYLE
    ),
    "slide-09-cta": (
        "A completed shield reassembled and glowing with strong purple light, "
        "green checkmark energy pattern visible inside, "
        "victory and security achieved concept, triumphant and confident mood, "
        "the shield now protected and whole, " + STYLE
    ),
}


def generate_with_gradio_api(prompt: str, output_path: Path) -> bool:
    """Generate image using FLUX.1-schnell via Gradio API."""
    print(f"  Generating: {output_path.name}")

    try:
        # Submit job
        resp = requests.post(
            f"{FLUX_API}/call/infer",
            json={
                "data": [
                    prompt,    # prompt
                    0,         # seed (0 = random)
                    True,      # randomize_seed
                    1024,      # width
                    1024,      # height
                    4,         # num_inference_steps
                ]
            },
            headers={"Content-Type": "application/json"},
            timeout=30,
        )
        resp.raise_for_status()
        event_id = resp.json().get("event_id")
        if not event_id:
            print(f"    ERROR: No event_id returned")
            return False

        print(f"    Job submitted: {event_id}")

        # Poll for result
        result_resp = requests.get(
            f"{FLUX_API}/call/infer/{event_id}",
            stream=True,
            timeout=120,
        )

        result_data = None
        for line in result_resp.iter_lines():
            line = line.decode("utf-8")
            if line.startswith("data: "):
                result_data = json.loads(line[6:])
                break

        if not result_data:
            print(f"    ERROR: No result data")
            return False

        # result_data is like [{"url": "...", "path": "..."}, seed]
        image_info = result_data[0]
        if isinstance(image_info, dict) and "url" in image_info:
            image_url = image_info["url"]
        elif isinstance(image_info, dict) and "path" in image_info:
            image_url = f"{FLUX_API}/file={image_info['path']}"
        else:
            print(f"    ERROR: Unexpected result format: {result_data}")
            return False

        # Download image
        img_resp = requests.get(image_url, timeout=60)
        img_resp.raise_for_status()

        output_path.write_bytes(img_resp.content)
        size_kb = len(img_resp.content) / 1024
        print(f"    OK — {size_kb:.0f} KB")
        return True

    except Exception as e:
        print(f"    ERROR: {e}")
        return False


def main():
    print("=" * 60)
    print("Generating presentation illustrations with FLUX.1-schnell")
    print("=" * 60)

    for name, prompt in SLIDES.items():
        output_path = OUTPUT_DIR / f"{name}.webp"
        # Save as PNG first, convert later if needed
        png_path = OUTPUT_DIR / f"{name}.png"

        if png_path.exists():
            print(f"  SKIP (exists): {name}")
            continue

        success = generate_with_gradio_api(prompt, png_path)
        if not success:
            print(f"  FAILED: {name}")

        # Rate limit: be polite to the free API
        time.sleep(2)

    print()
    print("Done! Images saved to:", OUTPUT_DIR)


if __name__ == "__main__":
    main()
