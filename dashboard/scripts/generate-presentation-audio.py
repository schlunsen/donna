#!/usr/bin/env python3
"""
Generate narration audio for the Donna presentation slides.
Uses Qwen3-TTS via HuggingFace Spaces FastAPI endpoint (same as the-agentic-crew).

Output: public/presentation-audio/slide-{01..09}.mp3

Usage:
    python scripts/generate-presentation-audio.py
"""

import base64
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

import requests

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIR = BASE_DIR / "public" / "presentation-audio"

# British woman voice reference (public domain, LibriVox Pride and Prejudice narrator)
CUSTOM_REF_AUDIO = BASE_DIR / "assets" / "voice-ref-british-woman.wav"

CUSTOM_REF_TEXT = (
    "My dear Mr Bennet, said his lady to him one day, "
    "have you heard that Nestle"
)

FASTAPI_BASE = "https://huggingfacem4-faster-qwen3-tts-demo.hf.space"
MAX_RETRIES = 5
INITIAL_BACKOFF = 10
SPEED = 0.92

HAS_FFMPEG = shutil.which("ffmpeg") is not None

# ---------------------------------------------------------------------------
# Narration scripts for 9 slides
# ---------------------------------------------------------------------------

SLIDE_NARRATIONS = {
    1: (
        "Welcome to Donna. "
        "Donna is an AI-powered pentesting platform that uses thirteen specialized agents "
        "to find vulnerabilities in your infrastructure. Automatically. Thoroughly. "
        "Let me show you how it works."
    ),
    2: (
        "What if security testing never sleeps? "
        "Attackers don't wait. Automated bots scan the internet twenty-four seven. "
        "New vulnerabilities are weaponized within hours of disclosure. "
        "That security assessment from last quarter? It's already obsolete. "
        "Meanwhile, there are three and a half million unfilled cybersecurity positions globally. "
        "The few experts available are overwhelmed and expensive. "
        "But large language models change the equation. "
        "They can reason about code, craft payloads, and chain vulnerabilities — "
        "the same creative thinking that makes great pentesters, now available on demand."
    ),
    3: (
        "Traditional penetration testing has a problem. "
        "It's slow, taking weeks per engagement. It's expensive, often costing "
        "tens of thousands of dollars. And it's inconsistent, with human testers "
        "missing up to sixty percent of vulnerabilities. "
        "There has to be a better way."
    ),
    4: (
        "Meet Donna's agent army. Thirteen specialized AI agents, each powered by Claude, "
        "working together to think like a hacker. "
        "Recon agents handle port scanning and technology detection. "
        "Analysis agents identify vulnerabilities across all attack surfaces. "
        "Exploit agents validate findings with proof-of-concept attacks. "
        "And the report agent structures everything into actionable findings."
    ),
    5: (
        "The pentesting pipeline runs in four phases. "
        "First, reconnaissance: target enumeration, port scanning, and technology detection. "
        "Second, analysis: vulnerability scanning and attack surface mapping. "
        "Third, exploitation: proof-of-concept validation with controlled payloads. "
        "And fourth, reporting: structured findings with severity ratings and remediation guidance. "
        "All fully automated. All durable."
    ),
    6: (
        "Each agent follows a simple but powerful loop. Observe, plan, execute, verify, repeat. "
        "They run inside isolated Docker containers with controlled tooling. "
        "No hallucinated findings. Every vulnerability is verified with real evidence. "
        "This is what separates Donna from simple vulnerability scanners."
    ),
    7: (
        "Under the hood, Donna is powered by Temporal, "
        "an open-source durable execution engine. "
        "Workflows survive crashes, network failures, and restarts. "
        "Every step is checkpointed. If something fails, it retries automatically. "
        "You get a full audit trail and real-time observability into every workflow."
    ),
    8: (
        "The Donna dashboard gives you real-time visibility into every workflow. "
        "Monitor running scans, track findings, filter by severity. "
        "See which targets have been tested, how long each scan took, "
        "and what critical vulnerabilities were found. All in one place."
    ),
    9: (
        "Every finding comes with structure. "
        "Severity ratings from critical to informational. "
        "Real evidence, like the exact HTTP request that triggered a vulnerability. "
        "CVSS scores for prioritization. And actionable remediation steps "
        "so your team knows exactly what to fix and how."
    ),
    10: (
        "Donna. Thirteen AI agents. Temporal orchestration. Full reports. "
        "Secure your infrastructure automatically. "
        "Start a scan with a single command, and let the agents do what they do best. "
        "Find every vulnerability before attackers do."
    ),
}

# ---------------------------------------------------------------------------
# TTS generation
# ---------------------------------------------------------------------------

def tts_generate(text: str) -> bytes:
    """Call the faster-qwen3-tts FastAPI mirror with voice cloning and return WAV bytes."""
    form_data = {
        "text": text,
        "ref_text": CUSTOM_REF_TEXT,
    }

    use_custom_ref = CUSTOM_REF_AUDIO.exists()

    if not use_custom_ref:
        form_data["ref_preset"] = "ref_audio_3"
        print("  WARNING: No custom voice reference found, using default preset")

    backoff = INITIAL_BACKOFF
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            files = None
            if use_custom_ref:
                files = {"ref_audio": ("ref.wav", open(CUSTOM_REF_AUDIO, "rb"), "audio/wav")}

            resp = requests.post(
                f"{FASTAPI_BASE}/generate",
                data=form_data,
                files=files,
                timeout=300,
            )
            if resp.status_code == 429 or resp.status_code >= 500:
                raise RuntimeError(f"HTTP {resp.status_code}: {resp.text[:200]}")
            resp.raise_for_status()

            result = resp.json()
            if "audio_b64" in result:
                return base64.b64decode(result["audio_b64"])
            else:
                raise RuntimeError(f"No audio_b64 in response: {list(result.keys())}")

        except Exception as e:
            print(f"  [attempt {attempt}/{MAX_RETRIES}] Error: {e}")
            if attempt < MAX_RETRIES:
                print(f"  Retrying in {backoff}s ...")
                time.sleep(backoff)
                backoff = min(backoff * 2, 120)
            else:
                raise RuntimeError(f"Failed after {MAX_RETRIES} attempts: {e}")


def wav_to_mp3(wav_path: Path, mp3_path: Path):
    """Convert WAV to MP3 using ffmpeg."""
    subprocess.run(
        ["ffmpeg", "-y", "-i", str(wav_path), "-codec:a", "libmp3lame", "-qscale:a", "2", str(mp3_path)],
        check=True, capture_output=True,
    )


def slow_down_audio(input_path: Path, output_path: Path, speed: float = SPEED):
    """Slow down audio using atempo filter."""
    subprocess.run(
        ["ffmpeg", "-y", "-i", str(input_path),
         "-af", f"atempo={speed}",
         "-codec:a", "libmp3lame", "-qscale:a", "2",
         str(output_path)],
        check=True, capture_output=True,
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print("Donna Presentation Audio Generator")
    print(f"  Voice ref: {CUSTOM_REF_AUDIO} ({'exists' if CUSTOM_REF_AUDIO.exists() else 'MISSING'})")
    print(f"  Output:    {OUTPUT_DIR}")
    print(f"  ffmpeg:    {'available' if HAS_FFMPEG else 'NOT available'}")
    print(f"  Speed:     {SPEED}x")
    print()

    for slide_num in sorted(SLIDE_NARRATIONS.keys()):
        text = SLIDE_NARRATIONS[slide_num]
        mp3_path = OUTPUT_DIR / f"slide-{slide_num:02d}.mp3"

        if mp3_path.exists() and mp3_path.stat().st_size > 1000:
            print(f"  Slide {slide_num:2d}: already exists ({mp3_path.stat().st_size / 1024:.0f} KB), skipping")
            continue

        print(f"  Slide {slide_num:2d}: generating ({len(text)} chars) ...", end=" ", flush=True)

        try:
            wav_bytes = tts_generate(text)

            with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as tmp:
                tmp.write(wav_bytes)
                tmp_wav = Path(tmp.name)

            if HAS_FFMPEG:
                tmp_mp3 = tmp_wav.with_suffix(".mp3")
                wav_to_mp3(tmp_wav, tmp_mp3)
                tmp_wav.unlink()

                slow_down_audio(tmp_mp3, mp3_path, SPEED)
                tmp_mp3.unlink()

                size_kb = mp3_path.stat().st_size / 1024
                print(f"OK ({size_kb:.0f} KB)")
            else:
                wav_path = OUTPUT_DIR / f"slide-{slide_num:02d}.wav"
                shutil.move(str(tmp_wav), str(wav_path))
                print(f"OK (WAV, no ffmpeg)")

        except Exception as e:
            print(f"FAILED: {e}")

        # Small delay between requests
        time.sleep(2)

    print()
    print("Done! Audio files are in:", OUTPUT_DIR)


if __name__ == "__main__":
    main()
