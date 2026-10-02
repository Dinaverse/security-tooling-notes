#!/usr/bin/env python3
"""
scan_secrets_ia.py — AI-powered secret & PII scanner
Backend: Ollama (qwen3.5:27b) via sovereign lab Tailscale mesh
Endpoint sourced from ~/.lab-ai.env or env vars
"""

import os
import sys
import json
import re
import argparse
import requests
from pathlib import Path

# ── Config ──────────────────────────────────────────────────────────────────
OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://<ARCH_CLUSTER_TAILSCALE_IP>:11434")
OLLAMA_MODEL    = os.environ.get("OLLAMA_MODEL",    "qwen3.5:27b")
CHUNK_LINES     = 40   # lines per AI call
TIMEOUT         = 120  # seconds — allow for 27B model inference

# Regex pre-filter (fast, no AI needed for obvious hits)
OBVIOUS_PATTERNS = [
    (r'AKIA[0-9A-Z]{16}',                         'AWS Access Key'),
    (r'(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}',   'GitHub Token'),
    (r'sk-[A-Za-z0-9]{48}',                        'OpenAI API Key'),
    (r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY','Private Key'),
    (r'password\s*=\s*["\']?[^\s"\']{6,}',         'Hardcoded Password'),
    (r'api[_-]?key\s*[=:]\s*["\']?[A-Za-z0-9]{16,}','API Key'),
    (r'secret\s*[=:]\s*["\']?[A-Za-z0-9]{10,}',   'Secret Value'),
    (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', 'Email (PII)'),
]

# ── Ollama helpers ───────────────────────────────────────────────────────────

def ollama_available() -> bool:
    try:
        r = requests.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=5)
        return r.status_code == 200
    except Exception:
        return False


def ai_analyze_chunk(chunk: str, filename: str) -> list[dict]:
    """Send a text chunk to qwen3.5:27b and parse findings."""
    prompt = f"""You are a security scanner. Analyze the following code/config snippet from file '{filename}' for:
- Hardcoded secrets (API keys, tokens, passwords)
- Private keys or certificates
- PII (emails, phone numbers, IDs)
- Suspicious credentials

Respond ONLY with a JSON array. Each finding: {{"line_hint": str, "type": str, "severity": "LOW|MEDIUM|HIGH|CRITICAL", "detail": str}}
If nothing found, respond with: []

--- SNIPPET ---
{chunk}
--- END ---"""

    try:
        resp = requests.post(
            f"{OLLAMA_BASE_URL}/api/generate",
            json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False},
            timeout=TIMEOUT
        )
        resp.raise_for_status()
        raw = resp.json().get("response", "[]").strip()
        # Extract JSON array from response
        match = re.search(r'\[.*\]', raw, re.DOTALL)
        if match:
            return json.loads(match.group())
    except (requests.RequestException, json.JSONDecodeError, Exception):
        pass
    return []

# ── Scanner ──────────────────────────────────────────────────────────────────

def regex_scan(content: str) -> list[dict]:
    findings = []
    for i, line in enumerate(content.splitlines(), 1):
        for pattern, label in OBVIOUS_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append({
                    "line": i,
                    "type": label,
                    "severity": "HIGH",
                    "detail": line.strip()[:120],
                    "source": "regex"
                })
    return findings


def ai_scan(content: str, filename: str, use_ai: bool) -> list[dict]:
    if not use_ai:
        return []
    lines = content.splitlines()
    findings = []
    for i in range(0, len(lines), CHUNK_LINES):
        chunk = "\n".join(f"{i+j+1}: {l}" for j, l in enumerate(lines[i:i+CHUNK_LINES]))
        results = ai_analyze_chunk(chunk, filename)
        for r in results:
            r["source"] = "ai"
        findings.extend(results)
    return findings


def scan_file(file_path: str, use_ai: bool, output_json: bool) -> list[dict]:
    path = Path(file_path)
    if not path.exists():
        print(f"❌ Not found: {file_path}")
        return []

    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        print(f"❌ Cannot read {file_path}: {e}")
        return []

    regex_hits  = regex_scan(content)
    ai_hits     = ai_scan(content, path.name, use_ai)
    all_findings = regex_hits + ai_hits

    if not output_json:
        if all_findings:
            print(f"\n⚠️  {path} — {len(all_findings)} finding(s):")
            for f in all_findings:
                sev  = f.get("severity", "?")
                src  = f.get("source", "?")
                ftype = f.get("type", "Unknown")
                detail = f.get("detail", f.get("line_hint", ""))
                line_no = f.get("line", "")
                prefix = f"  [{sev}][{src}]"
                print(f"{prefix} Line {line_no} — {ftype}: {str(detail)[:100]}")
        else:
            print(f"  ✅ {path} — clean")

    return all_findings


def main():
    parser = argparse.ArgumentParser(
        description="AI-powered secret scanner (Ollama / qwen3.5:27b)")
    parser.add_argument("path",      help="File or directory to scan")
    parser.add_argument("--no-ai",   action="store_true",
                        help="Regex-only mode (faster, no Ollama needed)")
    parser.add_argument("--json",    action="store_true",
                        help="Output results as JSON")
    parser.add_argument("--ext",     default="py,js,ts,env,conf,yaml,yml,sh,txt,log,json",
                        help="Comma-separated extensions to scan (default: common code/config)")
    args = parser.parse_args()

    use_ai = not args.no_ai
    extensions = {f".{e.lstrip('.')}" for e in args.ext.split(",")}

    if use_ai:
        if ollama_available():
            print(f"🤖 AI mode: {OLLAMA_MODEL} @ {OLLAMA_BASE_URL}")
        else:
            print(f"⚠️  Ollama unreachable at {OLLAMA_BASE_URL} — falling back to regex-only")
            use_ai = False
    else:
        print("🔍 Regex-only mode")

    target = Path(args.path)
    all_findings: list[dict] = []

    if target.is_file():
        all_findings = scan_file(str(target), use_ai, args.json)
    elif target.is_dir():
        files = [f for f in target.rglob("*")
                 if f.is_file() and f.suffix in extensions
                 and ".git" not in f.parts]
        print(f"📁 Scanning {len(files)} file(s) in {target}...")
        for f in files:
            all_findings.extend(scan_file(str(f), use_ai, args.json))
    else:
        print(f"❌ {args.path} is not a file or directory")
        sys.exit(1)

    if args.json:
        print(json.dumps(all_findings, indent=2))
    else:
        total = len(all_findings)
        critical = sum(1 for f in all_findings if f.get("severity") == "CRITICAL")
        high     = sum(1 for f in all_findings if f.get("severity") == "HIGH")
        print(f"\n{'='*50}")
        print(f"Total findings : {total}")
        print(f"  CRITICAL     : {critical}")
        print(f"  HIGH         : {high}")
        print(f"  OTHER        : {total - critical - high}")

    sys.exit(1 if all_findings else 0)


if __name__ == "__main__":
    main()
