#!/usr/bin/env python3
"""
PII Validator — pre-upload and post-upload validation.

Combines regex scanning with structural checks to ensure
a dataset is safe for public release.

Pre-upload:
    python3 validate.py data/cleaned.json

Post-upload (download from URL + verify):
    python3 validate.py data/cleaned.json \\
        --url https://huggingface.co/org/repo/raw/main/data/file.json

Strict mode (fails on ANY finding, including LOW severity):
    python3 validate.py data/cleaned.json --strict

Exit codes:
    0 — All checks passed
    1 — Validation failed
    2 — Error
"""

import json
import os
import re
import sys
import urllib.request
import urllib.error


# ── Required patterns that must be ABSENT ─────────────────────
# If any of these match, validation fails.

BLOCK_PATTERNS = {
    "CRITICAL": [
        ("WeChat ID", re.compile(r'@im\.wechat')),
        ("Account ID", re.compile(r'-im-bot')),
        ("OpenClaw Agent Log", re.compile(r'\[(?:agent/embedded|routing|diagnostic)\]')),
        ("Session UUID", re.compile(
            r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
        )),
        ("API Key", re.compile(r'(?:sk-|pk-|hf_|ghp_)[a-zA-Z0-9]{20,}')),
    ],
    "HIGH": [
        ("Phone Number", re.compile(r'1[3-9]\d{9}')),
        ("Email", re.compile(r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-z]{2,}\b')),
    ],
    "MEDIUM": [
        ("Timestamped System Log", re.compile(
            r'\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}\s*\['
        )),
        ("Chat Metadata", re.compile(r'chat_id["\']?\s*[:=]')),
        ("Untrusted Metadata", re.compile(r'Conversation info \(untrusted metadata\)', re.I)),
    ],
}


def check_string(text: str, strict: bool = False) -> list[dict]:
    """Check a string against all block patterns."""
    findings = []
    for severity, patterns in BLOCK_PATTERNS.items():
        if severity == "LOW" and not strict:
            continue
        for name, pattern in patterns:
            matches = pattern.findall(text)
            if matches:
                findings.append({
                    "severity": severity,
                    "name": name,
                    "count": len(matches),
                    "pattern": pattern.pattern[:60],
                })
    return findings


def scan_value(obj, strict: bool = False, path: str = "") -> list[dict]:
    """Recursively scan JSON structure."""
    findings = []
    if isinstance(obj, str):
        for f in check_string(obj, strict):
            f["path"] = path
            findings.append(f)
    elif isinstance(obj, dict):
        for k, v in obj.items():
            findings.extend(scan_value(v, strict, f"{path}.{k}" if path else k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            findings.extend(scan_value(v, strict, f"{path}[{i}]"))
    return findings


def load_json(path_or_url: str) -> tuple:
    """Load JSON from local file or URL."""
    if path_or_url.startswith(("http://", "https://")):
        try:
            req = urllib.request.Request(
                path_or_url,
                headers={"User-Agent": "data-sanitizer-validator/1.0"}
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode()), True
        except Exception as e:
            print(f"❌ Failed to fetch URL: {e}", file=sys.stderr)
            sys.exit(2)
    else:
        with open(path_or_url, "r", encoding="utf-8") as f:
            return json.load(f), False


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Validate dataset for PII before/after upload")
    parser.add_argument("input", help="Local JSON file or directory")
    parser.add_argument("--url", help="Remote URL for online validation")
    parser.add_argument("--strict", action="store_true",
                        help="Fail on LOW severity findings too")
    args = parser.parse_args()

    # Collect files to check
    if os.path.isdir(args.input):
        files = sorted(
            os.path.join(args.input, f)
            for f in os.listdir(args.input)
            if f.endswith(".json")
        )
    else:
        files = [args.input]

    # Also check remote if --url provided
    remote_data = None
    remote_from_url = False
    if args.url:
        remote_data, remote_from_url = load_json(args.url)

    all_fail = False

    # ── Local validation ──
    for fpath in files:
        fname = os.path.basename(fpath)
        print(f"\n{'='*50}")
        print(f"🔍 Validating local: {fname}")

        try:
            data = load_json(fpath)[0]
            findings = scan_value(data, args.strict)
        except Exception as e:
            print(f"❌ Error: {e}")
            all_fail = True
            continue

        if not findings:
            print(f"✅ PASSED — No issues found")
        else:
            all_fail = True
            by_severity = {}
            for f in findings:
                by_severity.setdefault(f["severity"], []).append(f)

            for sev in ["CRITICAL", "HIGH", "MEDIUM"]:
                if sev in by_severity:
                    for f in by_severity[sev]:
                        print(f"  ❌ [{sev}] {f['name']} ({f['count']}x) @ {f['path']}")

    # ── Remote validation ──
    if remote_data:
        print(f"\n{'='*50}")
        print(f"🔍 Validating remote: {args.url}")
        findings = scan_value(remote_data, args.strict)

        if not findings:
            print(f"✅ REMOTE PASSED — No issues found")
        else:
            all_fail = True
            for f in findings:
                print(f"  ❌ [{f['severity']}] {f['name']} ({f['count']}x) @ {f['path']}")

    # ── Summary ──
    print(f"\n{'='*50}")
    if all_fail:
        print("❌ VALIDATION FAILED — PII detected, do not upload")
        sys.exit(1)
    else:
        print("✅ ALL CHECKS PASSED — dataset is clean")
        sys.exit(0)


if __name__ == "__main__":
    main()
