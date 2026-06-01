#!/usr/bin/env python3
"""
PII Scanner — regex-based detection for text datasets.

Recursively walks JSON structures and flags all string values
that match known PII patterns. Supports multiple input formats:
ShareGPT, OpenAI Messages, Alpaca, and raw JSON arrays.

Usage:
    python3 scan_pii.py data/file.json
    python3 scan_pii.py data/dir/          # scan all JSON files in directory
    python3 scan_pii.py data/file.json --verbose
    python3 scan_pii.py data/file.json --json  # machine-readable output

Exit codes:
    0 — No PII detected
    1 — PII detected
    2 — Error
"""

import json
import os
import re
import sys


# ── PII patterns ──────────────────────────────────────────────
# Each entry: (name: str, pattern: Pattern, severity: str, sample: str)

PII_PATTERNS = [
    # Critical — direct user identity
    ("wechat_id", re.compile(r'[a-zA-Z0-9]{8,64}@im\.wechat'), "CRITICAL"),
    ("account_id", re.compile(r'[a-f0-9]{8,}-im-bot'), "CRITICAL"),
    ("session_uuid", re.compile(
        r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
    ), "CRITICAL"),
    ("api_key_sk", re.compile(r'(?:sk-|pk-)[a-zA-Z0-9]{20,}'), "CRITICAL"),
    ("api_key_hf", re.compile(r'hf_[a-zA-Z0-9]{20,}'), "CRITICAL"),
    ("github_token", re.compile(r'ghp_[a-zA-Z0-9]{36}'), "CRITICAL"),

    # High — personal contact info
    ("phone_cn", re.compile(r'1[3-9]\d{9}'), "HIGH"),
    ("email", re.compile(r'\b[a-zA-Z0-9._%+\-]{2,}@[a-zA-Z0-9.\-]{2,}\.(?:com|cn|org|net|edu|top|io|app|dev)\b'), "HIGH"),
    ("chinese_name", re.compile(
        r'(?:我是|我叫|姓名|名字|本人|笔者|作者)[：:\s]*([\u4e00-\u9fa5]{2,4})'
    ), "HIGH"),
    ("id_card", re.compile(r'\d{17}[\dXx]'), "HIGH"),

    # Medium — infrastructure
    ("ip_address", re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?\b'), "MEDIUM"),
    ("qq_number", re.compile(r'(?<!\d)[1-9]\d{5,10}(?!\d)'), "MEDIUM"),

    # High — system logs
    ("system_log_agent", re.compile(r'\[(?:agent/embedded|routing|diagnostic|session|message)\]'), "HIGH"),
    ("system_log_timestamp", re.compile(
        r'\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}\s*\[', re.MULTILINE
    ), "HIGH"),

    # Medium — chat metadata
    ("chat_id", re.compile(r'chat_id["\']?\s*[:=]\s*["\']?[a-zA-Z0-9@._-]+'), "MEDIUM"),
    ("message_id", re.compile(r'message_id["\']?\s*[:=]\s*["\']?[a-zA-Z0-9:_-]+'), "MEDIUM"),

    # Low — possible system paths
    ("untrusted_metadata", re.compile(
        r'Conversation info \(untrusted metadata\)', re.IGNORECASE
    ), "MEDIUM"),
    ("file_path_unix", re.compile(r'/(?:root|home|tmp|var|etc|usr)/[a-zA-Z0-9_./-]+'), "LOW"),
]


def scan_string(text: str) -> list[dict]:
    """Scan a single string for PII matches."""
    results = []
    for name, pattern, severity in PII_PATTERNS:
        for match in pattern.finditer(text):
            start = max(0, match.start() - 20)
            end = min(len(text), match.end() + 20)
            context = text[start:end]
            # Highlight the match in context
            hl_start = match.start() - start
            hl_end = match.end() - start
            context_hl = (
                context[:hl_start]
                + "<<<"
                + context[hl_start:hl_end]
                + ">>>"
                + context[hl_end:]
            )
            results.append({
                "pattern": name,
                "severity": severity,
                "match": match.group()[:80],  # truncate long matches
                "position": match.start(),
                "context": context_hl.strip(),
            })
    return results


def scan_value(obj, path: str = "") -> list[dict]:
    """Recursively scan a JSON value for PII."""
    results = []
    if isinstance(obj, str):
        matches = scan_string(obj)
        for m in matches:
            m["path"] = path
            results.append(m)
    elif isinstance(obj, dict):
        for key, val in obj.items():
            results.extend(scan_value(val, f"{path}.{key}" if path else key))
    elif isinstance(obj, list):
        for i, val in enumerate(obj):
            results.extend(scan_value(val, f"{path}[{i}]"))
    return results


def load_json(path: str):
    """Load JSON from file."""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def main():
    verbose = "--verbose" in sys.argv
    json_output = "--json" in sys.argv
    paths = [a for a in sys.argv[1:] if not a.startswith("--")]

    if not paths:
        print("Usage: scan_pii.py <file_or_dir> [--verbose] [--json]", file=sys.stderr)
        sys.exit(2)

    all_results = {}
    total_pii = 0

    for input_path in paths:
        if os.path.isdir(input_path):
            files = sorted(
                os.path.join(input_path, f)
                for f in os.listdir(input_path)
                if f.endswith(".json")
            )
        else:
            files = [input_path]

        for fpath in files:
            try:
                data = load_json(fpath)
                results = scan_value(data)
                if results:
                    all_results[fpath] = results
                    total_pii += len(results)
                    if verbose or not json_output:
                        print(f"\n{'='*60}")
                        print(f"📄 {fpath} — {len(results)} PII match(es)")
                        print(f"{'='*60}")
                        for r in results:
                            sev = r["severity"]
                            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "⚪"}.get(sev, "⚪")
                            print(f"  {icon} [{sev}] {r['pattern']} @ {r['path']}")
                            print(f"    Match: {r['match']}")
                            print(f"    Context: ...{r['context']}...")
                else:
                    if verbose:
                        print(f"✅ {fpath} — clean")
            except Exception as e:
                print(f"❌ Error reading {fpath}: {e}", file=sys.stderr)

    # Summary
    if json_output:
        print(json.dumps(all_results, ensure_ascii=False, indent=2))
    else:
        print(f"\n{'='*60}")
        if total_pii == 0:
            print("✅ No PII detected — dataset is clean!")
        else:
            print(f"⚠️  {total_pii} PII match(es) found across {len(all_results)} file(s).")
            severities = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            for results in all_results.values():
                for r in results:
                    severities[r["severity"]] += 1
            for sev, count in severities.items():
                if count > 0:
                    print(f"  {sev}: {count}")

    sys.exit(1 if total_pii > 0 else 0)


if __name__ == "__main__":
    main()
