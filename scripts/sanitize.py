#!/usr/bin/env python3
"""
PII Sanitizer — applies PII replacement and system-log stripping to datasets.

Replaces detected PII with `[REDACTED]` placeholders to preserve
sentence structure and context while removing sensitive information.

Usage:
    python3 sanitize.py data/input.json -o data/cleaned.json
    python3 sanitize.py data/input.json -o data/cleaned.json --in-place
    python3 sanitize.py data/dir/ -o data/cleaned/
"""

import copy
import json
import os
import re
import sys


# ── PII replacement rules ─────────────────────────────────────

# Rule: (name, pattern, replacement_callable_or_str)
# Ordered: more specific rules first to avoid partial replacements

REPLACEMENT_RULES = [
    # ── System log lines (strip entirely) ──
    ("log_line",
     re.compile(r'\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}\s*\[(?:agent/embedded|routing|diagnostic|session|message)\].*?(?=\n|\Z)', re.MULTILINE),
     ""),  # remove the line

    # ── Untrusted metadata blocks ──
    ("metadata_block",
     re.compile(r'Conversation info \(untrusted metadata\):\n```json\n.*?\n```', re.DOTALL),
     ""),

    # ── Critical: direct identifiers ──
    ("wechat_id", re.compile(r'[a-zA-Z0-9]{8,64}@im\.wechat'), "[REDACTED]"),
    ("account_id", re.compile(r'[a-f0-9]{8,}-im-bot'), "[REDACTED]"),
    ("run_id", re.compile(r'run(?:Id|ID|_id)=[0-9a-f-]{36}'), "runId=[REDACTED]"),
    ("api_key_sk", re.compile(r'(?:sk-|pk-)[a-zA-Z0-9]{20,}'), "[API_KEY]"),
    ("api_key_hf", re.compile(r'hf_[a-zA-Z0-9]{20,}'), "[API_KEY]"),
    ("github_token", re.compile(r'ghp_[a-zA-Z0-9]{36}'), "[TOKEN]"),

    # ── High: personal contact ──
    ("phone_cn", re.compile(r'1[3-9]\d{9}'), "[PHONE]"),
    ("email", re.compile(r'\b[a-zA-Z0-9._%+\-]{2,}@[a-zA-Z0-9.\-]{2,}\.(?:com|cn|org|net|edu|top)\b'), "[EMAIL]"),

    # ── Chinese name in self-intro context ──
    ("chinese_name_intro",
     re.compile(r'(我是|我叫|本人|笔者|作者|姓名[：:\s]*)[\u4e00-\u9fa5]{2,4}'),
     lambda m: m.group(1) + "[REDACTED]"),

    # ── Chat platform IDs ──
    ("chat_id_field", re.compile(r'chat_id["\']?\s*[:=]\s*["\']?[a-zA-Z0-9@._-]{8,}["\']?'), "chat_id: [REDACTED]"),
    ("message_id_field", re.compile(r'message_id["\']?\s*[:=]\s*["\']?[a-zA-Z0-9:_-]{8,}["\']?'), "message_id: [REDACTED]"),

    # ── Clean up double newlines from log removal ──
    ("excess_newlines", re.compile(r'\n{3,}'), "\n\n"),

    # ── Session UUID (careful: matches UUIDs anywhere) ──
    ("session_uuid",
     re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'),
     "[UUID]"),
]


def sanitize_string(text: str) -> str:
    """Apply all replacement rules to a single string."""
    if not isinstance(text, str):
        return text
    for name, pattern, replacement in REPLACEMENT_RULES:
        if callable(replacement):
            text = pattern.sub(replacement, text)
        else:
            text = pattern.sub(replacement, text)
    return text.strip()


def sanitize_value(obj):
    """Recursively sanitize all string values in a JSON structure."""
    if isinstance(obj, str):
        return sanitize_string(obj)
    elif isinstance(obj, dict):
        return {k: sanitize_value(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [sanitize_value(item) for item in obj]
    else:
        return obj


def load_json(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(data, path: str):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Sanitize PII from JSON datasets")
    parser.add_argument("input", help="Input JSON file or directory")
    parser.add_argument("-o", "--output", required=True, help="Output file or directory")
    parser.add_argument("--in-place", action="store_true", help="Modify input files in-place")
    args = parser.parse_args()

    input_path = args.input
    output_path = args.output

    if os.path.isdir(input_path):
        files = sorted(
            os.path.join(input_path, f)
            for f in os.listdir(input_path)
            if f.endswith(".json")
        )
        os.makedirs(output_path, exist_ok=True)
    else:
        files = [input_path]

    total_processed = 0
    for fpath in files:
        try:
            data = load_json(fpath)
            cleaned = sanitize_value(data)

            if args.in_place:
                out = fpath
            elif os.path.isdir(args.output):
                out = os.path.join(args.output, os.path.basename(fpath))
            else:
                out = output_path

            save_json(cleaned, out)
            total_processed += 1
            print(f"✅ {os.path.basename(fpath)} → {os.path.basename(out)}")
        except Exception as e:
            print(f"❌ {os.path.basename(fpath)}: {e}")

    print(f"\n✅ Sanitized {total_processed} file(s)")


if __name__ == "__main__":
    main()
