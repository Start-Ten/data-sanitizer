#!/usr/bin/env python3
"""
LLM PII Verifier — uses an LLM to check dataset entries for personal information.

Supports OpenAI-compatible APIs (OpenAI, MiniMax, deepseek, etc.)
and Anthropic API. Catches PII that regex patterns miss:
contextual names, indirect references, code artifacts that
contain personal data.

Usage:
    # OpenAI-compatible
    python3 llm_verify.py data/file.json --api-type openai \\
        --api-key $OPENAI_API_KEY --model gpt-4o

    # Anthropic
    python3 llm_verify.py data/file.json --api-type anthropic \\
        --api-key $ANTHROPIC_API_KEY --model claude-sonnet-4-20250514

    # Custom base URL (e.g. MiniMax)
    python3 llm_verify.py data/file.json --api-type openai \\
        --base-url https://api.minimaxi.com/v1 \\
        --api-key $KEY --model MiniMax-M3

    # Sample (check first N entries)
    python3 llm_verify.py data/file.json --api-type openai \\
        --api-key $KEY --model gpt-4o --sample 50

    # Verbose (show checked entries)
    python3 llm_verify.py data/file.json --api-type openai \\
        --api-key $KEY --model gpt-4o --verbose

Exit codes:
    0 — No PII found
    1 — PII detected
    2 — Error
"""

import json
import os
import sys
from typing import Optional


VERIFICATION_PROMPT = """You are a PII auditor for ML training datasets. Check the following JSON entry 
for any of these categories of personally identifiable information (PII):

1. **Direct identifiers**: real names, phone numbers, email addresses, government IDs, account IDs
2. **Digital identifiers**: chat IDs, session IDs, device IDs, tokens, API keys
3. **System data**: server logs, routing information, diagnostic output, timestamps from system logs
4. **Contact info**: home addresses, workplace details, URLs to personal profiles
5. **Institutional**: student/employee IDs, organization-internal identifiers

Return a JSON object (and ONLY valid JSON, no markdown):
{
  "has_pii": true/false,
  "pii_types": ["category1", "category2"],
  "sensitive_fields": ["field1", "field2"],
  "recommendation": "redact | keep | review"
}

Entry to check:
{entry}"""


def try_import_openai():
    try:
        from openai import OpenAI
        return OpenAI
    except ImportError:
        return None


def try_import_anthropic():
    try:
        import anthropic
        return anthropic
    except ImportError:
        return None


def verify_openai(entry_text: str, api_key: str, model: str,
                  base_url: Optional[str] = None) -> dict:
    """Verify a single entry using OpenAI-compatible API."""
    OpenAI = try_import_openai()
    if OpenAI is None:
        print("❌ 'openai' package not installed. Run: pip install openai", file=sys.stderr)
        sys.exit(2)

    kwargs = {"api_key": api_key}
    if base_url:
        kwargs["base_url"] = base_url

    client = OpenAI(**kwargs)
    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": "You are a PII auditor. Return only valid JSON."},
            {"role": "user", "content": VERIFICATION_PROMPT.format(entry=entry_text[:4000])}
        ],
        response_format={"type": "json_object"},
        temperature=0,
        max_tokens=300,
    )
    return json.loads(response.choices[0].message.content)


def verify_anthropic(entry_text: str, api_key: str, model: str) -> dict:
    """Verify a single entry using Anthropic API."""
    anthropic_module = try_import_anthropic()
    if anthropic_module is None:
        print("❌ 'anthropic' package not installed. Run: pip install anthropic", file=sys.stderr)
        sys.exit(2)

    client = anthropic_module.Anthropic(api_key=api_key)
    response = client.messages.create(
        model=model,
        system="You are a PII auditor. Return only valid JSON, no markdown formatting.",
        messages=[
            {
                "role": "user",
                "content": VERIFICATION_PROMPT.format(entry=entry_text[:4000])
            }
        ],
        temperature=0,
        max_tokens=300,
    )
    # Extract JSON from response
    text = response.content[0].text
    # Strip markdown fences if any
    text = text.replace("```json", "").replace("```", "").strip()
    return json.loads(text)


def extract_entries(data) -> list[str]:
    """Extract string representations of entries from common dataset formats."""
    entries = []
    if isinstance(data, list):
        for item in data:
            entries.append(json.dumps(item, ensure_ascii=False))
    elif isinstance(data, dict):
        # Handle OpenAI Messages format
        messages = data.get("messages", data)
        if isinstance(messages, list):
            entries = [json.dumps({"messages": messages}, ensure_ascii=False)]
        else:
            entries = [json.dumps(data, ensure_ascii=False)]
    return entries


def main():
    import argparse

    parser = argparse.ArgumentParser(description="LLM-based PII verification for datasets")
    parser.add_argument("input", help="Input JSON file")
    parser.add_argument("--api-type", required=True, choices=["openai", "anthropic"],
                        help="API type")
    parser.add_argument("--api-key", required=True, help="API key")
    parser.add_argument("--model", default="gpt-4o", help="Model name")
    parser.add_argument("--base-url", help="Custom base URL (for OpenAI-compatible APIs)")
    parser.add_argument("--sample", type=int, default=None,
                        help="Only check first N entries")
    parser.add_argument("--verbose", action="store_true",
                        help="Show each entry check result")
    args = parser.parse_args()

    # Load data
    try:
        with open(args.input, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"❌ Error loading {args.input}: {e}", file=sys.stderr)
        sys.exit(2)

    entries = extract_entries(data)
    total = len(entries)
    if args.sample and args.sample < total:
        entries = entries[:args.sample]
        print(f"📋 Checking {len(entries)}/{total} entries (sampled)")

    print(f"🔍 Running LLM verification ({args.api_type}/{args.model})...")

    found_pii = 0
    checked = 0
    errors = 0

    for i, entry_text in enumerate(entries):
        # Skip very short entries
        if len(entry_text.strip()) < 20:
            continue

        try:
            if args.api_type == "openai":
                result = verify_openai(
                    entry_text, args.api_key, args.model, args.base_url
                )
            else:
                result = verify_anthropic(entry_text, args.api_key, args.model)

            checked += 1

            if result.get("has_pii"):
                found_pii += 1
                print(f"\n🚨 Entry {i} — PII DETECTED")
                print(f"   Types: {', '.join(result.get('pii_types', []))}")
                print(f"   Fields: {', '.join(result.get('sensitive_fields', []))}")
                print(f"   Recommendation: {result.get('recommendation', 'N/A')}")
            elif args.verbose:
                print(f"✅ Entry {i} — clean")

        except Exception as e:
            errors += 1
            print(f"⚠️  Entry {i} — API error: {e}", file=sys.stderr)

    # Summary
    print(f"\n{'='*50}")
    print(f"📊 Results: {checked} checked, {found_pii} with PII, {errors} errors")
    if found_pii > 0:
        print(f"❌ FAILED: {found_pii} entry(ies) contain PII")
        sys.exit(1)
    else:
        print(f"✅ PASSED: No PII detected in verified entries")
        sys.exit(0)


if __name__ == "__main__":
    main()
