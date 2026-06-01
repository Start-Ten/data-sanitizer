---
name: data-sanitizer
description: "PII detection and sanitization for ML training datasets. Use when preparing text datasets for upload to Hugging Face or similar platforms. Covers: (1) Regex-based PII scanning of phone numbers, emails, IDs, tokens, (2) LLM-assisted semantic PII verification, (3) Automated data cleaning pipeline, (4) Pre-upload and post-upload validation."
---

# Data Sanitizer

Sanitize text datasets by removing personally identifiable information (PII) before public upload.

## Detection + Sanitization Pipeline

### Step 1 — Run regex scanner

```bash
python3 scripts/scan_pii.py data/input.json
```

Scans all string values in JSON files for phone numbers, emails, Chinese names, IDs, tokens, and system logs. Returns exit code 0 only when no PII is found.

### Step 2 — LLM semantic verification

Use any OpenAI-compatible or Anthropic API to catch what regex misses. The prompt template is in `scripts/llm_verify.py`:

```bash
python3 scripts/llm_verify.py data/input.json --api-key $KEY --model gpt-4o
```

Supported providers:

| Provider | Model example | SDK |
|----------|--------------|-----|
| OpenAI   | `gpt-4o`, `gpt-4o-mini` | `openai` Python / `curl` |
| Anthropic | `claude-sonnet-4-20250514` | `anthropic` Python / `curl` |
| MiniMax  | `MiniMax-M3` | OpenAI-compatible `curl` |
| Any OpenAI-compatible | `custom-model` | `openai` Python with `base_url` override |

### Step 3 — Apply sanitization

```bash
python3 scripts/sanitize.py data/input.json --output data/cleaned.json
```

Replaces PII with `[REDACTED]` placeholders and strips system log lines.

### Step 4 — Pre-upload validation

```bash
python3 scripts/validate.py data/cleaned.json
```

### Step 5 — Post-upload online validation

```bash
python3 scripts/validate.py data/cleaned.json --url https://huggingface.co/.../raw/main/data/file.json
```

Downloads the live file and runs the same checks to confirm no PII leaked.

## PII Detection Patterns

| Pattern | Flags | Severity |
|---------|-------|----------|
| `xxx@im.wechat` | Chat platform user ID | **Critical** |
| `[0-9a-f]{8}-[0-9a-f]{4}-...` | Session UUID | **Critical** |
| `1[3-9]\d{9}` | Chinese mobile | **High** |
| `[\w.+-]+@[\w.-]+\.\w{2,}` | Email address | **High** |
| Chinese names (2-4 CJK chars) | Real name | **High** |
| `\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}` | IP address | **Medium** |
| `[a-f0-9]+-im-bot` | Account ID | **Critical** |
| `sk-[a-zA-Z0-9]+` | API key | **Critical** |
| `ghp_\w+` | GitHub token | **Critical** |
| `[agent/embedded]`, `[routing]`, `[diagnostic]` | System logs | **High** |
| `\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}\s*\[` | Timestamped logs | **High** |

## Data Source Filters

### Allowed sources
- Pure conversation content (human/gpt text fields)
- Reasoning chains (`reasoning_content`)
- Model output (text only, no metadata)

### Forbidden sources
- System/diagnostic logs (`[agent/embedded]`, `[routing]`, `[diagnostic]`)
- API response metadata (`model`, `usage`, `id`, `created`, etc.)
- Unprocessed webhook payloads
- Raw API request/response bodies
- File paths or system paths
- Environment variables

## Detection Methods Reference

See `references/detection.md` for all regex patterns and edge cases handled by the scanner.

## Scripts

| Script | Purpose |
|--------|---------|
| `scripts/scan_pii.py` | Regex-based PII scanner (zero false negatives on known patterns) |
| `scripts/sanitize.py` | Apply PII replacement and log stripping to produce clean output |
| `scripts/llm_verify.py` | LLM-powered semantic PII detector (catches what regex misses) |
| `scripts/validate.py` | Pre-upload and post-upload validation runner |
