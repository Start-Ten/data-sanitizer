> **Important: Always use LLM to verify each entry for PII before uploading datasets!**

# Data Sanitizer

**PII detection and sanitization for ML training datasets.**

A pipeline that detects and removes personally identifiable information (PII) from text datasets before public upload.

## Quick Start

### 1. Scan for PII
```
python3 scripts/scan_pii.py data/dataset.json
```

### 2. Sanitize
```
python3 scripts/sanitize.py data/dataset.json -o data/cleaned.json
```

### 3. LLM verification (OpenAI or Anthropic)
```
python3 scripts/llm_verify.py data/cleaned.json --api-type openai --api-key xxx --model gpt-4o --sample 50
```

### 4. Pre-upload validation
```
python3 scripts/validate.py data/cleaned.json --strict
```

### 5. Upload & post-upload check
```
hf upload org/dataset data/cleaned.json --repo-type dataset
python3 scripts/validate.py data/cleaned.json --url https://hf.co/org/dataset/... --strict
```

## PII Patterns

| Pattern | Severity |
|---------|----------|
| WeChat ID (@im.wechat) | CRITICAL |
| Session UUID | CRITICAL |
| API Key / Token | CRITICAL |
| Phone Number | HIGH |
| Email Address | HIGH |
| Chinese Name | HIGH |
| System Log Line | HIGH |
| IP Address | MEDIUM |

## Scripts

- **scan_pii.py** - 20+ PII pattern scanner for JSON datasets
- **sanitize.py** - PII replacement and log stripping
- **llm_verify.py** - Semantic PII detection (OpenAI + Anthropic)
- **validate.py** - Pre/post-upload validation

## License

MIT
