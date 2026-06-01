# PII Detection Reference

## Edge Cases & False Positives

### Emails (@ in code, not real emails)
The `@` symbol is common in code. The scanner distinguishes:

| False positive | Reason |
|----------------|--------|
| `@decorator` | Python decorator syntax |
| `@param` | Docstring annotation |
| `git@github.com` | Git remote format |
| `n@torch.compile` | CUDA/Python decorator |
| `support8K@30fps` | Display resolution |
| `pass@8` | Benchmark notation |
| `Cortex-A73@1.8GHz` | CPU model |
| `TcpGolf@dbscb519...` | Network benchmark |

These are handled by requiring a TLD `.com|.cn|.org|...` in the email regex.

### Phone numbers (benchmark scores)
Numbers matching `1[3-9]\d{9}` that are not real phones:

| False positive | Reason |
|----------------|--------|
| `14073735435` | Memory address (decimal) |
| `15000001001` | Test/sample number |
| `19902325555` | Max uint32 boundary |

Error on the side of flagging. These are cheap to verify visually.

### Chinese names (context-dependent)
The regex `我是[\u4e00-\u9fa5]{2,4}` catches self-introductions
but misses names in other contexts. LLM verification catches:
- Names mentioned in third-person
- Names in email signatures
- Names in quoted messages

### Session UUIDs (legitimate content)
UUID-format strings can appear in:
- Conversation about programming (UUID generation)
- Example data in documentation
- Technical error messages

LLM verification helps distinguish real session IDs from examples.

## Severity Matrix

| Severity | Action | Examples |
|----------|--------|----------|
| **CRITICAL** | Block upload until resolved | Chat IDs, account IDs, API keys, tokens, session UUIDs in logs |
| **HIGH** | Block upload unless verified | Phone numbers, emails, real names, system log lines |
| **MEDIUM** | Flag for review | IP addresses, file paths, chat metadata field names (without values) |
| **LOW** | Advisory | File paths without user context |

## Supported Dataset Formats

| Format | Structure | Script support |
|--------|-----------|----------------|
| ShareGPT | `[{"from": "human", "value": "..."}, {"from": "gpt", "value": "..."}]` | All scripts |
| OpenAI Messages | `{"messages": [{"role": "user", "content": "..."}]}` | All scripts |
| Alpaca | `{"instruction": "...", "input": "...", "output": "..."}` | All scripts |
| Raw JSON | Any JSON structure with string values | All scripts (recursive) |

## Recommended Upload Workflow

```bash
# 1. Regex scan before anything
python3 scripts/scan_pii.py data/raw.json --verbose

# 2. Sanitize if PII found
python3 scripts/sanitize.py data/raw.json -o data/cleaned.json

# 3. Re-scan
python3 scripts/scan_pii.py data/cleaned.json

# 4. LLM verification (sample)
python3 scripts/llm_verify.py data/cleaned.json \
    --api-type openai --api-key $KEY --model gpt-4o --sample 100

# 5. Pre-upload validation
python3 scripts/validate.py data/cleaned.json --strict

# 6. Upload to Hugging Face
hf upload org/dataset data/cleaned.json --repo-type dataset

# 7. Post-upload validation
python3 scripts/validate.py data/cleaned.json \
    --url https://huggingface.co/org/dataset/raw/main/data/cleaned.json --strict
```
