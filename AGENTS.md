# key_scanner

Single-file Python project (`main.py` and `pyproject.toml`) that scrapes GitHub issues for leaked API keys and validates them.

## Setup

- **Python 3.13+** via `uv`
- `cp .env.example .env && uv sync`

## Commands

| Command | Effect |
|---|---|
| `uv run main.py` | Normal run |
| `uv run main.py --ignore-saved` | Re-verify keys already in `leaked_keys.json` |
| `uv run main.py --llm-scan` | Use LLM instead of regex to extract keys |
| `uv run main.py --debug` | Concurrency-disabled processing with 5s delay per issue |

## Env vars (.env, loaded via `load_dotenv()`)

- `GITHUB_API_KEY` — required
- `LLM_BASE_URL`, `LLM_API_KEY`, `LLM_MODEL_NAME`, `LLM_REASONING_MODE` — required when `--llm-scan` is used
- `LLM_REASONING_MODE` values: `off | low | medium | high | xhigh | max` (default: `off`)

## How it works

1. Searches `https://api.github.com/search/issues?q=your+key+leak+is:issue`
2. Extracts a `github.com/.../blob/...` file URL from each issue body
3. Downloads file, matches 25+ API key patterns (OpenAI, AWS, GitHub tokens, Stripe, Slack, etc.)
4. Extracts `model_name` and `base_url` from the same file (regex or LLM)
5. Verifies keys against the extracted `base_url` via OpenAI-compatible chat completion
6. Saves results as JSON array to `leaked_keys.json`

## Architecture notes

- `leaked_keys.json` acts as a dedup db — already-saved keys are skipped (overridable with `--ignore-saved`)
- No tests, no lint/typecheck config, no CI
- Concurrency: `ThreadPoolExecutor(max_workers=10)` per page; GitHub API paginates 100 per page
- `uv.lock` is committed — use `uv sync` (not `pip install`)

## Key validation

- `verify_key()` hits `/v1/models` then `/v1/chat/completions` via `openai` Python client
- `_classify_status()` maps HTTP codes: 402→out_of_balance, 401→invalid, 429→rate_limited/quota, else→valid
- `is_valid_key()` filters placeholders (test, example, changeme, your_key, etc.)
- `PROVIDER_MAP` has ~40 LLM providers with known base URLs

## --llm-scan mode

- Uses a separate LLM (configured via `LLM_*` env vars) to analyze leaked file content
- Preprocesses files per extension: strips markdown, filters JSON/YAML/TOML/ENV for relevant keys
- Injects known provider URLs into the prompt to help the LLM infer `base_url`
- Sends a truncated context window (10 chars around keyword matches)
