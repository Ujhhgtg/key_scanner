# key_scanner

scans github issues for leaked api keys and validates them

## setup

```bash
cp .env.example .env
# edit .env and set GITHUB_API_KEY
uv sync
```

## usage

```bash
uv run python main.py
uv run python main.py --ignore-saved   # re-verify already-saved keys
```

## how it works

1. searches github issues for "your key leak"
2. extracts the leaked file url from the issue body
3. reads the file and matches api key patterns (openai, aws, github tokens, stripe, slack, etc.)
4. extracts `model_name` and `base_url` from the same file
5. if `base_url` is present, calls the api to verify the key
6. saves results to `leaked_keys.json`
7. skips already-saved keys (unless `--ignore-saved` is passed)
