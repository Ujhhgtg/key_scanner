import argparse
import json
import os
import re
import sys
from pathlib import Path

import httpx
from dotenv import load_dotenv
from openai import (
    APIStatusError,
    AuthenticationError,
    OpenAI,
    RateLimitError,
)

DATA_FILE = Path("leaked_keys.json")

KEY_PATTERNS: list[tuple[str, str]] = [
    (r"sk-[a-zA-Z0-9]{20,}", "OpenAI API Key"),
    (r"sk-[a-zA-Z0-9]{32}T3BlbkFJ[a-zA-Z0-9]{32}", "OpenAI API Key (v2)"),
    (r"AIza[0-9A-Za-z_-]{35}", "Google API Key"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
    (r"(?i)(?:aws_access_key_id|aws_secret_access_key)\s*=\s*\S+", "AWS Credential"),
    (r"ghp_[a-zA-Z0-9]{36}", "GitHub Personal Access Token"),
    (r"gho_[a-zA-Z0-9]{36}", "GitHub OAuth Access Token"),
    (r"ghu_[a-zA-Z0-9]{36}", "GitHub User-to-Server Token"),
    (r"ghs_[a-zA-Z0-9]{36}", "GitHub Server-to-Server Token"),
    (r"ghr_[a-zA-Z0-9]{36}", "GitHub Refresh Token"),
    (r"xox[baprs]-[a-zA-Z0-9-]{10,}", "Slack Token"),
    (r"sk_live_[0-9a-zA-Z]{24,}", "Stripe Secret Key (Live)"),
    (r"pk_live_[0-9a-zA-Z]{24,}", "Stripe Publishable Key (Live)"),
    (r"rk_live_[0-9a-zA-Z]{24,}", "Stripe Restricted Key (Live)"),
    (r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "Private Key"),
    (r"-----BEGIN CERTIFICATE-----", "Certificate"),
    (r"-----BEGIN PGP PRIVATE KEY BLOCK-----", "PGP Private Key"),
    (r"(?i)(?:mongodb\+srv|mongodb)://[^\s'\"<>]+", "MongoDB Connection String"),
    (r"https?://hooks\.slack\.com/services/[A-Za-z0-9/]{40,}", "Slack Webhook"),
    (
        r"https?://[^\s'\"<>]+\.s3\.amazonaws\.com/[^\s'\"<>]*\.(?:pem|key|cred|credentials)",
        "S3 URL with Credential File",
    ),
    (
        r"https?://[^\s'\"<>]+\.compute[-.]amazonaws\.com/[^\s'\"<>]*\.(?:pem|key)",
        "EC2 Key Pair URL",
    ),
    (
        r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
        "Hardcoded Password",
    ),
    (r"(?i)(?:api[_-]?key|apikey)\s*[:=]\s*['\"][^'\"]+['\"]", "API Key (Generic)"),
    (r"(?i)(?:secret|token)\s*[:=]\s*['\"][^'\"]{8,}['\"]", "Secret/Token (Generic)"),
    (r"AAAA[0-9A-Za-z_-]{40,}", "Generic Long Token"),
]


def load_saved_keys() -> set[str]:
    if DATA_FILE.exists():
        raw = DATA_FILE.read_text()
        try:
            data = json.loads(raw)
            if isinstance(data, list):
                return {entry["key"] for entry in data if "key" in entry}
        except (json.JSONDecodeError, TypeError):
            return set()
    return set()


def save_key(entry: dict) -> None:
    data: list[dict] = []
    if DATA_FILE.exists():
        raw = DATA_FILE.read_text()
        try:
            data = json.loads(raw) or []
        except (json.JSONDecodeError, TypeError):
            data = []
    key = entry["key"]
    data = [e for e in data if e.get("key") != key]
    data.append(entry)
    DATA_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False))


def extract_file_url(body: str) -> str | None:
    for line in body.strip().splitlines():
        line = line.strip()
        if line.startswith("https://github.com/") and "/blob/" in line:
            return line
    return None


def file_url_to_raw(url: str) -> str:
    return url.replace(
        "https://github.com/", "https://raw.githubusercontent.com/"
    ).replace("/blob/", "/")


PLACEHOLDER_SUBSTRINGS = {
    "你的",
    "your_key",
    "your-key",
    "yourkey",
    "123456",
    "abcd",
    "example",
    "changeme",
    "change_me",
    "change-me",
    "xxxxx",
    "test",
    "placeholder",
    "fake",
    "dummy",
    "sample",
    "foobar",
    "barfoo",
}


def is_valid_key(key: str) -> bool:
    lower = key.lower()
    for sub in PLACEHOLDER_SUBSTRINGS:
        if sub in lower:
            return False
    return True


def extract_field(content: str, patterns: list[str]) -> str | None:
    for pat in patterns:
        m = re.search(pat, content)
        if m:
            return m.group(1)
    return None


MODEL_PATTERNS = [
    r"""(?i)(?:model|model_name)\s*[:=]\s*['"]([a-zA-Z0-9_.-]+)['"]""",
    r"""(?i)(?:model|model_name)\s*[:=]\s*"([^"]+)""",
    r"""(?i)(?:model|model_name)\s*[:=]\s*'([^']+)'""",
    r"""(?i)^\s*model\s*=\s*(\S+)""",
    r"""(?i)^\s*MODEL\s*=\s*(\S+)""",
]

BASE_URL_PATTERNS = [
    r"""(?i)(?:base_url|api_base|base-url|api_base_url|openai_base_url)\s*[:=]\s*['"](https?://[^'"]+)['"]""",
    r"""(?i)^\s*(?:BASE_URL|API_BASE|OPENAI_BASE_URL)\s*=\s*(\S+)""",
]


CHAT_MODEL_KEYWORDS = [
    "gpt",
    "chat",
    "o1",
    "o3",
    "claude",
    "gemini",
    "llama",
    "mistral",
    "qwen",
    "deepseek",
    "command",
    "phi",
    "mixtral",
    "nemotron",
    "dbrx",
    "cohere",
    "aya",
    "minicpm",
]
NON_CHAT_KEYWORDS = [
    "embedding",
    "davinci",
    "babbage",
    "curie",
    "ada",
    "whisper",
    "tts",
    "dall-e",
    "moderation",
    "instruct",
    "realtime",
]


def _pick_chat_model(models) -> str | None:
    candidates = []
    for m in models:
        mid = m.id.lower()
        if any(kw in mid for kw in NON_CHAT_KEYWORDS):
            continue
        if any(kw in mid for kw in CHAT_MODEL_KEYWORDS):
            candidates.append(m.id)
    if not candidates:
        for m in models:
            mid = m.id.lower()
            if any(kw in mid for kw in NON_CHAT_KEYWORDS):
                continue
            candidates.append(m.id)
    return candidates[0] if candidates else None


def _raw_body(e: APIStatusError) -> str:
    raw = e.body
    if isinstance(raw, dict):
        return json.dumps(raw, ensure_ascii=False)
    return str(raw or "")


def _classify_status(e: APIStatusError) -> str:
    status = e.status_code
    msg = _raw_body(e).lower()

    if status == 402:
        return "out_of_balance"
    if status == 401:
        return "invalid"
    if status == 429:
        if "quota" in msg or "insufficient_quota" in msg:
            return "out_of_quota"
        return "rate_limited"
    return "valid"


def verify_key(api_key: str, base_url: str, model_name: str | None) -> tuple[str, str]:
    client = OpenAI(
        api_key=api_key,
        base_url=base_url.rstrip("/") + "/v1",
        max_retries=0,
        timeout=15,
    )

    if not model_name:
        try:
            models = client.models.list()
            model_name = _pick_chat_model(models)
        except AuthenticationError as e:
            return "invalid", _raw_body(e)
        except RateLimitError as e:
            body = _raw_body(e)
            if "quota" in body.lower():
                return "out_of_quota", body
            return "rate_limited", body
        except APIStatusError as e:
            return _classify_status(e), _raw_body(e)
        except Exception as e:
            return "error", str(e)

    if not model_name:
        return "error", ""

    try:
        client.chat.completions.create(
            model=model_name,
            messages=[{"role": "user", "content": "hi"}],
            max_tokens=1,
        )
        return "valid", ""
    except AuthenticationError as e:
        return "invalid", _raw_body(e)
    except RateLimitError as e:
        body = _raw_body(e)
        if "quota" in body.lower():
            return "out_of_quota", body
        return "rate_limited", body
    except APIStatusError as e:
        return _classify_status(e), _raw_body(e)
    except Exception as e:
        return "error", str(e)


def extract_keys(content: str) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for pattern, name in KEY_PATTERNS:
        for m in re.finditer(pattern, content):
            found.append((m.group(), name))
    return found


def process_issue(
    issue: dict, saved_keys: set[str], ignore_saved: bool = False
) -> tuple[int, int]:
    repo_url: str = issue["repository_url"]
    parts = repo_url.rstrip("/").split("/")
    owner = parts[-2]
    repo_name = parts[-1]

    body: str = issue.get("body") or ""
    file_url = extract_file_url(body)
    if not file_url:
        print("error: failed to extract file url")
        return 0, 0

    print(f"\nFile URL: {file_url}")

    raw_url = file_url_to_raw(file_url)
    resp = httpx.get(raw_url, timeout=30.0)
    if resp.status_code != 200:
        print(f"  Could not read file (HTTP {resp.status_code})")
        return 0, 0

    content = resp.text
    keys = extract_keys(content)
    if not keys:
        print("  No keys found in file.")
        return 0, 0

    model_name = extract_field(content, MODEL_PATTERNS)
    base_url = extract_field(content, BASE_URL_PATTERNS)
    processed = 0
    skipped = 0

    for key_value, key_type in keys:
        if not is_valid_key(key_value):
            print("  Found invalid key")
            skipped += 1
            continue
        print(f"  Found: [{key_type}] {key_value}")
        if model_name:
            print(f"    model_name: {model_name}")
        if base_url:
            print(f"    base_url:  {base_url}")

        valid_type = ""
        validation_result = ""
        if base_url:
            valid_type, validation_result = verify_key(key_value, base_url, model_name)
            print(f"    verification: {valid_type}")

        if not ignore_saved and key_value in saved_keys:
            skipped += 1
            continue

        entry = {
            "key": key_value,
            "key_type": key_type,
            "repo_owner": owner,
            "repo_name": repo_name,
            "file_url": file_url,
            "valid_type": valid_type,
            "validation_result": validation_result,
        }
        if model_name:
            entry["model_name"] = model_name
        if base_url:
            entry["base_url"] = base_url
        save_key(entry)
        saved_keys.add(key_value)
        processed += 1

    return processed, skipped


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--ignore-saved", action="store_true", help="Re-verify and overwrite saved keys"
    )
    args = parser.parse_args()

    load_dotenv()
    token = os.environ.get("GITHUB_API_KEY", "").strip()
    if not token:
        print("error: GITHUB_API_KEY is not set", file=sys.stderr)
        sys.exit(1)

    saved_keys = load_saved_keys()
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json",
    }

    total_processed = 0
    total_skipped = 0
    page = 1

    with httpx.Client(headers=headers, timeout=30.0) as client:
        while True:
            resp = client.get(
                "https://api.github.com/search/issues",
                params={"q": "your key leak", "per_page": 100, "page": page},
            )
            if resp.status_code == 422 and page > 10:
                break
            if resp.status_code == 403:
                print("Rate limited. Waiting 60s...", file=sys.stderr)
                import time

                time.sleep(60)
                continue
            resp.raise_for_status()
            data = resp.json()
            batch = data.get("items", [])
            if not batch:
                break

            print(f"\n--- Page {page} ({len(batch)} issues) ---")
            for issue in batch:
                p, s = process_issue(issue, saved_keys, ignore_saved=args.ignore_saved)
                total_processed += p
                total_skipped += s

            if len(batch) < 100:
                break
            page += 1

    print(
        f"\nDone. Processed {total_processed} new key(s), skipped {total_skipped} already-saved key(s)."
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        sys.exit(130)
