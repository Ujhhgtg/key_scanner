import asyncio
import json
import sys
import threading
import time
from pathlib import Path

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

DATA_FILE = Path("leaked_keys.json")
BAN_DURATION = 60.0

PROVIDER_TIER: dict[str, int] = {
    "google": 1, "anthropic": 1, "openai": 1, "deepseek": 1,
    "aliyun": 1, "dashscope": 1,
    "moonshot": 1, "kimi": 1,
    "minimax": 1,
    "xiaomi": 1,
    "openrouter": 2,
    "ollama": 2,
    "baidu": 3, "qianfan": 3, "ernie": 3,
    "mistral": 3,
}

HOP_HEADERS = {
    "transfer-encoding", "connection", "keep-alive",
    "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "upgrade",
}

BEST_MODEL_MAP: dict[str, str] = {
    "openai": "gpt-5.5",
    "anthropic": "claude-opus-4-7",
    "google": "gemini-3.1-pro-preview",
    "deepseek": "deepseek-v4-pro",
    "aliyun": "qwen3.6-max",
    "dashscope": "qwen3.6-max",
    "moonshot": "kimi-k2.6",
    "kimi": "kimi-k2.6",
    "minimax": "MiniMax-M2.7",
    "baidu": "ernie-4.5",
    "qianfan": "ernie-4.5",
    "ernie": "ernie-4.5",
    "mistral": "mistral-large",
    "xai": "grok-4",
    "grok": "grok-4",
    "zhipu": "glm-5.1",
    "glm": "glm-5.1",
}

KNOWN_MODELS: list[dict] = [
    {"id": "auto", "object": "model", "created": 0, "owned_by": "system"},
    {"id": "gpt-5.5", "object": "model", "created": 0, "owned_by": "openai"},
    {"id": "gpt-5", "object": "model", "created": 0, "owned_by": "openai"},
    {"id": "gpt-4.1", "object": "model", "created": 0, "owned_by": "openai"},
    {"id": "claude-opus-4-7", "object": "model", "created": 0, "owned_by": "anthropic"},
    {"id": "claude-sonnet-4-5", "object": "model", "created": 0, "owned_by": "anthropic"},
    {"id": "gemini-3.1-pro-preview", "object": "model", "created": 0, "owned_by": "google"},
    {"id": "gemini-3.0-flash", "object": "model", "created": 0, "owned_by": "google"},
    {"id": "deepseek-v4-pro", "object": "model", "created": 0, "owned_by": "deepseek"},
    {"id": "deepseek-v3.2", "object": "model", "created": 0, "owned_by": "deepseek"},
    {"id": "qwen3.6-max", "object": "model", "created": 0, "owned_by": "aliyun"},
    {"id": "qwen3.6-plus", "object": "model", "created": 0, "owned_by": "aliyun"},
    {"id": "kimi-k2.6", "object": "model", "created": 0, "owned_by": "moonshot"},
    {"id": "MiniMax-M2.7", "object": "model", "created": 0, "owned_by": "minimax"},
    {"id": "ernie-4.5", "object": "model", "created": 0, "owned_by": "baidu"},
    {"id": "glm-5.1", "object": "model", "created": 0, "owned_by": "zhipu"},
    {"id": "mistral-large", "object": "model", "created": 0, "owned_by": "mistral"},
    {"id": "grok-4", "object": "model", "created": 0, "owned_by": "xai"},
]


class KeyStore:
    def __init__(self):
        self._lock = threading.Lock()
        self._entries: list[dict] = []
        self._banned: dict[str, float] = {}
        self.reload()

    def reload(self):
        if not DATA_FILE.exists():
            with self._lock:
                self._entries = []
            return
        try:
            data = json.loads(DATA_FILE.read_text())
        except (json.JSONDecodeError, TypeError):
            with self._lock:
                self._entries = []
            return

        valid_llm: list[dict] = []
        for entry in data:
            if not isinstance(entry, dict):
                continue
            if entry.get("valid_type") != "valid":
                continue
            kt = (entry.get("key_type") or "").lower()
            if "llm" not in kt:
                continue
            valid_llm.append(entry)

        def _sort_key(e: dict) -> tuple[int, str]:
            pn = (e.get("provider_name") or "").lower()
            tier = PROVIDER_TIER.get(pn, 99)
            return (tier, pn)

        valid_llm.sort(key=_sort_key)

        with self._lock:
            self._entries = valid_llm

    def count(self) -> int:
        with self._lock:
            return len(self._entries)

    def get_provider(self) -> dict | None:
        now = time.time()
        with self._lock:
            for entry in self._entries:
                pn = (entry.get("provider_name") or "").lower()
                if pn in self._banned:
                    if self._banned[pn] > now:
                        continue
                    del self._banned[pn]
                return entry
        return None

    def ban(self, provider_name: str):
        with self._lock:
            self._banned[provider_name.lower()] = time.time() + BAN_DURATION


store = KeyStore()
app = FastAPI(title="Key Scanner Proxy")


@app.on_event("startup")
async def _startup_watcher():
    asyncio.create_task(_file_poll())


async def _file_poll():
    last_mtime: float = DATA_FILE.stat().st_mtime if DATA_FILE.exists() else 0
    while True:
        await asyncio.sleep(5)
        try:
            mtime = DATA_FILE.stat().st_mtime
            if mtime != last_mtime:
                last_mtime = mtime
                store.reload()
                print(f"[watcher] reloaded — {store.count()} valid LLM keys loaded",
                      file=sys.stderr)
        except FileNotFoundError:
            if last_mtime != 0:
                last_mtime = 0
                store.reload()
                print("[watcher] file deleted — keys cleared", file=sys.stderr)


@app.get("/v1/models")
async def list_models():
    return JSONResponse({"object": "list", "data": KNOWN_MODELS})


@app.api_route("/v1/{path:path}", methods=[
    "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS",
])
async def proxy(request: Request, path: str):
    body = await request.body()
    body_json: dict | None = None
    is_auto = False
    try:
        body_json = json.loads(body)
        if isinstance(body_json, dict) and body_json.get("model") == "auto":
            is_auto = True
    except (json.JSONDecodeError, TypeError):
        pass

    max_attempts = max(store.count(), 1)
    for _ in range(max_attempts):
        entry = store.get_provider()
        if entry is None:
            break

        provider_name = entry.get("provider_name", "unknown")
        api_key = entry.get("key", "")
        base_url = entry.get("base_url", "")

        if not api_key or not base_url:
            continue

        forward_body = body
        if is_auto:
            pn_lower = provider_name.lower()
            best_model = BEST_MODEL_MAP.get(pn_lower)
            if not best_model:
                continue
            body_copy = dict(body_json)
            body_copy["model"] = best_model
            forward_body = json.dumps(body_copy).encode()

        base = base_url.rstrip("/")
        if base.endswith("/v1"):
            base = base[:-3]
        target_url = f"{base}/v1/{path}"
        if request.url.query:
            target_url += f"?{request.url.query}"

        req_headers = {}
        for k, v in request.headers.items():
            kl = k.lower()
            if kl in ("host", "authorization"):
                continue
            req_headers[k] = v
        req_headers["authorization"] = f"Bearer {api_key}"

        client = httpx.AsyncClient(timeout=httpx.Timeout(60.0))
        try:
            req = client.build_request(
                method=request.method,
                url=target_url,
                headers=req_headers,
                content=forward_body,
            )
            resp = await client.send(req, stream=True)

            if resp.status_code >= 400:
                await resp.aread()
                await resp.aclose()
                await client.aclose()
                print(f"[proxy] {provider_name} returned {resp.status_code} — banning {BAN_DURATION}s",
                      file=sys.stderr)
                store.ban(provider_name)
                continue

            content_type = resp.headers.get("content-type", "")
            is_stream = "text/event-stream" in content_type

            if is_stream:
                async def _stream_body():
                    try:
                        async for chunk in resp.aiter_bytes():
                            yield chunk
                    finally:
                        await resp.aclose()
                        await client.aclose()

                resp_headers = {
                    k: v for k, v in resp.headers.items()
                    if k.lower() not in HOP_HEADERS
                }
                return StreamingResponse(
                    _stream_body(),
                    status_code=resp.status_code,
                    headers=resp_headers,
                )
            else:
                content = await resp.aread()
                await resp.aclose()
                await client.aclose()

                resp_headers = {
                    k: v for k, v in resp.headers.items()
                    if k.lower() not in HOP_HEADERS
                }
                return Response(
                    content=content,
                    status_code=resp.status_code,
                    headers=resp_headers,
                )
        except Exception as exc:
            await client.aclose()
            print(f"[proxy] {provider_name} exception: {exc} — banning {BAN_DURATION}s",
                  file=sys.stderr)
            store.ban(provider_name)
            continue

    return JSONResponse({"error": "all providers failed or are banned"}, status_code=502)


def serve(host: str = "localhost", port: int = 6767):
    print(f"Key Scanner Proxy starting on http://{host}:{port}/v1/")
    print(f"Loaded {store.count()} valid LLM keys from {DATA_FILE}")
    import uvicorn
    uvicorn.run(app, host=host, port=port, log_level="warning")
