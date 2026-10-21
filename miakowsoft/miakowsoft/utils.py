"""Shared helpers for HTTP, caching and timing."""

from __future__ import annotations

import json
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Callable


USER_AGENT = "miakowsoft/1.1.0 (+public research; contact via local operator)"
DEFAULT_TIMEOUT = 8
MAX_RESPONSE_BYTES = 2_000_000
MAX_RETRIES = 1
RETRY_STATUSES = {408, 425, 429, 500, 502, 503, 504}

_cache_lock = threading.Lock()
_response_cache: dict[str, tuple[float, tuple[int, str, dict[str, str]]]] = {}
CACHE_TTL_SEC = 300


def http_get(
    url: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    headers: dict[str, str] | None = None,
    max_bytes: int = MAX_RESPONSE_BYTES,
    use_cache: bool = True,
    retries: int = MAX_RETRIES,
) -> tuple[int, str, dict[str, str]]:
    """Synchronous GET with size limit, TLS verification, retries and TTL cache."""
    if use_cache:
        with _cache_lock:
            hit = _response_cache.get(url)
            if hit and (time.time() - hit[0]) < CACHE_TTL_SEC:
                return hit[1]

    req_headers = {"User-Agent": USER_AGENT, "Accept": "application/json, text/plain, */*"}
    if headers:
        req_headers.update(headers)

    last_error: Exception | None = None
    attempts = max(1, retries + 1)
    for attempt in range(attempts):
        request = urllib.request.Request(url, headers=req_headers, method="GET")
        ctx = ssl.create_default_context()
        try:
            with urllib.request.urlopen(request, timeout=timeout, context=ctx) as resp:
                status = getattr(resp, "status", 200)
                data = resp.read(max_bytes + 1)
                if len(data) > max_bytes:
                    raise ValueError("Response exceeded size limit")
                charset = "utf-8"
                ctype = resp.headers.get("Content-Type", "")
                if "charset=" in ctype.lower():
                    charset = ctype.lower().split("charset=")[-1].split(";")[0].strip() or "utf-8"
                text = data.decode(charset, errors="replace")
                hdrs = {k: v for k, v in resp.headers.items()}
                result = (status, text, hdrs)
                if use_cache and status == 200:
                    with _cache_lock:
                        if len(_response_cache) > 600:
                            _response_cache.clear()
                        _response_cache[url] = (time.time(), result)
                return result
        except urllib.error.HTTPError as exc:
            body = exc.read(max_bytes).decode("utf-8", errors="replace") if exc.fp else ""
            hdrs = dict(exc.headers.items()) if exc.headers else {}
            if exc.code in RETRY_STATUSES and attempt + 1 < attempts:
                delay = 0.35 * (attempt + 1)
                ra = hdrs.get("Retry-After")
                if ra:
                    try:
                        delay = min(float(ra), 4.0)
                    except ValueError:
                        pass
                time.sleep(delay)
                continue
            return exc.code, body, hdrs
        except (urllib.error.URLError, socket.timeout, TimeoutError, ValueError, OSError) as exc:
            last_error = exc
            if attempt + 1 < attempts:
                time.sleep(0.3 * (attempt + 1))
                continue
            raise ConnectionError(str(exc)) from exc
    if last_error:
        raise ConnectionError(str(last_error)) from last_error
    raise ConnectionError("HTTP request failed")


def http_get_json(url: str, **kwargs: Any) -> tuple[int, Any]:
    status, text, _ = http_get(url, **kwargs)
    if not text.strip():
        return status, None
    try:
        return status, json.loads(text)
    except json.JSONDecodeError:
        return status, text


def parallel_map(
    func: Callable[[Any], Any],
    items: list[Any],
    max_workers: int = 8,
) -> list[Any]:
    if not items:
        return []
    results: list[Any] = [None] * len(items)
    with ThreadPoolExecutor(max_workers=min(max_workers, len(items))) as pool:
        future_map = {pool.submit(func, item): idx for idx, item in enumerate(items)}
        for fut in as_completed(future_map):
            idx = future_map[fut]
            try:
                results[idx] = fut.result()
            except Exception as exc:
                results[idx] = exc
    return results


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def timed(fn: Callable[..., Any]) -> Callable[..., tuple[Any, int]]:
    def wrapper(*args: Any, **kwargs: Any) -> tuple[Any, int]:
        start = time.perf_counter()
        result = fn(*args, **kwargs)
        ms = int((time.perf_counter() - start) * 1000)
        return result, ms
    return wrapper


def clear_http_cache() -> None:
    with _cache_lock:
        _response_cache.clear()
