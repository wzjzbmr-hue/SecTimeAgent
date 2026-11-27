from __future__ import annotations

import json
import logging
import re
import threading
import time
from pathlib import Path
from typing import Any

import requests

LOG = logging.getLogger(__name__)

SUCCESS_CODE = "AD-000000"
ERR_RATE_LIMIT = "AD-002002"
ERR_SCENE_LIMIT = "AD-162006"
ERR_DUPLICATE_FLAG = "AD-160014"
ERR_NO_SCENE = "AD-161003"
ERR_INVALID_TOKEN = "AD-160019"
ERR_PARAM_OR_MISSING = "AD-160003"
ERR_SCENE_CREATE_FAIL = "AD-160013"

NON_RETRYABLE_CODES = frozenset(
    {
        ERR_PARAM_OR_MISSING,
        ERR_INVALID_TOKEN,
        ERR_NO_SCENE,
        ERR_DUPLICATE_FLAG,
        ERR_SCENE_LIMIT,
        ERR_SCENE_CREATE_FAIL,
    }
)

WAIT_SECONDS_RE = re.compile(r"(\d+(?:\.\d+)?)\s*秒")


class RaceApiError(RuntimeError):
    def __init__(self, code: str, message: str = "", detail: str = "", http_status: int = 200):
        super().__init__(f"Race API error code={code} http={http_status} message={message!r} detail={detail!r}")
        self.code = code
        self.message = message
        self.detail = detail
        self.http_status = http_status


class TokenBucket:
    """Thread-safe global rate limiter shared across all platform API calls."""

    def __init__(self, rate_per_sec: float = 2.0, capacity: float = 2.0):
        self._rate = max(0.1, float(rate_per_sec))
        self._capacity = max(1.0, float(capacity))
        self._tokens = self._capacity
        self._updated = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self) -> None:
        while True:
            with self._lock:
                now = time.monotonic()
                elapsed = now - self._updated
                self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
                self._updated = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                wait_for = (1.0 - self._tokens) / self._rate
            time.sleep(min(wait_for, 1.0))


def is_question_complete(item: dict[str, Any]) -> bool:
    """Official multi-flag completion formula: total_flag_num > 0 && current_user_solved == total_flag_num."""
    total = int(item.get("total_flag_num") or 0)
    solved = int(item.get("current_user_solved") or 0)
    return total > 0 and solved >= total


def parse_rate_limit_wait(message: str, detail: str = "") -> float:
    for text in (message, detail):
        match = WAIT_SECONDS_RE.search(text or "")
        if match:
            return max(0.5, float(match.group(1)))
    return 1.5


class OfficialRaceClient:
    """Deterministic client for the official AI-Race HTTP API (API_接入.md).

    - Base URL: http://<SERVER_HOST>/api/ct/agent/ai_race/race
    - Auth: Authorization: Bearer <AGENT_TOKEN> (omitted on attachment downloads)
    - Enforces code == 'AD-000000' (business errors always return HTTP 200)
    - Enforces global token-bucket throttling (< 3 req/s across all endpoints)
    """

    def __init__(
        self,
        base_url: str,
        agent_token: str,
        *,
        rate_per_sec: float = 2.0,
        timeout: float = 20.0,
        max_retries: int = 3,
    ):
        base = base_url.rstrip("/")
        if "/api/ct/agent/ai_race/race" not in base:
            base = f"{base}/api/ct/agent/ai_race/race"
        self.base_url = base
        self._token = agent_token.strip()
        self._timeout = timeout
        self._max_retries = max(1, int(max_retries))
        self._bucket = TokenBucket(rate_per_sec=rate_per_sec, capacity=max(1.0, rate_per_sec))
        self._local = threading.local()

    def _session(self) -> requests.Session:
        sess = getattr(self._local, "session", None)
        if sess is None:
            sess = requests.Session()
            self._local.session = sess
        return sess

    def _request(
        self,
        method: str,
        endpoint: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> Any:
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        headers = {"Authorization": f"Bearer {self._token}"}
        if json_body is not None:
            headers["Content-Type"] = "application/json"

        last_exc: Exception | None = None
        for attempt in range(self._max_retries + 1):
            self._bucket.acquire()
            try:
                resp = self._session().request(
                    method,
                    url,
                    params=params,
                    json=json_body,
                    headers=headers,
                    timeout=self._timeout,
                )
            except requests.RequestException as exc:
                last_exc = exc
                if attempt >= self._max_retries:
                    raise RaceApiError("NETWORK_ERROR", str(exc), http_status=0) from exc
                wait = min(8.0, float(2 ** (attempt + 1)))
                LOG.warning("race api network error endpoint=%s attempt=%s wait=%.1fs err=%s", endpoint, attempt + 1, wait, exc)
                time.sleep(wait)
                continue

            if resp.status_code >= 500:
                if attempt >= self._max_retries:
                    raise RaceApiError("HTTP_5XX", f"HTTP {resp.status_code}", resp.text[:300], http_status=resp.status_code)
                wait = min(8.0, float(2 ** (attempt + 1)))
                LOG.warning("race api HTTP %s endpoint=%s wait=%.1fs", resp.status_code, endpoint, wait)
                time.sleep(wait)
                continue

            if resp.status_code != 200:
                raise RaceApiError(f"HTTP_{resp.status_code}", f"HTTP {resp.status_code}", resp.text[:300], http_status=resp.status_code)

            try:
                payload = resp.json()
            except ValueError as exc:
                raise RaceApiError("INVALID_JSON", "non-JSON response", resp.text[:300], http_status=resp.status_code) from exc

            code = str(payload.get("code") or "")
            message = str(payload.get("message") or "")
            detail = str(payload.get("detail") or "")

            if code == SUCCESS_CODE:
                return payload.get("data")

            if code == ERR_RATE_LIMIT:
                if attempt >= self._max_retries:
                    raise RaceApiError(code, message, detail, http_status=resp.status_code)
                wait = parse_rate_limit_wait(message, detail) + 0.25
                LOG.warning("race api rate limited (%s) endpoint=%s sleeping %.2fs", code, endpoint, wait)
                time.sleep(wait)
                continue

            raise RaceApiError(code or "UNKNOWN", message, detail, http_status=resp.status_code)

        raise RaceApiError("RETRY_EXHAUSTED", str(last_exc or "retries exhausted"), http_status=0)

    def question_list(self, direction: str | None = None) -> list[dict[str, Any]]:
        params = {"direction": direction} if direction else None
        data = self._request("GET", "checkpoints/robot/question_list", params=params) or {}
        items = data.get("list") or []
        return list(items)

    def question_info(self, question_id: str) -> dict[str, Any]:
        data = self._request("GET", "checkpoints/robot/question_info", params={"question_id": str(question_id)})
        return dict(data or {})

    def question_start(self, question_id: str) -> bool:
        data = self._request("POST", "checkpoints/robot/question_start", json_body={"question_id": str(question_id)})
        return bool(data)

    def question_instance_info(self, question_id: str) -> dict[str, Any]:
        data = self._request(
            "GET",
            "checkpoints/robot/question_instance_info",
            params={"question_id": str(question_id)},
        )
        return dict(data or {})

    def question_stop(self, question_id: str) -> bool:
        data = self._request("POST", "checkpoints/robot/question_stop", json_body={"question_id": str(question_id)})
        return bool(data)

    def submit_flag(self, question_id: str, flag: str) -> dict[str, Any]:
        """Submit flag. Normalizes AD-160014 into is_duplicate=True without retrying."""
        try:
            data = self._request(
                "POST",
                "checkpoints/robot/question/submit_flag",
                json_body={"question_id": str(question_id), "flag": flag.strip()},
            ) or {}
            return {
                "ok": True,
                "code": SUCCESS_CODE,
                "is_pass": bool(data.get("is_pass")),
                "score": data.get("score", 0),
                "is_duplicate": bool(data.get("is_duplicate")),
            }
        except RaceApiError as exc:
            if exc.code == ERR_DUPLICATE_FLAG:
                return {
                    "ok": True,
                    "code": exc.code,
                    "is_pass": True,
                    "score": 0,
                    "is_duplicate": True,
                }
            raise

    def download_attachment(self, url: str, dest_path: Path) -> Path:
        """Download attachment using full URL with NO Authorization header (per API_接入.md §7)."""
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        with self._session().get(url, stream=True, timeout=max(30.0, self._timeout)) as resp:
            resp.raise_for_status()
            with dest_path.open("wb") as fh:
                for chunk in resp.iter_content(chunk_size=65536):
                    if chunk:
                        fh.write(chunk)
        return dest_path

    def ensure_scene_running(
        self,
        question_id: str,
        *,
        wait_timeout: float = 120.0,
        poll_interval: float = 3.0,
    ) -> dict[str, Any]:
        """Start scene and wait until scene_status == 1 with valid addresses.

        Handles scene_status == 20 recovery: question_stop -> wait for 3 -> question_start.
        """
        qid = str(question_id)
        deadline = time.monotonic() + wait_timeout
        info = self.question_instance_info(qid)
        status = info.get("scene_status")

        if status is None:
            return info

        if status == 1 and info.get("scene_addresses"):
            return info

        if status == 20:
            LOG.warning("scene_status=20 detected for question=%s; stopping to recover", qid)
            self.question_stop(qid)
            while time.monotonic() < deadline:
                time.sleep(poll_interval)
                info = self.question_instance_info(qid)
                status = info.get("scene_status")
                if status == 3:
                    break
            else:
                raise RaceApiError("SCENE_RECOVERY_TIMEOUT", f"question {qid} stuck in status={status} after stop")

        if status == 3:
            self.question_start(qid)

        while time.monotonic() < deadline:
            time.sleep(poll_interval)
            info = self.question_instance_info(qid)
            status = info.get("scene_status")
            if status == 1 and info.get("scene_addresses"):
                return info
            if status == 20:
                LOG.warning("scene_status=20 during start wait for question=%s; retrying stop->3->start once", qid)
                self.question_stop(qid)
                while time.monotonic() < deadline:
                    time.sleep(poll_interval)
                    info = self.question_instance_info(qid)
                    if info.get("scene_status") == 3:
                        self.question_start(qid)
                        break
            elif status == 3:
                self.question_start(qid)

        raise RaceApiError("SCENE_START_TIMEOUT", f"question {qid} did not reach scene_status=1 within {wait_timeout}s")


class StreamableMCPClient:
    """Minimal zero-extra-dependency Streamable HTTP MCP fallback client (MCP_接入.md)."""

    def __init__(self, mcp_url: str, agent_token: str, *, timeout: float = 30.0):
        self.mcp_url = mcp_url.rstrip("/")
        self._token = agent_token.strip()
        self._timeout = timeout
        self._session_id: str | None = None
        self._req_id = 0
        self._http = requests.Session()

    def _headers(self) -> dict[str, str]:
        h = {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if self._session_id:
            h["Mcp-Session-Id"] = self._session_id
        return h

    def _rpc(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self._req_id += 1
        body: dict[str, Any] = {"jsonrpc": "2.0", "id": self._req_id, "method": method}
        if params is not None:
            body["params"] = params
        resp = self._http.post(self.mcp_url, headers=self._headers(), json=body, timeout=self._timeout)
        if resp.headers.get("Mcp-Session-Id"):
            self._session_id = resp.headers["Mcp-Session-Id"]
        resp.raise_for_status()
        ctype = resp.headers.get("content-type", "")
        if "text/event-stream" in ctype:
            for line in resp.text.splitlines():
                line = line.strip()
                if line.startswith("data:"):
                    payload = line[5:].strip()
                    if payload:
                        return json.loads(payload)
            raise RaceApiError("MCP_EMPTY_SSE", "empty SSE response from MCP server")
        return resp.json()

    def initialize(self) -> dict[str, Any]:
        return self._rpc(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "cairn-race", "version": "1.0.0"},
            },
        )

    def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        if not self._session_id:
            self.initialize()
        rpc = self._rpc("tools/call", {"name": name, "arguments": arguments})
        result = rpc.get("result") or {}
        if result.get("isError"):
            raise RaceApiError("MCP_TOOL_ERROR", str(result.get("content")))
        structured = result.get("structuredContent")
        if structured is None:
            for item in result.get("content") or []:
                if isinstance(item, dict) and "text" in item:
                    try:
                        structured = json.loads(item["text"])
                    except ValueError:
                        structured = item["text"]
                    break
        if isinstance(structured, dict) and structured.get("code") not in (None, SUCCESS_CODE):
            raise RaceApiError(
                str(structured.get("code")),
                str(structured.get("message") or ""),
                str(structured.get("detail") or ""),
            )
        return structured.get("data") if isinstance(structured, dict) and "data" in structured else structured
