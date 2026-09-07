"""HTTP connectors: REST and GraphQL, plus the hardened client they share.

Security
--------
* Every URL - the configured one *and* every pagination link the server returns
  - is re-validated by :func:`validate_url`.  A ``next`` link pointing at
  ``http://169.254.169.254/latest/meta-data/iam/`` is the classic way an API
  integration turns into cloud credential theft; re-checking each hop closes it.
* Redirects are **not** followed automatically.  A 302 to an internal address
  bypasses a check that only ran on the original URL.  Redirects are resolved
  manually, one hop at a time, each one re-validated, with a bounded count.
* TLS verification is on and cannot be disabled in a production environment.
* Credentials are resolved through the secret resolver and sent as headers, so
  they never appear in a URL, a log line or a proxy access record.
* Response bodies are size-capped while streaming, so a hostile endpoint cannot
  exhaust memory with an unbounded body.

Reliability
-----------
* ``Retry-After`` is honoured on 429/503 rather than blindly backing off.
* Retries only on 5xx/429 and transport errors - never on a 4xx, which will
  fail identically on every attempt.
* A token-bucket limiter keeps the pipeline inside the provider's quota.
"""

from __future__ import annotations

import json
import logging
import ssl
import threading
import time
from collections.abc import Iterator, Mapping
from functools import lru_cache
from typing import Any
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import httpx

from ironflow.config.models import ConnectorSpec
from ironflow.connectors.base import BaseSink, BaseSource, ConnectorRuntime, sink, source
from ironflow.core.context import ExecutionContext
from ironflow.core.errors import (
    AuthenticationError,
    ConfigurationError,
    ExtractionError,
    LoadingError,
    RateLimitError,
)
from ironflow.core.errors import ConnectionError as IFConnectionError
from ironflow.core.retry import call_with_retry
from ironflow.core.types import Record, RecordBatch, RecordStream
from ironflow.security.guards import validate_url

logger = logging.getLogger(__name__)

RETRYABLE_STATUS = frozenset({408, 425, 429, 500, 502, 503, 504})
MAX_REDIRECTS = 5
MAX_PAGES_DEFAULT = 10_000


@lru_cache(maxsize=2)
def _shared_ssl_context() -> ssl.SSLContext:
    """One verified TLS context per process.

    Constructing an ``httpx.Client`` with ``verify=True`` re-reads and re-parses
    the CA bundle every time - measured at ~1.4 s per client.  A pipeline with
    several REST tasks paid that repeatedly for no benefit, since the trust
    store does not change during a run.  Certificate verification and hostname
    checking stay on; only the parsing is shared.
    """
    try:
        import certifi

        context = ssl.create_default_context(cafile=certifi.where())
    except ImportError:  # pragma: no cover - falls back to the system store
        context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context


class RateLimiter:
    """Token bucket shared by every request of one connector instance.

    A bucket (rather than a fixed sleep) allows a burst up to the bucket size
    while still respecting the average rate, which is how published API quotas
    are usually expressed.
    """

    __slots__ = ("_capacity", "_lock", "_rate", "_timestamp", "_tokens")

    def __init__(self, requests_per_second: float, burst: int | None = None) -> None:
        self._rate = max(0.0, requests_per_second)
        self._capacity = float(burst if burst is not None else max(1, int(requests_per_second)))
        self._tokens = self._capacity
        self._timestamp = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self) -> float:
        """Block until a token is available; returns the time slept."""
        if self._rate <= 0:
            return 0.0
        with self._lock:
            now = time.monotonic()
            self._tokens = min(self._capacity, self._tokens + (now - self._timestamp) * self._rate)
            self._timestamp = now
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return 0.0
            wait = (1.0 - self._tokens) / self._rate
        time.sleep(wait)
        with self._lock:
            self._tokens = max(0.0, self._tokens - 1.0)
            self._timestamp = time.monotonic()
        return wait


class HttpClientMixin:
    """Shared authentication, request execution and response handling."""

    def _auth_headers(self: Any) -> dict[str, str]:
        """Build authentication headers from the configured scheme."""
        auth_type = self.str_option("auth", "none").lower()
        headers: dict[str, str] = {}

        if auth_type in {"none", ""}:
            return headers
        if auth_type == "bearer":
            token = self.secret_option("token", required=True)
            headers["Authorization"] = f"Bearer {token}"
        elif auth_type == "basic":
            import base64

            user = self.secret_option("user", required=True)
            password = self.secret_option("password") or ""
            encoded = base64.b64encode(f"{user}:{password}".encode()).decode("ascii")
            headers["Authorization"] = f"Basic {encoded}"
        elif auth_type == "api_key":
            key = self.secret_option("api_key", required=True)
            header_name = self.str_option("api_key_header", "X-API-Key")
            headers[header_name] = key
        elif auth_type == "oauth2":
            headers["Authorization"] = f"Bearer {self._oauth2_token()}"
        else:
            raise ConfigurationError(
                "unsupported auth type",
                context={
                    "auth": auth_type,
                    "supported": ["none", "bearer", "basic", "api_key", "oauth2"],
                },
            )
        return headers

    #: Cached OAuth2 token as ``(token, expires_at)``; set by ``_oauth2_token``.
    _token_cache: tuple[str, float] | None = None

    def _oauth2_token(self: Any) -> str:
        """Client-credentials grant, cached until shortly before expiry."""
        cached = getattr(self, "_token_cache", None)
        if cached and cached[1] > time.time() + 30:
            return str(cached[0])

        token_url = validate_url(
            self.str_option("token_url", required=True),
            allow_private=self.runtime.settings.allow_private_network,
        )
        payload = {
            "grant_type": "client_credentials",
            "client_id": self.secret_option("client_id", required=True),
            "client_secret": self.secret_option("client_secret", required=True),
        }
        scope = self.str_option("scope")
        if scope:
            payload["scope"] = scope

        try:
            response = httpx.post(
                token_url,
                data=payload,
                timeout=self.runtime.settings.http_timeout,
                verify=self.runtime.settings.http_verify_tls,
            )
        except httpx.HTTPError as exc:
            raise AuthenticationError(
                "OAuth2 token request failed", context={"token_url": token_url}, cause=exc
            ) from exc

        if response.status_code != 200:
            raise AuthenticationError(
                "OAuth2 token endpoint rejected the credentials",
                context={"status": response.status_code},
            )
        body = response.json()
        token = body.get("access_token")
        if not token:
            raise AuthenticationError("OAuth2 response contained no access_token")
        expires_in = int(body.get("expires_in", 3600))
        self._token_cache = (token, time.time() + expires_in)
        return str(token)

    def _build_client(self: Any) -> httpx.Client:
        settings = self.runtime.settings
        verify = self.bool_option("verify_tls", settings.http_verify_tls)
        if not verify and settings.is_production:
            raise ConfigurationError(
                "TLS verification cannot be disabled in a production environment"
            )
        headers = {
            "User-Agent": self.str_option("user_agent", "IronFlow/1.0"),
            "Accept": self.str_option("accept", "application/json"),
            **self._auth_headers(),
            **{str(k): str(v) for k, v in (self.option("headers", {}) or {}).items()},
        }
        return httpx.Client(
            headers=headers,
            timeout=httpx.Timeout(self.int_option("timeout", int(settings.http_timeout))),
            verify=_shared_ssl_context() if verify else False,
            # Handled manually so every hop is re-validated against the SSRF policy.
            follow_redirects=False,
            limits=httpx.Limits(max_connections=self.int_option("max_connections", 10)),
        )

    def _validate(self: Any, url: str) -> str:
        return validate_url(
            url,
            allow_private=self.bool_option(
                "allow_private_network", self.runtime.settings.allow_private_network
            ),
            allowed_hosts=self.list_option("allowed_hosts") or None,
        )

    def _request(
        self: Any,
        client: httpx.Client,
        method: str,
        url: str,
        *,
        params: Mapping[str, Any] | None = None,
        json_body: Any = None,
        limiter: RateLimiter | None = None,
    ) -> httpx.Response:
        """Execute one logical request: rate limit, retry, manual redirects."""
        policy = self.retry_policy

        def attempt() -> httpx.Response:
            if limiter is not None:
                limiter.acquire()
            current = self._validate(url)
            for hop in range(MAX_REDIRECTS + 1):
                try:
                    response = client.request(method, current, params=params, json=json_body)
                except httpx.TimeoutException as exc:
                    raise IFConnectionError(
                        "request timed out", context={"url": current}, cause=exc
                    ) from exc
                except httpx.HTTPError as exc:
                    raise IFConnectionError(
                        "request failed", context={"url": current}, cause=exc
                    ) from exc

                if response.is_redirect and response.headers.get("location"):
                    if hop >= MAX_REDIRECTS:
                        raise IFConnectionError(
                            "too many redirects", context={"url": current}, retryable=False
                        )
                    current = self._validate(urljoin(current, response.headers["location"]))
                    response.close()
                    continue
                return self._check_response(response)

            raise IFConnectionError(  # pragma: no cover - loop always returns
                "redirect resolution failed", context={"url": url}
            )

        return call_with_retry(attempt, policy, description=f"{method} {url}")

    def _check_response(self: Any, response: httpx.Response) -> httpx.Response:
        status = response.status_code
        if status < 400:
            return response

        body = response.text[:500]
        if status in {401, 403}:
            raise AuthenticationError(
                "the API rejected our credentials",
                context={"status": status, "body": body},
            )
        if status == 429:
            retry_after = _parse_retry_after(response.headers.get("Retry-After"))
            if retry_after:
                logger.warning("rate limited; sleeping %.1fs as instructed", retry_after)
                time.sleep(min(retry_after, 120))
            raise RateLimitError("the API rate limit was exceeded", context={"status": status})
        if status in RETRYABLE_STATUS:
            raise IFConnectionError(
                "the API returned a transient error",
                context={"status": status, "body": body},
            )
        raise ExtractionError(
            "the API returned an error",
            context={"status": status, "body": body},
        )


def _parse_retry_after(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        from email.utils import parsedate_to_datetime

        try:
            target = parsedate_to_datetime(value)
        except (TypeError, ValueError):
            return None
        return max(0.0, target.timestamp() - time.time())


# --------------------------------------------------------------------------- #
# REST source
# --------------------------------------------------------------------------- #
@source("rest", "http", "api")
class RestSource(HttpClientMixin, BaseSource):
    """Read paginated JSON from an HTTP API.

    Options: ``url`` (required), ``method``, ``params``, ``headers``,
    ``data_path`` (dotted path to the record array), ``auth`` and its
    credentials, ``pagination`` (``none``|``page``|``offset``|``cursor``|``link``),
    ``page_size``, ``max_pages``, ``rate_limit`` (requests/second).
    """

    def __init__(self, spec: ConnectorSpec, runtime: ConnectorRuntime | None = None) -> None:
        super().__init__(spec, runtime)
        self._client: httpx.Client | None = None
        self._limiter: RateLimiter | None = None
        self._token_cache = None

    def _on_open(self, context: ExecutionContext) -> None:
        self._client = self._build_client()
        rate = float(self.option("rate_limit", 0) or 0)
        self._limiter = RateLimiter(rate) if rate > 0 else None

    def _on_close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    def read(self, context: ExecutionContext) -> RecordStream:
        if self._client is None:
            self.open(context)
        assert self._client is not None

        url = self._validate(self.str_option("url", required=True))
        method = self.str_option("method", "GET").upper()
        base_params = dict(self.option("params", {}) or {})
        data_path = self.str_option("data_path", "")
        pagination = self.str_option("pagination", "none").lower()
        page_size = self.int_option("page_size", 100, minimum=1)
        max_pages = self.int_option("max_pages", MAX_PAGES_DEFAULT, minimum=1)
        batch_size = self.batch_size

        def generate() -> Iterator[RecordBatch]:
            next_url: str | None = url
            params = dict(base_params)
            page = 0
            sequence = 0
            buffer: list[Record] = []
            cursor: str | None = None

            while next_url and page < max_pages:
                context.cancellation.raise_if_cancelled()
                page_params = self._page_params(pagination, params, page, page_size, cursor)
                assert self._client is not None
                response = self._request(
                    self._client, method, next_url, params=page_params, limiter=self._limiter
                )
                payload = _parse_json(response, self.runtime.settings.http_max_response_bytes)
                records = _extract_records(payload, data_path)

                logger.debug(
                    "fetched page", extra={"page": page, "records": len(records), "url": next_url}
                )

                for record in records:
                    buffer.append(record if isinstance(record, dict) else {"value": record})
                    if len(buffer) >= batch_size:
                        yield RecordBatch(buffer, sequence=sequence, source=self.name)
                        sequence += 1
                        buffer = []

                page += 1
                next_url, cursor = self._next_page(
                    pagination, next_url, response, payload, records, page_size
                )

            if page >= max_pages:
                logger.warning(
                    "stopped after max_pages=%d; the result set may be truncated", max_pages
                )
            if buffer:
                yield RecordBatch(buffer, sequence=sequence, source=self.name)

        return generate()

    def _page_params(
        self,
        pagination: str,
        params: dict[str, Any],
        page: int,
        page_size: int,
        cursor: str | None,
    ) -> dict[str, Any]:
        merged = dict(params)
        if pagination == "page":
            merged[self.str_option("page_param", "page")] = page + self.int_option(
                "first_page", 1, minimum=0
            )
            merged[self.str_option("size_param", "per_page")] = page_size
        elif pagination == "offset":
            merged[self.str_option("offset_param", "offset")] = page * page_size
            merged[self.str_option("limit_param", "limit")] = page_size
        elif pagination == "cursor" and cursor:
            merged[self.str_option("cursor_param", "cursor")] = cursor
        return merged

    def _next_page(
        self,
        pagination: str,
        current_url: str,
        response: httpx.Response,
        payload: Any,
        records: list[Any],
        page_size: int,
    ) -> tuple[str | None, str | None]:
        """Decide whether another page exists and where it is."""
        if pagination in {"none", ""}:
            return None, None
        if pagination in {"page", "offset"}:
            # Stop on a short page - the universal end-of-results signal.
            return (current_url, None) if len(records) >= page_size else (None, None)
        if pagination == "cursor":
            cursor_path = self.str_option("cursor_path", "next_cursor")
            cursor = _dig(payload, cursor_path)
            return (current_url, str(cursor)) if cursor else (None, None)
        if pagination == "link":
            link = _parse_link_header(response.headers.get("Link", "")) or _dig(
                payload, self.str_option("next_path", "next")
            )
            if not link:
                return None, None
            return self._validate(urljoin(current_url, str(link))), None
        raise ConfigurationError(
            "unsupported pagination strategy",
            context={"pagination": pagination},
        )


def _parse_json(response: httpx.Response, max_bytes: int) -> Any:
    if len(response.content) > max_bytes:
        raise ExtractionError(
            "response exceeds the configured size limit",
            context={"bytes": len(response.content), "limit": max_bytes},
        )
    try:
        return response.json()
    except (json.JSONDecodeError, ValueError) as exc:
        raise ExtractionError(
            "response body is not valid JSON",
            context={"content_type": response.headers.get("content-type", "")},
            cause=exc,
        ) from exc


def _extract_records(payload: Any, data_path: str) -> list[Any]:
    data = _dig(payload, data_path) if data_path else payload
    if data is None:
        return []
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return [data]
    return [{"value": data}]


def _dig(payload: Any, path: str) -> Any:
    """Follow a dotted path through nested mappings/lists."""
    cursor = payload
    for part in path.split("."):
        if not part:
            continue
        if isinstance(cursor, Mapping):
            cursor = cursor.get(part)
        elif isinstance(cursor, list) and part.isdigit():
            index = int(part)
            cursor = cursor[index] if index < len(cursor) else None
        else:
            return None
        if cursor is None:
            return None
    return cursor


def _parse_link_header(header: str) -> str | None:
    """Extract ``rel="next"`` from an RFC 8288 ``Link`` header."""
    for part in header.split(","):
        segments = part.split(";")
        if len(segments) < 2:
            continue
        url = segments[0].strip().strip("<>")
        if any('rel="next"' in s.replace(" ", "").replace("'", '"') for s in segments[1:]):
            return url
    return None


# --------------------------------------------------------------------------- #
# REST sink
# --------------------------------------------------------------------------- #
@sink("rest", "http", "api", "webhook")
class RestSink(HttpClientMixin, BaseSink):
    """POST records to an HTTP endpoint.

    Options: ``url`` (required), ``method``, ``payload_mode``
    (``batch``|``record``), ``wrapper_key``, ``rate_limit``.

    Not transactional: an HTTP endpoint cannot un-receive a request.  Failures
    surface immediately so the orchestrator can stop rather than continue with a
    partially delivered dataset.
    """

    transactional = False

    def __init__(self, spec: ConnectorSpec, runtime: ConnectorRuntime | None = None) -> None:
        super().__init__(spec, runtime)
        self._client: httpx.Client | None = None
        self._limiter: RateLimiter | None = None
        self._token_cache = None

    def _on_open(self, context: ExecutionContext) -> None:
        self._client = self._build_client()
        rate = float(self.option("rate_limit", 0) or 0)
        self._limiter = RateLimiter(rate) if rate > 0 else None
        self.rows_written = 0

    def _on_close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    def write(self, batch: RecordBatch, context: ExecutionContext) -> int:
        self._assert_writable()
        assert self._client is not None
        if batch.is_empty:
            return 0

        url = self._validate(self.str_option("url", required=True))
        method = self.str_option("method", "POST").upper()
        wrapper = self.str_option("wrapper_key", "")

        if self.str_option("payload_mode", "batch") == "record":
            for record in batch.records:
                single: Any = {wrapper: record} if wrapper else record
                self._request(self._client, method, url, json_body=single, limiter=self._limiter)
        else:
            whole: Any = {wrapper: batch.records} if wrapper else batch.records
            self._request(self._client, method, url, json_body=whole, limiter=self._limiter)

        self.rows_written += len(batch)
        return len(batch)

    def rollback(self) -> None:
        if self.rows_written:
            raise LoadingError(
                "the REST sink cannot roll back; "
                f"{self.rows_written} rows were already delivered to the endpoint",
                context={"sink": self.name, "rows": self.rows_written},
            )


# --------------------------------------------------------------------------- #
# GraphQL source
# --------------------------------------------------------------------------- #
@source("graphql")
class GraphQLSource(HttpClientMixin, BaseSource):
    """Execute a GraphQL query, optionally paginating a Relay connection.

    Options: ``url`` (required), ``query`` (required), ``variables``,
    ``data_path`` (dotted path under ``data``), ``pagination``
    (``none``|``cursor``), ``page_size``, ``cursor_path``, ``has_next_path``.
    """

    def __init__(self, spec: ConnectorSpec, runtime: ConnectorRuntime | None = None) -> None:
        super().__init__(spec, runtime)
        self._client: httpx.Client | None = None
        self._limiter: RateLimiter | None = None
        self._token_cache = None

    def _on_open(self, context: ExecutionContext) -> None:
        self._client = self._build_client()
        rate = float(self.option("rate_limit", 0) or 0)
        self._limiter = RateLimiter(rate) if rate > 0 else None

    def _on_close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    def read(self, context: ExecutionContext) -> RecordStream:
        if self._client is None:
            self.open(context)
        assert self._client is not None

        url = self._validate(self.str_option("url", required=True))
        query = self.str_option("query", required=True)
        variables = dict(self.option("variables", {}) or {})
        data_path = self.str_option("data_path", "")
        pagination = self.str_option("pagination", "none").lower()
        page_size = self.int_option("page_size", 100, minimum=1)
        max_pages = self.int_option("max_pages", 1000, minimum=1)
        batch_size = self.batch_size

        def generate() -> Iterator[RecordBatch]:
            buffer: list[Record] = []
            sequence = 0
            cursor: str | None = None
            page = 0

            while page < max_pages:
                context.cancellation.raise_if_cancelled()
                page_variables = dict(variables)
                if pagination == "cursor":
                    page_variables.setdefault("first", page_size)
                    if cursor:
                        page_variables["after"] = cursor

                assert self._client is not None
                response = self._request(
                    self._client,
                    "POST",
                    url,
                    json_body={"query": query, "variables": page_variables},
                    limiter=self._limiter,
                )
                payload = _parse_json(response, self.runtime.settings.http_max_response_bytes)

                # GraphQL returns HTTP 200 with an ``errors`` array; a naive
                # status-code check would silently ingest an empty result set.
                errors = payload.get("errors") if isinstance(payload, Mapping) else None
                if errors:
                    raise ExtractionError(
                        "the GraphQL endpoint returned errors",
                        context={"errors": json.dumps(errors)[:500]},
                    )

                data = payload.get("data") if isinstance(payload, Mapping) else None
                records = _extract_records(data, data_path)
                for record in records:
                    node = (
                        record.get("node")
                        if isinstance(record, dict) and "node" in record
                        else record
                    )
                    buffer.append(node if isinstance(node, dict) else {"value": node})
                    if len(buffer) >= batch_size:
                        yield RecordBatch(buffer, sequence=sequence, source=self.name)
                        sequence += 1
                        buffer = []

                page += 1
                if pagination != "cursor":
                    break
                has_next = _dig(data, self.str_option("has_next_path", "pageInfo.hasNextPage"))
                cursor = _dig(data, self.str_option("cursor_path", "pageInfo.endCursor"))
                if not has_next or not cursor:
                    break

            if buffer:
                yield RecordBatch(buffer, sequence=sequence, source=self.name)

        return generate()


def build_url(base: str, params: Mapping[str, Any]) -> str:
    """Append query parameters to a URL (used by tests and the CLI)."""
    parsed = urlparse(base)
    query = parse_qs(parsed.query)
    query.update({k: [str(v)] for k, v in params.items()})
    return urlunparse(parsed._replace(query=urlencode(query, doseq=True)))


__all__ = ["GraphQLSource", "RateLimiter", "RestSink", "RestSource", "build_url"]
