"""HTTP connectors: REST and GraphQL, plus the hardened client they share.

Security
--------
* Every URL - the configured one *and* every pagination link the server returns
  - is re-validated by :func:`validate_url`.  A ``next`` link pointing at
  ``http://169.254.169.254/latest/meta-data/iam/`` is the classic way an API
  integration turns into cloud credential theft; re-checking each hop closes it.
* Every *connection* is checked too.  The client comes from
  :mod:`ironflow.security.net`, which resolves, checks and connects in one
  step, so a name that answers the pre-flight check with a public address and
  the socket with a private one (DNS rebinding) is refused.
* The network policy is the operator's.  A pipeline may narrow it -
  ``allowed_hosts``, ``allow_private_network: false`` - and may not widen it.
* Redirects are **not** followed automatically.  A 302 to an internal address
  bypasses a check that only ran on the original URL.  Redirects are resolved
  manually, one hop at a time, each one re-validated, with a bounded count.
* TLS verification is on and cannot be disabled in a production environment.
* Credentials are resolved through the secret resolver and sent as headers, so
  they never appear in a URL, a log line or a proxy access record - and only to
  the origin they were configured for.  A redirect or a ``next`` link to any
  other host gets no ``Authorization``, API key or custom header: a hostile
  API that answered with ``Location: https://evil.example`` used to receive
  the bearer token on the next request.
* Response bodies are size-capped while streaming, on the decoded bytes, so
  neither an unbounded body nor a small gzip bomb can exhaust memory.  Error
  bodies are read only as far as the message quotes them.

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
import threading
import time
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, replace
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
from ironflow.security.guards import NetworkPolicy, validate_url
from ironflow.security.net import build_client, read_capped, read_prefix

logger = logging.getLogger(__name__)

RETRYABLE_STATUS = frozenset({408, 425, 429, 500, 502, 503, 504})
MAX_REDIRECTS = 5
MAX_PAGES_DEFAULT = 10_000
#: An OAuth2 token response is a few hundred bytes; anything past this is not one.
MAX_TOKEN_RESPONSE_BYTES = 64 * 1024

Origin = tuple[str, str, int | None]


def _origin(url: str) -> Origin | None:
    """``(scheme, host, port)`` - the unit credentials are bound to."""
    try:
        parsed = urlparse(url)
        port = parsed.port or {"http": 80, "https": 443}.get(parsed.scheme.lower())
    except ValueError:
        return None
    return parsed.scheme.lower(), (parsed.hostname or "").lower().rstrip("."), port


@dataclass(frozen=True)
class HttpReply:
    """A response whose body has been read, and size-checked, in full."""

    status_code: int
    headers: httpx.Headers
    content: bytes

    def json(self) -> Any:
        return json.loads(self.content)


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

    #: Cached OAuth2 token as ``(token, expires_at)``; set by ``_oauth2_token``.
    _token_cache: tuple[str, float] | None = None

    def _init_http(self: Any) -> None:
        """Per-connector state; runs the policy checks at construction.

        Building the policy here, not at open, is what lets ``ironflow pipeline
        validate`` report a pipeline that tries to switch the SSRF guard off.
        """
        self._warned_cross_origin = False
        self._policy = self._network_policy()
        self._credential_origin = _origin(self.str_option("url", required=True))

    def _network_policy(self: Any) -> NetworkPolicy:
        """The operator's policy, narrowed - never widened - by this connector.

        ``allow_private_network: true`` in a pipeline used to *override* the
        platform setting, production included: one line of YAML put
        ``169.254.169.254`` back in reach.  A pipeline may now only switch
        private addresses off; reaching an internal API is the operator's call,
        through ``IRONFLOW_HTTP_PRIVATE_HOSTS``.
        """
        platform = NetworkPolicy.from_settings(self.runtime.settings)
        requested = self.option("allow_private_network")
        wants_private = (
            None if requested is None else self.bool_option("allow_private_network", False)
        )
        if wants_private and not platform.allow_private:
            raise ConfigurationError(
                "a pipeline cannot switch off the SSRF guard; list the host in "
                "IRONFLOW_HTTP_PRIVATE_HOSTS to reach an internal API",
                context={"connector": self.name},
            )
        return platform.narrowed(
            allow_private=wants_private,
            allowed_hosts=self.list_option("allowed_hosts") or None,
        )

    def _credential_headers(self: Any) -> dict[str, str]:
        """Authentication plus the pipeline's own ``headers``.

        Both are treated as credentials: a custom header is as likely to carry a
        token as ``Authorization`` is.
        """
        return {
            **self._auth_headers(),
            **{str(k): str(v) for k, v in (self.option("headers", {}) or {}).items()},
        }

    def _headers_for(self: Any, url: str) -> dict[str, str]:
        """Credentials for the configured origin; nothing for any other."""
        if _origin(url) == self._credential_origin:
            return self._credential_headers()
        if not self._warned_cross_origin:
            logger.warning(
                "not sending credentials to %s: it is not the origin they were configured for",
                urlparse(url).hostname,
            )
            self._warned_cross_origin = True
        return {}

    def _verify_tls(self: Any) -> bool:
        settings = self.runtime.settings
        verify = bool(self.bool_option("verify_tls", settings.http_verify_tls))
        if not verify and settings.is_production:
            raise ConfigurationError(
                "TLS verification cannot be disabled in a production environment"
            )
        return verify

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

    def _oauth2_token(self: Any) -> str:
        """Client-credentials grant, cached until shortly before expiry."""
        cached = self._token_cache
        if cached and cached[1] > time.time() + 30:
            return str(cached[0])

        token_url = validate_url(
            self.str_option("token_url", required=True), policy=self._token_policy()
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
            with (
                self._build_token_client() as client,
                client.stream("POST", token_url, data=payload) as response,
            ):
                if response.status_code != 200:
                    raise AuthenticationError(
                        "OAuth2 token endpoint rejected the credentials",
                        context={"status": response.status_code},
                    )
                content = read_capped(response, MAX_TOKEN_RESPONSE_BYTES)
        except httpx.HTTPError as exc:
            raise AuthenticationError(
                "OAuth2 token request failed", context={"token_url": token_url}, cause=exc
            ) from exc
        except ExtractionError as exc:
            raise AuthenticationError("OAuth2 token response is too large") from exc

        try:
            body = json.loads(content)
        except ValueError as exc:
            raise AuthenticationError("OAuth2 token response is not JSON") from exc
        token = body.get("access_token") if isinstance(body, Mapping) else None
        if not token or not isinstance(token, str):
            raise AuthenticationError("OAuth2 response contained no access_token")
        try:
            expires_in = max(0, int(body.get("expires_in", 3600)))
        except (TypeError, ValueError):
            expires_in = 300  # unparseable: refresh soon rather than trust it
        self._token_cache = (token, time.time() + expires_in)
        return token

    def _token_policy(self: Any) -> NetworkPolicy:
        """The token endpoint is its own origin, so the connector's
        ``allowed_hosts`` (which names the API) does not apply to it - the
        operator's allow-list and private-network rules still do."""
        platform = NetworkPolicy.from_settings(self.runtime.settings)
        return replace(self._policy, host_allowlists=platform.host_allowlists)

    def _build_token_client(self: Any) -> httpx.Client:
        return build_client(
            self._token_policy(),
            verify=self._verify_tls(),
            timeout=self.runtime.settings.http_timeout,
        )

    def _build_client(self: Any) -> httpx.Client:
        settings = self.runtime.settings
        # Credentials are attached per request (only to their own origin), but
        # resolved here as well, so a missing secret or a rejected OAuth2 client
        # fails at open - before a sink has accepted a single record.
        self._auth_headers()
        return build_client(
            self._policy,
            verify=self._verify_tls(),
            timeout=float(self.int_option("timeout", int(settings.http_timeout), maximum=600)),
            headers={
                "User-Agent": self.str_option("user_agent", "IronFlow/1.0"),
                "Accept": self.str_option("accept", "application/json"),
            },
            max_connections=self.int_option("max_connections", 10, maximum=100),
        )

    def _validate(self: Any, url: str) -> str:
        return validate_url(url, policy=self._policy)

    def _request(
        self: Any,
        client: httpx.Client,
        method: str,
        url: str,
        *,
        params: Mapping[str, Any] | None = None,
        json_body: Any = None,
        limiter: RateLimiter | None = None,
        read_body: bool = True,
    ) -> HttpReply:
        """Execute one logical request: rate limit, retry, manual redirects."""
        policy = self.retry_policy
        max_bytes = self.runtime.settings.http_max_response_bytes

        def attempt() -> HttpReply:
            if limiter is not None:
                limiter.acquire()
            current = self._validate(url)
            query = params
            for hop in range(MAX_REDIRECTS + 1):
                request = client.build_request(
                    method,
                    current,
                    params=query,
                    json=json_body,
                    headers=self._headers_for(current),
                )
                try:
                    response = client.send(request, stream=True)
                except httpx.TimeoutException as exc:
                    raise IFConnectionError(
                        "request timed out", context={"url": current}, cause=exc
                    ) from exc
                except httpx.HTTPError as exc:
                    raise IFConnectionError(
                        "request failed", context={"url": current}, cause=exc
                    ) from exc

                try:
                    if response.is_redirect and response.headers.get("location"):
                        if hop >= MAX_REDIRECTS:
                            raise IFConnectionError(
                                "too many redirects", context={"url": current}, retryable=False
                            )
                        current = self._validate(urljoin(current, response.headers["location"]))
                        # The Location is a complete URL: re-appending the
                        # original query would send it somewhere it was not meant.
                        query = None
                        continue
                    _raise_for_status(response)
                    content = read_capped(response, max_bytes) if read_body else b""
                    return HttpReply(response.status_code, response.headers, content)
                finally:
                    response.close()

            raise IFConnectionError(  # pragma: no cover - loop always returns
                "redirect resolution failed", context={"url": url}
            )

        return call_with_retry(attempt, policy, description=f"{method} {url}")


def _raise_for_status(response: httpx.Response) -> None:
    """Map an error status to the right exception, quoting only a prefix of the body."""
    status = response.status_code
    if status < 400:
        return
    body = read_prefix(response, 500)
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
        self._token_cache: tuple[str, float] | None = None
        self._init_http()

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
                payload = _parse_json(response)
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
        response: HttpReply,
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


def _parse_json(response: HttpReply) -> Any:
    # The size limit was enforced while the body streamed in (`read_capped`).
    try:
        return response.json()
    except (ValueError, RecursionError) as exc:  # RecursionError: absurd nesting
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
        self._token_cache: tuple[str, float] | None = None
        self._init_http()

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
                self._request(
                    self._client,
                    method,
                    url,
                    json_body=single,
                    limiter=self._limiter,
                    read_body=False,
                )
        else:
            whole: Any = {wrapper: batch.records} if wrapper else batch.records
            self._request(
                self._client,
                method,
                url,
                json_body=whole,
                limiter=self._limiter,
                read_body=False,
            )

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
        self._token_cache: tuple[str, float] | None = None
        self._init_http()

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
                payload = _parse_json(response)

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
