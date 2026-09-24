"""Outbound HTTP with the SSRF policy enforced where it cannot be raced.

:func:`~ironflow.security.guards.validate_url` resolves a host name and checks
the addresses - and then the HTTP client resolves the name *again* when it
opens the socket, with nothing tying the second answer to the first.  A
resolver that hands the check a public address and the connection
``169.254.169.254`` (DNS rebinding: a zero TTL, or a round-robin mixing both)
walks straight through a guard that only ran first.

The transport here moves the check to the one place it cannot be raced: the
network backend's ``connect_tcp``.  It resolves the name, checks every answer
against the :class:`~ironflow.security.guards.NetworkPolicy`, and connects to an
address it has just approved.  TLS still verifies the certificate against the
*host name*, so the connection is pinned, not downgraded.

Clients built here also:

* ignore proxy environment variables (``HTTP_PROXY`` and friends) - through a
  proxy, the address the policy approved is not the one the proxy connects to;
* never follow redirects - callers re-validate every hop themselves;
* are read through :func:`read_capped`, which enforces a size limit on the
  *decoded* body as it streams - inflating compressed bodies itself, a bounded
  number of bytes at a time, so a small gzip bomb cannot inflate past it.
"""

from __future__ import annotations

import ssl
import zlib
from collections.abc import Iterable, Iterator, Mapping
from functools import lru_cache
from typing import Any

import httpcore
import httpx

from ironflow.core.errors import ExtractionError
from ironflow.security.guards import NetworkPolicy


@lru_cache(maxsize=1)
def verified_ssl_context() -> ssl.SSLContext:
    """One verified TLS context per process.

    Constructing an ``httpx.Client`` with ``verify=True`` re-reads and re-parses
    the CA bundle every time - measured at ~1.4 s per client.  Certificate
    verification and hostname checking stay on; only the parsing is shared.
    """
    try:
        import certifi

        context = ssl.create_default_context(cafile=certifi.where())
    except ImportError:  # pragma: no cover - falls back to the system store
        context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def _unverified_ssl_context() -> ssl.SSLContext:
    """For a connector that explicitly disabled verification outside production."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


class _GuardedBackend(httpcore.NetworkBackend):
    """Resolves, checks and connects in one step, to an address it approved."""

    def __init__(self, policy: NetworkPolicy) -> None:
        self._policy = policy
        self._backend = httpcore.SyncBackend()

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.NetworkStream:
        last_error: Exception | None = None
        # `resolve` raises SecurityError when any answer is off-limits, and
        # never returns an empty list.
        for address in self._policy.resolve(host, port):
            try:
                return self._backend.connect_tcp(
                    address,
                    port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                last_error = exc
        assert last_error is not None
        raise last_error

    def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.NetworkStream:
        raise httpcore.ConnectError("unix sockets are not reachable through a guarded client")

    def sleep(self, seconds: float) -> None:
        self._backend.sleep(seconds)


class GuardedTransport(httpx.HTTPTransport):
    """An ``httpx`` transport whose every connection passes the network policy."""

    def __init__(
        self,
        policy: NetworkPolicy,
        *,
        verify: bool = True,
        limits: httpx.Limits | None = None,
    ) -> None:
        ssl_context = verified_ssl_context() if verify else _unverified_ssl_context()
        limits = limits or httpx.Limits(max_connections=10)
        super().__init__(verify=ssl_context, trust_env=False, limits=limits)
        # httpx builds its connection pool with no hook for a network backend,
        # so the pool is rebuilt around the guarded one.  `_pool` is httpx's own
        # attribute; tests/test_network_policy.py exercises a rebinding resolver
        # end to end, so a change in httpx fails the suite instead of quietly
        # reopening the hole.
        self._pool = httpcore.ConnectionPool(
            ssl_context=ssl_context,
            max_connections=limits.max_connections,
            max_keepalive_connections=limits.max_keepalive_connections,
            keepalive_expiry=limits.keepalive_expiry,
            network_backend=_GuardedBackend(policy),
        )


def build_client(
    policy: NetworkPolicy,
    *,
    verify: bool = True,
    timeout: float = 30.0,
    headers: Mapping[str, str] | None = None,
    max_connections: int = 10,
) -> httpx.Client:
    """A client that connects only where ``policy`` allows."""
    return httpx.Client(
        transport=GuardedTransport(
            policy, verify=verify, limits=httpx.Limits(max_connections=max_connections)
        ),
        headers={"Accept-Encoding": ACCEPT_ENCODING, **dict(headers or {})},
        timeout=httpx.Timeout(timeout),
        follow_redirects=False,
        trust_env=False,
    )


#: What clients built here ask for.  Only encodings :class:`_BoundedDecoder`
#: can inflate a bounded number of bytes at a time.
ACCEPT_ENCODING = "gzip, deflate"


class _BoundedDecoder:
    """Inflates ``gzip``/``deflate`` without ever producing more than asked for.

    httpx's own decoders inflate each network read in one call, and one 64 KB
    read of a gzip bomb is ~64 MB decoded before any cap can look at it.
    ``zlib``'s ``max_length`` makes the output of every call bounded instead,
    so the memory a hostile body can claim is the cap plus one read.
    """

    def __init__(self, encoding: str) -> None:
        self._zlib: Any = None
        # RFC 9110's deflate is zlib-wrapped; some servers send it raw, which
        # only shows as an error on the first block.
        self._raw_fallback = encoding == "deflate"
        if encoding in ("gzip", "x-gzip"):
            self._zlib = zlib.decompressobj(zlib.MAX_WBITS | 16)
        elif encoding == "deflate":
            self._zlib = zlib.decompressobj()
        self._pending = b""

    def decode(self, data: bytes, budget: int) -> bytes:
        """Up to ``budget`` decoded bytes of ``data`` (plus anything held back).

        ``budget`` must be at least 1: zlib reads a ``max_length`` of 0 as
        "unlimited".
        """
        if self._zlib is None:
            return data
        source = self._pending + data
        try:
            out = self._zlib.decompress(source, budget)
        except zlib.error:
            if not self._raw_fallback:
                raise
            self._zlib = zlib.decompressobj(-zlib.MAX_WBITS)
            out = self._zlib.decompress(source, budget)
        self._raw_fallback = False
        self._pending = self._zlib.unconsumed_tail
        return bytes(out)

    @property
    def has_pending(self) -> bool:
        return bool(self._pending)


def _decoder_for(response: httpx.Response) -> _BoundedDecoder:
    encoding = response.headers.get("content-encoding", "identity").strip().lower()
    if encoding not in ("", "identity", "gzip", "x-gzip", "deflate"):
        # br and zstd have no bounded-output API in the standard library; a
        # server that sends them despite `Accept-Encoding` is refused.
        raise ExtractionError(
            "response uses a content encoding this client does not accept",
            context={"content_encoding": encoding},
        )
    return _BoundedDecoder(encoding)


def _decoded_chunks(response: httpx.Response, limit: int) -> Iterator[bytes]:
    """Decoded body, stopping as soon as ``limit`` bytes have been exceeded."""
    if response.is_stream_consumed:
        # Built in memory (httpx reads such a response on construction) or read
        # by the caller: it is already decoded, so only the size check is left.
        yield response.content
        return
    decoder = _decoder_for(response)
    produced = 0
    try:
        for raw in response.iter_raw():
            chunk = decoder.decode(raw, limit - produced + 1)
            while True:
                produced += len(chunk)
                yield chunk
                if produced > limit or not decoder.has_pending:
                    break
                chunk = decoder.decode(b"", limit - produced + 1)
            if produced > limit:
                return
    except zlib.error as exc:
        raise ExtractionError("response body is not validly compressed") from exc


def read_capped(response: httpx.Response, limit: int) -> bytes:
    """Read a streamed body, refusing more than ``limit`` *decoded* bytes.

    Checking ``len(response.content)`` after a non-streaming request bounds
    nothing: the whole body - already decompressed - is in memory by then.
    ~200 KB of gzip on the wire became 200 MB before a 1 MB cap was consulted.
    """
    declared = response.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > limit:
        raise ExtractionError(
            "response exceeds the configured size limit",
            context={"declared_bytes": int(declared), "limit": limit},
        )
    received = bytearray()
    for chunk in _decoded_chunks(response, limit):
        received += chunk
        if len(received) > limit:
            raise ExtractionError(
                "response exceeds the configured size limit",
                context={"limit": limit},
            )
    return bytes(received)


def read_prefix(response: httpx.Response, limit: int = 500) -> str:
    """The start of a body, for an error message - never the whole of it.

    An error response is as untrusted as any other, and reading a 5 GB error
    page in full to quote 500 characters of it is its own denial of service.
    """
    received = bytearray()
    try:
        for chunk in _decoded_chunks(response, limit):
            received += chunk
            if len(received) >= limit:
                break
    except ExtractionError:
        pass  # an undecodable error body still leaves a status to report
    try:
        return bytes(received[:limit]).decode(response.charset_encoding or "utf-8", "replace")
    except LookupError:  # a charset name Python does not know
        return bytes(received[:limit]).decode("utf-8", "replace")


__all__ = [
    "GuardedTransport",
    "build_client",
    "read_capped",
    "read_prefix",
    "verified_ssl_context",
]
