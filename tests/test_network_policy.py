"""The outbound-HTTP policy: who decides it, and where it is enforced.

Each class pins one way a pipeline file - or a server it talks to - used to get
past the SSRF guard or walk off with a credential:

* a connector option that switched the guard off, in production too;
* DNS rebinding between the pre-flight check and the connection;
* a redirect or a pagination link that carried the bearer token to another host;
* a response-size cap that ran after the whole (decompressed) body was in memory.
"""

from __future__ import annotations

import http.server
import ipaddress
import json
import smtplib
import socket
import ssl
import threading
import zlib
from collections.abc import Iterator
from typing import Any

import httpx
import pytest

from ironflow.config.models import ConnectorSpec, NotificationSpec
from ironflow.config.settings import Settings
from ironflow.connectors.factory import ConnectorFactory
from ironflow.core.errors import ConfigurationError, ExtractionError, SecurityError
from ironflow.security.guards import (
    NetworkPolicy,
    assert_no_sql_injection,
    classify_address,
    validate_identifier,
    validate_url,
)
from ironflow.security.net import GuardedTransport, build_client, read_capped, read_prefix
from ironflow.services.notifications import EmailNotifier, SlackNotifier, WebhookNotifier


def spec(connector_type: str, **options: Any) -> ConnectorSpec:
    return ConnectorSpec.model_validate({"type": connector_type, **options})


def stub(connector: Any, handler: Any) -> Any:
    """Serve a connector's requests from ``handler`` (a MockTransport)."""
    transport = httpx.MockTransport(handler)
    original = connector._build_client

    def build() -> httpx.Client:
        client = original()
        client._transport = transport
        return client

    connector._build_client = build
    return connector


def read_all(source: Any, context: Any) -> list[dict[str, Any]]:
    source.open(context)
    try:
        return [record for batch in source.read(context) for record in batch.records]
    finally:
        source.close()


class TestAddressClassification:
    @pytest.mark.parametrize(
        ("address", "kind"),
        [
            ("8.8.8.8", "public"),
            ("2606:4700:4700::1111", "public"),
            ("10.0.0.5", "private"),
            ("127.0.0.1", "private"),
            ("::1", "private"),
            ("fd00:ec2::254", "private"),
            # Carrier-grade NAT: `is_private` does not cover it, `is_global` does.
            ("100.64.0.1", "private"),
            ("::ffff:10.0.0.1", "private"),
            ("169.254.169.254", "forbidden"),
            ("fe80::1", "forbidden"),
            ("0.0.0.0", "forbidden"),  # noqa: S104 - an address under test, not a bind
            ("224.0.0.1", "forbidden"),
        ],
    )
    def test_addresses_are_sorted_by_what_the_policy_may_do_with_them(self, address, kind):
        assert classify_address(ipaddress.ip_address(address)) == kind

    def test_cloud_metadata_stays_unreachable_even_with_private_addresses_open(self):
        with pytest.raises(SecurityError, match="no setting opens"):
            validate_url("http://169.254.169.254/latest/meta-data/", allow_private=True)

    def test_carrier_grade_nat_is_not_treated_as_public(self):
        with pytest.raises(SecurityError, match="non-public"):
            validate_url("http://100.64.0.1/", allow_private=False)


class TestOperatorPolicy:
    def test_private_hosts_open_named_destinations_only(self):
        policy = NetworkPolicy(private_hosts=("10.20.0.0/16", "internal-api.corp"))
        assert validate_url("http://10.20.3.4/x", policy=policy)
        with pytest.raises(SecurityError, match="non-public"):
            validate_url("http://10.99.0.1/x", policy=policy)

    def test_a_connector_cannot_widen_the_platform_policy(self):
        policy = NetworkPolicy().narrowed(allow_private=True)
        assert policy.allow_private is False

    def test_a_connector_can_narrow_it(self):
        policy = NetworkPolicy(allow_private=True).narrowed(allow_private=False)
        assert policy.allow_private is False

    def test_the_operator_allow_list_bounds_every_destination(self):
        policy = NetworkPolicy(
            host_allowlists=(("IRONFLOW_HTTP_ALLOWED_HOSTS", ("api.partner.com",)),),
            allow_private=True,
        )
        assert validate_url("https://eu.api.partner.com/v1", policy=policy)
        with pytest.raises(SecurityError, match="IRONFLOW_HTTP_ALLOWED_HOSTS"):
            validate_url("https://paste.example.com/upload", policy=policy)
        # A connector's own list narrows further but cannot escape the operator's.
        with pytest.raises(SecurityError, match="IRONFLOW_HTTP_ALLOWED_HOSTS"):
            validate_url(
                "https://paste.example.com/upload",
                policy=policy,
                allowed_hosts=["paste.example.com"],
            )

    def test_settings_feed_the_policy(self, tmp_path):
        settings = Settings(
            home=tmp_path,
            http_allowed_hosts="api.partner.com, hooks.slack.com",
            http_private_hosts='["10.1.0.0/16"]',
        )
        policy = NetworkPolicy.from_settings(settings)
        assert policy.private_hosts == ("10.1.0.0/16",)
        assert policy.host_allowlists == (
            ("IRONFLOW_HTTP_ALLOWED_HOSTS", ("api.partner.com", "hooks.slack.com")),
        )


class TestConnectorsCannotSwitchTheGuardOff:
    """``allow_private_network: true`` in a pipeline used to override the platform.

    Production refused the *setting*, but the per-connector option was read with
    the setting only as its default - so any pipeline could re-open
    ``169.254.169.254`` with one line of YAML, in production included.
    """

    @pytest.fixture
    def guarded_factory(self, tmp_path) -> ConnectorFactory:
        return ConnectorFactory(
            Settings(
                home=tmp_path / ".ironflow", data_roots=[tmp_path], allow_private_network=False
            )
        )

    def test_the_option_is_refused_when_the_operator_has_not_opened_private_networks(
        self, guarded_factory
    ):
        with pytest.raises(ConfigurationError, match="cannot switch off the SSRF guard"):
            guarded_factory.create_source(
                spec("rest", url="http://169.254.169.254/latest/", allow_private_network=True)
            )

    def test_pipeline_validate_reports_it(self, guarded_factory):
        problems = guarded_factory.validate(
            spec("rest", url="http://10.0.0.5/x", allow_private_network=True), kind="source"
        )
        assert problems and "SSRF guard" in problems[0]

    def test_switching_it_off_still_works(self, factory, context):
        source = factory.create_source(
            spec("rest", url="http://127.0.0.1/x", allow_private_network=False)
        )
        with pytest.raises(SecurityError, match="non-public"):
            read_all(source, context)


class TestDnsRebinding:
    """The pre-flight check and the socket used to resolve the name separately."""

    @pytest.fixture
    def internal_service(self) -> Iterator[int]:
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                body = b'{"secret": "internal-only"}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: Any) -> None:
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        yield server.server_address[1]
        server.shutdown()
        server.server_close()

    @pytest.fixture
    def rebinding_resolver(self, monkeypatch) -> dict[str, int]:
        """Public for the first lookup of ``rebind.test``, loopback afterwards."""
        real = socket.getaddrinfo
        lookups = {"count": 0}

        def resolver(host: str, port: Any, *args: Any, **kwargs: Any) -> Any:
            if host != "rebind.test":
                return real(host, port, *args, **kwargs)
            lookups["count"] += 1
            address = "93.184.216.34" if lookups["count"] == 1 else "127.0.0.1"
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port or 0))]

        monkeypatch.setattr(socket, "getaddrinfo", resolver)
        return lookups

    def test_the_connection_is_checked_not_just_the_first_lookup(
        self, internal_service, rebinding_resolver
    ):
        url = f"http://rebind.test:{internal_service}/latest/meta-data"
        policy = NetworkPolicy()
        # The pre-flight check sees the public answer and lets it through...
        assert validate_url(url, policy=policy) == url
        # ...and the connection, which resolves again, is refused.
        with build_client(policy) as client, pytest.raises(SecurityError, match="non-public"):
            client.get(url)
        assert rebinding_resolver["count"] == 2

    def test_an_allow_listed_private_host_is_reachable(self, internal_service):
        policy = NetworkPolicy(private_hosts=("127.0.0.1/32",))
        with build_client(policy) as client:
            assert client.get(f"http://127.0.0.1:{internal_service}/").json() == {
                "secret": "internal-only"
            }

    def test_clients_ignore_proxy_environment_variables(self, monkeypatch):
        """Through a proxy, the address the policy approved is not the one used."""
        monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example:3128")
        with build_client(NetworkPolicy()) as client:
            assert client.trust_env is False
            assert isinstance(client._transport, GuardedTransport)


class TestCredentialsStayWithTheirOrigin:
    TOKEN = "Bearer SUPER-SECRET-BEARER-TOKEN"

    def _source(self, factory: ConnectorFactory, monkeypatch, **options: Any) -> Any:
        monkeypatch.setenv("API_TOKEN", "SUPER-SECRET-BEARER-TOKEN")
        return factory.create_source(
            spec(
                "rest",
                url="https://api.example.com/items",
                auth="bearer",
                token="env:API_TOKEN",
                headers={"X-Tenant-Key": "tenant-secret"},
                allow_private_network=True,
                **options,
            )
        )

    def test_a_cross_origin_redirect_gets_no_credentials(self, factory, context, monkeypatch):
        seen: dict[str, httpx.Headers] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen[request.url.host] = request.headers
            if request.url.host == "api.example.com":
                return httpx.Response(302, headers={"Location": "https://evil.example.com/steal"})
            return httpx.Response(200, json=[{"id": 1}])

        source = stub(self._source(factory, monkeypatch), handler)
        assert read_all(source, context) == [{"id": 1}]
        assert seen["api.example.com"]["authorization"] == self.TOKEN
        assert "authorization" not in seen["evil.example.com"]
        assert "x-tenant-key" not in seen["evil.example.com"]

    def test_a_same_origin_redirect_keeps_them(self, factory, context, monkeypatch):
        seen: list[httpx.Headers] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request.headers)
            if request.url.path == "/items":
                return httpx.Response(301, headers={"Location": "/v2/items"})
            return httpx.Response(200, json=[])

        read_all(stub(self._source(factory, monkeypatch), handler), context)
        assert [headers.get("authorization") for headers in seen] == [self.TOKEN, self.TOKEN]

    def test_a_next_link_to_another_host_gets_no_credentials(self, factory, context, monkeypatch):
        seen: dict[str, httpx.Headers] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen[request.url.host] = request.headers
            if request.url.host == "api.example.com":
                return httpx.Response(
                    200,
                    json=[{"id": 1}],
                    headers={"Link": '<https://collector.example.net/page2>; rel="next"'},
                )
            return httpx.Response(200, json=[{"id": 2}])

        source = stub(self._source(factory, monkeypatch, pagination="link"), handler)
        assert [r["id"] for r in read_all(source, context)] == [1, 2]
        assert "authorization" not in seen["collector.example.net"]


class TestResponseSizeIsBoundedWhileStreaming:
    @staticmethod
    def _gzip_bomb(decoded_mib: int) -> bytes:
        compressor = zlib.compressobj(9, zlib.DEFLATED, 31)
        zeros = b"\0" * (1 << 20)
        return b"".join(compressor.compress(zeros) for _ in range(decoded_mib)) + (
            compressor.flush()
        )

    @staticmethod
    def _streamed(body: bytes, headers: dict[str, str]) -> tuple[httpx.Client, httpx.Response]:
        chunks = [body[i : i + 65536] for i in range(0, len(body), 65536)]
        client = httpx.Client(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(200, headers=headers, content=iter(chunks))
            )
        )
        return client, client.send(client.build_request("GET", "https://x.example/"), stream=True)

    def test_a_gzip_bomb_is_refused_before_it_inflates(self):
        """~200 KB on the wire used to become 200 MB before a 1 MB cap was consulted."""
        import tracemalloc

        client, response = self._streamed(self._gzip_bomb(200), {"Content-Encoding": "gzip"})
        tracemalloc.start()
        try:
            with pytest.raises(ExtractionError, match="size limit"):
                read_capped(response, 1 << 20)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
            client.close()
        assert peak < 32 * (1 << 20)

    @pytest.mark.parametrize(
        ("encoding", "encode"),
        [
            ("gzip", lambda data: zlib.compress(data, wbits=31)),
            ("deflate", zlib.compress),
            ("deflate", lambda data: zlib.compress(data)[2:-4]),  # raw deflate
            ("identity", lambda data: data),
        ],
    )
    def test_ordinary_compressed_bodies_still_decode(self, encoding, encode):
        payload = json.dumps([{"id": i} for i in range(500)]).encode()
        client, response = self._streamed(encode(payload), {"Content-Encoding": encoding})
        try:
            assert read_capped(response, 1 << 20) == payload
        finally:
            client.close()

    def test_an_encoding_that_cannot_be_bounded_is_refused(self):
        client, response = self._streamed(b"\x0b" * 100, {"Content-Encoding": "br"})
        try:
            with pytest.raises(ExtractionError, match="content encoding"):
                read_capped(response, 1 << 20)
        finally:
            client.close()

    def test_an_error_body_is_quoted_not_read(self):
        pulled = {"chunks": 0}

        def endless() -> Iterator[bytes]:
            while True:
                pulled["chunks"] += 1
                yield b"x" * 65536

        client = httpx.Client(
            transport=httpx.MockTransport(lambda request: httpx.Response(500, content=endless()))
        )
        with client:
            response = client.send(client.build_request("GET", "https://x.example/"), stream=True)
            assert read_prefix(response, 500) == "x" * 500
        assert pulled["chunks"] == 1

    def test_the_connector_cap_applies_to_the_decoded_body(self, tmp_path, context):
        settings = Settings(
            home=tmp_path / ".ironflow", allow_private_network=True, http_max_response_bytes=4096
        )
        source = ConnectorFactory(settings).create_source(
            spec("rest", url="https://api.example.com/x")
        )
        bomb = zlib.compress(json.dumps([{"pad": "0" * 100_000}]).encode(), wbits=31)
        stub(
            source,
            lambda request: httpx.Response(
                200, headers={"Content-Encoding": "gzip"}, content=iter([bomb])
            ),
        )
        with pytest.raises(ExtractionError, match="size limit"):
            read_all(source, context)


class TestNotificationTransport:
    def test_webhooks_go_through_the_guarded_client(self, settings):
        notifier = WebhookNotifier(
            NotificationSpec(type="webhook", target="https://hooks.example.com/x"), settings
        )
        with notifier.http_client() as client:
            assert isinstance(client._transport, GuardedTransport)

    def test_slack_keeps_its_default_host_list(self, settings):
        notifier = SlackNotifier(
            NotificationSpec(type="slack", target="https://hooks.slack.com/services/x"), settings
        )
        policy = notifier.network_policy()
        with pytest.raises(SecurityError, match="allow-list"):
            policy.check_host("attacker.example.com")

    def test_smtp_starttls_verifies_the_server(self, settings, monkeypatch):
        """``starttls()`` without a context encrypts and authenticates nothing."""
        seen: dict[str, Any] = {}

        class FakeSMTP:
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                pass

            def __enter__(self) -> FakeSMTP:
                return self

            def __exit__(self, *args: Any) -> None:
                pass

            def starttls(self, context: ssl.SSLContext | None = None) -> None:
                seen["context"] = context

            def login(self, user: str, password: str) -> None:
                seen["login"] = user

            def send_message(self, message: Any) -> None:
                pass

        monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
        monkeypatch.setenv("SMTP_USER", "ironflow")
        monkeypatch.setenv("SMTP_PASSWORD", "mail-password")
        notifier = EmailNotifier(
            NotificationSpec(
                type="email",
                target="ops@example.com",
                options={
                    "host": "smtp.example.com",
                    "user": "env:SMTP_USER",
                    "password": "env:SMTP_PASSWORD",
                },
            ),
            settings,
        )
        assert notifier.notify("subject", "body", {})
        context = seen["context"]
        assert isinstance(context, ssl.SSLContext)
        assert context.verify_mode is ssl.CERT_REQUIRED
        assert context.check_hostname is True
        assert seen["login"] == "ironflow"


class TestSqlGuards:
    def test_an_identifier_with_a_trailing_newline_is_refused(self):
        """``$`` also matches before a final newline; ``re.match`` let this through."""
        with pytest.raises(SecurityError):
            validate_identifier("orders\n")
        with pytest.raises(SecurityError):
            validate_identifier("public.orders\n", qualified=True)

    @pytest.mark.parametrize(
        "fragment",
        [
            "1=1 OR pg_sleep(10) IS NULL",
            "1=1 AND SLEEP(10)",
            "benchmark(10000000, md5('x')) > 0",
            "data = load_file('/etc/passwd')",
            "id = 1 # trailing comment",
            "1=1 INTO OUTFILE '/tmp/x'",
            "id IN (1) UNION SELECT password FROM users",
            "id = 1; DROP TABLE users",
            "pg_read_file('/etc/passwd') IS NOT NULL",
        ],
    )
    def test_the_where_screen_rejects_statement_changing_shapes(self, fragment):
        with pytest.raises(SecurityError, match="forbidden tokens"):
            assert_no_sql_injection(fragment, field="where")

    @pytest.mark.parametrize(
        "fragment",
        [
            "amount > 0 AND region IN ('EU', 'US')",
            "created_at >= '2024-01-01'",
            "last_update IS NOT NULL",
            "status <> 'deleted' OR copy_count > 1",
        ],
    )
    def test_ordinary_predicates_pass(self, fragment):
        assert assert_no_sql_injection(fragment, field="where") == fragment
