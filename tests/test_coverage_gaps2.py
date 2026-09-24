"""Remaining uncovered paths: FTP transfers, OAuth2, key files, secret sources."""

from __future__ import annotations

import ftplib
import os
from pathlib import Path
from urllib.parse import parse_qs

import httpx
import pytest

from ironflow.config.models import ConnectorSpec
from ironflow.core.errors import (
    AuthenticationError,
    ConfigurationError,
    ExtractionError,
    LoadingError,
    SecretError,
)
from ironflow.core.errors import ConnectionError as IFConnectionError
from ironflow.core.types import RecordBatch
from ironflow.security.crypto import CryptoService, derive_key, generate_key
from ironflow.security.secrets import SecretResolver


def spec(connector_type: str, **options) -> ConnectorSpec:
    return ConnectorSpec.model_validate({"type": connector_type, **options})


class FakeFtp:
    """A minimal in-memory FTP server double."""

    files: dict[str, bytes] = {}

    def __init__(self, timeout=None):
        self.quit_called = False

    def connect(self, host, port):
        pass

    def login(self, user, password):
        pass

    def prot_p(self):
        pass

    def set_pasv(self, value):
        pass

    def retrbinary(self, command, callback, blocksize=8192):
        path = command.split(" ", 1)[1]
        if path not in FakeFtp.files:
            raise ftplib.error_perm("550 no such file")
        callback(FakeFtp.files[path])

    def storbinary(self, command, handle, blocksize=8192):
        path = command.split(" ", 1)[1]
        FakeFtp.files[path] = handle.read()

    def quit(self):
        self.quit_called = True

    def close(self):
        pass


@pytest.fixture
def fake_ftp(monkeypatch):
    FakeFtp.files = {}
    monkeypatch.setattr(ftplib, "FTP_TLS", FakeFtp)
    monkeypatch.setattr(ftplib, "FTP", FakeFtp)
    return FakeFtp


class TestFtpTransfer:
    def test_download_and_parse(self, factory, fake_ftp, context):
        fake_ftp.files["/remote/orders.csv"] = b"id,name\n1,Alice\n2,Bob\n"
        source = factory.create_source(
            spec("ftp", host="h", user="u", password="p", remote_path="/remote/orders.csv")
        )
        source.open(context)
        rows = [record for batch in source.read(context) for record in batch]
        assert rows == [{"id": "1", "name": "Alice"}, {"id": "2", "name": "Bob"}]

    def test_download_of_a_missing_file_is_reported(self, factory, fake_ftp, context):
        source = factory.create_source(
            spec(
                "ftp",
                host="h",
                user="u",
                password="p",
                remote_path="/nope.csv",
                retry={"max_attempts": 1},
            )
        )
        source.open(context)
        with pytest.raises(ExtractionError, match="FTP download failed"):
            list(source.read(context))

    def test_staging_is_cleaned_up_after_reading(self, factory, fake_ftp, context):
        fake_ftp.files["/o.csv"] = b"a\n1\n"
        source = factory.create_source(
            spec("ftp", host="h", user="u", password="p", remote_path="/o.csv")
        )
        source.open(context)
        list(source.read(context))
        assert source._staging_dir is None or not source._staging_dir.exists()

    def test_json_format_delegate(self, factory, fake_ftp, context):
        fake_ftp.files["/d.jsonl"] = b'{"a": 1}\n{"a": 2}\n'
        source = factory.create_source(
            spec("ftp", host="h", user="u", password="p", remote_path="/d.jsonl")
        )
        source.open(context)
        rows = [record for batch in source.read(context) for record in batch]
        assert rows == [{"a": 1}, {"a": 2}]

    def test_upload_only_on_commit(self, factory, fake_ftp, context):
        sink = factory.create_sink(
            spec("ftp", host="h", user="u", password="p", remote_path="/out.csv")
        )
        sink.open(context)
        sink.write(RecordBatch([{"a": 1}, {"a": 2}]), context)
        assert "/out.csv" not in fake_ftp.files
        sink.commit()
        assert fake_ftp.files["/out.csv"] == b"a\n1\n2\n"
        sink.close()

    def test_rollback_uploads_nothing(self, factory, fake_ftp, context):
        sink = factory.create_sink(
            spec("ftp", host="h", user="u", password="p", remote_path="/out.csv")
        )
        sink.open(context)
        sink.write(RecordBatch([{"a": 1}]), context)
        sink.rollback()
        sink.close()
        assert "/out.csv" not in fake_ftp.files

    def test_upload_failure_is_reported(self, factory, fake_ftp, context, monkeypatch):
        def explode(self, command, handle, blocksize=8192):
            raise ftplib.error_perm("550 permission denied")

        monkeypatch.setattr(FakeFtp, "storbinary", explode)
        sink = factory.create_sink(
            spec("ftp", host="h", user="u", password="p", remote_path="/out.csv")
        )
        sink.open(context)
        sink.write(RecordBatch([{"a": 1}]), context)
        with pytest.raises(LoadingError, match="FTP upload failed"):
            sink.commit()
        sink.close()

    def test_unsupported_sink_format(self, factory, fake_ftp, context):
        sink = factory.create_sink(
            spec("ftp", host="h", user="u", password="p", remote_path="/out.bin")
        )
        with pytest.raises(ConfigurationError, match="unsupported remote file format"):
            sink.open(context)

    def test_authentication_failure_is_mapped(self, factory, fake_ftp, context, monkeypatch):
        def explode(self, user, password):
            raise ftplib.error_perm("530 login incorrect")

        monkeypatch.setattr(FakeFtp, "login", explode)
        source = factory.create_source(
            spec(
                "ftp",
                host="h",
                user="u",
                password="bad",
                remote_path="/o.csv",
                retry={"max_attempts": 1},
            )
        )
        source.open(context)
        with pytest.raises(AuthenticationError, match="FTP authentication failed"):
            list(source.read(context))


class TestFtpConnectionErrorMapping:
    def test_socket_failure_maps_to_a_connection_error(self, factory, fake_ftp, monkeypatch):
        """Regression: ``except (OSError, ftplib.all_errors)`` nests a tuple.

        Python rejects a nested tuple in an ``except`` clause with
        "catching classes that do not inherit from BaseException", so the real
        failure was replaced by a confusing TypeError.
        """
        from ironflow.connectors.remote import _ftp_connect

        def explode(self, host, port):
            raise OSError("connection refused")

        monkeypatch.setattr(FakeFtp, "connect", explode)
        connector = factory.create_source(
            spec("ftp", host="h", user="u", password="p", remote_path="/x.csv")
        )
        with pytest.raises(IFConnectionError, match="FTP connection failed"):
            _ftp_connect(connector)

    def test_protocol_failure_maps_to_a_connection_error(self, factory, fake_ftp, monkeypatch):
        from ironflow.connectors.remote import _ftp_connect

        def explode(self, value):
            raise ftplib.error_temp("421 service not available")

        monkeypatch.setattr(FakeFtp, "set_pasv", explode)
        connector = factory.create_source(
            spec("ftp", host="h", user="u", password="p", remote_path="/x.csv")
        )
        with pytest.raises(IFConnectionError, match="FTP connection failed"):
            _ftp_connect(connector)


class TestSftpSinkFormats:
    def test_unsupported_sink_format(self, factory, context, monkeypatch):
        import sys
        import types

        module = types.ModuleType("paramiko")
        module.SSHClient = object
        monkeypatch.setitem(sys.modules, "paramiko", module)
        sink = factory.create_sink(
            spec("sftp", host="h", user="u", password="p", remote_path="/out.bin")
        )
        with pytest.raises(ConfigurationError, match="unsupported remote file format"):
            sink.open(context)


def answer_token_requests(connector, handler):
    """Serve the connector's OAuth2 token request from ``handler``."""
    connector._build_token_client = lambda: httpx.Client(transport=httpx.MockTransport(handler))


class TestOAuth2:
    def test_token_is_fetched_and_used(self, factory, context, monkeypatch):
        monkeypatch.setenv("CID", "client-1")
        monkeypatch.setenv("CSECRET", "shhh")
        captured = {}

        def token_handler(request):
            captured["url"] = str(request.url)
            captured["data"] = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
            return httpx.Response(200, json={"access_token": "tok-abc", "expires_in": 3600})

        def handler(request):
            captured["auth"] = request.headers.get("authorization")
            return httpx.Response(200, json=[])

        connector = factory.create_source(
            spec(
                "rest",
                url="https://api.example.com/x",
                auth="oauth2",
                token_url="https://auth.example.com/token",
                client_id="env:CID",
                client_secret="env:CSECRET",
                scope="read:data",
                allow_private_network=True,
            )
        )
        transport = httpx.MockTransport(handler)
        original = connector._build_client

        def build():
            client = original()
            client._transport = transport
            for key in list(client._mounts):
                client._mounts[key] = transport
            return client

        connector._build_client = build
        answer_token_requests(connector, token_handler)
        connector.open(context)
        list(connector.read(context))
        connector.close()

        assert captured["url"] == "https://auth.example.com/token"
        assert captured["data"]["grant_type"] == "client_credentials"
        assert captured["data"]["client_id"] == "client-1"
        assert captured["data"]["scope"] == "read:data"
        assert captured["auth"] == "Bearer tok-abc"

    def test_token_endpoint_rejection_is_mapped(self, factory, context, monkeypatch):
        monkeypatch.setenv("CID", "c")
        monkeypatch.setenv("CSECRET", "s")
        connector = factory.create_source(
            spec(
                "rest",
                url="https://api.example.com/x",
                auth="oauth2",
                token_url="https://auth.example.com/token",
                client_id="env:CID",
                client_secret="env:CSECRET",
                allow_private_network=True,
            )
        )
        answer_token_requests(
            connector, lambda request: httpx.Response(401, json={"error": "invalid_client"})
        )
        with pytest.raises(AuthenticationError, match="rejected the credentials"):
            connector.open(context)

    def test_token_response_without_a_token(self, factory, context, monkeypatch):
        monkeypatch.setenv("CID", "c")
        monkeypatch.setenv("CSECRET", "s")
        connector = factory.create_source(
            spec(
                "rest",
                url="https://api.example.com/x",
                auth="oauth2",
                token_url="https://auth.example.com/token",
                client_id="env:CID",
                client_secret="env:CSECRET",
                allow_private_network=True,
            )
        )
        answer_token_requests(
            connector, lambda request: httpx.Response(200, json={"token_type": "bearer"})
        )
        with pytest.raises(AuthenticationError, match="no access_token"):
            connector.open(context)

    def test_transport_failure_is_mapped(self, factory, context, monkeypatch):
        monkeypatch.setenv("CID", "c")
        monkeypatch.setenv("CSECRET", "s")

        def explode(request):
            raise httpx.ConnectError("dns failure")

        connector = factory.create_source(
            spec(
                "rest",
                url="https://api.example.com/x",
                auth="oauth2",
                token_url="https://auth.example.com/token",
                client_id="env:CID",
                client_secret="env:CSECRET",
                allow_private_network=True,
            )
        )
        answer_token_requests(connector, explode)
        with pytest.raises(AuthenticationError, match="token request failed"):
            connector.open(context)


class TestRetryAfter:
    def test_numeric_retry_after_is_honoured(self, factory, context, monkeypatch):
        import ironflow.connectors.http as http_module

        slept: list[float] = []
        monkeypatch.setattr(http_module.time, "sleep", slept.append)
        calls = {"n": 0}

        def handler(request):
            calls["n"] += 1
            if calls["n"] == 1:
                return httpx.Response(429, headers={"Retry-After": "7"}, json={})
            return httpx.Response(200, json=[{"i": 1}])

        connector = factory.create_source(
            spec(
                "rest",
                url="https://api.example.com/x",
                allow_private_network=True,
                retry={"max_attempts": 2, "initial_delay": 0, "jitter": False},
            )
        )
        transport = httpx.MockTransport(handler)
        original = connector._build_client

        def build():
            client = original()
            client._transport = transport
            for key in list(client._mounts):
                client._mounts[key] = transport
            return client

        connector._build_client = build
        connector.open(context)
        rows = [r for b in connector.read(context) for r in b]
        connector.close()
        assert rows == [{"i": 1}]
        assert 7 in slept, "the server's Retry-After must be respected"

    def test_http_date_retry_after_is_parsed(self):
        from ironflow.connectors.http import _parse_retry_after

        assert _parse_retry_after(None) is None
        assert _parse_retry_after("5") == 5.0
        assert _parse_retry_after("not a date") is None
        assert _parse_retry_after("Wed, 21 Oct 2099 07:28:00 GMT") > 0


class TestGraphQLPagination:
    def test_relay_cursor_pagination(self, factory, context):
        pages = [
            {
                "data": {
                    "items": [{"node": {"id": 1}}],
                    "pageInfo": {"hasNextPage": True, "endCursor": "c1"},
                }
            },
            {
                "data": {
                    "items": [{"node": {"id": 2}}],
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                }
            },
        ]
        calls = {"n": 0}

        def handler(request):
            payload = pages[calls["n"]]
            calls["n"] += 1
            return httpx.Response(200, json=payload)

        connector = factory.create_source(
            spec(
                "graphql",
                url="https://api.example.com/graphql",
                query="{ items }",
                data_path="items",
                pagination="cursor",
                allow_private_network=True,
            )
        )
        transport = httpx.MockTransport(handler)
        original = connector._build_client

        def build():
            client = original()
            client._transport = transport
            for key in list(client._mounts):
                client._mounts[key] = transport
            return client

        connector._build_client = build
        connector.open(context)
        rows = [r for b in connector.read(context) for r in b]
        connector.close()
        assert rows == [{"id": 1}, {"id": 2}]


class TestCryptoEdgeCases:
    def test_key_file_loading(self, tmp_path: Path):
        key_file = tmp_path / "key"
        key_file.write_text(generate_key(), encoding="ascii")
        if os.name == "posix":
            key_file.chmod(0o600)
        crypto = CryptoService.from_key_file(key_file)
        assert crypto.decrypt(crypto.encrypt("x")) == "x"

    def test_missing_key_file(self, tmp_path: Path):
        with pytest.raises(SecretError, match="key file not found"):
            CryptoService.from_key_file(tmp_path / "absent")

    @pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits only")
    def test_world_readable_key_file_is_refused(self, tmp_path: Path):
        key_file = tmp_path / "key"
        key_file.write_text(generate_key(), encoding="ascii")
        key_file.chmod(0o644)
        with pytest.raises(SecretError, match="accessible by group or others"):
            CryptoService.from_key_file(key_file)

    def test_from_env(self, monkeypatch):
        monkeypatch.setenv("IRONFLOW_ENCRYPTION_KEY", generate_key())
        crypto = CryptoService.from_env()
        assert crypto.decrypt(crypto.encrypt("x")) == "x"

    def test_derive_key_requires_a_passphrase(self):
        with pytest.raises(ConfigurationError, match="must not be empty"):
            derive_key("", b"salt" * 4)

    def test_derive_key_is_salt_dependent(self):
        assert derive_key("pw", b"a" * 16) != derive_key("pw", b"b" * 16)

    @pytest.mark.parametrize(
        "envelope",
        ["not-an-envelope", "ironflow:v1:notbase64!!:token", "a:b:c"],
    )
    def test_malformed_envelopes_are_rejected(self, envelope):
        with pytest.raises(SecretError):
            CryptoService.from_key(generate_key()).decrypt(envelope)


class TestSecretResolverEdgeCases:
    def test_non_string_reference_is_rejected(self):
        with pytest.raises(SecretError, match="must be a string"):
            SecretResolver().resolve(12345)

    def test_empty_env_name_is_rejected(self):
        with pytest.raises(SecretError, match="empty environment variable"):
            SecretResolver().resolve("env:")

    def test_missing_secret_file(self, tmp_path: Path):
        with pytest.raises(SecretError, match="not found"):
            SecretResolver(file_roots=(str(tmp_path),)).resolve(f"file:{tmp_path / 'absent'}")

    def test_literal_prefix_is_explicit(self):
        assert SecretResolver().resolve("literal:value").reveal() == "value"

    def test_already_resolved_secret_passes_through(self):
        from ironflow.security.secrets import SecretStr

        secret = SecretStr("v")
        assert SecretResolver().resolve(secret) is secret

    def test_reveal_with_a_default(self):
        assert SecretResolver().reveal(None, default="fallback") == "fallback"

    def test_resolve_mapping_walks_nested_structures(self, monkeypatch):
        monkeypatch.setenv("PW", "hunter2")
        resolved = SecretResolver().resolve_mapping(
            {"host": "db", "auth": {"password": "env:PW"}, "port": 5432}
        )
        assert resolved["host"] == "db"
        assert resolved["port"] == 5432
        assert resolved["auth"]["password"].reveal() == "hunter2"

    def test_is_reference_detection(self):
        assert SecretResolver.is_reference("env:X")
        assert SecretResolver.is_reference("file:/x")
        assert SecretResolver.is_reference("enc:x")
        assert SecretResolver.is_reference("literal:x")
        assert not SecretResolver.is_reference("plain")
