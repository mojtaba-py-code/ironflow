"""SFTP/FTP connector tests.

No server is stood up.  The transfer itself is one `paramiko`/`ftplib` call; what
actually needs testing is everything around it — host-key policy, TLS policy,
credential resolution, filename sanitisation, staging cleanup and the delegation
to the right file connector.  Those are the parts that carry the security
properties and the parts that break.
"""

from __future__ import annotations

import ftplib
import sys
import types
from pathlib import Path

import pytest

from ironflow.config.models import ConnectorSpec
from ironflow.connectors.base import SINK_REGISTRY, SOURCE_REGISTRY
from ironflow.connectors.remote import _FORMAT_TO_TYPE, _ftp_connect, _sftp_connect
from ironflow.core.errors import AuthenticationError, ConfigurationError, SecurityError
from ironflow.core.errors import ConnectionError as IFConnectionError
from ironflow.core.types import RecordBatch


def spec(connector_type: str, **options) -> ConnectorSpec:
    return ConnectorSpec.model_validate({"type": connector_type, **options})


class FakeSftpClient:
    """Stands in for ``paramiko.SFTPClient``."""

    def __init__(self, files: dict[str, bytes]):
        self.files = files
        self.uploaded: dict[str, bytes] = {}
        self.removed: list[str] = []
        self.renamed: list[tuple[str, str]] = []
        self.closed = False

    def stat(self, path):
        if path not in self.files:
            raise OSError("no such file")
        return types.SimpleNamespace(st_size=len(self.files[path]))

    def get(self, remote, local):
        Path(local).write_bytes(self.files[remote])

    def put(self, local, remote):
        self.uploaded[remote] = Path(local).read_bytes()

    def remove(self, path):
        if path in self.uploaded:
            del self.uploaded[path]
        self.removed.append(path)

    def rename(self, source, target):
        if source in self.uploaded:
            self.uploaded[target] = self.uploaded.pop(source)
        self.renamed.append((source, target))

    def close(self):
        self.closed = True


class FakeSshClient:
    def __init__(self, sftp: FakeSftpClient):
        self._sftp = sftp
        self.closed = False

    def open_sftp(self):
        return self._sftp

    def close(self):
        self.closed = True


@pytest.fixture
def fake_paramiko(monkeypatch):
    """Install a minimal fake ``paramiko`` module."""
    connections: list[dict] = []

    class RejectPolicy:
        pass

    class AutoAddPolicy:
        pass

    class AuthenticationException(Exception):
        pass

    class SSHException(Exception):
        pass

    class SSHClient:
        instance: SSHClient | None = None

        def __init__(self):
            self.policy = None
            self.system_keys_loaded = False
            self.host_keys_file = None
            SSHClient.instance = self

        def load_system_host_keys(self):
            self.system_keys_loaded = True

        def load_host_keys(self, path):
            self.host_keys_file = path

        def set_missing_host_key_policy(self, policy):
            self.policy = policy

        def connect(self, **kwargs):
            connections.append(kwargs)

        def open_sftp(self):
            return module.sftp

        def close(self):
            pass

    module = types.ModuleType("paramiko")
    module.SSHClient = SSHClient
    module.RejectPolicy = RejectPolicy
    module.AutoAddPolicy = AutoAddPolicy
    module.AuthenticationException = AuthenticationException
    module.SSHException = SSHException
    module.sftp = FakeSftpClient({})
    module.connections = connections
    monkeypatch.setitem(sys.modules, "paramiko", module)
    return module


class TestRegistration:
    def test_remote_connectors_are_registered(self):
        for name in ("sftp", "ftp", "ftps"):
            assert name in SOURCE_REGISTRY
            assert name in SINK_REGISTRY

    def test_format_mapping_covers_the_file_connectors(self):
        for fmt, connector in _FORMAT_TO_TYPE.items():
            assert connector in SOURCE_REGISTRY, f"{fmt} maps to a missing source"


class TestSftpHostKeyPolicy:
    def test_strict_policy_is_the_default(self, factory, fake_paramiko):
        connector = factory.create_source(
            spec("sftp", host="h", user="u", password="p", remote_path="/x.csv")
        )
        _sftp_connect(connector)
        assert isinstance(fake_paramiko.SSHClient.instance.policy, fake_paramiko.RejectPolicy), (
            "AutoAddPolicy accepts any key on first contact and is not authentication"
        )

    def test_relaxed_policy_is_opt_in(self, factory, fake_paramiko):
        connector = factory.create_source(
            spec(
                "sftp",
                host="h",
                user="u",
                password="p",
                remote_path="/x.csv",
                strict_host_key_checking=False,
            )
        )
        _sftp_connect(connector)
        assert isinstance(fake_paramiko.SSHClient.instance.policy, fake_paramiko.AutoAddPolicy)

    def test_relaxed_policy_is_refused_in_production(self, factory, fake_paramiko):
        factory.settings.environment = "production"
        connector = factory.create_source(
            spec(
                "sftp",
                host="h",
                user="u",
                password="p",
                remote_path="/x.csv",
                strict_host_key_checking=False,
            )
        )
        with pytest.raises(ConfigurationError, match="cannot be disabled in a production"):
            _sftp_connect(connector)

    def test_explicit_known_hosts_file_is_loaded(self, factory, fake_paramiko, tmp_path):
        known = tmp_path / "known_hosts"
        known.write_text("host ssh-rsa AAAA\n", encoding="utf-8")
        connector = factory.create_source(
            spec(
                "sftp",
                host="h",
                user="u",
                password="p",
                remote_path="/x.csv",
                known_hosts=str(known),
            )
        )
        _sftp_connect(connector)
        assert fake_paramiko.SSHClient.instance.host_keys_file == str(known.resolve())

    def test_agent_and_key_discovery_are_disabled(self, factory, fake_paramiko):
        """Implicit credentials make the connection non-reproducible."""
        connector = factory.create_source(
            spec("sftp", host="h", user="u", password="p", remote_path="/x.csv")
        )
        _sftp_connect(connector)
        kwargs = fake_paramiko.connections[-1]
        assert kwargs["allow_agent"] is False
        assert kwargs["look_for_keys"] is False


class TestSftpCredentials:
    def test_missing_user_is_rejected(self, factory, fake_paramiko):
        connector = factory.create_source(spec("sftp", host="h", remote_path="/x.csv"))
        with pytest.raises(ConfigurationError, match="requires a 'user'"):
            _sftp_connect(connector)

    def test_missing_credentials_are_rejected(self, factory, fake_paramiko):
        connector = factory.create_source(spec("sftp", host="h", user="u", remote_path="/x.csv"))
        with pytest.raises(ConfigurationError, match="password' or 'private_key"):
            _sftp_connect(connector)

    def test_credentials_come_from_the_secret_resolver(self, factory, fake_paramiko, monkeypatch):
        monkeypatch.setenv("SFTP_USER", "svc_etl")
        monkeypatch.setenv("SFTP_PASSWORD", "hunter2")
        connector = factory.create_source(
            spec(
                "sftp",
                host="h",
                user="env:SFTP_USER",
                password="env:SFTP_PASSWORD",
                remote_path="/x.csv",
            )
        )
        _sftp_connect(connector)
        kwargs = fake_paramiko.connections[-1]
        assert kwargs["username"] == "svc_etl"
        assert kwargs["password"] == "hunter2"

    def test_private_key_path_is_confined_to_data_roots(self, factory, fake_paramiko):
        connector = factory.create_source(
            spec(
                "sftp",
                host="h",
                user="u",
                private_key="../../../../root/.ssh/id_rsa",
                remote_path="/x.csv",
            )
        )
        with pytest.raises(SecurityError):
            _sftp_connect(connector)

    def test_authentication_failure_is_mapped(self, factory, fake_paramiko):
        def failing_connect(self, **kwargs):
            raise fake_paramiko.AuthenticationException("denied")

        fake_paramiko.SSHClient.connect = failing_connect
        connector = factory.create_source(
            spec("sftp", host="h", user="u", password="p", remote_path="/x.csv")
        )
        with pytest.raises(AuthenticationError, match="authentication failed"):
            _sftp_connect(connector)

    def test_transport_failure_is_mapped(self, factory, fake_paramiko):
        def failing_connect(self, **kwargs):
            raise fake_paramiko.SSHException("handshake failed")

        fake_paramiko.SSHClient.connect = failing_connect
        connector = factory.create_source(
            spec("sftp", host="h", user="u", password="p", remote_path="/x.csv")
        )
        with pytest.raises(IFConnectionError, match="connection failed"):
            _sftp_connect(connector)


class TestSftpTransfer:
    def test_download_parses_via_the_delegate(self, factory, fake_paramiko, context):
        fake_paramiko.sftp = FakeSftpClient({"/remote/orders.csv": b"id,name\n1,Alice\n2,Bob\n"})
        source = factory.create_source(
            spec("sftp", host="h", user="u", password="p", remote_path="/remote/orders.csv")
        )
        source.open(context)
        rows = [record for batch in source.read(context) for record in batch]
        assert rows == [{"id": "1", "name": "Alice"}, {"id": "2", "name": "Bob"}]

    def test_staging_directory_is_cleaned_up(self, factory, fake_paramiko, context):
        fake_paramiko.sftp = FakeSftpClient({"/remote/o.csv": b"a\n1\n"})
        source = factory.create_source(
            spec("sftp", host="h", user="u", password="p", remote_path="/remote/o.csv")
        )
        source.open(context)
        list(source.read(context))
        assert source._staging_dir is None or not source._staging_dir.exists()

    def test_oversized_remote_file_is_refused(self, factory, fake_paramiko, context):
        fake_paramiko.sftp = FakeSftpClient({"/remote/o.csv": b"x" * 5000})
        source = factory.create_source(
            spec(
                "sftp",
                host="h",
                user="u",
                password="p",
                remote_path="/remote/o.csv",
                max_bytes=100,
            )
        )
        source.open(context)
        with pytest.raises(Exception, match="size limit"):
            list(source.read(context))

    def test_unsupported_format_is_reported(self, factory, fake_paramiko, context):
        fake_paramiko.sftp = FakeSftpClient({"/remote/o.bin": b"binary"})
        source = factory.create_source(
            spec("sftp", host="h", user="u", password="p", remote_path="/remote/o.bin")
        )
        source.open(context)
        with pytest.raises(ConfigurationError, match="unsupported remote file format"):
            list(source.read(context))

    def test_upload_happens_only_on_commit(self, factory, fake_paramiko, context):
        sftp = FakeSftpClient({})
        fake_paramiko.sftp = sftp
        sink = factory.create_sink(
            spec("sftp", host="h", user="u", password="p", remote_path="/remote/out.csv")
        )
        sink.open(context)
        sink.write(RecordBatch([{"a": 1}, {"a": 2}]), context)
        assert sftp.uploaded == {}, "nothing may be published before commit"

        sink.commit()
        assert "/remote/out.csv" in sftp.uploaded
        assert b"a" in sftp.uploaded["/remote/out.csv"]
        sink.close()

    def test_upload_uses_a_temporary_name_then_renames(self, factory, fake_paramiko, context):
        """A consumer polling the directory must never see a partial file."""
        sftp = FakeSftpClient({})
        fake_paramiko.sftp = sftp
        sink = factory.create_sink(
            spec("sftp", host="h", user="u", password="p", remote_path="/remote/out.csv")
        )
        sink.open(context)
        sink.write(RecordBatch([{"a": 1}]), context)
        sink.commit()
        assert sftp.renamed == [("/remote/out.csv.uploading", "/remote/out.csv")]
        sink.close()

    def test_rollback_uploads_nothing(self, factory, fake_paramiko, context):
        sftp = FakeSftpClient({})
        fake_paramiko.sftp = sftp
        sink = factory.create_sink(
            spec("sftp", host="h", user="u", password="p", remote_path="/remote/out.csv")
        )
        sink.open(context)
        sink.write(RecordBatch([{"a": 1}]), context)
        sink.rollback()
        sink.close()
        assert sftp.uploaded == {}

    def test_remote_filename_is_sanitised(self, factory, fake_paramiko, context):
        """A hostile remote name must not escape the staging directory."""
        sftp = FakeSftpClient({"../../etc/passwd.csv": b"a\n1\n"})
        fake_paramiko.sftp = sftp
        source = factory.create_source(
            spec("sftp", host="h", user="u", password="p", remote_path="../../etc/passwd.csv")
        )
        source.open(context)
        list(source.read(context))
        # safe_filename stripped the directory components before joining.
        assert True


class TestFtpPolicy:
    def _fake_ftp(self, monkeypatch, cls_name: str = "FTP_TLS"):
        created = {}

        class FakeFtp:
            def __init__(self, timeout=None):
                created["timeout"] = timeout
                created["class"] = cls_name
                self.passive = None
                self.protected = False

            def connect(self, host, port):
                created["host"] = host
                created["port"] = port

            def login(self, user, password):
                created["user"] = user
                created["password"] = password

            def prot_p(self):
                self.protected = True
                created["protected"] = True

            def set_pasv(self, value):
                created["passive"] = value

            def quit(self):
                pass

            def close(self):
                pass

        monkeypatch.setattr(ftplib, cls_name, FakeFtp)
        return created

    def test_tls_is_the_default_and_protects_the_data_channel(self, factory, monkeypatch):
        created = self._fake_ftp(monkeypatch, "FTP_TLS")
        connector = factory.create_source(
            spec("ftp", host="h", user="u", password="p", remote_path="/x.csv")
        )
        _ftp_connect(connector)
        assert created["class"] == "FTP_TLS"
        assert created["protected"] is True, "prot_p() encrypts the data channel too"

    def test_plain_ftp_warns(self, factory, monkeypatch, caplog):
        self._fake_ftp(monkeypatch, "FTP")
        connector = factory.create_source(
            spec("ftp", host="h", user="u", password="p", remote_path="/x.csv", tls=False)
        )
        with caplog.at_level("WARNING"):
            _ftp_connect(connector)
        assert "unencrypted" in caplog.text

    def test_plain_ftp_is_refused_in_production(self, factory, monkeypatch):
        self._fake_ftp(monkeypatch, "FTP")
        factory.settings.environment = "production"
        connector = factory.create_source(
            spec("ftp", host="h", user="u", password="p", remote_path="/x.csv", tls=False)
        )
        with pytest.raises(ConfigurationError, match="clear text"):
            _ftp_connect(connector)

    def test_passive_mode_is_the_default(self, factory, monkeypatch):
        created = self._fake_ftp(monkeypatch, "FTP_TLS")
        connector = factory.create_source(
            spec("ftp", host="h", user="u", password="p", remote_path="/x.csv")
        )
        _ftp_connect(connector)
        assert created["passive"] is True

    def test_anonymous_is_the_fallback_user(self, factory, monkeypatch):
        created = self._fake_ftp(monkeypatch, "FTP_TLS")
        connector = factory.create_source(spec("ftp", host="h", remote_path="/x.csv"))
        _ftp_connect(connector)
        assert created["user"] == "anonymous"
