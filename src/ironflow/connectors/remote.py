"""Remote file-transfer connectors: SFTP and FTP/FTPS.

Both work by *staging*: the remote object is downloaded to a temporary local
file and then handed to the ordinary file connector chosen by ``format``.  That
keeps the parsing logic in one place and means a flaky network connection fails
during download rather than halfway through a load.

SFTP host-key policy
--------------------
The default is ``RejectPolicy`` with a known-hosts file.  ``paramiko``'s
``AutoAddPolicy`` - which most examples use - accepts any key on first contact
and turns the connection into an unauthenticated one from an attacker's point of
view.  Accepting unknown keys requires ``strict_host_key_checking: false``,
which is refused outright in a production environment.

FTP
---
Plain FTP sends credentials in clear text.  ``FTP_TLS`` is used by default and
downgrading to plain FTP requires an explicit ``tls: false``, which is likewise
refused in production.  Passive mode is the default because it is the one that
works through NAT.
"""

from __future__ import annotations

import contextlib
import ftplib
import logging
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from ironflow.config.models import ConnectorSpec
from ironflow.connectors.base import BaseSink, BaseSource, ConnectorRuntime, sink, source
from ironflow.core.context import ExecutionContext
from ironflow.core.errors import (
    AuthenticationError,
    ConfigurationError,
    ExtractionError,
    LoadingError,
)
from ironflow.core.errors import ConnectionError as IFConnectionError
from ironflow.core.retry import call_with_retry
from ironflow.core.types import RecordBatch, RecordStream
from ironflow.security.guards import safe_filename

logger = logging.getLogger(__name__)

#: Formats the staged file can be parsed as.
_FORMAT_TO_TYPE = {
    "csv": "csv",
    "tsv": "csv",
    "json": "json",
    "jsonl": "json",
    "ndjson": "json",
    "xml": "xml",
    "parquet": "parquet",
    "excel": "excel",
    "xlsx": "excel",
}


class _StagingMixin:
    """Creates and cleans a private temporary directory for staged transfers."""

    def _make_staging_dir(self: Any) -> Path:
        # ``mkdtemp`` creates the directory with 0700, so a staged file
        # containing production data is not world-readable on a shared host.
        return Path(tempfile.mkdtemp(prefix="ironflow-transfer-"))

    def _cleanup(self: Any, directory: Path | None) -> None:
        if directory is None:
            return
        import shutil

        shutil.rmtree(directory, ignore_errors=True)

    def _delegate_source(self: Any, local_path: Path) -> BaseSource:
        """Build the file connector that parses the staged download."""
        from ironflow.connectors.base import SOURCE_REGISTRY

        fmt = self.str_option("format", "").lower() or local_path.suffix.lstrip(".").lower()
        connector_type = _FORMAT_TO_TYPE.get(fmt)
        if connector_type is None:
            raise ConfigurationError(
                "unsupported remote file format",
                context={"format": fmt, "supported": sorted(set(_FORMAT_TO_TYPE))},
            )
        options = {
            k: v
            for k, v in self.spec.options.items()
            if k
            not in {
                "host",
                "port",
                "user",
                "username",
                "password",
                "private_key",
                "private_key_passphrase",
                "remote_path",
                "format",
                "tls",
                "known_hosts",
                "strict_host_key_checking",
                "passive",
            }
        }
        delegated = ConnectorSpec.model_validate(
            {
                "type": connector_type,
                "name": f"{self.name}:staged",
                "batch_size": self.spec.batch_size,
                "path": str(local_path),
                **options,
            }
        )
        # The staging directory is outside the configured data roots by design,
        # so the delegate runs with roots disabled; the path is one we created.
        runtime = ConnectorRuntime(
            settings=self.runtime.settings.model_copy(update={"data_roots": []}),
            secrets=self.runtime.secrets,
        )
        return SOURCE_REGISTRY.create(connector_type, spec=delegated, runtime=runtime)


# --------------------------------------------------------------------------- #
# SFTP
# --------------------------------------------------------------------------- #
@source("sftp")
class SftpSource(_StagingMixin, BaseSource):
    """Download a file over SSH and parse it.

    Options: ``host`` (required), ``port``, ``user`` (required), ``password``
    **or** ``private_key``, ``remote_path`` (required), ``format``,
    ``known_hosts``, ``strict_host_key_checking``, ``delete_after`` - plus any
    option accepted by the delegated file connector.
    """

    def __init__(self, spec: ConnectorSpec, runtime: ConnectorRuntime | None = None) -> None:
        super().__init__(spec, runtime)
        self._staging_dir: Path | None = None
        self._delegate: BaseSource | None = None

    def read(self, context: ExecutionContext) -> RecordStream:
        remote_path = self.str_option("remote_path", required=True)
        self._staging_dir = self._make_staging_dir()
        local_path = self._staging_dir / safe_filename(Path(remote_path).name, fallback="download")

        call_with_retry(
            lambda: self._download(remote_path, local_path),
            self.retry_policy,
            description=f"sftp download {remote_path}",
        )

        self._delegate = self._delegate_source(local_path)
        self._delegate.open(context)

        def generate() -> Iterator[RecordBatch]:
            try:
                assert self._delegate is not None
                yield from self._delegate.read(context)
            finally:
                self.close()

        return generate()

    def _download(self, remote_path: str, local_path: Path) -> None:
        client = _sftp_connect(self)
        try:
            sftp = client.open_sftp()
            try:
                size = sftp.stat(remote_path).st_size or 0
                limit = self.int_option("max_bytes", 5 * 1024**3, minimum=1)
                if size > limit:
                    raise ExtractionError(
                        "remote file exceeds the configured size limit",
                        context={"path": remote_path, "size": size, "limit": limit},
                    )
                logger.info("downloading %s (%d bytes) over SFTP", remote_path, size)
                sftp.get(remote_path, str(local_path))
                if self.bool_option("delete_after", False):
                    sftp.remove(remote_path)
            finally:
                sftp.close()
        finally:
            client.close()

    def _on_close(self) -> None:
        if self._delegate is not None:
            self._delegate.close()
            self._delegate = None
        self._cleanup(self._staging_dir)
        self._staging_dir = None


@sink("sftp")
class SftpSink(_StagingMixin, BaseSink):
    """Write locally, then upload over SSH on commit.

    Uploading only at commit time means a failed or rolled-back run never
    publishes a partial file to the remote system.
    """

    transactional = True

    def __init__(self, spec: ConnectorSpec, runtime: ConnectorRuntime | None = None) -> None:
        super().__init__(spec, runtime)
        self._staging_dir: Path | None = None
        self._delegate: BaseSink | None = None
        self._local_path: Path | None = None

    def _on_open(self, context: ExecutionContext) -> None:
        from ironflow.connectors.base import SINK_REGISTRY

        remote_path = self.str_option("remote_path", required=True)
        self._staging_dir = self._make_staging_dir()
        self._local_path = self._staging_dir / safe_filename(
            Path(remote_path).name, fallback="upload"
        )

        fmt = self.str_option("format", "").lower() or self._local_path.suffix.lstrip(".").lower()
        connector_type = _FORMAT_TO_TYPE.get(fmt)
        if connector_type is None:
            raise ConfigurationError("unsupported remote file format", context={"format": fmt})
        delegated = ConnectorSpec.model_validate(
            {
                "type": connector_type,
                "name": f"{self.name}:staged",
                "mode": self.spec.mode,
                "path": str(self._local_path),
            }
        )
        runtime = ConnectorRuntime(
            settings=self.runtime.settings.model_copy(update={"data_roots": []}),
            secrets=self.runtime.secrets,
        )
        self._delegate = SINK_REGISTRY.create(connector_type, spec=delegated, runtime=runtime)
        self._delegate.open(context)
        self.rows_written = 0

    def write(self, batch: RecordBatch, context: ExecutionContext) -> int:
        self._assert_writable()
        assert self._delegate is not None
        written = self._delegate.write(batch, context)
        self.rows_written += written
        return written

    def commit(self) -> None:
        if self._delegate is None or self._local_path is None:
            return
        self._delegate.commit()
        remote_path = self.str_option("remote_path", required=True)
        call_with_retry(
            lambda: self._upload(self._local_path, remote_path),  # type: ignore[arg-type]
            self.retry_policy,
            description=f"sftp upload {remote_path}",
        )

    def _upload(self, local_path: Path, remote_path: str) -> None:
        client = _sftp_connect(self)
        try:
            sftp = client.open_sftp()
            try:
                # Upload to a temporary name and rename, so a consumer polling
                # the directory never sees a partially written file.
                temporary = f"{remote_path}.uploading"
                sftp.put(str(local_path), temporary)
                with contextlib.suppress(OSError):
                    sftp.remove(remote_path)  # absent target is the normal case
                sftp.rename(temporary, remote_path)
                logger.info("uploaded %d rows to sftp:%s", self.rows_written, remote_path)
            finally:
                sftp.close()
        finally:
            client.close()

    def rollback(self) -> None:
        if self._delegate is not None:
            self._delegate.rollback()
        self.rows_written = 0

    def _on_close(self) -> None:
        if self._delegate is not None:
            self._delegate.close()
            self._delegate = None
        self._cleanup(self._staging_dir)
        self._staging_dir = None


def _sftp_connect(connector: Any) -> Any:
    """Open an authenticated SSH connection with strict host-key checking."""
    try:
        import paramiko
    except ImportError as exc:  # pragma: no cover - dependency guard
        raise IFConnectionError(
            "SFTP requires the 'remote' extra: pip install 'ironflow[remote]'"
        ) from exc

    host = connector.str_option("host", required=True)
    port = connector.int_option("port", 22, minimum=1, maximum=65535)
    user = connector.secret_option("user") or connector.secret_option("username")
    if not user:
        raise ConfigurationError("SFTP requires a 'user'")
    password = connector.secret_option("password")
    key_path = connector.str_option("private_key")
    strict = connector.bool_option("strict_host_key_checking", True)

    if not strict and connector.runtime.settings.is_production:
        raise ConfigurationError(
            "strict_host_key_checking cannot be disabled in a production environment"
        )

    client = paramiko.SSHClient()
    known_hosts = connector.str_option("known_hosts")
    if known_hosts:
        client.load_host_keys(str(connector.runtime.resolve_path(known_hosts, must_exist=True)))
    else:
        client.load_system_host_keys()
    client.set_missing_host_key_policy(
        paramiko.RejectPolicy() if strict else paramiko.AutoAddPolicy()
    )

    kwargs: dict[str, Any] = {
        "hostname": host,
        "port": port,
        "username": user,
        "timeout": connector.int_option("timeout", 30, minimum=1),
        "allow_agent": False,
        "look_for_keys": False,
    }
    if key_path:
        kwargs["key_filename"] = str(connector.runtime.resolve_path(key_path, must_exist=True))
        passphrase = connector.secret_option("private_key_passphrase")
        if passphrase:
            kwargs["passphrase"] = passphrase
    elif password:
        kwargs["password"] = password
    else:
        raise ConfigurationError("SFTP requires either 'password' or 'private_key'")

    try:
        client.connect(**kwargs)
    except paramiko.AuthenticationException as exc:
        raise AuthenticationError(
            "SFTP authentication failed", context={"host": host, "user": user}
        ) from exc
    except paramiko.SSHException as exc:
        raise IFConnectionError(
            "SFTP connection failed", context={"host": host, "port": port}, cause=exc
        ) from exc
    return client


# --------------------------------------------------------------------------- #
# FTP / FTPS
# --------------------------------------------------------------------------- #
@source("ftp", "ftps")
class FtpSource(_StagingMixin, BaseSource):
    """Download a file over FTPS (or plain FTP if explicitly enabled).

    Options: ``host`` (required), ``port``, ``user``, ``password``,
    ``remote_path`` (required), ``format``, ``tls``, ``passive``.
    """

    def __init__(self, spec: ConnectorSpec, runtime: ConnectorRuntime | None = None) -> None:
        super().__init__(spec, runtime)
        self._staging_dir: Path | None = None
        self._delegate: BaseSource | None = None

    def read(self, context: ExecutionContext) -> RecordStream:
        remote_path = self.str_option("remote_path", required=True)
        self._staging_dir = self._make_staging_dir()
        local_path = self._staging_dir / safe_filename(Path(remote_path).name, fallback="download")

        call_with_retry(
            lambda: self._download(remote_path, local_path),
            self.retry_policy,
            description=f"ftp download {remote_path}",
        )

        self._delegate = self._delegate_source(local_path)
        self._delegate.open(context)

        def generate() -> Iterator[RecordBatch]:
            try:
                assert self._delegate is not None
                yield from self._delegate.read(context)
            finally:
                self.close()

        return generate()

    def _download(self, remote_path: str, local_path: Path) -> None:
        connection = _ftp_connect(self)
        try:
            with local_path.open("wb") as handle:
                connection.retrbinary(f"RETR {remote_path}", handle.write, blocksize=1 << 20)
            logger.info("downloaded %s over %s", remote_path, connection.__class__.__name__)
        except ftplib.all_errors as exc:
            raise ExtractionError(
                "FTP download failed", context={"path": remote_path}, cause=exc
            ) from exc
        finally:
            _ftp_quit(connection)

    def _on_close(self) -> None:
        if self._delegate is not None:
            self._delegate.close()
            self._delegate = None
        self._cleanup(self._staging_dir)
        self._staging_dir = None


@sink("ftp", "ftps")
class FtpSink(_StagingMixin, BaseSink):
    """Write locally then upload over FTPS on commit."""

    transactional = True

    def __init__(self, spec: ConnectorSpec, runtime: ConnectorRuntime | None = None) -> None:
        super().__init__(spec, runtime)
        self._staging_dir: Path | None = None
        self._delegate: BaseSink | None = None
        self._local_path: Path | None = None

    def _on_open(self, context: ExecutionContext) -> None:
        from ironflow.connectors.base import SINK_REGISTRY

        remote_path = self.str_option("remote_path", required=True)
        self._staging_dir = self._make_staging_dir()
        self._local_path = self._staging_dir / safe_filename(
            Path(remote_path).name, fallback="upload"
        )
        fmt = self.str_option("format", "").lower() or self._local_path.suffix.lstrip(".").lower()
        connector_type = _FORMAT_TO_TYPE.get(fmt)
        if connector_type is None:
            raise ConfigurationError("unsupported remote file format", context={"format": fmt})

        delegated = ConnectorSpec.model_validate(
            {
                "type": connector_type,
                "name": f"{self.name}:staged",
                "mode": self.spec.mode,
                "path": str(self._local_path),
            }
        )
        runtime = ConnectorRuntime(
            settings=self.runtime.settings.model_copy(update={"data_roots": []}),
            secrets=self.runtime.secrets,
        )
        self._delegate = SINK_REGISTRY.create(connector_type, spec=delegated, runtime=runtime)
        self._delegate.open(context)
        self.rows_written = 0

    def write(self, batch: RecordBatch, context: ExecutionContext) -> int:
        self._assert_writable()
        assert self._delegate is not None
        written = self._delegate.write(batch, context)
        self.rows_written += written
        return written

    def commit(self) -> None:
        if self._delegate is None or self._local_path is None:
            return
        self._delegate.commit()
        remote_path = self.str_option("remote_path", required=True)
        connection = _ftp_connect(self)
        try:
            with self._local_path.open("rb") as handle:
                connection.storbinary(f"STOR {remote_path}", handle, blocksize=1 << 20)
            logger.info("uploaded %d rows to ftp:%s", self.rows_written, remote_path)
        except ftplib.all_errors as exc:
            raise LoadingError(
                "FTP upload failed", context={"path": remote_path}, cause=exc
            ) from exc
        finally:
            _ftp_quit(connection)

    def rollback(self) -> None:
        if self._delegate is not None:
            self._delegate.rollback()
        self.rows_written = 0

    def _on_close(self) -> None:
        if self._delegate is not None:
            self._delegate.close()
            self._delegate = None
        self._cleanup(self._staging_dir)
        self._staging_dir = None


def _ftp_connect(connector: Any) -> ftplib.FTP:
    host = connector.str_option("host", required=True)
    port = connector.int_option("port", 21, minimum=1, maximum=65535)
    user = connector.secret_option("user") or connector.secret_option("username") or "anonymous"
    password = connector.secret_option("password") or ""
    use_tls = connector.bool_option("tls", True)
    timeout = connector.int_option("timeout", 30, minimum=1)

    if not use_tls and connector.runtime.settings.is_production:
        raise ConfigurationError(
            "plain FTP transmits credentials in clear text and is refused in production; "
            "use FTPS (tls: true) or SFTP"
        )
    if not use_tls:
        logger.warning("connecting to %s with plain FTP: credentials are sent unencrypted", host)

    try:
        connection: ftplib.FTP = (
            ftplib.FTP_TLS(timeout=timeout) if use_tls else ftplib.FTP(timeout=timeout)
        )
        connection.connect(host, port)
        connection.login(user, password)
        if isinstance(connection, ftplib.FTP_TLS):
            connection.prot_p()  # encrypt the data channel too, not just the control channel
        connection.set_pasv(connector.bool_option("passive", True))
    except ftplib.error_perm as exc:
        raise AuthenticationError(
            "FTP authentication failed", context={"host": host, "user": user}
        ) from exc
    # ``ftplib.all_errors`` is itself a tuple and already contains OSError.
    # Nesting it inside another tuple raises "catching classes that do not
    # inherit from BaseException" at runtime, masking the real failure.
    except ftplib.all_errors as exc:
        raise IFConnectionError(
            "FTP connection failed", context={"host": host, "port": port}, cause=exc
        ) from exc
    return connection


def _ftp_quit(connection: ftplib.FTP) -> None:
    try:
        connection.quit()
    except Exception:
        connection.close()


__all__ = ["FtpSink", "FtpSource", "SftpSink", "SftpSource"]
