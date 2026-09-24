"""Credentials inside URLs must never reach a log line, an error or ``config show``.

``redact_url`` used to be a single regex that stopped the password at the first
``/`` and never looked at the query string. A base64 password - which routinely
contains ``/`` - came back verbatim from ``config show``, ``config check`` and
the state-database error context, and ``?password=`` was ignored altogether.
"""

from __future__ import annotations

import json
import logging
import sys

import pytest
from typer.testing import CliRunner

from ironflow.cli.main import app
from ironflow.cli.main import main as console_entry_point
from ironflow.config.settings import reset_settings
from ironflow.observability.logging import RedactionFilter
from ironflow.security.masking import redact_url

#: The password from the original proof of concept: base64, so it carries "/",
#: "+" and "=" - every character the old pattern tripped over.  Assembled at
#: import rather than written out: gitleaks reads the whole history, and a
#: credential-shaped literal would be flagged there for good.
BASE64_PASSWORD = "/".join(("Qm9vS2Vl", "cGVy+ZmFrZQ=="))


class TestUserinfoPassword:
    @pytest.mark.parametrize(
        "password",
        [
            BASE64_PASSWORD,
            "p@ss@word",  # "@" - SQLAlchemy's make_url stops at the first one
            "pa:ss",
            "what?no#really",  # "?" and "#" - urlsplit starts the query / fragment
            "a/b@c/d",  # "/" and "@" together, the case every simple parser splits
        ],
    )
    def test_the_whole_password_is_masked_and_the_rest_stays_readable(self, password):
        redacted = redact_url(f"postgresql+psycopg://etl:{password}@db.internal:5432/prod")
        assert redacted == "postgresql+psycopg://etl:***@db.internal:5432/prod"

    def test_every_fragment_of_the_password_is_gone(self):
        redacted = redact_url(f"postgresql://etl:{BASE64_PASSWORD}@db:5432/prod")
        for fragment in BASE64_PASSWORD.split("/"):
            assert fragment not in redacted

    def test_a_password_without_a_user_is_masked(self):
        """``redis://:secret@host`` - the old pattern required a username."""
        assert redact_url("redis://:s3cret-value@cache:6379/0") == "redis://:***@cache:6379/0"

    def test_a_username_containing_at_keeps_its_host(self):
        """Azure-style ``user@server`` usernames must not swallow the password."""
        redacted = redact_url("postgresql://etl@srv:s3cret@srv.postgres.example:5432/db")
        assert redacted == "postgresql://etl@srv:***@srv.postgres.example:5432/db"

    def test_an_empty_password_is_not_disguised_as_a_set_one(self):
        """``***`` for an unset password would send an operator down the wrong path."""
        assert redact_url("postgresql://etl:@db/prod") == "postgresql://etl:@db/prod"

    @pytest.mark.parametrize(
        "url",
        [
            "sqlite:///C:/Users/me/.ironflow/state.db",
            "sqlite:////var/lib/ironflow/state.db",
            "sqlite:///:memory:",
            "https://api.example.com:8443/v1/items?page=2&sort=asc",
            "postgresql://etl@db.internal/prod?sslmode=require",
            "file:///srv/data/a:b@c.csv",
            "http://[::1]:8080/health",
        ],
    )
    def test_urls_without_credentials_are_unchanged(self, url):
        assert redact_url(url) == url


class TestQueryCredentials:
    @pytest.mark.parametrize(
        "name",
        [
            "password",
            "pwd",
            "PWD",
            "passwd",
            "secret",
            "client_secret",
            "token",
            "access_token",
            "api_key",
            "apikey",
            "key",
            "sslpassword",
            "sig",
            "X-Amz-Signature",
            "X-Amz-Security-Token",
            "pass%77ord",  # percent-encoded name
        ],
    )
    def test_credential_parameters_are_masked(self, name):
        redacted = redact_url(f"postgresql://db.internal/prod?sslmode=require&{name}=s3cr3t-v4lue")
        assert "s3cr3t-v4lue" not in redacted
        assert redacted == f"postgresql://db.internal/prod?sslmode=require&{name}=***"

    def test_ordinary_parameters_stay_visible(self):
        url = "postgresql://db/prod?sslmode=verify-full&application_name=ironflow&connect_timeout=5"
        assert redact_url(url) == url

    def test_a_value_runs_to_the_next_ampersand(self):
        redacted = redact_url("https://api.example.com/v1?token=ab;cd#ef&page=2")
        assert redacted == "https://api.example.com/v1?token=***&page=2"

    def test_semicolon_separated_parameters_are_each_considered(self):
        redacted = redact_url("sqlserver://db.internal:1433;user=etl;password=s3cr3t-v4lue")
        assert "s3cr3t-v4lue" not in redacted
        assert redacted.startswith("sqlserver://db.internal:1433;user=etl;password=")

    def test_userinfo_and_query_credentials_together(self):
        redacted = redact_url(
            "postgresql://etl:pw1-secret@db/prod?password=pw2-secret&sslmode=require"
        )
        assert redacted == "postgresql://etl:***@db/prod?password=***&sslmode=require"


class TestUrlsInsideText:
    def test_a_url_in_a_log_line(self):
        line = f"connecting to postgresql://etl:{BASE64_PASSWORD}@db:5432/prod for task load"
        assert redact_url(line) == "connecting to postgresql://etl:***@db:5432/prod for task load"

    def test_a_url_in_an_error_context_repr(self):
        text = f"unable to connect (url='mysql://etl:{BASE64_PASSWORD}@db/prod', attempt=3)"
        redacted = redact_url(text)
        assert BASE64_PASSWORD not in redacted
        assert "db/prod" in redacted and "attempt=3" in redacted

    def test_several_urls_in_one_message(self):
        text = "primary postgresql://a:one-secret@h1/db replica postgresql://b:two-secret@h2/db"
        assert (
            redact_url(text) == "primary postgresql://a:***@h1/db replica postgresql://b:***@h2/db"
        )

    def test_the_log_filter_masks_a_base64_password_passed_as_an_argument(self):
        dsn = f"postgresql://etl:{BASE64_PASSWORD}@db/prod"
        record = logging.LogRecord("t", logging.INFO, "f.py", 1, "engine for %s", (dsn,), None)
        RedactionFilter().filter(record)
        assert BASE64_PASSWORD.split("/")[1] not in record.getMessage()
        assert "postgresql://etl:***@db/prod" in record.getMessage()


class TestMalformedInput:
    @pytest.mark.parametrize(
        "text",
        [
            "postgresql://etl:pw-secret@[::1",  # broken IPv6 literal: urlsplit raises
            "http://[",
            "://",
            "a://",
            "postgresql://etl:pw-secret@",
            "x://:@",
            "",
            "no url here at all",
        ],
    )
    def test_never_raises_and_never_leaks(self, text):
        redacted = redact_url(text)
        assert "pw-secret" not in redacted

    def test_ambiguous_text_is_masked_more_not_less(self):
        """An "@" in the query could end the userinfo; mask as if it did."""
        redacted = redact_url("postgresql://etl:pw-secret@db/prod?password=p@ss-secret")
        assert "pw-secret" not in redacted
        assert "ss-secret" not in redacted


class TestOperatorFacingOutput:
    """The two places the proof of concept printed the password."""

    runner = CliRunner()

    def test_config_show_json_masks_the_state_database_password(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv(
            "IRONFLOW_STATE_DATABASE_URL",
            f"postgresql+psycopg://etl:{BASE64_PASSWORD}@db.internal:5432/ironflow",
        )
        reset_settings()
        result = self.runner.invoke(app, ["--json", "config", "show"], catch_exceptions=False)
        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["state_database_url"] == (
            "postgresql+psycopg://etl:***@db.internal:5432/ironflow"
        )
        assert "cGVy" not in result.stdout

    def test_the_engine_error_context_masks_the_password(self, tmp_path, monkeypatch, capsys):
        """``config check`` reaches the database first; a bad driver fails there.

        The failure is raised while the service is built, so it surfaces through
        the console entry point with the URL from the error context in it.
        """
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv(
            "IRONFLOW_STATE_DATABASE_URL",
            f"postgresql+nosuchdriver://etl:{BASE64_PASSWORD}@db.internal:5432/ironflow",
        )
        monkeypatch.setattr(sys, "argv", ["ironflow", "config", "check"])
        reset_settings()
        assert console_entry_point() != 0
        stderr = capsys.readouterr().err
        assert "cGVy" not in stderr and "Qm9v" not in stderr
        assert "etl:***@db.internal:5432/ironflow" in stderr
