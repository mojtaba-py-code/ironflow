"""Tests for pipeline specifications, the loader and application settings."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError as PydanticValidationError

from ironflow.config.loader import (
    PipelineRepository,
    deep_merge,
    interpolate,
    load_document,
    load_pipeline,
)
from ironflow.config.models import PipelineSpec, RetrySpec, ScheduleSpec, validate_cron
from ironflow.config.settings import Settings
from ironflow.core.errors import ConfigurationError

MINIMAL = {
    "name": "demo",
    "tasks": [
        {
            "name": "t1",
            "source": {"type": "csv", "path": "in.csv"},
            "destination": {"type": "csv", "path": "out.csv"},
        }
    ],
}


def write(path: Path, document: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    return path


class TestPipelineSpec:
    def test_minimal_pipeline_validates(self):
        spec = PipelineSpec.model_validate(MINIMAL)
        assert spec.name == "demo"
        assert spec.tasks[0].source.type == "csv"

    def test_connector_type_is_normalised(self):
        spec = PipelineSpec.model_validate(
            {**MINIMAL, "tasks": [{**MINIMAL["tasks"][0], "source": {"type": " CSV-File "}}]}
        )
        assert spec.tasks[0].source.type == "csv_file"

    def test_extra_connector_options_are_preserved(self):
        spec = PipelineSpec.model_validate(MINIMAL)
        assert spec.tasks[0].source.options["path"] == "in.csv"

    def test_unknown_top_level_key_is_rejected(self):
        """A silently ignored typo is worse than a load-time failure."""
        with pytest.raises(PydanticValidationError, match=r"[Ee]xtra"):
            PipelineSpec.model_validate({**MINIMAL, "retires": 3})

    @pytest.mark.parametrize("name", ["1bad", "has space", "", "a" * 65, "-leading"])
    def test_invalid_names_are_rejected(self, name):
        with pytest.raises(PydanticValidationError):
            PipelineSpec.model_validate({**MINIMAL, "name": name})

    def test_etl_tasks_require_source_and_destination(self):
        with pytest.raises(Exception, match="require a 'source'"):
            PipelineSpec.model_validate({"name": "d", "tasks": [{"name": "t"}]})

    def test_sql_tasks_require_a_statement(self):
        with pytest.raises(Exception, match="require a 'sql'"):
            PipelineSpec.model_validate({"name": "d", "tasks": [{"name": "t", "type": "sql"}]})

    def test_incremental_strategy_requires_a_watermark_block(self):
        task = {**MINIMAL["tasks"][0], "strategy": "incremental"}
        with pytest.raises(Exception, match="requires an 'incremental' block"):
            PipelineSpec.model_validate({**MINIMAL, "tasks": [task]})

    def test_self_dependency_is_rejected(self):
        task = {**MINIMAL["tasks"][0], "depends_on": ["t1"]}
        with pytest.raises(Exception, match="cannot depend on itself"):
            PipelineSpec.model_validate({**MINIMAL, "tasks": [task]})

    def test_duplicate_task_names_are_rejected(self):
        with pytest.raises(Exception, match="duplicate task names"):
            PipelineSpec.model_validate(
                {**MINIMAL, "tasks": [MINIMAL["tasks"][0], MINIMAL["tasks"][0]]}
            )

    def test_unknown_dependency_is_rejected(self):
        task = {**MINIMAL["tasks"][0], "depends_on": ["ghost"]}
        with pytest.raises(Exception, match="unknown task"):
            PipelineSpec.model_validate({**MINIMAL, "tasks": [task]})

    def test_defaults_propagate_to_tasks(self):
        spec = PipelineSpec.model_validate(
            {**MINIMAL, "defaults": {"batch_size": 500, "retry": {"max_attempts": 5}}}
        ).with_defaults_applied()
        assert spec.tasks[0].batch_size == 500
        assert spec.tasks[0].retry.max_attempts == 5

    def test_task_level_settings_win_over_defaults(self):
        task = {**MINIMAL["tasks"][0], "batch_size": 10}
        spec = PipelineSpec.model_validate(
            {**MINIMAL, "tasks": [task], "defaults": {"batch_size": 500}}
        ).with_defaults_applied()
        assert spec.tasks[0].batch_size == 10

    def test_retry_bounds(self):
        with pytest.raises(PydanticValidationError):
            RetrySpec(max_attempts=0)
        with pytest.raises(PydanticValidationError, match="max_delay"):
            RetrySpec(initial_delay=10, max_delay=1)

    def test_json_schema_is_generated(self):
        schema = PipelineSpec.json_schema()
        assert "properties" in schema
        assert "tasks" in schema["properties"]


class TestSchedule:
    @pytest.mark.parametrize(
        "cron", ["0 2 * * *", "*/15 * * * *", "0 0 1 * *", "30 8 * * 1-5", "0 0,12 * * *"]
    )
    def test_valid_cron(self, cron):
        assert validate_cron(cron)

    @pytest.mark.parametrize("cron", ["0 2 * *", "bad", "* * * * * *", "@daily"])
    def test_invalid_cron(self, cron):
        with pytest.raises(ValueError):
            validate_cron(cron)

    def test_exactly_one_of_cron_or_interval(self):
        with pytest.raises(Exception, match="exactly one"):
            ScheduleSpec(cron="0 2 * * *", interval_seconds=60)
        with pytest.raises(Exception, match="exactly one"):
            ScheduleSpec()
        assert ScheduleSpec(cron="0 2 * * *").cron
        assert ScheduleSpec(interval_seconds=60).interval_seconds


class TestLoader:
    def test_load_yaml_and_json(self, tmp_path: Path):
        yaml_file = write(tmp_path / "p.yaml", MINIMAL)
        json_file = tmp_path / "p.json"
        json_file.write_text('{"name": "demo", "tasks": []}', encoding="utf-8")
        assert load_document(yaml_file)["name"] == "demo"
        assert load_document(json_file)["name"] == "demo"

    def test_unsupported_format_is_rejected(self, tmp_path: Path):
        bad = tmp_path / "p.txt"
        bad.write_text("name: demo", encoding="utf-8")
        with pytest.raises(ConfigurationError, match="unsupported configuration format"):
            load_document(bad)

    def test_malformed_yaml_reports_the_file(self, tmp_path: Path):
        bad = tmp_path / "p.yaml"
        bad.write_text("name: [unclosed", encoding="utf-8")
        with pytest.raises(ConfigurationError, match="not valid YAML"):
            load_document(bad)

    def test_on_off_yes_no_stay_strings(self, tmp_path: Path):
        """YAML 1.1 turns these six words into booleans; YAML 1.2 does not.

        ``on:`` is the notification trigger key, and ``NO`` is Norway's ISO-3166
        code - coercing either is a correctness bug, not a curiosity.
        """
        path = tmp_path / "p.yaml"
        path.write_text(
            "on: [failed]\n"
            "countries: [NO, SE, NL]\n"
            "flags: {yes_word: yes, off_word: off}\n"
            "real_bools: {t: true, f: false}\n",
            encoding="utf-8",
        )
        document = load_document(path)
        assert "on" in document, "the key must stay the string 'on'"
        assert document["countries"] == ["NO", "SE", "NL"], "NO is Norway, not False"
        assert document["flags"] == {"yes_word": "yes", "off_word": "off"}
        assert document["real_bools"] == {"t": True, "f": False}

    def test_notification_on_key_survives_a_round_trip(self, tmp_path: Path):
        """Regression: `on: [failed]` parsed as `True: [failed]` and failed."""
        document = {
            **MINIMAL,
            "notifications": [{"type": "console", "on": ["failed", "partial"]}],
        }
        path = tmp_path / "p.yaml"
        path.write_text(
            "name: demo\n"
            "tasks:\n"
            "  - name: t1\n"
            "    source: {type: csv, path: in.csv}\n"
            "    destination: {type: csv, path: out.csv}\n"
            "notifications:\n"
            "  - type: console\n"
            "    on: [failed, partial]\n",
            encoding="utf-8",
        )
        spec = load_pipeline(path)
        assert spec.notifications[0].on == ["failed", "partial"]
        del document

    def test_yaml_cannot_construct_python_objects(self, tmp_path: Path):
        """safe_load, not load: a crafted tag must not become code execution."""
        bad = tmp_path / "p.yaml"
        bad.write_text("name: !!python/object/apply:os.system ['echo pwned']\n", encoding="utf-8")
        with pytest.raises(ConfigurationError):
            load_document(bad)

    def test_deep_merge_replaces_lists_and_merges_mappings(self):
        base = {"a": {"x": 1, "y": 2}, "list": [1, 2]}
        overlay = {"a": {"y": 3, "z": 4}, "list": [9]}
        merged = deep_merge(base, overlay)
        assert merged["a"] == {"x": 1, "y": 3, "z": 4}
        assert merged["list"] == [9], "replacing lets a profile remove entries"

    def test_profile_overlay(self, tmp_path: Path):
        document = {
            **MINIMAL,
            "defaults": {"batch_size": 100},
            "profiles": {"production": {"defaults": {"batch_size": 50000}}},
        }
        path = write(tmp_path / "p.yaml", document)
        assert load_pipeline(path).defaults["batch_size"] == 100
        assert load_pipeline(path, profile="production").defaults["batch_size"] == 50000

    def test_unknown_profile_lists_the_available_ones(self, tmp_path: Path):
        path = write(tmp_path / "p.yaml", {**MINIMAL, "profiles": {"prod": {}}})
        with pytest.raises(ConfigurationError) as info:
            load_pipeline(path, profile="staging")
        assert "prod" in info.value.context["available"]

    def test_includes_are_merged(self, tmp_path: Path):
        write(tmp_path / "_common.yaml", {"defaults": {"batch_size": 777}, "owner": "shared"})
        path = write(tmp_path / "p.yaml", {**MINIMAL, "include": ["_common.yaml"]})
        spec = load_pipeline(path)
        assert spec.defaults["batch_size"] == 777
        assert spec.owner == "shared"

    def test_including_pipeline_wins_over_the_fragment(self, tmp_path: Path):
        write(tmp_path / "_common.yaml", {"owner": "shared"})
        path = write(tmp_path / "p.yaml", {**MINIMAL, "include": ["_common.yaml"], "owner": "mine"})
        assert load_pipeline(path).owner == "mine"

    def test_circular_includes_terminate(self, tmp_path: Path):
        write(tmp_path / "_a.yaml", {"include": ["_b.yaml"]})
        write(tmp_path / "_b.yaml", {"include": ["_a.yaml"]})
        path = write(tmp_path / "p.yaml", {**MINIMAL, "include": ["_a.yaml"]})
        with pytest.raises(ConfigurationError, match="include depth"):
            load_pipeline(path)


class TestInterpolation:
    def test_env_and_variable_substitution(self, monkeypatch):
        monkeypatch.setenv("REGION", "eu-west-1")
        result = interpolate(
            {"a": "${REGION}", "b": "${var.name}", "c": "prefix-${REGION}-suffix"},
            {"name": "sales"},
        )
        assert result == {"a": "eu-west-1", "b": "sales", "c": "prefix-eu-west-1-suffix"}

    def test_whole_string_reference_preserves_type(self):
        assert interpolate("${size}", {"size": 500}) == 500
        assert isinstance(interpolate("${size}", {"size": 500}), int)

    def test_embedded_reference_stringifies(self):
        assert interpolate("n=${size}", {"size": 500}) == "n=500"

    def test_default_value_syntax(self, monkeypatch):
        monkeypatch.delenv("MISSING_VAR", raising=False)
        assert interpolate("${MISSING_VAR:-fallback}", {}) == "fallback"

    def test_unresolved_variable_fails_loudly(self, monkeypatch):
        monkeypatch.delenv("ABSENT", raising=False)
        with pytest.raises(ConfigurationError, match="unresolved variable"):
            interpolate({"path": "/data/${ABSENT}/out.csv"}, {})

    def test_unresolved_reports_its_location(self, monkeypatch):
        monkeypatch.delenv("ABSENT", raising=False)
        with pytest.raises(ConfigurationError) as info:
            interpolate({"tasks": [{"path": "${ABSENT}"}]}, {})
        assert "tasks" in info.value.context["location"]

    def test_non_strict_mode_leaves_the_reference(self, monkeypatch):
        monkeypatch.delenv("ABSENT", raising=False)
        assert interpolate("${ABSENT}", {}, strict=False) == "${ABSENT}"

    def test_pipeline_variables_are_applied(self, tmp_path: Path):
        document = {
            **MINIMAL,
            "variables": {"dir": "/data"},
            "tasks": [
                {
                    "name": "t1",
                    "source": {"type": "csv", "path": "${var.dir}/in.csv"},
                    "destination": {"type": "csv", "path": "${var.dir}/out.csv"},
                }
            ],
        }
        spec = load_pipeline(write(tmp_path / "p.yaml", document))
        assert spec.tasks[0].source.options["path"] == "/data/in.csv"

    def test_cli_variables_override_file_variables(self, tmp_path: Path):
        document = {
            **MINIMAL,
            "variables": {"dir": "/data"},
            "tasks": [
                {
                    "name": "t1",
                    "source": {"type": "csv", "path": "${var.dir}/in.csv"},
                    "destination": {"type": "csv", "path": "out.csv"},
                }
            ],
        }
        spec = load_pipeline(write(tmp_path / "p.yaml", document), variables={"dir": "/override"})
        assert spec.tasks[0].source.options["path"] == "/override/in.csv"

    def test_dotted_overrides_expand(self, tmp_path: Path):
        path = write(tmp_path / "p.yaml", {**MINIMAL, "defaults": {"batch_size": 10}})
        spec = load_pipeline(path, overrides={"defaults.batch_size": 999})
        assert spec.defaults["batch_size"] == 999


class TestPipelineRepository:
    def test_discovery_ignores_underscore_fragments(self, tmp_path: Path):
        write(tmp_path / "a.yaml", MINIMAL)
        write(tmp_path / "_fragment.yaml", {"defaults": {}})
        repository = PipelineRepository(tmp_path)
        assert [p.name for p in repository.discover()] == ["a.yaml"]

    def test_get_by_declared_name(self, tmp_path: Path):
        write(tmp_path / "whatever.yaml", {**MINIMAL, "name": "actual_name"})
        assert PipelineRepository(tmp_path).get("actual_name").name == "actual_name"

    def test_missing_pipeline_is_reported(self, tmp_path: Path):
        with pytest.raises(ConfigurationError, match="no pipeline named"):
            PipelineRepository(tmp_path).get("ghost")

    def test_invalid_pipelines_are_skipped_by_load_all(self, tmp_path: Path, caplog):
        write(tmp_path / "good.yaml", MINIMAL)
        (tmp_path / "bad.yaml").write_text("name: [broken", encoding="utf-8")
        with caplog.at_level("ERROR"):
            specs = PipelineRepository(tmp_path).load_all()
        assert [s.name for s in specs] == ["demo"]
        assert "bad.yaml" in caplog.text

    def test_a_typo_reports_the_typo_not_a_missing_pipeline(self, tmp_path: Path):
        """One bad key used to surface as "no pipeline named 'demo' was found".

        That sends an operator looking for a file that is sitting right there,
        and the CLI then suggests `config init`, which would scaffold over it.
        """
        write(tmp_path / "demo.yaml", {**MINIMAL, "versionn": "1"})
        with pytest.raises(ConfigurationError, match="failed validation") as caught:
            PipelineRepository(tmp_path).get("demo")
        assert "versionn" in str(caught.value)

    def test_an_absent_pipeline_still_says_not_found_but_names_what_would_not_load(
        self, tmp_path: Path
    ):
        write(tmp_path / "broken.yaml", {**MINIMAL, "versionn": "1"})
        with pytest.raises(ConfigurationError, match="no pipeline named") as caught:
            PipelineRepository(tmp_path).get("ghost")
        assert "broken.yaml" in str(caught.value)

    def test_a_valid_neighbour_is_still_found_when_another_file_is_broken(self, tmp_path: Path):
        write(tmp_path / "good.yaml", MINIMAL)
        (tmp_path / "bad.yaml").write_text("name: [broken", encoding="utf-8")
        assert PipelineRepository(tmp_path).get("demo").name == "demo"

    def test_relative_directory_does_not_double_join(self, tmp_path: Path, monkeypatch):
        """Regression: discover() returning relative paths broke load()."""
        monkeypatch.chdir(tmp_path)
        write(tmp_path / "pipelines" / "a.yaml", MINIMAL)
        repository = PipelineRepository(Path("pipelines"))
        assert repository.get("demo").name == "demo"

    def test_cache_is_invalidated_by_mtime(self, tmp_path: Path):
        import os
        import time

        path = write(tmp_path / "a.yaml", MINIMAL)
        repository = PipelineRepository(tmp_path)
        assert repository.load(path).owner == ""
        time.sleep(0.01)
        write(tmp_path / "a.yaml", {**MINIMAL, "owner": "new-owner"})
        os.utime(path, (path.stat().st_atime, path.stat().st_mtime + 10))
        assert repository.load(path).owner == "new-owner"


class TestSettings:
    def test_defaults(self):
        settings = Settings()
        assert settings.environment == "local"
        assert settings.http_verify_tls is True
        assert settings.state_database_url.startswith("sqlite:///")

    def test_env_prefix(self, monkeypatch):
        monkeypatch.setenv("IRONFLOW_LOG_LEVEL", "debug")
        monkeypatch.setenv("IRONFLOW_MAX_PARALLEL_TASKS", "16")
        settings = Settings()
        assert settings.log_level == "DEBUG"
        assert settings.max_parallel_tasks == 16

    def test_comma_separated_lists_from_env(self, monkeypatch):
        """Regression: pydantic-settings JSON-decodes complex types by default."""
        monkeypatch.setenv("IRONFLOW_DATA_ROOTS", "/data/a,/data/b")
        assert len(Settings().data_roots) == 2

    def test_json_list_from_env_also_works(self, monkeypatch):
        monkeypatch.setenv("IRONFLOW_API_CORS_ORIGINS", '["https://a.com"]')
        assert Settings().api_cors_origins == ["https://a.com"]

    def test_invalid_log_level_is_rejected(self):
        with pytest.raises(Exception, match="log_level"):
            Settings(log_level="CHATTY")

    def test_production_hardening_reports_every_problem(self):
        problems = Settings(environment="production").validate_production_hardening()
        joined = " ".join(problems)
        assert "auth_enabled" in joined
        assert "encryption_key" in joined
        assert "data_roots" in joined
        assert "SQLite" in joined or "sqlite" in joined

    def test_hardened_production_config_passes(self, tmp_path: Path):
        settings = Settings(
            environment="production",
            auth_enabled=True,
            jwt_secret="x" * 40,
            encryption_key="k" * 44,
            allow_literal_secrets=False,
            allow_private_network=False,
            data_roots=[tmp_path],
            state_database_url="postgresql+psycopg://u@h/db",
            audit_enabled=True,
        )
        assert settings.validate_production_hardening() == []

    def test_local_environment_is_not_hardened(self):
        assert Settings(environment="local").validate_production_hardening() == []

    @pytest.mark.parametrize("environment", ["local", "development", "staging", "production"])
    def test_auth_without_a_signing_secret_is_refused_in_every_environment(self, environment: str):
        """Auth on with no key accepts tokens the attacker signs themselves.

        The check used to run only under ``production``, so a staging deployment
        - which normally holds a copy of production data - would happily verify
        an ``admin`` token signed with the empty string.
        """
        with pytest.raises(PydanticValidationError, match="jwt_secret"):
            Settings(environment=environment, auth_enabled=True, jwt_secret="")

    def test_a_short_signing_secret_is_refused(self):
        with pytest.raises(PydanticValidationError, match="jwt_secret"):
            Settings(environment="local", auth_enabled=True, jwt_secret="too-short")

    def test_a_strong_signing_secret_is_accepted(self):
        settings = Settings(environment="local", auth_enabled=True, jwt_secret="s" * 32)
        assert settings.auth_enabled

    def test_auth_disabled_does_not_require_a_secret(self):
        assert Settings(environment="local", auth_enabled=False).jwt_secret == ""

    def test_redacted_hides_secrets(self):
        settings = Settings(jwt_secret="super-secret", encryption_key="key-material")
        dumped = settings.redacted()
        assert "super-secret" not in str(dumped)
        assert "key-material" not in str(dumped)
