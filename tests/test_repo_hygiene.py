"""The repository's own security posture, pinned by tests.

Workflows, the container build and the compose stack are code that a careless
edit can weaken without a single test failing: an action referenced by a tag
that someone can move, a job that inherits a write token, a checkout that keeps
credentials on disk, a base image that floats, a port published to every
interface.  These tests read the files themselves and fail when that happens.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Any

import pytest
import yaml

from ironflow.core.extras import EXTRAS, install_hint

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
DOCKERFILE = ROOT / "docker" / "Dockerfile"
COMPOSE = ROOT / "docker" / "docker-compose.yml"
SHA = re.compile(r"[0-9a-f]{40}")


def load(path: Path) -> dict[str, Any]:
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return document


def steps(workflow: Path) -> list[dict[str, Any]]:
    return [step for job in load(workflow)["jobs"].values() for step in job.get("steps", [])]


def test_the_workflows_are_found():
    assert {path.name for path in WORKFLOWS} >= {
        "ci.yml",
        "codeql.yml",
        "release.yml",
        "scorecard.yml",
        "security.yml",
    }


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda path: path.name)
class TestWorkflows:
    def test_every_action_is_pinned_to_a_commit(self, workflow):
        """A tag is a pointer its owner can move - which is how 76 of Trivy's 77
        action tags came to point at a credential stealer in March 2026."""
        for step in steps(workflow):
            if "uses" not in step:
                continue
            action, _, ref = str(step["uses"]).partition("@")
            assert SHA.fullmatch(ref), f"{workflow.name}: {action} is not pinned to a commit"

    def test_the_default_token_is_read_only(self, workflow):
        assert load(workflow).get("permissions") == {"contents": "read"}

    def test_no_checkout_keeps_the_token_on_disk(self, workflow):
        for step in steps(workflow):
            if str(step.get("uses", "")).startswith("actions/checkout@"):
                assert (step.get("with") or {}).get("persist-credentials") is False

    def test_every_job_has_a_timeout(self, workflow):
        for name, job in load(workflow)["jobs"].items():
            assert "timeout-minutes" in job, f"{workflow.name}: job {name!r} has no timeout"

    def test_no_event_data_is_interpolated_into_a_script(self, workflow):
        """``${{ github.event.* }}`` inside ``run:`` is a script-injection sink."""
        for step in steps(workflow):
            script = str(step.get("run", ""))
            assert "github.event." not in script
            assert "github.head_ref" not in script

    def test_no_workflow_runs_untrusted_code_with_secrets(self, workflow):
        assert "pull_request_target" not in workflow.read_text(encoding="utf-8")


class TestSecurityWorkflow:
    def test_the_dependency_audit_can_fail_the_build(self):
        """It ran with continue-on-error, failed on every run, and reported a pass."""
        security = load(ROOT / ".github" / "workflows" / "security.yml")
        for job in security["jobs"].values():
            assert "continue-on-error" not in job
            for step in job.get("steps", []):
                assert "continue-on-error" not in step

    def test_gitleaks_is_verified_before_it_runs(self):
        text = (ROOT / ".github" / "workflows" / "security.yml").read_text(encoding="utf-8")
        assert "sha256sum --check --strict" in text
        assert "fetch-depth: 0" in text


class TestContainer:
    def test_every_base_image_is_pinned_by_digest(self):
        stages = [
            line
            for line in DOCKERFILE.read_text(encoding="utf-8").splitlines()
            if line.startswith("FROM ")
        ]
        assert len(stages) == 2
        for line in stages:
            assert re.search(r"@sha256:[0-9a-f]{64}\b", line), line

    def test_the_runtime_stage_is_unprivileged_and_minimal(self):
        stage = DOCKERFILE.read_text(encoding="utf-8").split(" AS runtime", 1)[1]
        runtime = "\n".join(
            line for line in stage.splitlines() if not line.lstrip().startswith("#")
        )
        assert "\nUSER ironflow" in runtime
        assert "build-essential" not in runtime
        assert "curl" not in runtime
        assert "pip uninstall --yes pip" in runtime

    def test_the_build_context_is_an_allow_list(self):
        lines = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
        rules = [line.strip() for line in lines if line.strip() and not line.startswith("#")]
        assert rules[0] == "*"

    def test_the_image_installs_only_hash_locked_packages(self):
        """Third-party code enters only from a hash-locked file; the project resolves nothing."""
        text = DOCKERFILE.read_text(encoding="utf-8")
        installs = re.findall(r"pip install ([^\\\n]+)", text)
        assert len(installs) == 3, installs
        for args in installs:
            assert "--no-deps" in args, args
            locked = "--require-hashes" in args and " -r requirements/" in args
            project = "--no-build-isolation" in args and args.rstrip().endswith(" .")
            assert locked or project, args
        assert "--upgrade pip" not in text

    def test_the_build_context_admits_the_locks_the_image_copies(self):
        rules = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
        copied = re.findall(r"requirements/[\w.-]+\.txt", DOCKERFILE.read_text(encoding="utf-8"))
        assert copied
        for path in set(copied):
            assert f"!{path}" in rules, path


class TestCompose:
    @pytest.fixture
    def services(self) -> dict[str, Any]:
        return load(COMPOSE)["services"]

    def test_nothing_is_published_beyond_loopback(self, services):
        for service in services.values():
            for port in service.get("ports", []):
                assert str(port).startswith("127.0.0.1:"), port

    def test_there_is_no_default_database_password(self):
        text = COMPOSE.read_text(encoding="utf-8")
        assert "POSTGRES_PASSWORD:-" not in text
        assert "POSTGRES_PASSWORD:?" in text

    def test_ironflow_containers_are_hardened(self):
        common = load(COMPOSE)["x-ironflow-common"]
        assert common["read_only"] is True
        assert common["cap_drop"] == ["ALL"]
        assert "no-new-privileges:true" in common["security_opt"]


class TestInstallAdvice:
    """IronFlow is not on PyPI, and the ``ironflow`` package there is another project.

    Error messages and guides said ``pip install 'ironflow[api]'``: run where
    IronFlow was not installed yet, that installs the other project's code.
    """

    BARE_NAME = re.compile(r"pip install\s+['\"]?ironflow(?![-\w.])")

    def test_nothing_advises_installing_ironflow_by_name(self):
        files = [*ROOT.glob("*.md"), *(ROOT / "docs").glob("*.md"), *(ROOT / "src").rglob("*.py")]
        offenders = [
            f"{path.relative_to(ROOT)}:{number}"
            for path in files
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
            if self.BARE_NAME.search(line)
        ]
        assert offenders == []

    def test_the_advice_names_what_each_extra_installs(self):
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
        declared = {
            name: tuple(requirements)
            for name, requirements in project["optional-dependencies"].items()
            if name not in {"dev", "all"}
        }
        assert declared == EXTRAS

    def test_a_missing_extra_is_named_by_its_packages(self):
        assert install_hint("api") == "pip install 'fastapi>=0.111' 'uvicorn[standard]>=0.29'"


@pytest.mark.parametrize(
    "lock", sorted((ROOT / "requirements").glob("*.txt")), ids=lambda path: path.name
)
def test_every_locked_requirement_is_pinned_with_hashes(lock: Path):
    """`pip install --require-hashes` refuses a lock with a loose or unhashed line."""
    requirements: list[tuple[str, int]] = []
    for line in lock.read_text(encoding="utf-8").splitlines():
        if re.match(r"[A-Za-z0-9]", line):
            requirements.append((line, 0))
        elif "--hash=sha256:" in line and requirements:
            name, hashes = requirements[-1]
            requirements[-1] = (name, hashes + 1)
    assert requirements, lock.name
    for requirement, hashes in requirements:
        pinned = re.match(r"[A-Za-z0-9][A-Za-z0-9._-]*(\[[^\]]+\])?==[^\s;]+", requirement)
        assert pinned, requirement
        assert hashes, requirement


def test_the_locks_cover_what_the_image_and_the_audit_install():
    names = {path.name for path in (ROOT / "requirements").glob("*.txt")}
    assert {"build.txt", "runtime.txt", "audit.txt", "tools.txt"} <= names


def test_dependabot_limits_routine_pip_updates_to_the_toolchain():
    """Security updates are unaffected; routine floor bumps are not wanted."""
    config = load(ROOT / ".github" / "dependabot.yml")
    pip = next(update for update in config["updates"] if update["package-ecosystem"] == "pip")
    assert pip["allow"]
