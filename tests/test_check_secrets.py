"""The committed-secret scanner must catch the cases it exists for.

It missed the very accident it was written for - an unquoted YAML
``password:`` - skipped ``.github`` altogether, and knew nothing of fine-grained
GitHub tokens, Slack tokens, AWS secret keys, JWTs, encrypted and PGP private
keys, or files such as ``*.pem`` and ``.env.*``.

Every fake credential here is assembled at run time, so this file never holds
one literally: the scanner allow-lists ``tests/``, but GitHub's push protection
and the ``detect-private-key`` pre-commit hook do not.
"""

from __future__ import annotations

import importlib.util
import re
import shutil
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPOSITORY = Path(__file__).resolve().parents[1]


def load_scanner() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "check_secrets", REPOSITORY / "scripts" / "check_secrets.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses resolve annotations through it
    spec.loader.exec_module(module)
    return module


scanner = load_scanner()


def join(*parts: str) -> str:
    return "".join(parts)


GITHUB_CLASSIC = join("gh", "p_", "A1b2C3d4" * 5)
GITHUB_FINE_GRAINED = join("github", "_pat_", "11ABCDEFG0" * 3, "_", "aBcDeFgHiJ" * 6)
SLACK_TOKEN = join("xo", "xb-", "123456789012-1234567890123-", "AbCdEfGhIjKlMnOpQrStUvWx")
SLACK_WEBHOOK = join("https://hooks.slack.com/services/", "T0000000/B0000000/", "a1B2" * 6)
AWS_KEY_ID = join("AK", "IA", "Q3EGRZ7N2VXL6PDA")
AWS_SECRET_KEY = join("aB3/", "cD4+" * 9)
JWT = join("eyJ", "hbGciOiJIUzI1NiJ9", ".", "eyJ", "zdWIiOiJhZG1pbiJ9", ".", "c2ln" * 6)
PASSWORD = join("Corr3ct", "HorseBattery", "Staple")
PRIVATE_KEY_HEADERS = [
    join("-----BEGIN ", kind, "PRIVATE KEY", suffix, "-----")
    for kind, suffix in [
        ("", ""),
        ("RSA ", ""),
        ("EC ", ""),
        ("OPENSSH ", ""),
        ("ENCRYPTED ", ""),
        ("PGP ", " BLOCK"),
    ]
]


def labels(text: str, *, code: bool = False) -> list[str]:
    return [finding.label for finding in scanner.find_secrets(text, code=code)]


class TestCredentialFormats:
    @pytest.mark.parametrize(
        ("line", "label"),
        [
            (f"echo {GITHUB_CLASSIC}", "GitHub token"),
            (f"GH={GITHUB_FINE_GRAINED}", "GitHub token"),
            (f"notify: {SLACK_TOKEN}", "Slack token"),
            (f"target: {SLACK_WEBHOOK}", "Slack webhook URL"),
            (f"aws_access_key_id = {AWS_KEY_ID}", "AWS access key id"),
            (f"aws_secret_access_key = {AWS_SECRET_KEY}", "AWS secret access key"),
            (f'"SecretAccessKey": "{AWS_SECRET_KEY}",', "AWS secret access key"),
            (f"Authorization: Bearer {JWT}", "JSON Web Token"),
            *[(header, "private key block") for header in PRIVATE_KEY_HEADERS],
        ],
    )
    def test_each_format_is_detected(self, line, label):
        assert labels(line) == [label]

    @pytest.mark.parametrize(
        "url",
        [
            join("postgresql://etl:", "Qm9vS2Vl/cGVy+ZmFrZQ==", "@db:5432/prod"),
            join("redis://:", "s3cr3t-v4lue", "@cache:6379/0"),
            join("amqp://etl:", "p@ss-w0rd", "@mq/vhost"),
            join("https://deploy:", GITHUB_CLASSIC, "@github.com/org/repo.git"),
        ],
    )
    def test_a_password_inside_a_url_is_detected(self, url):
        assert labels(f"dsn: {url}")[0] in ("URL with an inline password", "GitHub token")


class TestAssignedLiterals:
    @pytest.mark.parametrize(
        "line",
        [
            f"password: {PASSWORD}",  # the case the scanner was written for
            f'password: "{PASSWORD}"',
            f"  db_password: {PASSWORD}  # temporary",
            f"IRONFLOW_JWT_SECRET={PASSWORD}{PASSWORD}",
            f"export DB_PASSWORD={PASSWORD}",
            f'"client_secret": "{PASSWORD}",',
            f"api-key = {PASSWORD}",
            f"{{password: {PASSWORD}, user: etl}}",
        ],
    )
    def test_quoted_or_not_a_literal_is_flagged(self, line):
        assert labels(line) == ["assigned secret literal"]

    def test_in_code_only_a_quoted_literal_counts(self):
        assert labels(f'connect(password="{PASSWORD}")', code=True) == ["assigned secret literal"]
        assert labels("password = settings.db_password", code=True) == []
        assert labels("jwt_secret: str = ''", code=True) == []

    @pytest.mark.parametrize(
        "line",
        [
            "password: env:DB_PASSWORD",
            "password: file:/run/secrets/db_password",
            "password: enc:c2VjcmV0LWVudmVsb3Bl",
            "password: ironflow:v1:c2FsdA==:gAAAAABlZXhhbXBsZQ==",
            "password: ${DB_PASSWORD}",
            "token: ${{ secrets.GITHUB_TOKEN }}",
            "POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-local-dev-default}",
            'password: "***"',
            "password: ********",
            "password: <your-database-password>",
            "password: changeme",
            "password: CHANGE_ME_BEFORE_USE",
            "api_key: example-api-key-12345",
            "password:",
            'password: ""',
            "private_key: ~/.ssh/id_ed25519",
            "password_min_length: 12",
            'token: "a sentence, not a credential"',
            "dsn: postgresql://etl:${PGPASSWORD}@db/prod",
            "dsn: postgresql://etl:***@db/prod",
            f"password: {PASSWORD}  # {scanner.ALLOW_MARKER}",
        ],
    )
    def test_references_and_placeholders_are_not_secrets(self, line):
        assert labels(line) == []

    def test_the_report_does_not_republish_the_secret(self):
        (finding,) = scanner.find_secrets(f"password: {PASSWORD}")
        assert PASSWORD not in finding.snippet
        assert finding.snippet == "password: ***"


class TestFileNames:
    @pytest.mark.parametrize(
        "name",
        [".env", ".env.production", "server.pem", "CERT.PEM", "tls.key", "id_rsa", "store.jks"],
    )
    def test_key_material_is_flagged_by_name(self, name):
        assert scanner.sensitive_file_label(name) is not None

    @pytest.mark.parametrize("name", ["id_rsa.pub", ".envrc", "environment.yaml", "keys.py"])
    def test_ordinary_names_are_not(self, name):
        assert scanner.sensitive_file_label(name) is None


def git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)  # noqa: S603, S607


@pytest.fixture
def repo(tmp_path: Path, monkeypatch) -> Path:
    """An empty git repository as the working directory."""
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    git(tmp_path, "init", "-q")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def track(repo: Path, relative: str, content: str | bytes) -> Path:
    path = repo / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")
    git(repo, "add", "--", relative)
    return path


class TestScanningARepository:
    def test_a_secret_in_a_workflow_is_found(self, repo, capsys):
        track(repo, "README.md", "hello\n")
        track(repo, ".github/workflows/deploy.yml", f"env:\n  DEPLOY_TOKEN: {GITHUB_CLASSIC}\n")
        assert scanner.main([]) == 1
        assert ".github/workflows/deploy.yml:2: possible GitHub token" in capsys.readouterr().err

    def test_files_are_flagged_by_name_whatever_they_contain(self, repo, capsys):
        track(repo, "certs/server.pem", "not really a certificate\n")
        track(repo, "config/.env.production", "LOG_LEVEL=INFO\n")
        assert scanner.main([]) == 1
        err = capsys.readouterr().err
        assert "certs/server.pem: possible file that normally holds key material" in err
        assert "config/.env.production: possible" in err

    def test_fixtures_stay_possible_under_tests_only(self, repo, capsys):
        track(repo, "tests/test_login.py", f'PASSWORD = "{PASSWORD}"\n')
        track(repo, "src/app.py", "print('hello')\n")
        assert scanner.main([]) == 0
        track(repo, "src/settings.py", f'PASSWORD = "{PASSWORD}"\n')
        assert scanner.main([]) == 1
        assert "src/settings.py:1" in capsys.readouterr().err

    def test_the_env_template_is_scanned_though_its_name_is_allowed(self, repo):
        track(repo, ".env.example", "API_TOKEN=\nIRONFLOW_JWT_SECRET=\n")
        assert scanner.main([]) == 0
        track(repo, ".env.example", f"API_TOKEN=\nIRONFLOW_JWT_SECRET={PASSWORD}\n")
        assert scanner.main([]) == 1

    def test_the_ci_allowance_covers_only_its_one_value(self, repo):
        workflow = (
            "services:\n"
            "  postgres:\n"
            "    env:\n"
            "      POSTGRES_PASSWORD: ironflow\n"
            "env:\n"
            "  URL: postgresql+psycopg://ironflow:ironflow@localhost:5432/ironflow\n"
        )
        track(repo, ".github/workflows/ci.yml", workflow)
        assert scanner.main([]) == 0
        track(repo, ".github/workflows/ci.yml", workflow + f"  REGISTRY_PASSWORD: {PASSWORD}\n")
        assert scanner.main([]) == 1

    def test_a_binary_file_is_skipped(self, repo, capsys):
        track(repo, "README.md", "hello\n")
        track(repo, "data/blob.bin", b"\0\x01" + f"password: {PASSWORD}".encode())
        assert scanner.main([]) == 0
        assert "1 file(s) scanned, 1 allow-listed or binary" in capsys.readouterr().out

    def test_a_name_git_would_quote_is_still_scanned(self, repo):
        """Without -z, git prints such a name quoted - a path that does not exist."""
        track(repo, "configs/prod é.yml", f"password: {PASSWORD}\n")
        assert scanner.main([]) == 1

    def test_explicit_paths_are_scanned_as_given(self, repo):
        clean = track(repo, "clean.yml", "name: fine\n")
        dirty = track(repo, "dirty.yml", f"password: {PASSWORD}\n")
        assert scanner.main([str(clean)]) == 0
        assert scanner.main([str(clean), str(dirty)]) == 1

    def test_scanning_nothing_is_not_a_pass(self, repo, capsys):
        assert scanner.main([]) == 2
        track(repo, "tests/test_only.py", "x = 1\n")
        assert scanner.main([]) == 2, "only allow-listed files is still nothing scanned"
        assert "nothing was scanned" in capsys.readouterr().err


class TestThisRepository:
    @pytest.fixture
    def checkout(self, monkeypatch) -> Path:
        if shutil.which("git") is None or not (REPOSITORY / ".git").exists():
            pytest.skip("needs a git checkout of the repository")
        monkeypatch.chdir(REPOSITORY)
        return REPOSITORY

    def test_the_repository_scans_clean(self, checkout, capsys):
        assert scanner.main([]) == 0
        counted = re.search(r"(\d+) file\(s\) scanned", capsys.readouterr().out)
        assert counted is not None
        assert int(counted.group(1)) > 50, "a clean result must come from scanning the tree"

    def test_the_workflows_are_scanned_and_the_ci_allowance_is_needed(self, checkout):
        (allowance,) = scanner.allowances_for(".github/workflows/ci.yml")
        assert allowance.value == "ironflow", "the workflow itself must stay in scope"
        text = (checkout / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        found = scanner.find_secrets(text)
        assert found, "without the allowance the throwaway password would be reported"
        assert {finding.secret for finding in found} == {"ironflow"}
