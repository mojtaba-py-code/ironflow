"""Security tests: crypto, secrets, masking, guards and RBAC.

These are the tests that must never be weakened to make something else pass.
Each one encodes a specific attack that the implementation is supposed to stop.
"""

from __future__ import annotations

import base64
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from ironflow.core.errors import (
    AuthenticationError,
    AuthorizationError,
    ConfigurationError,
    SecretError,
    SecurityError,
)
from ironflow.security.crypto import (
    CryptoService,
    constant_time_equals,
    generate_key,
    is_encrypted,
)
from ironflow.security.guards import (
    assert_no_sql_injection,
    quote_identifier,
    resolve_within,
    safe_filename,
    validate_identifier,
    validate_url,
)
from ironflow.security.masking import (
    ALLOWED_HASH_ALGORITHMS,
    REDACTED,
    detect_pii_columns,
    hash_value,
    is_sensitive_key,
    luhn_valid,
    mask,
    mask_auto,
    mask_card,
    mask_email,
    redact_mapping,
    redact_url,
)
from ironflow.security.rbac import (
    ADMIN,
    OPERATOR,
    VIEWER,
    AccessControl,
    Permission,
    Principal,
    issue_token,
    principal_from_claims,
    verify_token,
)
from ironflow.security.secrets import SecretResolver, SecretStr


class TestCrypto:
    def test_round_trip(self):
        crypto = CryptoService.from_key(generate_key())
        assert crypto.decrypt(crypto.encrypt("hunter2")) == "hunter2"

    def test_ciphertext_is_never_deterministic(self):
        crypto = CryptoService.from_key(generate_key())
        first, second = crypto.encrypt("same"), crypto.encrypt("same")
        assert first != second, "a fresh salt/IV per encryption is required"
        assert crypto.decrypt(first) == crypto.decrypt(second) == "same"

    def test_passphrase_mode_round_trips(self):
        crypto = CryptoService.from_passphrase("correct horse battery staple")
        assert crypto.decrypt(crypto.encrypt("secret")) == "secret"

    def test_wrong_key_cannot_decrypt(self):
        envelope = CryptoService.from_key(generate_key()).encrypt("secret")
        with pytest.raises(SecretError):
            CryptoService.from_key(generate_key()).decrypt(envelope)

    def test_tampered_ciphertext_is_rejected(self):
        crypto = CryptoService.from_key(generate_key())
        envelope = crypto.encrypt("secret")
        prefix, _, token = envelope.rpartition(":")
        flipped = token[:-4] + ("AAAA" if not token.endswith("AAAA") else "BBBB")
        with pytest.raises(SecretError):
            crypto.decrypt(f"{prefix}:{flipped}")

    def test_error_message_does_not_distinguish_wrong_key_from_tampering(self):
        """Distinguishing the two hands an attacker a decryption oracle."""
        crypto_a, crypto_b = CryptoService.from_key(generate_key()), None
        crypto_b = CryptoService.from_key(generate_key())
        envelope = crypto_a.encrypt("secret")
        with pytest.raises(SecretError) as wrong_key:
            crypto_b.decrypt(envelope)
        tampered = envelope[:-4] + "ZZZZ"
        with pytest.raises(SecretError) as corrupt:
            crypto_a.decrypt(tampered)
        assert str(wrong_key.value) == str(corrupt.value)

    def test_invalid_key_is_rejected_at_construction(self):
        with pytest.raises(ConfigurationError, match="invalid encryption key"):
            CryptoService.from_key("not-a-real-key")

    def test_from_env_refuses_to_fall_back(self, monkeypatch):
        monkeypatch.delenv("IRONFLOW_ENCRYPTION_KEY", raising=False)
        with pytest.raises(SecretError, match="not set"):
            CryptoService.from_env()

    def test_envelope_is_self_describing(self):
        envelope = CryptoService.from_key(generate_key()).encrypt("x")
        assert envelope.startswith("ironflow:v1:")
        assert is_encrypted(envelope)
        assert not is_encrypted("plain text")

    def test_unsupported_version_is_rejected(self):
        crypto = CryptoService.from_key(generate_key())
        envelope = crypto.encrypt("x").replace("ironflow:v1:", "ironflow:v9:")
        with pytest.raises(SecretError, match="unsupported ciphertext version"):
            crypto.decrypt(envelope)

    def test_repr_never_leaks_the_key(self):
        crypto = CryptoService.from_key(generate_key())
        assert "key" not in repr(crypto).replace("mode='key'", "")

    def test_constant_time_equals(self):
        assert constant_time_equals("abc", "abc")
        assert not constant_time_equals("abc", "abd")


class TestSecretResolver:
    def test_env_reference(self, monkeypatch):
        monkeypatch.setenv("MY_DB_PASSWORD", "s3cret")
        secret = SecretResolver().resolve("env:MY_DB_PASSWORD")
        assert secret.reveal() == "s3cret"
        assert secret.source == "env:MY_DB_PASSWORD"

    def test_missing_env_variable_fails_loudly(self, monkeypatch):
        monkeypatch.delenv("ABSENT_VAR", raising=False)
        with pytest.raises(SecretError, match="not set"):
            SecretResolver().resolve("env:ABSENT_VAR")

    def test_file_reference(self, tmp_path: Path):
        secret_file = tmp_path / "password"
        secret_file.write_text("from-file\n", encoding="utf-8")
        resolver = SecretResolver(file_roots=(str(tmp_path),))
        assert resolver.resolve(f"file:{secret_file}").reveal() == "from-file"

    def test_file_reference_is_confined_to_roots(self, tmp_path: Path):
        resolver = SecretResolver(file_roots=(str(tmp_path / "allowed"),))
        (tmp_path / "allowed").mkdir()
        with pytest.raises(SecurityError):
            resolver.resolve("file:../../../../etc/passwd")

    def test_encrypted_reference(self):
        crypto = CryptoService.from_key(generate_key())
        envelope = crypto.encrypt("decrypted!")
        resolver = SecretResolver(crypto=crypto)
        assert resolver.resolve(envelope).reveal() == "decrypted!"
        assert resolver.resolve(f"enc:{envelope}").reveal() == "decrypted!"

    def test_encrypted_reference_without_a_key_is_actionable(self):
        crypto = CryptoService.from_key(generate_key())
        with pytest.raises(SecretError, match="IRONFLOW_ENCRYPTION_KEY"):
            SecretResolver().resolve(crypto.encrypt("x"))

    def test_literal_can_be_forbidden_by_policy(self):
        with pytest.raises(SecretError, match="literal secrets are disabled"):
            SecretResolver(allow_literal=False).resolve("plaintext-password")

    def test_literal_is_allowed_but_warned_about(self, caplog):
        with caplog.at_level("WARNING"):
            assert SecretResolver().resolve("plaintext").reveal() == "plaintext"
        assert "literal" in caplog.text

    def test_values_are_cached(self, monkeypatch):
        monkeypatch.setenv("CACHED", "one")
        resolver = SecretResolver()
        first = resolver.resolve("env:CACHED")
        monkeypatch.setenv("CACHED", "two")
        assert resolver.resolve("env:CACHED") is first

    def test_none_passes_through(self):
        assert SecretResolver().resolve(None) is None


class TestSecretStr:
    def test_never_renders_its_value(self):
        secret = SecretStr("super-secret", source="test")
        assert str(secret) == "***"
        assert "super-secret" not in repr(secret)
        assert f"{secret}" == "***"
        assert "super-secret" not in json.dumps({"k": str(secret)})

    def test_is_not_a_str_subclass(self):
        """Inheriting from str would leak the value through every conversion."""
        assert not isinstance(SecretStr("x"), str)

    def test_reveal_is_the_only_way_out(self):
        assert SecretStr("value").reveal() == "value"

    def test_equality_and_truthiness(self):
        assert SecretStr("a") == SecretStr("a")
        assert SecretStr("a") != SecretStr("b")
        assert bool(SecretStr("a"))
        assert not bool(SecretStr(""))


class TestMasking:
    @pytest.mark.parametrize(
        "key", ["password", "api_key", "SECRET_TOKEN", "authorization", "db_dsn", "ssn"]
    )
    def test_sensitive_key_detection(self, key):
        assert is_sensitive_key(key)

    @pytest.mark.parametrize("key", ["username", "amount", "region", "created_at"])
    def test_ordinary_keys_are_not_flagged(self, key):
        assert not is_sensitive_key(key)

    def test_mask_keeps_the_tail(self):
        assert mask("1234567890", keep_end=4) == "******7890"

    def test_short_values_are_fully_masked(self):
        assert mask("abc") == "***", "revealing 4 of 5 characters is not masking"

    def test_mask_email(self):
        assert mask_email("john.doe@corp.com") == "j*******@corp.com"

    def test_mask_card_keeps_at_most_four_digits(self):
        assert mask_card("4111 1111 1111 1111") == "************1111"

    def test_mask_auto_dispatches_on_shape(self):
        assert "@" in mask_auto("a@b.com")
        assert mask_auto("4111111111111111").endswith("1111")

    def test_luhn(self):
        assert luhn_valid("4111111111111111")
        assert not luhn_valid("4111111111111112")

    def test_keyed_hash_is_deterministic_but_key_dependent(self):
        assert hash_value("a@b.com", key="k1") == hash_value("a@b.com", key="k1")
        assert hash_value("a@b.com", key="k1") != hash_value("a@b.com", key="k2")

    def test_unkeyed_hash_differs_from_keyed(self):
        assert hash_value("x") != hash_value("x", key="k")

    @pytest.mark.parametrize("algorithm", ["md5", "sha1", "shake_128", "nonsense"])
    def test_a_broken_digest_is_refused(self, algorithm):
        """This is the one function whose whole purpose is irreversibility.

        `hashlib.new` accepts "md5" happily, so a pipeline file copied from an
        old example would pseudonymise PII with a broken hash and say nothing.
        """
        with pytest.raises(ConfigurationError, match="not allowed"):
            hash_value("a@b.com", key="k", algorithm=algorithm)

    @pytest.mark.parametrize("algorithm", sorted(ALLOWED_HASH_ALGORITHMS))
    def test_every_allowed_digest_works_keyed_and_unkeyed(self, algorithm):
        assert len(hash_value("a@b.com", algorithm=algorithm)) >= 64
        assert len(hash_value("a@b.com", key="k", algorithm=algorithm)) >= 64

    def test_redact_url_removes_the_password_only(self):
        redacted = redact_url("postgresql://user:hunter2@db.internal:5432/prod")
        assert "hunter2" not in redacted
        assert "user" in redacted and "db.internal" in redacted

    def test_redact_mapping_is_recursive(self):
        payload = {
            "user": "alice",
            "password": "hunter2",
            "nested": {"api_key": "abc", "keep": 1},
            "list": [{"token": "t"}, "plain"],
        }
        redacted = redact_mapping(payload)
        assert redacted["password"] == REDACTED
        assert redacted["nested"]["api_key"] == REDACTED
        assert redacted["nested"]["keep"] == 1
        assert redacted["list"][0]["token"] == REDACTED
        assert redacted["user"] == "alice"

    def test_redact_mapping_survives_self_reference(self):
        payload: dict = {"a": 1}
        payload["self"] = payload
        redact_mapping(payload)  # must terminate, not recurse forever

    def test_detect_pii_columns(self):
        findings = detect_pii_columns(
            [
                {"email": "a@b.com", "card": "4111111111111111", "ip": "10.0.0.1", "n": 5},
            ]
        )
        assert findings["email"] == "email"
        assert findings["card"] == "card_number"
        assert findings["ip"] == "ip_address"
        assert "n" not in findings


class TestPathGuards:
    def test_allows_paths_inside_a_root(self, tmp_path: Path):
        target = tmp_path / "data" / "file.csv"
        target.parent.mkdir()
        target.write_text("x", encoding="utf-8")
        assert resolve_within(target, [tmp_path]) == target.resolve()

    @pytest.mark.parametrize(
        "attack",
        [
            "../../../../etc/passwd",
            pytest.param(
                "..\\..\\..\\Windows\\System32\\config\\SAM",
                marks=pytest.mark.skipif(
                    os.name != "nt",
                    reason=(
                        "A backslash is an ordinary filename character on "
                        "POSIX, so this payload names one oddly-spelled file "
                        "inside the sandbox rather than escaping it. "
                        "resolve_within is right not to raise, and asserting "
                        "that it does only tests which separator the runner "
                        "happens to use."
                    ),
                ),
            ),
            "data/../../outside.txt",
        ],
    )
    def test_blocks_traversal(self, tmp_path: Path, attack):
        with pytest.raises(SecurityError, match="escapes"):
            resolve_within(tmp_path / attack, [tmp_path])

    def test_blocks_symlink_escape(self, tmp_path: Path):
        """Checking the string before resolution is bypassed by a symlink."""
        outside = tmp_path.parent / "outside_target"
        outside.mkdir(exist_ok=True)
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        link = allowed / "escape"
        try:
            link.symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError):
            pytest.skip("symlinks require privileges on this platform")
        with pytest.raises(SecurityError):
            resolve_within(link / "file.txt", [allowed])

    def test_empty_roots_means_unrestricted(self, tmp_path: Path):
        assert resolve_within(tmp_path / "anything", [])

    def test_safe_filename_strips_directories(self):
        assert safe_filename("../../etc/passwd") == "passwd"
        assert safe_filename("a b;rm -rf.csv") == "a_b_rm_-rf.csv"
        assert safe_filename("") == "file"


class TestUrlGuards:
    def test_allows_public_https(self):
        assert validate_url("https://api.example.com/v1", allow_private=True)

    @pytest.mark.parametrize("url", ["file:///etc/passwd", "gopher://x", "ftp://x/y"])
    def test_rejects_non_http_schemes(self, url):
        with pytest.raises(SecurityError, match="scheme"):
            validate_url(url)

    @pytest.mark.parametrize(
        "url",
        [
            "http://127.0.0.1:8080/admin",
            "http://localhost/x",
            "http://169.254.169.254/latest/meta-data/",  # cloud metadata
            "http://10.0.0.5/internal",
            "http://192.168.1.1/",
        ],
    )
    def test_blocks_private_and_metadata_addresses(self, url):
        with pytest.raises(SecurityError, match="non-public"):
            validate_url(url, allow_private=False)

    def test_credentials_are_stripped_from_the_url(self):
        cleaned = validate_url("https://user:pass@api.example.com/x", allow_private=True)
        assert "pass" not in cleaned

    def test_host_allow_list(self):
        # allow_private=True keeps this test off the network: it exercises the
        # allow-list, not the address policy.
        assert validate_url(
            "https://hooks.slack.com/x", allowed_hosts=["hooks.slack.com"], allow_private=True
        )
        assert validate_url(
            "https://a.example.com/x", allowed_hosts=["example.com"], allow_private=True
        )
        with pytest.raises(SecurityError, match="allow-list"):
            validate_url("https://evil.com/x", allowed_hosts=["example.com"], allow_private=True)

    def test_unresolvable_host_fails_closed(self):
        with pytest.raises(SecurityError):
            validate_url("https://this-host-does-not-exist.invalid/x", allow_private=False)


class TestSqlGuards:
    @pytest.mark.parametrize("name", ["orders", "_tmp", "Order_2026", "a" * 63])
    def test_accepts_valid_identifiers(self, name):
        assert validate_identifier(name) == name

    @pytest.mark.parametrize(
        "name",
        [
            "orders; DROP TABLE users--",
            "orders'",
            '"orders"',
            "1_starts_with_digit",
            "has space",
            "a" * 64,
            "",
            "tbl`",
        ],
    )
    def test_rejects_injection_shaped_identifiers(self, name):
        with pytest.raises(SecurityError):
            validate_identifier(name)

    def test_qualified_identifiers(self):
        assert validate_identifier("public.orders", qualified=True)
        with pytest.raises(SecurityError):
            validate_identifier("public.orders", qualified=False)

    def test_quoting_per_dialect(self):
        assert quote_identifier("orders") == '"orders"'
        assert quote_identifier("orders", dialect="mysql") == "`orders`"

    def test_quote_validates_before_quoting(self):
        with pytest.raises(SecurityError):
            quote_identifier('x"; DROP TABLE y--')

    @pytest.mark.parametrize(
        "fragment",
        ["a = 1; DROP TABLE t", "1=1 UNION SELECT * FROM users", "x -- comment", "/* c */ 1=1"],
    )
    def test_rejects_dangerous_where_fragments(self, fragment):
        with pytest.raises(SecurityError):
            assert_no_sql_injection(fragment)

    def test_allows_ordinary_predicates(self):
        assert assert_no_sql_injection("status = 'active' AND amount > 0")


class TestRbac:
    def test_role_permissions_follow_least_privilege(self):
        assert not VIEWER.has(Permission.PIPELINE_RUN)
        assert OPERATOR.has(Permission.PIPELINE_RUN)
        assert not OPERATOR.has(Permission.SECRET_READ)
        assert not OPERATOR.has(Permission.PIPELINE_WRITE)
        assert ADMIN.has(Permission.SECRET_READ)

    def test_operator_inherits_viewer(self):
        assert VIEWER.permissions <= OPERATOR.permissions

    def test_authorize_allows_and_denies(self):
        access = AccessControl(enabled=True)
        operator = Principal("bob", roles=(OPERATOR,))
        access.authorize(operator, Permission.PIPELINE_RUN)
        with pytest.raises(AuthorizationError, match="lacks permission"):
            access.authorize(operator, Permission.SECRET_READ)

    def test_pipeline_scoping(self):
        access = AccessControl(enabled=True)
        scoped = Principal("team", roles=(OPERATOR,), pipeline_scopes=("sales_*",))
        access.authorize(scoped, Permission.PIPELINE_RUN, pipeline="sales_daily")
        with pytest.raises(AuthorizationError, match="not scoped"):
            access.authorize(scoped, Permission.PIPELINE_RUN, pipeline="hr_payroll")

    def test_missing_principal_is_an_authentication_error(self):
        with pytest.raises(AuthenticationError):
            AccessControl(enabled=True).authorize(None, Permission.PIPELINE_READ)

    def test_disabled_access_control_permits_everything(self):
        assert AccessControl(enabled=False).authorize(None, Permission.SECRET_READ)

    def test_check_is_non_raising(self):
        access = AccessControl(enabled=True)
        assert not access.check(Principal.anonymous(), Permission.PIPELINE_RUN)


class TestJwt:
    SECRET = "a-secret-at-least-32-characters-long!!"

    def test_round_trip(self):
        token = issue_token({"sub": "alice", "roles": ["operator"]}, self.SECRET)
        claims = verify_token(token, self.SECRET)
        assert claims["sub"] == "alice"

    def test_wrong_secret_is_rejected(self):
        token = issue_token({"sub": "alice"}, self.SECRET)
        with pytest.raises(AuthenticationError, match="signature"):
            verify_token(token, "different-secret")

    def test_alg_none_attack_is_blocked(self):
        """The classic JWT bypass: swap the algorithm to 'none'."""
        header = (
            base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode())
            .decode()
            .rstrip("=")
        )
        payload = (
            base64.urlsafe_b64encode(json.dumps({"sub": "attacker", "roles": ["admin"]}).encode())
            .decode()
            .rstrip("=")
        )
        with pytest.raises(AuthenticationError, match="algorithm is not allowed"):
            verify_token(f"{header}.{payload}.", self.SECRET)

    def test_algorithm_confusion_is_blocked(self):
        header = (
            base64.urlsafe_b64encode(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
            .decode()
            .rstrip("=")
        )
        payload = base64.urlsafe_b64encode(json.dumps({"sub": "x"}).encode()).decode().rstrip("=")
        with pytest.raises(AuthenticationError, match="algorithm is not allowed"):
            verify_token(f"{header}.{payload}.sig", self.SECRET)

    def test_tampered_payload_is_rejected(self):
        token = issue_token({"sub": "alice", "roles": ["viewer"]}, self.SECRET)
        header, _, rest = token.partition(".")
        _, _, signature = rest.partition(".")
        forged = (
            base64.urlsafe_b64encode(json.dumps({"sub": "alice", "roles": ["admin"]}).encode())
            .decode()
            .rstrip("=")
        )
        with pytest.raises(AuthenticationError, match="signature"):
            verify_token(f"{header}.{forged}.{signature}", self.SECRET)

    def test_expiry_is_enforced(self):
        expired = int((datetime.now(UTC) - timedelta(hours=2)).timestamp())
        token = issue_token({"sub": "a", "exp": expired}, self.SECRET, expires_in=-7200)
        with pytest.raises(AuthenticationError, match="expired"):
            verify_token(token, self.SECRET)

    def test_not_before_is_enforced(self):
        future = int((datetime.now(UTC) + timedelta(hours=2)).timestamp())
        token = issue_token({"sub": "a", "nbf": future}, self.SECRET)
        with pytest.raises(AuthenticationError, match="not yet valid"):
            verify_token(token, self.SECRET)

    def test_issuer_and_audience_are_enforced(self):
        token = issue_token({"sub": "a", "iss": "them", "aud": "other"}, self.SECRET)
        with pytest.raises(AuthenticationError, match="issuer"):
            verify_token(token, self.SECRET, issuer="us")
        with pytest.raises(AuthenticationError, match="audience"):
            verify_token(token, self.SECRET, audience="ours")

    def test_malformed_tokens_are_rejected(self):
        for bad in ("", "a.b", "not.a.token", "a.b.c.d"):
            with pytest.raises(AuthenticationError):
                verify_token(bad, self.SECRET)

    def test_an_empty_signing_secret_is_refused(self):
        """HMAC with an empty key is reproducible by anyone who guesses it is empty."""
        with pytest.raises(AuthenticationError, match="signing secret"):
            issue_token({"sub": "alice"}, "")

    def test_verification_with_an_empty_secret_is_refused(self):
        token = issue_token({"sub": "alice"}, self.SECRET)
        with pytest.raises(AuthenticationError, match="signing secret"):
            verify_token(token, "")

    def test_claims_map_to_a_principal(self):
        principal = principal_from_claims(
            {"sub": "alice", "roles": ["operator", "nonexistent"], "pipelines": ["sales_*"]}
        )
        assert principal.subject == "alice"
        assert principal.role_names == ("operator",), "unknown roles are dropped, not fatal"
        assert principal.can_access_pipeline("sales_daily")
        assert not principal.can_access_pipeline("hr_data")
