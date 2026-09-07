# Contributing

## Setup

```bash
git clone https://github.com/mojtaba-py-code/ironflow.git && cd ironflow
python -m venv .venv && . .venv/bin/activate    # Windows: .venv\Scripts\activate
make install-dev                                 # or: pip install -e ".[dev,columnar,excel,remote,api]"
```

`make install-dev` also installs the pre-commit hooks, which mirror the CI lint
job — a red build is then caught before the push rather than after it.

Use a virtual environment, not the system interpreter. A globally installed
package hides an undeclared dependency: the suite passes for you and a fresh
clone fails.

## The loop

```bash
make check      # lint + typecheck + test + security, i.e. everything CI runs
```

Individually:

```bash
make lint       # ruff check
make format     # ruff check --fix and ruff format
make typecheck  # mypy
make test       # pytest
make coverage   # pytest with an HTML report in htmlcov/
make security   # committed-secret scan, bandit rules, pip-audit
```

CI additionally runs the suite on Python 3.11 and 3.12 across Linux and Windows,
installs without the optional extras to prove the slim path still works, runs
the integration tests against a real PostgreSQL, and builds the container image.
Green locally does not mean green in CI — the cross-platform jobs exist because
they have caught real bugs.

## What a change needs

**A test that fails before it and passes after.** For a bug fix, write the
failing test first; a fix with no test is a fix that comes back.

**Coverage stays at or above 88 %** — CI enforces the floor. That is a floor,
not a target: a line executed by no assertion is not covered in any useful
sense.

**`make check` is clean.** Lint, format, types and the secret scan all pass.

**Comments explain the decision, not the syntax.** The codebase documents *why*
a thing is the way it is — why Fernet rather than raw AES, why the retry wraps
the task and not the batch, why text arithmetic raises instead of concatenating.
A comment restating the code adds nothing; a comment recording the reasoning
saves the next reader an hour.

## Adding a component

`docs/developer-guide.md` walks through adding a connector, a transformation or
a validation rule. The short version: subclass the base, register it with the
decorator, read options through the typed `*_option` helpers (they give
consistent errors and route secrets through the resolver), and add it to the
component lists in `README.md`.

Three rules that are not negotiable:

1. **Stream.** A source yields batches; it does not build a list. An operation
   that genuinely cannot stream declares itself blocking and caps itself.
2. **Never log a secret.** Resolve through `SecretResolver`; if you must log a
   structure, pass it as an `extra` so the redaction filter sees it.
3. **Treat configuration as untrusted.** Paths go through `resolve_within`, URLs
   through `validate_url`, SQL identifiers through `validate_identifier`, and
   values are bound — never interpolated.

## Security

Do not open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md).

## Commits and pull requests

Write the commit subject in the imperative and say *why* in the body. Keep a
pull request to one concern; two unrelated fixes are two pull requests. Update
`CHANGELOG.md` under the appropriate heading for anything a user would notice.
