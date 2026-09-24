"""Loading, merging and templating of pipeline definitions.

Features
--------
* **YAML and JSON**, loaded with ``yaml.safe_load`` - never ``yaml.load``, which
  can instantiate arbitrary Python objects from a crafted document.
* **Profiles.**  ``pipeline.yaml`` may carry a ``profiles:`` block; selecting
  ``--profile production`` deep-merges that overlay onto the base document.  One
  definition, environment-specific overrides, no copy-paste drift.
* **Variable interpolation.**  ``${VAR}``, ``${VAR:-default}`` and
  ``${var.pipeline_variable}`` are substituted from the environment, the
  pipeline's own ``variables`` block and CLI ``--set`` overrides.  Unresolved
  references are an error, so a missing production variable fails at load rather
  than silently writing to a path named ``/data/${REGION}/out.csv``.
* **Includes.**  ``include: [common/defaults.yaml]`` composes shared fragments,
  resolved relative to the including file and confined to the pipelines root.

Interpolation deliberately does *not* execute anything.  It is a string
substitution over a parsed document, so a pipeline file cannot become a code
execution vector.  It cannot become a way to read the process environment
either: every ``${NAME}`` that reaches for it passes the operator's
:class:`~ironflow.security.secrets.EnvironmentPolicy`.  Interpolated values land
in ordinary fields - ``owner``, ``description``, a URL - that the API, the
dashboard and every log line show in plaintext, so ``owner:
"${IRONFLOW_JWT_SECRET}"`` used to publish the token-signing key.

Documents are bounded before they are built: a size cap on the file, and a cap
on how far its aliases expand.  YAML anchors are legitimate, but nine of them
nested nine deep describe 387 million nodes in under 500 bytes.
"""

from __future__ import annotations

import json
import logging
import os
import re
from collections.abc import Mapping, MutableMapping
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError as PydanticValidationError

from ironflow.config.models import PipelineSpec
from ironflow.core.errors import ConfigurationError, SecretError
from ironflow.security.guards import resolve_within
from ironflow.security.secrets import EnvironmentPolicy

logger = logging.getLogger(__name__)

#: ``${NAME}`` or ``${NAME:-default}``
_VAR_RE = re.compile(r"\$\{(?P<name>[A-Za-z_][A-Za-z0-9_.]*)(?::-(?P<default>[^}]*))?\}")

SUPPORTED_SUFFIXES = (".yaml", ".yml", ".json")
MAX_INCLUDE_DEPTH = 5
#: A pipeline definition is a few kilobytes; a megabyte is two orders past any real one.
MAX_DOCUMENT_BYTES = 1024 * 1024
#: Nodes a document may describe once its aliases are expanded.
MAX_DOCUMENT_NODES = 100_000

#: Only these spellings become booleans. See :func:`_build_loader`.
_STRICT_BOOL_RE = re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$")


def _build_loader() -> type[yaml.SafeLoader]:
    """A ``SafeLoader`` without YAML 1.1's ``yes``/``no``/``on``/``off`` coercion.

    PyYAML implements YAML 1.1, where those six bare words are booleans.  In a
    data tool that is not a curiosity, it is a correctness bug:

    * ``on: [failed]`` - the notification trigger key - parses as ``True:``,
      which is not even a valid mapping key for a Pydantic model;
    * the ISO-3166 country code ``NO`` (Norway) parses as ``False``, silently
      corrupting any country list written in a config file;
    * a column literally named ``on`` or ``off`` becomes unreferenceable.

    YAML 1.2 dropped this behaviour, and so do we.  ``true``/``false`` still
    work; everything else stays a string, which is what an author writing
    ``NO`` means.
    """

    class Loader(yaml.SafeLoader):
        pass

    # Copy the table before editing so PyYAML's global SafeLoader is untouched.
    Loader.yaml_implicit_resolvers = {
        key: [
            (tag, _STRICT_BOOL_RE if tag == "tag:yaml.org,2002:bool" else regexp)
            for tag, regexp in resolvers
        ]
        for key, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
    }
    return Loader


IronFlowLoader = _build_loader()


def _parse_yaml(text: str) -> Any:
    """Compose, bound, then construct - never construct an unbounded document.

    ``IronFlowLoader`` derives from ``SafeLoader``, so a crafted tag can never
    build an arbitrary Python object; what ``SafeLoader`` does not stop is an
    alias bomb, whose cost only appears when something walks the result.
    """
    loader = IronFlowLoader(text)
    try:
        node = loader.get_single_node()
        if node is None:
            return None
        _assert_expansion_bounded(node)
        return loader.construct_document(node)
    finally:
        loader.dispose()


def _assert_expansion_bounded(root: yaml.Node) -> None:
    """Refuse a document whose aliases expand past :data:`MAX_DOCUMENT_NODES`.

    Each node's expanded size is computed once, bottom-up, so the check costs
    the size of the *written* document however far it would expand.  An alias
    that refers back to its own ancestor would make the document infinite and is
    refused outright.  Iterative, so nesting depth cannot overflow the stack.
    """
    sizes: dict[int, int] = {}
    visiting: set[int] = set()
    stack: list[tuple[yaml.Node, bool]] = [(root, False)]
    while stack:
        node, expanded = stack.pop()
        key = id(node)
        children = _children(node)
        if not expanded:
            if key in sizes:
                continue
            if key in visiting:
                raise ConfigurationError("configuration contains a recursive YAML alias")
            visiting.add(key)
            stack.append((node, True))
            stack.extend((child, False) for child in children if id(child) not in sizes)
            continue
        total = 1 + sum(sizes[id(child)] for child in children)
        if total > MAX_DOCUMENT_NODES:
            raise ConfigurationError(
                "configuration expands past the node limit; check its YAML aliases",
                context={"limit": MAX_DOCUMENT_NODES},
            )
        sizes[key] = total
        visiting.discard(key)


def _children(node: yaml.Node) -> list[yaml.Node]:
    if isinstance(node, yaml.SequenceNode):
        return list(node.value)
    if isinstance(node, yaml.MappingNode):
        return [part for pair in node.value for part in pair]
    return []


def load_document(path: str | Path, *, roots: tuple[Path, ...] = ()) -> dict[str, Any]:
    """Parse a YAML/JSON file into a plain dict."""
    resolved = resolve_within(path, roots, must_exist=True)
    if resolved.suffix.lower() not in SUPPORTED_SUFFIXES:
        raise ConfigurationError(
            "unsupported configuration format",
            context={"path": str(resolved), "supported": list(SUPPORTED_SUFFIXES)},
        )
    try:
        size = resolved.stat().st_size
        if size > MAX_DOCUMENT_BYTES:
            raise ConfigurationError(
                "configuration file is too large",
                context={"path": str(resolved), "bytes": size, "limit": MAX_DOCUMENT_BYTES},
            )
        text = resolved.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigurationError(
            "unable to read configuration file", context={"path": str(resolved)}
        ) from exc

    try:
        data = json.loads(text) if resolved.suffix.lower() == ".json" else _parse_yaml(text)
    except (yaml.YAMLError, json.JSONDecodeError) as exc:
        raise ConfigurationError(
            "configuration file is not valid YAML/JSON",
            context={"path": str(resolved), "detail": str(exc)[:300]},
        ) from exc
    except RecursionError as exc:
        raise ConfigurationError(
            "configuration file is nested too deeply", context={"path": str(resolved)}
        ) from exc
    except ConfigurationError as exc:
        exc.with_context(path=str(resolved))
        raise

    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ConfigurationError(
            "configuration root must be a mapping", context={"path": str(resolved)}
        )
    return data


def deep_merge(base: Mapping[str, Any], overlay: Mapping[str, Any]) -> dict[str, Any]:
    """Recursively merge ``overlay`` onto ``base``.

    Mappings merge key-wise; every other type (including lists) is replaced.
    Replacing lists is intentional: appending would make it impossible for a
    profile to *remove* a task or a transformation.
    """
    result: dict[str, Any] = dict(base)
    for key, value in overlay.items():
        current = result.get(key)
        if isinstance(current, Mapping) and isinstance(value, Mapping):
            result[key] = deep_merge(current, value)
        else:
            result[key] = value
    return result


def interpolate(
    value: Any,
    variables: Mapping[str, Any],
    *,
    environ: Mapping[str, str] | None = None,
    strict: bool = True,
    env_policy: EnvironmentPolicy | None = None,
    _path: str = "",
) -> Any:
    """Recursively substitute ``${...}`` references inside a parsed document.

    Resolution order: pipeline ``variables`` (also reachable as ``var.NAME``),
    then the process environment - through ``env_policy`` - then the inline
    ``:-default``.
    """
    env = environ if environ is not None else os.environ
    policy = env_policy or EnvironmentPolicy.default()

    if isinstance(value, str):
        return _interpolate_string(value, variables, env, policy, strict=strict, path=_path)
    if isinstance(value, Mapping):
        return {
            key: interpolate(
                item,
                variables,
                environ=env,
                strict=strict,
                env_policy=policy,
                _path=f"{_path}.{key}".lstrip("."),
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [
            interpolate(
                item,
                variables,
                environ=env,
                strict=strict,
                env_policy=policy,
                _path=f"{_path}[{index}]",
            )
            for index, item in enumerate(value)
        ]
    return value


def _interpolate_string(
    text: str,
    variables: Mapping[str, Any],
    environ: Mapping[str, str],
    policy: EnvironmentPolicy,
    *,
    strict: bool,
    path: str,
) -> Any:
    match = _VAR_RE.fullmatch(text.strip())
    if match:
        # A whole-string reference preserves the referenced value's type,
        # so ``batch_size: "${BATCH}"`` can still yield an int.
        resolved = _lookup(match, variables, environ, policy, strict=strict, path=path)
        return resolved

    def _replace(m: re.Match[str]) -> str:
        return str(_lookup(m, variables, environ, policy, strict=strict, path=path))

    return _VAR_RE.sub(_replace, text)


def _lookup(
    match: re.Match[str],
    variables: Mapping[str, Any],
    environ: Mapping[str, str],
    policy: EnvironmentPolicy,
    *,
    strict: bool,
    path: str,
) -> Any:
    name = match.group("name")
    default = match.group("default")

    key = name[4:] if name.startswith("var.") else name
    if key in variables:
        return variables[key]
    if not name.startswith("var."):
        # Checked whether or not the variable is set: a pipeline that names
        # IRONFLOW_JWT_SECRET is refused even where it happens to be empty.
        try:
            policy.check(name)
        except SecretError as exc:
            exc.with_context(location=path or "<root>")
            raise
        if name in environ:
            return environ[name]
    if default is not None:
        return default
    if strict:
        raise ConfigurationError(
            f"unresolved variable ${{{name}}}",
            context={"variable": name, "location": path or "<root>"},
        )
    logger.warning("leaving unresolved variable ${%s} at %s", name, path or "<root>")
    return match.group(0)


def _apply_includes(
    document: MutableMapping[str, Any],
    base_dir: Path,
    roots: tuple[Path, ...],
    depth: int = 0,
) -> dict[str, Any]:
    """Resolve the ``include:`` key by merging the referenced documents first."""
    includes = document.pop("include", None)
    if not includes:
        return dict(document)
    if depth >= MAX_INCLUDE_DEPTH:
        raise ConfigurationError(
            "include depth exceeded; check for a circular include",
            context={"max_depth": MAX_INCLUDE_DEPTH},
        )
    if isinstance(includes, str):
        includes = [includes]
    if not isinstance(includes, list):
        raise ConfigurationError("'include' must be a string or a list of strings")

    merged: dict[str, Any] = {}
    for reference in includes:
        target = (base_dir / str(reference)).resolve()
        fragment = load_document(target, roots=roots)
        fragment = _apply_includes(fragment, target.parent, roots, depth + 1)
        merged = deep_merge(merged, fragment)
    return deep_merge(merged, dict(document))


def load_pipeline(
    path: str | Path,
    *,
    profile: str | None = None,
    overrides: Mapping[str, Any] | None = None,
    variables: Mapping[str, Any] | None = None,
    roots: tuple[Path, ...] = (),
    strict_variables: bool = True,
    env_policy: EnvironmentPolicy | None = None,
) -> PipelineSpec:
    """Load, merge, interpolate and validate a pipeline definition.

    Order matters: includes -> profile overlay -> CLI overrides -> variable
    interpolation -> model validation.  Interpolating before merging would make
    a profile unable to override a value that referenced a variable.

    ``env_policy`` defaults to the operator's, from the process settings.
    """
    if env_policy is None:
        from ironflow.config.settings import get_settings

        env_policy = EnvironmentPolicy.from_settings(get_settings())
    resolved = resolve_within(path, roots, must_exist=True)
    document = load_document(resolved, roots=roots)
    document = _apply_includes(document, resolved.parent, roots)

    profiles = document.pop("profiles", {}) or {}
    if profile:
        if profile not in profiles:
            raise ConfigurationError(
                f"profile {profile!r} is not defined in this pipeline",
                context={"path": str(resolved), "available": sorted(profiles)},
            )
        document = deep_merge(document, profiles[profile])
        logger.info("applied profile %r from %s", profile, resolved.name)

    if overrides:
        document = deep_merge(document, _expand_dotted(overrides))

    merged_variables: dict[str, Any] = dict(document.get("variables") or {})
    if variables:
        merged_variables.update(variables)
    document["variables"] = merged_variables

    document = interpolate(
        document, merged_variables, strict=strict_variables, env_policy=env_policy
    )

    try:
        spec = PipelineSpec.model_validate(document)
    except PydanticValidationError as exc:
        raise ConfigurationError(
            "pipeline definition failed validation",
            context={"path": str(resolved), "errors": _format_pydantic_errors(exc)},
        ) from exc

    spec.source_file = str(resolved)
    return spec.with_defaults_applied()


def _expand_dotted(overrides: Mapping[str, Any]) -> dict[str, Any]:
    """Turn ``{"defaults.batch_size": 100}`` into a nested mapping."""
    result: dict[str, Any] = {}
    for key, value in overrides.items():
        parts = key.split(".")
        cursor = result
        for part in parts[:-1]:
            cursor = cursor.setdefault(part, {})
            if not isinstance(cursor, dict):
                raise ConfigurationError("conflicting override paths", context={"override": key})
        cursor[parts[-1]] = value
    return result


def _format_pydantic_errors(exc: PydanticValidationError) -> list[str]:
    formatted = []
    for error in exc.errors()[:20]:
        location = ".".join(str(p) for p in error["loc"])
        formatted.append(f"{location or '<root>'}: {error['msg']}")
    return formatted


class PipelineRepository:
    """Discovers and caches pipeline definitions in a directory tree.

    Caches on ``(path, mtime, profile)`` so an edited file is picked up without
    restarting a long-running scheduler, while a hot loop that lists pipelines
    does not re-parse every file each time.
    """

    def __init__(self, directory: str | Path, *, roots: tuple[Path, ...] = ()) -> None:
        self.directory = Path(directory).expanduser()
        self._roots = roots or (self.directory.resolve(),)
        self._cache: dict[tuple[str, float, str | None], PipelineSpec] = {}

    def discover(self) -> list[Path]:
        """All pipeline files under the directory, sorted for stable output.

        Paths are returned absolute so that :meth:`load` cannot re-join them to
        ``self.directory`` when the repository was configured with a relative
        path.
        """
        if not self.directory.is_dir():
            return []
        files: list[Path] = []
        for suffix in SUPPORTED_SUFFIXES:
            files.extend(self.directory.rglob(f"*{suffix}"))
        # ``_``-prefixed files are shared fragments, not standalone pipelines.
        return sorted(f.resolve() for f in files if not f.name.startswith("_"))

    def load_all(self, *, profile: str | None = None) -> list[PipelineSpec]:
        """Load every discoverable pipeline, skipping ones that fail to parse.

        Files that declare the same pipeline ``name`` are skipped *together*:
        run history, watermarks and the schedule are all keyed by name, so two
        files sharing one would take turns running under one identity - the
        scheduler registered the last, a manual run used the first, and each
        advanced the other's watermark.  Neither is trusted to be the real one.
        """
        loaded: list[tuple[Path, PipelineSpec]] = []
        for file in self.discover():
            try:
                loaded.append((file, self.load(file, profile=profile)))
            except ConfigurationError as exc:
                logger.error("skipping invalid pipeline %s: %s", file.name, exc)
        duplicates = _duplicate_names(loaded)
        for name, files in duplicates.items():
            logger.error(
                "skipping pipeline %r: it is declared by more than one file (%s)",
                name,
                ", ".join(f.name for f in files),
            )
        return [spec for _, spec in loaded if spec.name not in duplicates]

    def load(self, path: str | Path, *, profile: str | None = None, **kwargs: Any) -> PipelineSpec:
        target = Path(path)
        if not target.is_absolute():
            # A bare name ("sales.yaml") is looked up inside the repository;
            # an existing relative path is honoured as given.
            candidate = self.directory / target
            target = candidate if candidate.exists() else target
        target = target.resolve()
        try:
            mtime = target.stat().st_mtime
        except OSError as exc:
            raise ConfigurationError(
                "pipeline file not found", context={"path": str(target)}
            ) from exc

        key = (str(target), mtime, profile)
        cached = self._cache.get(key)
        if cached is not None and not kwargs:
            return cached

        spec = load_pipeline(target, profile=profile, roots=self._roots, **kwargs)
        if not kwargs:
            self._cache[key] = spec
        return spec

    def get(self, name: str, *, profile: str | None = None) -> PipelineSpec:
        """Look a pipeline up by its declared ``name``.

        A file that will not load is *not* silently skipped here the way it is
        in :meth:`load_all`.  One mistyped key used to surface as "no pipeline
        named 'sales' was found", which sends an operator hunting for a missing
        file instead of at the typo on line four - and the CLI then suggests
        ``config init``, which would scaffold straight over the file they are
        trying to fix.
        """
        failures: list[tuple[Path, ConfigurationError]] = []
        matches: list[tuple[Path, PipelineSpec]] = []
        for file in self.discover():
            try:
                spec = self.load(file, profile=profile)
            except ConfigurationError as exc:
                failures.append((file, exc))
                continue
            if spec.name == name:
                matches.append((file, spec))

        if len(matches) > 1:
            raise ConfigurationError(
                f"pipeline {name!r} is declared by more than one file; rename one of them",
                context={"files": [str(f) for f, _ in matches]},
            )
        if matches:
            return matches[0][1]

        # A file named after the pipeline that would not load is almost always
        # the one being asked for, so report why it failed rather than denying
        # it exists.
        for file, failure in failures:
            if file.stem == name:
                raise failure

        if failures:
            raise ConfigurationError(
                f"no pipeline named {name!r} was found; "
                f"{len(failures)} file(s) here could not be loaded",
                context={
                    "directory": str(self.directory),
                    "unloadable": [f.name for f, _ in failures],
                },
            )
        raise ConfigurationError(
            f"no pipeline named {name!r} was found",
            context={"directory": str(self.directory)},
        )

    def invalidate(self) -> None:
        self._cache.clear()


def _duplicate_names(loaded: list[tuple[Path, PipelineSpec]]) -> dict[str, list[Path]]:
    """Pipeline names declared by more than one file, with those files."""
    by_name: dict[str, list[Path]] = {}
    for file, spec in loaded:
        by_name.setdefault(spec.name, []).append(file)
    return {name: files for name, files in by_name.items() if len(files) > 1}


__all__ = [
    "PipelineRepository",
    "deep_merge",
    "interpolate",
    "load_document",
    "load_pipeline",
]
