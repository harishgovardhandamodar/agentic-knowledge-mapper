"""A reproducibility manifest: name everything a result depended on.

An assessment that says "residual 49%" is unfalsifiable without knowing which
threat pack, which control catalogue, which benchmark crosswalk and which random
seed produced it. Reproduce it a month later and the number may differ -- not
because the reasoning changed, but because one of those moved underneath it.

This module captures that context as a single **manifest** and reduces it to a
**fingerprint**: a short hash over every input, seed, config value and component
version the run used. A stored fingerprint makes a result reproducible in the
only sense that matters -- a second run with the same fingerprint *must* agree,
and a run with a different one can say exactly which part changed.

Inputs are hashed, never stored, so a manifest can live on the ledger without
becoming a new place the source content leaks. Stdlib only.
"""
import hashlib
import json
import platform
import sys

#: Bump when the manifest's own shape changes, so old fingerprints are not
#: silently compared against new ones.
MANIFEST_VERSION = "1"

#: The sections that make up the fingerprinted body. Kept explicit so ``verify``
#: cannot accidentally fold the fingerprint into what it is hashing.
_SECTIONS = ("environment", "inputs", "seeds", "config", "versions")


def canonical(obj) -> str:
    """Stable JSON: sorted keys, no incidental whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def fingerprint(obj) -> str:
    """Short content hash. 16 hex chars is ample for identifying a run."""
    return hashlib.sha256(canonical(obj).encode("utf-8")).hexdigest()[:16]


def hash_input(value) -> str:
    """Fingerprint an input without keeping it.

    A string is treated as content; anything else is canonicalised first. Only
    the digest is stored, so an investigation's sources can be pinned
    reproducibly without a second copy of them sitting in the manifest.
    """
    if isinstance(value, str):
        return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]
    return fingerprint(value)


def environment() -> dict:
    return {
        "manifest_version": MANIFEST_VERSION,
        "python": platform.python_version(),
        "platform": platform.system(),
        "implementation": sys.implementation.name,
    }


def manifest(*, inputs=None, seeds=None, config=None, versions=None,
             label: str | None = None) -> dict:
    """Build a manifest. ``inputs``/``versions`` values are hashed; the rest are
    stored verbatim because they are small and describing them is the point.
    """
    body = {
        "environment": environment(),
        "inputs": {k: hash_input(v) for k, v in (inputs or {}).items()},
        "seeds": dict(seeds or {}),
        "config": dict(config or {}),
        "versions": {k: hash_input(v) for k, v in (versions or {}).items()},
    }
    m = dict(body)
    m["fingerprint"] = fingerprint(body)
    if label:
        m["label"] = label
    return m


def _body(m: dict) -> dict:
    return {k: m[k] for k in _SECTIONS if k in m}


def verify(m: dict) -> bool:
    """Does the stored fingerprint match the body it claims to describe?"""
    return bool(m) and fingerprint(_body(m)) == m.get("fingerprint")


def diff(a: dict, b: dict) -> dict:
    """Which sections differ between two manifests.

    Returns the changed section names with their before/after values (the
    *hashed* ones for inputs/versions), so a mismatch names its own cause rather
    than just failing.
    """
    changed = {}
    for section in _SECTIONS:
        if a.get(section) != b.get(section):
            changed[section] = {"a": a.get(section), "b": b.get(section)}
    return {
        "same": a.get("fingerprint") == b.get("fingerprint"),
        "changed": sorted(changed),
        "detail": changed,
    }
