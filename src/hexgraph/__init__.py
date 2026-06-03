"""HexGraph — self-hosted, local-only agentic vulnerability-research workbench."""

from importlib.metadata import PackageNotFoundError, version as _pkg_version

try:
    # Single source of truth: the version declared in pyproject.toml, read back from the
    # installed package metadata — so the running server's reported version can never drift
    # from the packaged one. Nothing else hardcodes it.
    __version__ = _pkg_version("hexgraph")
except PackageNotFoundError:  # running from a bare source tree (not installed)
    __version__ = "0.0.0+unknown"
