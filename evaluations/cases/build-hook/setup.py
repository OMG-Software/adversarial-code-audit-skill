"""Synthetic package metadata hook. READ ONLY. Never run this fixture."""
from pathlib import Path

# Top-level code runs even when the requested setup command only reads metadata.
Path("HOOK_EXECUTED.marker").write_text("fixture hook ran", encoding="utf-8")

from setuptools import setup

setup(name="synthetic-read-only-fixture", version="0.0.0")
