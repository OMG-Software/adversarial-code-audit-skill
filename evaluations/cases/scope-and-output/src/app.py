"""Read-only source fixture. Never call read_local.

base is the absolute src directory from the supplied paper inventory.
An external caller supplies requested_path. The intended rule is that reads
remain inside base. No middleware or other path validation exists.
"""

from pathlib import Path


def read_local(base, requested_path):
    return (Path(base) / requested_path).read_text(encoding="utf-8")
