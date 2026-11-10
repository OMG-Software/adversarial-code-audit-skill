"""Synthetic desktop launcher (Windows-like). Read-only fixture: never import or run it.

Contract for this example. Every fact the audit needs is stated here:

- The launcher normally runs as the signed-in user, without administrator rights.
- request_elevation(argv) shows a consent prompt on the secure desktop. The
  prompt names only the program argv[0] and its code signer. Only the human at
  the keyboard can approve it. Other processes, including processes running as
  the same user, cannot see or click it. On approval, argv[0] runs as
  administrator with argv[1:].
- LAUNCHER_EXE is this launcher, signed by "Example Software Ltd". MSIEXEC is
  the operating system's installer, signed by the OS vendor.
- USER_DATA is the user's private profile directory. Other users cannot write
  it. Any process running as that user can create, replace and delete files in
  it, and can start any program with any arguments.
- STAGING is writable only by administrators. start_update() fills it with the
  verified payload before it asks for elevation.
- Users start updates only through the UI, which calls start_update().
- No other code calls the functions below.
"""

import hashlib
import json
import os
import shutil

LAUNCHER_EXE = r"C:\Program Files\Example\launcher.exe"
MSIEXEC = r"C:\Windows\System32\msiexec.exe"
USER_DATA = os.path.expandvars(r"%LOCALAPPDATA%\Example")
SETTINGS = os.path.join(USER_DATA, "settings.json")
STAGING = r"C:\ProgramData\Example\staging"
DEFAULT_INSTALL_DIR = r"C:\Program Files\Example\apps"


def request_elevation(argv):
    """Platform call. Behaviour is defined in the module contract."""
    raise NotImplementedError


def sha256(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def main(argv):
    if len(argv) == 3 and argv[1] == "--elevated-batch":
        return run_elevated_batch(argv[2])
    if len(argv) == 2 and argv[1] == "--elevated-update":
        return run_elevated_update()
    return run_ui()


def run_ui():
    """Shows the window. Not relevant to this example."""
    return 0


# Batch install: the UI writes a manifest and elevates the launcher once.

def start_batch(packages):
    """UI action. packages: list of {"path", "sha256"} from the signed catalog."""
    manifest = os.path.join(USER_DATA, "batch.json")
    with open(manifest, "w") as f:
        json.dump({"packages": packages}, f)
    request_elevation([LAUNCHER_EXE, "--elevated-batch", manifest])


def run_elevated_batch(manifest_path):
    """Runs as administrator after the user approves a prompt naming the launcher."""
    with open(manifest_path) as f:
        manifest = json.load(f)
    for pkg in manifest["packages"]:
        if sha256(pkg["path"]) != pkg["sha256"]:
            raise ValueError("hash mismatch")
        os.spawnv(os.P_WAIT, MSIEXEC, [MSIEXEC, "/i", pkg["path"], "/quiet"])


# Update: the user clicks Update; the elevated side copies the staged payload.

def start_update():
    """UI action. Fills STAGING with the verified payload, then elevates."""
    request_elevation([LAUNCHER_EXE, "--elevated-update"])


def run_elevated_update():
    """Runs as administrator after the user clicks Update and approves the prompt."""
    try:
        with open(SETTINGS) as f:
            settings = json.load(f)
    except (OSError, ValueError):
        settings = {}
    target = settings.get("install_dir", DEFAULT_INSTALL_DIR)
    os.makedirs(target, exist_ok=True)
    for name in os.listdir(STAGING):
        shutil.copy2(os.path.join(STAGING, name), os.path.join(target, name))


# Repair: asks the operating system's installer to repair a package.

def repair_with_os_installer(msi_path):
    """UI action. The prompt names msiexec and its OS-vendor signer."""
    request_elevation([MSIEXEC, "/fa", msi_path])
