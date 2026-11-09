# Running target code

Read this file before you build, test or run any code from the target. That includes the target's build scripts, test suites, install hooks and dev-container files: all of them are target code.

The user decides how target code runs. You detect the options, explain the risk of each, and ask. You never choose a weaker isolation level yourself.

## 1. Isolation levels

| Level | Name | Meaning |
|---|---|---|
| **I3** | Full sandbox | All five controls in section 2 are in place. |
| **I2** | Partial isolation | Separated from the user's normal environment, but one or more controls are missing. Example: WSL with default settings; a container with network access. |
| **I1** | Host, guarded | Runs on the user's machine as the user, with the guards in section 5. Last resort. |
| **I0** | No execution | Source analysis only. |

Record the level, the missing controls (for I2) and the approval mode in `plan.md`. Each E3 finding records the level it ran at. The report states both.

The isolation level does not change the evidence bar. An E3 result at I1 is still E3. It changes the risk to the user's machine, not the truth of the result.

## 2. The five controls of a full sandbox

1. **No external network.** Loopback inside the sandbox is allowed for a local test server.
2. **Empty environment.** Start from no variables. Add only what the command needs, with safe values. `HOME` and temporary directories point into scratch.
3. **Read-only target.** Target code cannot change the original checkout. Build in a copy inside scratch.
4. **Scratch-only writes.** Target code can write only inside one scratch directory. It cannot see the user's home directory, credentials, SSH or cloud config, sockets of other services, or the audit output directory.
5. **Resource limits.** CPU, memory, process count, file size and wall-clock time are limited.

## 3. Detect the options

Run these checks (T1 needed). Record what you find in `plan.md`.

**Operating system**
- Linux or macOS: `uname -s`. WSL: `grep -qi microsoft /proc/version && echo wsl`.
- Windows (PowerShell): `$env:OS`; WSL present: `wsl --status` and `wsl -l -v`.

**Sandbox tools.** A tool counts only if a test command succeeds:
| Tool | Test | Notes |
|---|---|---|
| Docker | `docker info` and `docker run --rm --network none <local image> true` | Needs a local image. Pulling one uses the network: ask first. |
| Podman | `podman info`, then the same test | Rootless by default. Preferred over Docker where both exist. |
| bubblewrap (Linux) | `bwrap --ro-bind / / --unshare-all true` | No image needed. Needs unprivileged user namespaces. |
| firejail, nsjail (Linux) | `firejail --net=none true`, `nsjail --help` | |
| Disposable VM | the user tells you | Full isolation if the VM has no network and no shared folders other than scratch. |
| Windows Sandbox | the user tells you | Disposable VM on Windows Pro and Enterprise. Hard to drive from an agent; the user runs commands in it. |

## 4. Ask the user

Ask once, before the first execution. In Full mode, ask during phase 0. In Focused mode, ask when the first execution is needed. Use the agent's question tool if it has one. Otherwise ask in plain text and wait.

Explain what you want to run and why: "to reproduce findings that need E3 (memory safety, races, parser differences), and to raise confidence in others".

Offer only the options that apply. Put the safest available option first.

```text
Some findings need the target's code to run so they can be reproduced.
I detected: <OS>, <sandbox tools that passed the test, or "no sandbox tool">.

How should I run target code?

1. <Detected sandbox> – full sandbox (I3). Recommended.
2. Set up a sandbox first. I give you the steps (section 6). You run them, or
   allow me to run them. Some steps need admin rights or a download.
3. WSL (Windows only). <Hardened: I3/I2 | default settings: I2>.
   Default WSL can read your Windows drives, start Windows programs and use
   the network. Section 6 shows how to close these gaps.
4. On this machine with guards (I1). Last resort. Target code runs as you.
   It can read your files, including keys and tokens, and use your network.
   The guards reduce this risk; they do not remove it.
5. Do not run target code (I0). Findings that need reproduction stay
   "needs validation", each with a test plan you can run later.

And for the chosen option:
a. Ask me before each command.
b. Run commands at this level for this audit without asking.
```

Defaults for the approval question: `b` for I3, `a` for I2 and I1.

**Rules**
- Never fall back to a weaker level on your own. If the chosen sandbox fails, stop executing and ask again.
- In an unattended run (no one can answer), use only a level the user approved before (in `plan.md` or a standing instruction). Otherwise use I0.
- With approval mode `a`, show the exact command, its working directory and its expected effect, then wait. Sub-agents with mode `a` do not run commands: they return the commands to the orchestrator, which asks the user.
- Ask again before you download anything (container images, packages, toolchains), even inside a sandbox. Target dependencies are fetched only if the user allows it, and only inside the sandbox.
- Do not install system software or change system configuration (including `wsl.conf`) without the user's approval of the exact change. Prefer to give the user the steps.

## 5. Safety floor at every level

These apply at I1, I2 and I3:
- Work on a copy of the target in scratch. Never build in the original checkout.
- Use dummy accounts, keys and data. Never real credentials or production data.
- Never send traffic to a live or deployed system.
- Use a wall-clock limit on every command (`timeout 300 <cmd>` or equivalent).
- Stop at the minimum effect (SKILL.md section 3).
- Do not run as root or administrator.

Extra guards at I1 (host):
- Clean environment: `env -i PATH=/usr/bin:/bin HOME="$SCRATCH" TMPDIR="$SCRATCH/tmp" <cmd>`.
- Limits on Linux: `prlimit --as=4000000000 --fsize=1000000000 --nproc=512 -- <cmd>`. Without `prlimit`, use one `ulimit` per option (`ulimit -v 4000000; ulimit -f 1000000; <cmd>`): `sh` (dash) rejects several options in one call and has no `-u`. macOS ignores some limits. `--nproc` counts all processes of the user, so raise it if the user already runs many.
- No network if the system allows it without admin rights: on Linux try `unshare -rn <cmd>`. If this fails, tell the user the command has network access.
- Prefer the smallest possible run: one unit test or one harness, not the full test suite or a full build, when that is enough.
- Before each command, check that it does not touch paths outside scratch.

## 6. Recipes

Replace `$SCRATCH` with the run's scratch directory and `$IMAGE` with a local image that has the needed toolchain. Copy the target into `$SCRATCH/src` first.

**Podman or Docker (I3)**
```sh
podman run --rm --network none --read-only \
  --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 256 --memory 2g --cpus 2 \
  --tmpfs /tmp:rw,size=256m \
  -v "$SCRATCH":/scratch:rw -w /scratch/src \
  --env HOME=/scratch \
  "$IMAGE" timeout 300 <command>
```
Use `docker` with the same flags if Podman is absent. Do not mount the original checkout, the home directory or the container socket. Do not build images from the target's own Dockerfile or dev-container files unless the user allows it: building them runs target instructions, often with network access.

**bubblewrap (I3, Linux)**
```sh
bwrap --unshare-all --die-with-parent --new-session \
  --ro-bind / / --tmpfs /home --tmpfs /root --tmpfs /run --tmpfs /tmp \
  --dev /dev --proc /proc \
  --bind "$SCRATCH" "$SCRATCH" --chdir "$SCRATCH/src" \
  --clearenv --setenv PATH /usr/bin:/bin --setenv HOME "$SCRATCH" \
  prlimit --as=4000000000 --fsize=1000000000 --nproc=512 -- \
  timeout 300 <command>
```
`--ro-bind / /` makes system files readable. The `--tmpfs` lines hide home directories and runtime sockets. If scratch is under `/home` or `/tmp`, put it elsewhere or bind it after the `--tmpfs` lines, as shown.

**WSL on Windows**
- Default WSL is I2: Windows drives are mounted under `/mnt/c` and similar, Windows programs can be started, and the network is on.
- To harden, use a separate distribution only for audits (for example, import a clean root file system with `wsl --import`). In that distribution's `/etc/wsl.conf` set:
  ```ini
  [automount]
  enabled=false
  [interop]
  enabled=false
  appendWindowsPath=false
  ```
  Then run `wsl --shutdown` from Windows and start the distribution again.
- The network is still on. For I3, run commands inside the hardened distribution with bubblewrap or Podman as above. Without them, the hardened distribution is I2 (missing control: network).
- Do not change the user's everyday distribution without approval.

**Setup steps to offer (option 2)**
- Linux: install `bubblewrap` or `podman` from the distribution's package manager.
- macOS: install Podman (with `podman machine init`) or another container runtime. `sandbox-exec` is deprecated; do not rely on it.
- Windows: install WSL (`wsl --install`) and set up a hardened distribution as above, with Podman or bubblewrap inside it. Or use Windows Sandbox or a VM.
- Any OS: a disposable VM with no network and one shared scratch folder.

The user runs these, or approves each command you run. Admin rights may be needed.
