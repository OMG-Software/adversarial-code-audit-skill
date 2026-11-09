# Language: Shell (Bash, POSIX sh, PowerShell)

## Scope
- Covers: Bash 3.2 to 5.x, POSIX sh (dash, busybox ash), Windows PowerShell 5.1 and PowerShell 7+. Zsh and `cmd.exe` batch files are only noted where they differ.
- Contexts: install scripts and `curl | sh`, CI scripts (GitHub Actions `run:`, GitLab `script:`, Jenkins `sh`), cron jobs, systemd units, git hooks, container entrypoints, Makefile recipes, wrappers run through `sudo`, CGI scripts.

## Entry points
Shell scripts have no routes. Input comes from arguments, environment, files, other commands and CI context values.

- **Find scripts:** files with a shebang (`^#!.*\b(ba|da|z|k)?sh\b`), `*.sh`, `*.bash`, `*.ps1`, `*.psm1`, `Makefile`, `Dockerfile` `RUN` lines and entrypoints, `.github/workflows/*.yml` `run:`, `.gitlab-ci.yml` `script:`, `Jenkinsfile` `sh`, `crontab`, `/etc/cron.*`, `*.service` `Exec*`, `hooks/` directories, `sudoers` entries.
- **Direct input:** `$1`, `$@`, `$*`, `getopts`, `read`, stdin, `$QUERY_STRING` and `HTTP_*` variables (CGI), `$REPLY`, PowerShell `param()`, `$args`, `Read-Host`, `$input`.
- **Environment input:** `$PATH`, `$IFS`, `$HOME`, `$TMPDIR`, `$USER`, `$ENV`, `$BASH_ENV`, `$SHELLOPTS`, `$PS4`, `$LD_PRELOAD`, `$http_proxy`, PowerShell `$env:*`, `$PSModulePath`.
- **Data input:** file names from globs and `find`, output of `$(...)`, files read with `read` or sourced with `.` or `source`, API replies parsed with `jq`, `grep` or `ConvertFrom-Json`.
- **CI context values:** GitHub `${{ github.event.* }}`, `github.head_ref`, issue and pull request titles, branch names, commit messages. These are pasted into the script text before the shell runs. Also writes to `$GITHUB_ENV`, `$GITHUB_PATH` and `$GITHUB_OUTPUT`, and the triggers `pull_request_target` and `workflow_run`. GitLab `$CI_COMMIT_BRANCH`, `$CI_MERGE_REQUEST_TITLE`. Jenkins `${params.X}` inside Groovy double-quoted `sh "..."`.
- **Cron:** an unescaped `%` in a crontab command line means newline. Cron runs with a small `PATH`.
- **Privilege entry:** commands allowed in `sudoers` with a script path or wildcard arguments.

## Sinks by domain

| Domain | Dangerous API or pattern | Safer alternative | Notes |
|---|---|---|---|
| `injection` | `eval`, `bash -c "...$x..."`, `sh -c`, `ssh host "...$x..."`, `xargs -I{} sh -c '... {}'`, `find -exec sh -c '... {}'`, backticks, `source`/`.` of data | Run the program directly with an argument array: `cmd "${args[@]}"`. Pass values as `$1`: `sh -c 'cmd "$1"' _ "$x"` | `ssh` joins the arguments and the remote shell parses them again. |
| `injection` | Unquoted `$var` (word splitting and globbing) | `"$var"` | See the traps section. |
| `injection` | Option injection: `grep $pat file`, `rm $f`, `tar xf $f` | `--` before operands, `grep -e "$pat" -- file`, `./*` globs | A value that starts with `-` is an option. |
| `injection` | Arithmetic on strings: `$(( x ))`, `let`, `[[ $a -eq 1 ]]`, `((...))` | Check `[[ $x =~ ^[0-9]+$ ]]` first | Bash evaluates names in arithmetic. A value such as `a[$(cmd)]` can run a command. |
| `injection` | SQL or scripts in other languages inside strings: `psql -c "...$x"`, `mysql -e`, `sed "s/$x/y/"`, `awk "...$x"`, `jq ".$key"` | `psql -v name="$x"` with `:'name'`, `jq --arg k "$x"`, `awk -v` | GNU `sed` can run commands with the `e` flag. |
| `injection` | PowerShell `Invoke-Expression` (`iex`), `[scriptblock]::Create`, `& $cmd`, `Add-Type -TypeDefinition`, `$ExecutionContext.InvokeCommand.ExpandString`, `Start-Process -ArgumentList` string | Call the command with fixed name and an array of arguments | `ExpandString` runs `$(...)` in the text. |
| `input-parsing` | `read` without `-r`, `for f in $(ls)`, `ls \| while read`, parsing `ls` output, `tar`/`unzip`/`cpio` extraction, `curl -OJ` | `IFS= read -r`, `find -print0 \| xargs -0`, check entry names before extracting | File names can contain spaces, newlines and a leading `-`. GNU `tar` strips a leading `/` unless `-P`. |
| `input-parsing` | PowerShell `Get-ChildItem -Path $x`, `Remove-Item -Path $x` | `-LiteralPath` | `-Path` expands wildcards such as `[` and `*`. |
| `filesystem-process` | `/tmp/name.$$`, `> /tmp/x`, `mktemp -u`, `chmod 777`, `chmod -R`/`chown -R` through symlinks, `rm -rf "$d/"*` with empty `d`, `ln -sf` into shared directories | `mktemp -d` plus `trap ... EXIT`, `umask 077`, `${d:?}`, `chown -h` | Shared directories are hostile. |
| `filesystem-process` | Relative commands in privileged scripts, `PATH` with `.` or an empty entry, `#!/usr/bin/env bash` in privileged code, `sudo -E`, `env_keep`, `LD_PRELOAD`, `BASH_ENV`, `PS4` with `set -x`, PowerShell `$env:PATH`, `$PSModulePath`, writable `$PROFILE` | Set `PATH` at the top, absolute program paths, `env -i`, `-NoProfile` | A shell script with the setuid bit is not honoured by Linux. Do not rely on it. |
| `outbound-network` | `curl -k`, `wget --no-check-certificate`, `curl -L` to unvalidated hosts, `curl "$url"` with input, `ssh -o StrictHostKeyChecking=no`, `UserKnownHostsFile=/dev/null`, PowerShell `-SkipCertificateCheck` (7+), `ServerCertificateValidationCallback = {$true}` | `--proto '=https' --tlsv1.2`, pin hosts, `curl -fsS` | `file://` and other schemes work with `curl "$url"` unless limited with `--proto`. In CGI scripts the `HTTP_PROXY` variable can come from a request header. |
| `crypto` | `$RANDOM`, `date +%s` seeds, `openssl enc` without `-pbkdf2` (older default key derivation is weak), unauthenticated `-aes-*-cbc`, `md5sum`/`sha1sum` for trust, PowerShell `Get-Random` | `/dev/urandom` with `od` or `openssl rand`, `age` or `gpg`, `sha256sum -c` with a trusted checksum | `$RANDOM` has 15 bits. A checksum fetched from the same place as the file proves nothing. |
| `authn` / `authz` | Identity from `$USER`, `$SUDO_USER`, `$LOGNAME`; `[ "$EUID" = 0 ]` checks only; script runs as root for convenience | `id -u`, drop privileges early | Users can set `$USER`. |
| `secrets-config` | Secrets in script text, in arguments (`mysql -p"$PW"`, `curl -H "Authorization: $T"`), `export SECRET`, `set -x`, `env`/`printenv` dumps, `source .env` | Files with mode 600, `--config` or `-H @file`, `read -s`, no xtrace around secrets | Arguments show in `ps` and `/proc/<pid>/cmdline`. |
| `logging-privacy` | `set -x` in CI, verbose flags, `echo "$TOKEN"`, PowerShell `Start-Transcript`, script block logging of secrets, logs with loose mode | Mask values, avoid printing | GitHub `::add-mask::` hides only exact strings. |
| `supply-chain` | `curl ... \| sh`, `bash <(curl ...)`, `iex (irm ...)`, `wget -O- \| sudo bash`, unpinned `git clone`, `apt-get install` without versions, `npm install` instead of `npm ci`, `Install-Module` without `-RequiredVersion`, `uses: owner/action@v1` | Download, verify a signature or pinned digest, then run. Pin to a commit SHA | Hand off to `supply-chain`. |
| `cloud-deploy` | Dockerfile shell-form `RUN`/`ENTRYPOINT`, `docker run --privileged -v /:/host`, `kubectl apply -f <(...)`, `kubectl exec` with built strings | Exec form, least privilege | Hand off to `cloud-deploy`. |
| `local-ipc` | `nc -l`, `socat TCP-LISTEN:` without `bind=`, sockets in `/tmp`, `mkfifo` with open mode, `python3 -m http.server` on all interfaces | Bind to loopback, mode 600, owner check | |
| `concurrency` | `[ -e lock ] \|\| touch lock`, pid files, `kill $(cat pid)` | `mkdir lock`, `flock` | See the concurrency section. |
| `resource-exhaustion` | `:(){ :\|:& };:`, unbounded loops, `cat` of unbounded input, huge globs | `timeout`, `ulimit`, `xargs -P` bounds | A glob that exceeds the argument limit fails. If the script ignores failure, it continues. |
| `sandbox` | `rbash`/`bash -r` as a boundary, PowerShell execution policy as a boundary | OS-level isolation | See the build and runtime section. |
| `business-logic` | Exit-code logic, `&&`/`\|\|` chains used as if-else | Explicit `if` | `a && b \|\| c` runs `c` when `b` fails. |

## Language traps

- **Unquoted expansion.** Wrong: `rm -rf $dir/*` (empty `dir` becomes `/*`; spaces split). Right: `rm -rf -- "${dir:?}"/*`.
- **Option injection.** Wrong: `grep $pat "$file"`. Right: `grep -e "$pat" -- "$file"`. Use `./*` instead of `*` in loops.
- **Re-parsing.** Wrong: `bash -c "tar xf $f"`. Right: `tar xf -- "$f"`, or `bash -c 'tar xf -- "$1"' _ "$f"`.
- **`set -e` gaps.** It does not stop on a failure inside `if`, `while`, `&&`, `||`, `!`, or in a function called in such a context. `local x=$(cmd)` hides the status of `cmd`. Command substitutions ignore it unless `shopt -s inherit_errexit` (Bash 4.4+).
  - Wrong: `local out=$(risky)`. Right: `local out; out=$(risky)`.
- **`pipefail` limits.** `set -o pipefail` is not in every `sh`. Test the target shell. A reader that closes early (`yes | head -1`) gives status 141 and a false failure.
- **`set -u` limits.** Bash before 4.4 reports an empty array as unset with `"${a[@]}"`.
- **Failing test fails open.** Wrong: `[ "$count" -gt 5 ] && deny` (an empty or non-numeric `count` makes `[` fail, so `deny` does not run). Right: validate the number first and make the default branch deny.
- **Subshell pipelines.** Wrong: `cat f \| while read l; do n=1; done; echo "$n"` (the loop is a subshell). Right: `while read -r l; do n=1; done < f`.
- **Pattern match.** `[[ $a == $b ]]` treats `$b` as a pattern. Right: `[[ $a == "$b" ]]`. Bash `=~` with a quoted right side matches literally.
- **Octal.** `$((08))` fails and `$((010))` is 8. Right: `$((10#$n))`.
- **`echo`.** `echo "$x"` can eat `-n` or expand `\n` (dash). Right: `printf '%s\n' "$x"`. A `printf "$x"` call is a format string bug.
- **Filenames.** Wrong: `for f in $(ls)`. Right: `for f in ./*`, or `find . -print0 | while IFS= read -r -d '' f`.
- **Temp files.** Wrong: `tmp=/tmp/app.$$`. Right: `tmp=$(mktemp -d) && trap 'rm -rf -- "$tmp"' EXIT`.
- **Command lookup.** Aliases and functions beat programs. `\cmd` and `command cmd` bypass them. In privileged scripts set `PATH` first.
- **Shell dialect.** `sh` is dash on many systems. `[[`, arrays, `<(...)`, `${v//a/b}` and `local` may fail there. macOS ships Bash 3.2: no `mapfile`, no `declare -A`, no `${v@Q}`.
- **CRLF.** `\r` in a shebang gives "bad interpreter". `\r` at the end of a value breaks comparisons.
- **Shebang flags.** `#!/bin/bash -e` is ignored when a user starts the script with `bash script`. Put `set -e` in the file.
- **PowerShell comparison.** `-eq` is case-insensitive (`-ceq` is exact). `-like` uses wildcards. `-match` is an unanchored regex. With an array on the left, `-eq` filters instead of comparing.
- **PowerShell output pollution.** Every uncaptured output becomes part of the return value.
  - Wrong: `function Test-Admin { Get-Thing; return $false }` returns an array that is true. Right: `$null = Get-Thing`.
- **PowerShell errors.** `$ErrorActionPreference` defaults to `Continue`. `try/catch` catches terminating errors only. Use `-ErrorAction Stop`. A native program's exit code is in `$LASTEXITCODE`. `$PSNativeCommandUseErrorActionPreference` (7.3 experimental, stable in 7.4) can turn it into an error.
- **PowerShell strings.** `"$x"` and `"$(...)"` expand. Use single quotes for text. `Start-Process -ArgumentList` joins its values and does not quote them. Native command quoting changed in 7.3 (`$PSNativeCommandArgumentPassing`). State the version.

## Deserialisation and reflection

- **Eval-like features in Bash:** `eval`, `source` and `.`, `bash -c`, `declare`/`typeset`, `printf -v`, indirect expansion `${!name}`, namerefs (`declare -n`), `trap "$cmd"`, `xargs sh -c`, `export -f` (functions in the environment), `alias` (only in interactive shells unless `expand_aliases`).
- **Sourced configuration.** `. /etc/app.conf` runs code with the script's rights. Check who can write the file. A parsing alternative is `while IFS== read -r k v` with an allow-list of `k`.
- **Data to code.** `eval "$(cmd)"` is safe only if `cmd` output is trusted. `base64 -d | bash` is code download. If `eval` is unavoidable, quote with `printf '%q'` or `${v@Q}` (Bash 4.4+).
- **PowerShell:** `Invoke-Expression`, `iex`, `[scriptblock]::Create`, `Invoke-Command -ScriptBlock`, `Start-Job -ScriptBlock`, `Add-Type`, `[Reflection.Assembly]::Load`, `New-Object -ComObject`, dot-sourcing (`. .\file.ps1`), `Import-Module` from a path.
- **Data loaders.** `ConvertFrom-Json` and `Import-PowerShellDataFile` parse data without running code. Prefer them over dot-sourcing a config. `Import-Clixml` rebuilds object graphs with limited types. Treat the file as input and check sizes.
- **Execution policy.** It is a safety feature against accidental runs, not a security boundary. `-ExecutionPolicy Bypass`, `Get-Content f \| iex` and `-EncodedCommand` skip it. A control that relies on the policy alone is not a control.
- **Constrained Language mode** (`$ExecutionContext.SessionState.LanguageMode`) and Just Enough Administration limit what scripts can do. They are real controls only when the system enforces them.

## Concurrency

- **Locks.** `[ -e lock ] || touch lock` has a gap. Use `mkdir lockdir` (atomic) or `flock`. Pid files can point to a reused pid.
- **Cron overlap.** A job can start again before the last run ends. Use `flock -n`.
- **Background jobs.** `cmd &` hides failures. `wait` returns the status of the job you name, or zero.
- **Signals.** `trap ... EXIT` does not run on `kill -9`. Temp files stay. A `trap` set after the file is created leaves a gap.
- **Check then use.** `[ -f "$f" ] && cat "$f"` races with a symlink swap in a shared directory.
- **PowerShell.** `Start-Job`, `ForEach-Object -Parallel` (7+), and mutexes (`[System.Threading.Mutex]`). Variables do not share state across jobs unless `$using:` copies them.

## Build and runtime settings

- **The usual header.** `set -euo pipefail` is a debugging aid, not a safety proof. See the `set -e` traps above. Add `IFS=$'\n\t'`, `umask 077` and an explicit `PATH`. `shopt -s nullglob failglob inherit_errexit` (Bash 4.4+ for the last).
- **Bash privileged mode.** `bash -p` does not read `$ENV` or import functions when the real and effective user differ. Use `env -i` for a clean environment.
- **Debug output.** `set -x` and `bash -x` print expanded values, including secrets. `PS4` can hold command substitutions.
- **GitHub Actions.** A step without `shell:` runs `bash -e {0}` (no `pipefail`). With `shell: bash` it runs `bash --noprofile --norc -eo pipefail {0}`. Treat `${{ }}` in `run:` as text pasted into the script. Safe pattern: pass the value through `env:` and read `"$VAR"`. Permissions: check `permissions:` and the secrets that `pull_request_target` steps can read.
- **GitLab.** Check whether a failing command in the middle of a multi-line `script` block stops the job in the runner in use.
- **Cron and systemd.** `%` in crontab, a small `PATH`, a missing `HOME`. systemd `Exec*` does not use a shell unless you write `sh -c`.
- **PowerShell.** `Set-StrictMode -Version Latest`, `$ErrorActionPreference = 'Stop'`, `-NoProfile -NonInteractive` for scheduled tasks, `$ConfirmPreference`, `$PSModuleAutoLoadingPreference`. Script block logging and transcription policies can capture secrets.
- **`cmd.exe` batch.** `%var%` expands before parsing. `^`, `&` and `|` need escaping. Treat it as unsafe for input handling.

## Tools

Run only tools that are installed. This section agrees with `phase-leads.md` section 2.1: the multi-language row (Semgrep with local rules, `--metrics=off`) and the secrets row apply. ShellCheck and PSScriptAnalyzer are extra tools for this language.

| Tool | Offline-safe command | Notes |
|---|---|---|
| ShellCheck | `shellcheck -x -S style -f gcc script.sh`, add `-s bash`, `-s sh` or `-s dash` | `-x` follows `source`. Useful codes: SC2086 (unquoted), SC2046 (unquoted substitution), SC2064 (trap quoting), SC2115 (`rm -rf "$x/"` may be empty), SC2155 (declare and assign), SC2162 (`read` without `-r`), SC2029 (`ssh` expands locally), SC2294 (`eval` with arrays), SC2012 (`ls` parsing), SC2016 (single quotes block expansion). |
| Syntax check | `bash -n script.sh`, `sh -n script.sh`, `dash -n script.sh` | Parses only. Does not run the script. |
| checkbashisms | `checkbashisms script.sh` | Part of devscripts. Finds Bash-only syntax in `sh` scripts. |
| PSScriptAnalyzer | `pwsh -NoProfile -Command "Invoke-ScriptAnalyzer -Path . -Recurse -Severity Warning,Error"` | Module must exist already. Rules to read: `PSAvoidUsingInvokeExpression`, `PSAvoidUsingPlainTextForPassword`, `PSAvoidUsingConvertToSecureStringWithPlainText`, `PSAvoidUsingUsernameAndPasswordParams`, `PSUsePSCredentialType`, `PSAvoidUsingBrokenHashAlgorithms`, `PSAvoidUsingCmdletAliases`. |
| actionlint | `actionlint -no-color` | Reads `.github/workflows`. Reports untrusted context values in `run:` and runs ShellCheck on scripts if present. `zizmor` is another workflow analyser. |
| Semgrep | `semgrep --config ./local-rules --metrics=off .` | Never `--config auto`. |
| Secrets | `gitleaks`, `trufflehog --no-verification` | Never verify. Never copy values. |
| Test runners | Bats (`bats test/`), Pester (`Invoke-Pester`) | Test code is target code. See `execution.md`. |

Do not run an install script, a CI script or a cron job on the host to "see what it does". Read it, or run it with stubs in the sandbox.

## Lead searches

| Regex | Meaning | False-hit notes |
|---|---|---|
| `\beval\b\|\bsource\b\|^\s*\.\s+\S\|bash\s+-c\|sh\s+-c\|xargs\b.*\bsh\b\|-exec\s+(ba)?sh` | Re-parsing and code loading | Fixed strings are fine. `eval "$(ssh-agent -s)"` is a known pattern. |
| `(curl\|wget)[^\n]*\|\s*(sudo\s+)?(ba)?sh\b\|bash\s+<\(\s*(curl\|wget)\|iex\b.*(irm\|iwr\|Invoke-(Rest\|Web)Method)` | Download and run | Documentation text and comments. |
| `\$[A-Za-z_][A-Za-z0-9_]*[^"A-Za-z0-9_}]` outside quotes | Unquoted variable | Many false hits. Prefer ShellCheck SC2086. |
| `rm\s+-[a-zA-Z]*[rf][a-zA-Z]*\s+[^\n]*\$` | Delete with a variable | Check for `${var:?}` and `--`. |
| `/tmp/[^\s"']*\$\$\|mktemp\s+-u\|>\s*/tmp/\|chmod\s+(-R\s+)?(0?777\|a\+w\|o\+w)` | Weak temp files and modes | |
| `(curl\|wget)[^\n]*(\s-k\b\|--insecure\|--no-check-certificate)\|StrictHostKeyChecking\s*=?\s*no\|SkipCertificateCheck\|ServerCertificateValidationCallback` | TLS and host key checks off | Local test scripts. |
| `\$\{\{\s*(github\.(event\|head_ref)\|inputs\.\|steps\.[^}]*outputs)[^}]*\}\}` in `run:` | CI expression injection | A value passed through `env:` is safe. Fixed values such as `github.sha` are low risk. |
| `GITHUB_(ENV\|PATH\|OUTPUT)\|pull_request_target\|workflow_run\|uses:\s*[^@\s]+@(v?[0-9]\|main\|master)` | CI trust and pinning | Pin to a full commit SHA. |
| `-p\s*["']?\$\|--password\|Authorization:\s*\$\|export\s+\w*(TOKEN\|SECRET\|PASSWORD\|KEY)` | Secrets in arguments or environment | |
| `set\s+-[a-zA-Z]*x\|bash\s+-x\|Start-Transcript` | Debug output | Check what is in scope. |
| `\$RANDOM\|openssl\s+enc\b\|md5sum\|sha1sum` | Weak randomness or hashes | Non-security use is fine. |
| `\$\(\(.*\$\|let\s+\w+=.*\$\|\[\[?\s+[^]]*-(eq\|ne\|lt\|gt\|le\|ge)\s` | Arithmetic on input | Validate numbers first. |
| `Invoke-Expression\|\biex\b\|\[scriptblock\]::Create\|ExpandString\|Add-Type\|Start-Process[^\n]*-ArgumentList` | PowerShell dynamic code and quoting | |
| `-ExecutionPolicy\s+Bypass\|Set-ExecutionPolicy\|-EncodedCommand\|-enc\b` | Policy bypass | Developer helper scripts. |
| `ConvertTo-SecureString[^\n]*-AsPlainText\|-Path\s+\$` | Plain-text secrets, wildcard paths | |
| `\[\s+-e\s+[^]]*\]\s*(&&\|\|\|)\|kill\s+\$\(cat\|\.pid\b` | Lock and pid races | |
| `shellcheck\s+disable\|#\s*nosec\|PSScriptAnalyzer.*SuppressMessage` | Silenced analyser | Strong lead. |

## Verification notes

- **Smallest harness: command stubs.** Create a scratch directory with fake `rm`, `curl`, `sudo`, `ssh`, `psql` and similar programs. Each stub records its arguments with `printf '%s\0' "$@" >> "$SCRATCH/argv.log"` and exits. Run the script (or one function, after `source`) with `env -i PATH="$SCRATCH/bin:/usr/bin:/bin" HOME="$SCRATCH"` and a hostile value. Assert on the recorded arguments. No real effect occurs.
- **Hostile values to use:** a value with a space, a leading `-`, `$(touch "$SCRATCH/canary")`, a newline, a glob `*`, an empty string, and an unset variable. Check that the canary file does not exist.
- **CI scripts.** Copy the `run:` body to a file. Replace each `${{ ... }}` with the hostile value as text, as the runner would. Run it with stubs. This shows the injection without a CI service.
- **Install scripts and `curl | sh`.** Do not run them. Trace the URL scheme, the verification step and the pinning by reading. E1 is enough for the finding "downloaded code runs unverified" when the code path is plain.
- **PowerShell.** Run `pwsh -NoProfile -NonInteractive -File test.ps1` with Pester `Mock` for external commands. Record the PowerShell version, since native argument handling depends on it.
- **Shell dialect.** Run the test with the shell named in the shebang (`dash`, `bash`). Many bugs exist in only one.
- **False positives.** Unquoted variables that hold a script-set constant or a number. `eval` of output from a trusted local tool. `rm -rf "$tmp"` where `tmp` comes from `mktemp -d` in the same script. Documentation or comments that contain `curl | sh`. A CI value that is only passed through `env:`.
- **Needs E3.** Word-splitting and `set -e` claims that depend on shell version, races in lock and temp file code, PowerShell native-command quoting, and any claim about cron, systemd or runner behaviour.
