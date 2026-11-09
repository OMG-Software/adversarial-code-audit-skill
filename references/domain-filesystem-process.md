# Domain: Filesystem and Process

## Scope

- **Load when:** the code creates, opens, moves or deletes files, directories, sockets or pipes; sets permissions; uses temporary directories; runs with more privilege than the user who gives it work; starts child processes; reads environment variables that change behaviour; installs signal handlers; or runs as a service, daemon, installer, updater or setuid program.
- **Covers:** file modes, umask and Windows ACLs; temporary files; symlink, hard-link and junction attacks; file TOCTOU; privileged writes to user-writable paths; setuid programs; privilege dropping; child-process environment and inherited descriptors; environment variables and search paths; signal handlers; cleanup after crashes; Windows path features.
- **Hand off to:**
  - `domain-input-parsing.md` – path strings from input: traversal, encodings, archive entry names, upload names. Here the dividing line is the file system object: links, races, modes and owners.
  - `domain-injection.md` – input that becomes part of a shell string or argument list (INJ-03). This file owns the process attributes: environment, descriptors, privileges and search path.
  - `domain-local-ipc.md` – who may connect to a local socket or pipe, and what the peer may ask. This file owns the permissions of the socket or pipe object.
  - `domain-concurrency.md` – races inside one process. This file keeps races between processes through the file system.
  - `domain-secrets-config.md` – secret storage policy and configuration precedence. This file owns the file mode and location of those files.

## Invariants

Fill the placeholders from `threat-model.md`.

1. **Creation mode:** Every file, directory, socket and pipe that holds <sensitive data or controls behaviour> is created with a mode or ACL that only <owner or service account> can use. The mode is set at creation, not afterwards.
2. **Private temporary space:** Temporary files are created with unpredictable names, in a directory that other users cannot write, with exclusive creation.
3. **No link following:** Code with privilege that opens a path in a directory writable by a lower-trust user does not follow links, junctions or reparse points that the lower-trust user can place.
4. **Check is use:** The object that a check examines is the object that the code then opens, reads or changes. The code holds one handle between the check and the use.
5. **Trusted locations:** Privileged code reads code, configuration and libraries only from locations that lower-trust users cannot write. It writes only to locations that it controls.
6. **Complete drop:** When the program drops privilege, it drops all groups, all user IDs and all capabilities or token privileges, in the right order, and it checks the result.
7. **Clean child:** A child process gets only the environment, working directory, descriptors and handles it needs. It does not get secrets in its command line.
8. **Controlled search:** The program finds executables and libraries by fixed absolute path, or by a search path that lower-trust users cannot write or set.
9. **Safe handlers:** Signal handlers do only async-signal-safe work. A crash or kill leaves no state that a later run or another user can abuse.

## Recon additions

Add a heading "Privilege and file map" to `threat-model.md`.

| Process or component | Runs as (user, privileges) | Starts from (installer, service, setuid, user) | Files and directories it writes (path, mode or ACL, who else can write the directory) | Files and directories it reads that others can write | Child processes it starts | Environment variables it reads |
|---|---|---|---|---|---|---|

Then add these notes:
1. **Privilege boundaries.** List each place where a higher-privilege process acts on data, paths or names from a lower-privilege user: services, daemons, setuid binaries, update helpers, installers, scheduled jobs, backup tools, log rotators, container entry points.
2. **Shared locations.** List each use of shared directories: temporary directories, runtime directories, cache, spool, home directories, mounted volumes, shared network folders.
3. **Environment reads.** List each environment variable the code or its dependencies read. Mark the ones that change code loading, paths or behaviour.

## Lead searches

Adapt the patterns to the language. The language file adds the concrete APIs.

| Search | A hit may mean | False-hit notes |
|---|---|---|
| `chmod\|umask\|0o?777\|0o?666\|0o?644\|S_IW(OTH\|GRP)\|FILE_ALL_ACCESS\|Everyone\|BUILTIN\\Users\|SetSecurity\|icacls\|chown` | Permission setting (FP-01) | A wide mode on a public file is normal. Check what the file holds. |
| `/tmp\|/var/tmp\|%TEMP%\|GetTempPath\|tmpnam\|tempnam\|mktemp\|tempfile\|TMPDIR\|os\.tmpdir\|getpid\(\)` in a file name | Predictable or shared temporary path (FP-02) | `mkstemp`-style and `mkdtemp`-style calls are the safe forms. |
| `symlink\|readlink\|lstat\|realpath\|O_NOFOLLOW\|FILE_FLAG_OPEN_REPARSE_POINT\|junction\|link\(` | Link handling (FP-03) | A `realpath` before use is not safe by itself (FP-04). |
| `access\(\|stat\(\|exists\|isfile\|is_file\|isdir\|os\.path\.\|File\.Exists\|faccessat` then `open\|rename\|unlink\|chmod\|copy` | Check then use (FP-04) | Fine when both calls use one open handle. |
| `setuid\|seteuid\|setgid\|setgroups\|initgroups\|setresuid\|setresgid\|prctl\|cap_set\|capset\|AdjustTokenPrivileges\|ImpersonateLoggedOnUser\|RevertToSelf\|runas\|sudo\|drop_?priv` | Privilege change (FP-06) | The order and the checks of return values are the lead. |
| `fork\|exec\w*\(\|posix_spawn\|CreateProcess\|ShellExecute\|Popen\|spawn\|system\(\|popen\|inherit\|close_fds\|O_CLOEXEC\|FD_CLOEXEC\|bInheritHandles` | Child process setup (FP-07) | Argument content is injection's lead. Here check env, descriptors and handles. |
| `getenv\|environ\|os\.environ\|process\.env\|Environment\.GetEnvironmentVariable\|putenv\|setenv\|PATH\|LD_PRELOAD\|LD_LIBRARY_PATH\|DYLD_\|PYTHONPATH\|NODE_OPTIONS\|RUBYLIB\|PERL5LIB\|CLASSPATH\|IFS\|TMPDIR\|HOME` | Behaviour set by environment (FP-08) | Reading `HOME` for a user program is normal. In setuid or service code it is a lead. |
| `dlopen\|LoadLibrary\|LoadLibraryEx\|SetDllDirectory\|SearchPath\|CreateProcess.*NULL\|import \w+` for a bare name in a privileged program; unquoted service paths with spaces | Search path load (FP-08) | A full path or a safe-search flag is the control. |
| `signal\(\|sigaction\|SIGINT\|SIGTERM\|SIGHUP\|SIGCHLD\|SIGPIPE\|atexit\|SetConsoleCtrlHandler` | Signal and exit handling (FP-09) | A handler that sets a flag only is safe. |
| `:\$DATA\|::\$DATA\|~1\|CON\b\|PRN\|AUX\|NUL\|COM[1-9]\|LPT[1-9]\|\\\\\?\\\|\\\\\.\\\|GetShortPathName\|GetFullPathName` | Windows path features (FP-10) | |

## Attack classes

### FP-01 Creation modes, umask and permissions

- **What fails:** a file, directory, socket, pipe, shared-memory object or registry key is created with rights wider than the data needs. Another local user reads secrets, or changes data or code that a privileged process trusts.
- **Where to look:** key, token and database files; log and crash-dump files; pid files and sockets; install directories and service binaries; files written before `chmod`; code that depends on the process umask; Windows code that passes a default security descriptor; shared memory and named pipes; backup files.
- **Questions:**
  - Is the mode set in the creating call, or after it? The gap is a window.
  - Does the code depend on the inherited umask or the parent directory's ACL? Who controls those?
- **Sad-path inputs:** a permissive umask; a parent directory owned by another user; a pre-existing file with a wider mode; an update or rotation that recreates the file.
- **Evidence for confirmed:** the creating call with its mode or ACL, the data it holds, the principal that can read or write, and the effect. A mode set explicitly in code can be E1. Effective rights that depend on a deployment umask or ACL inheritance are external: `needs-validation`, or E3 in a sandbox.
- **Not a finding:** a public file by design; a private parent directory with correct rights; a lower-trust user who is the file owner.
- **CWE:** CWE-276; CWE-732 (class-level; use CWE-276 or a more specific child when one fits).

### FP-02 Temporary files and shared directories

- **What fails:** the program uses a predictable name, a shared directory or a non-exclusive create. Another user pre-creates, replaces, reads or races the file.
- **Where to look:** temporary files in the system temp directory; names built from process ID, time or a counter; helper scripts and installers; sockets and lock files in shared runtime directories; download and extract staging areas; editors and tools that write swap or backup files; code that reuses an existing path if it exists.
- **Questions:**
  - Does the code create the file with an exclusive-create flag and an unpredictable name? Does it use the platform's safe temporary-file function?
  - Is the directory private to the user or the service, or is it shared?
- **Sad-path inputs:** a pre-created file, link or directory at the predicted path with another owner; two instances that start together; a full disk.
- **Evidence for confirmed:** the name construction, the missing exclusive create or private directory, and the lower-trust actor that can pre-create the path. A planted file in a scratch directory that the program then uses is E3. E1 is acceptable for plain predictable names when the API semantics are documented.
- **Not a finding:** the file lives in a private per-user directory with exclusive creation; the file holds public, non-controlling data.
- **CWE:** CWE-377 (class-level); CWE-379; CWE-378.

### FP-03 Symlink, hard-link and junction attacks

- **What fails:** a privileged program opens, writes, changes the mode of or deletes a path in a location that a lower-trust user can influence. The user plants a link, so the operation hits a different file.
- **Where to look:** services and installers that write to user-writable directories; log rotation and cache cleaning; backup, restore and update helpers; recursive delete and recursive chown or chmod; privileged extraction; Windows services that use paths in user profiles or `ProgramData`.
- **Questions:**
  - Can a lower-trust user create entries in the directory? If not, links are not a risk there.
  - Does the open use a no-follow flag, or open relative to a directory handle? On Windows, does it use flags that do not follow reparse points?
  - On Windows, can a junction or mount point redirect a directory that the program creates or deletes in?
- **Sad-path inputs:** a symbolic link at the target name pointing to a scratch file; a hard link to a scratch file; a directory replaced by a link between two operations; on Windows, a junction at a directory name.
- **Evidence for confirmed:** the privileged operation, the writable directory, the missing no-follow protection, and a scratch test in which the operation changes a marker file outside the intended tree. Link behaviour depends on the OS and file system, so E3 is the normal level.
- **Not a finding:** the directory is writable only by the same principal that runs the program; the operation uses no-follow semantics throughout.
- **CWE:** CWE-59; CWE-61; CWE-62; CWE-64; CWE-65.

### FP-04 File TOCTOU (check, then open)

- **What fails:** the code examines a path, then acts on the path. A lower-trust actor changes what the path names between the two steps.
- **Where to look:** existence, type, owner, size or mode checks before an open, rename, delete or exec; resolve-then-open containment checks; hash or signature checks of a file on disk followed by a separate load; lock-file and pid-file logic; installers that verify then install from the same path.
- **Questions:**
  - Between check and use, does the code re-resolve the path name? Or does it hold one open handle or descriptor for both?
  - Can a lower-trust actor write to the directory, or to any directory on the path?
  - Does a verify-then-load flow read the bytes it verified, or does it read the file again?
- **Sad-path inputs:** replace the file, directory or link between check and use; a swap with a controlled delay in a test build; two processes that start together.
- **Evidence for confirmed:** the check line, the use line, the gap, the writable location, and a deterministic reproduction (a barrier or injected pause in a test build) with the effect on a marker file. A race seen once is not E3. E3 is required (SKILL.md section 6). Without T2, the verdict is `needs-validation` with a reproduction plan.
- **Not a finding:** the check and the use run on one open handle; the directory is writable only by the same principal; the check is only a hint and the use re-validates.
- **CWE:** CWE-367.

### FP-05 Privileged code that reads or writes untrusted locations

- **What fails:** a privileged process writes to, or trusts files in, a place that a lower-trust user can write. The user then controls what the privileged code writes, reads, loads or runs.
- **Where to look:** services that read configuration, scripts, plugins or libraries from a directory with weak rights; installers that put binaries in writable directories; unquoted service paths with spaces on Windows; scheduled jobs that run scripts from writable paths; update helpers that stage files in a user directory.
- **Questions:**
  - For each privileged read of code or configuration: who can write the file and each parent directory?
  - For each privileged write: who can read the result? Who can replace the target or its parent?
- **Sad-path inputs:** a writable configuration file; a writable plugin directory; a path argument that names a protected file; a service path with spaces and no quotes.
- **Evidence for confirmed:** the privileged consumer, the location and its rights (from the installer or the code), and the lower-trust writer. Rights set by an installer in the repository can be E1. Rights that depend on the deployment are external.
- **Not a finding:** the writer is already as privileged as the consumer; the location is root-owned or admin-only in the default install.
- **CWE:** CWE-732 (class-level); CWE-426; CWE-427 for search-path variants; CWE-250 for needless privilege.

### FP-06 Setuid, setgid and privilege dropping

- **What fails:** a program that holds elevated rights uses them for a lower-trust request, drops them incompletely or in the wrong order, or fails to check that the drop worked.
- **Where to look:** setuid and setgid binaries; services that start as root or as an administrator and then switch user; helpers started by a more privileged parent; code that uses capabilities or token privileges; Windows impersonation; container entry points; code that keeps a privileged descriptor after the drop.
- **Questions:**
  - Is the order correct? Supplementary groups, then group ID, then user ID. Does the code use calls that set real, effective and saved IDs together?
  - Does the code clear supplementary groups and drop capabilities, not only change the user?
  - Is every return value checked? Does the program continue if the drop fails?
  - Does the program keep an open privileged descriptor, or a saved ID that lets it regain rights?
  - Does a setuid program trust its environment, its arguments, its working directory or files in the caller's control?
  - On Windows, does impersonation revert on every path, including errors?
- **Sad-path inputs:** a drop call that fails (a test build with the call forced to fail); a caller with unusual groups; a hostile environment and working directory; an error path in impersonated code.
- **Evidence for confirmed:** the drop sequence at file:line, the missing step or check, and the retained right that a later step uses. A wrong order or an unchecked return is E1 when documented API behaviour fixes the result. A claim that depends on kernel behaviour needs E3.
- **Not a finding:** a program that never holds extra rights; a drop that happens in a helper that the code checks.
- **CWE:** CWE-273; CWE-250. For general escalation, name the weakness in words.

### FP-07 Child processes, descriptors and inherited state

- **What fails:** a child process receives more than it needs: secret descriptors, handles, environment, working directory or command-line secrets. Or the parent mishandles its pipes and exit status.
- **Where to look:** every process start; descriptors opened without the close-on-exec flag; Windows handle inheritance; secrets passed on the command line (visible to other users in process listings); environment copied whole to children; children started with a user-controlled working directory; pipes whose peers can block; zombie or orphan handling.
- **Questions:**
  - Which descriptors or handles does the child inherit? Does the code set close-on-exec by default, or list inherited handles explicitly?
  - Does the child get the full environment, including tokens and credentials?
  - Does the child start in a working directory that a lower-trust user controls, and does it load files from there?
- **Sad-path inputs:** a descriptor open to a secret file at the time of the spawn; a full environment with a marker secret; a child that exits with an error; a child that never exits.
- **Evidence for confirmed:** the spawn call, the leaked item, and the child that gains access it must not have (a child less trusted than the parent, such as a plugin, an unprivileged helper or a user-chosen program). A listing of the child's open descriptors in a scratch test is E3.
- **Not a finding:** the child is as trusted as the parent and needs the item; the secret is only in the parent's memory.
- **CWE:** CWE-403; CWE-214.

### FP-08 Environment variables and search paths

- **What fails:** the environment or a search path changes what code the program loads or runs. A lower-trust actor who controls the variable or the search directory runs their code or changes behaviour in a more privileged program.
- **Where to look:** setuid programs, services and helpers started with a caller's environment; `PATH` lookups for helper programs; library-loading variables (`LD_PRELOAD`, `LD_LIBRARY_PATH`, `DYLD_*`); interpreter variables (`PYTHONPATH`, `NODE_OPTIONS`, `RUBYLIB`, `CLASSPATH`); `TMPDIR`, `HOME` and locale; Windows DLL search order, current directory and `PATHEXT`; CGI-style servers that map request headers to variables.
- **Questions:**
  - Which variables can a lower-trust actor set for this process? (A user for a setuid program; an HTTP client for a CGI handler; a plugin author for a host.)
  - Does the program clear or rebuild the environment before it starts children or loads code?
  - Does it find helper programs by bare name, or by absolute path?
  - On Windows, does it load libraries by bare name from the application or current directory? Does it use a safe-search setting or a full path?
- **Sad-path inputs:** a search directory with a marker program or library placed first; a changed `PATH`; a hostile `TMPDIR`; an unusual locale; a request header that maps to a variable.
- **Evidence for confirmed:** the lookup or the variable read, the attacker's control of the variable or directory, and a scratch test in which a marker helper or library from the planted location loads. Windows search-order claims depend on OS behaviour and need E3.
- **Not a finding:** a user program that only trusts its own user's environment; a variable that only the operator sets.
- **CWE:** CWE-426; CWE-427.

### FP-09 Signal handlers, shutdown and crash state

- **What fails:** a signal handler does unsafe work, or a crash, kill or restart leaves state that a later run, a lower-trust user or an attacker-triggered restart can abuse.
- **Where to look:** signal handlers that allocate, log, lock or call library functions; stale lock files, pid files and sockets; files written without atomic replace; temporary files left by a crash; core dumps with secrets; cleanup scripts that remove paths in a shared directory.
- **Questions:**
  - Does each handler call only async-signal-safe functions, or set a flag that the main loop reads?
  - After a crash, does the next start trust a stale lock, pid or socket? Could a lower-trust user plant one?
- **Sad-path inputs:** a signal during a critical update; a kill at each step of a multi-file write; a stale lock owned by another user; a restart with a half-written state file.
- **Evidence for confirmed:** the handler or the crash path, the unsafe action or leftover state, and the actor who triggers or abuses it. A signal race is a race claim and needs E3. A secret in a world-readable crash file can be E1.
- **Not a finding:** a handler that sets a flag only; leftover state that the next start validates and discards.
- **CWE:** CWE-364; CWE-479; CWE-459.

### FP-10 Windows path and file features

- **What fails:** Windows file name rules make two different names mean one object, or make a name mean a device or a hidden stream. A check that works on the string fails on the object.
- **Where to look:** upload, extract and export code that runs on Windows; allow-lists and deny-lists of file names or extensions; checks that compare path strings; code that builds paths from names in input; services that open paths in user-controlled folders.
- **Questions:**
  - Does the code reject or handle alternate data streams (`name:stream`), short 8.3 names (`PROGRA~1`), reserved device names (`CON`, `NUL`, `COM1`) with or without an extension, trailing dots and spaces, and case-insensitive equality?
  - Does the extension check see the real name after the system strips trailing dots and spaces?
- **Sad-path inputs:** a name with a stream suffix; a short-name form of a long name; a device name with an extension; a name that ends in a dot or a space; a UNC form; names that differ only in case.
- **Evidence for confirmed:** the check, the sink, and the name that the check passes while the OS resolves it to another object. This depends on OS behaviour: E3 on Windows, or `needs-validation` when only a POSIX host is available.
- **Not a finding:** the code uses an allow-list of generated names; the program never runs on Windows (state the evidence).
- **CWE:** CWE-67; CWE-69; CWE-58; CWE-41.

## Variant search

When you find one file or process failure:
1. **Same API call.** List every use of the same create, open, copy, rename or spawn call. Compare the flags and modes.
2. **Same directory.** List every component that reads or writes the same shared directory.
3. **Same privilege.** List every code path that runs with the same elevated rights and takes a path or name from a lower-trust caller.
5. **Other platforms.** Check the Windows code and the POSIX code for the same operation. They often differ.

## Chain primitives

This domain often **gives**:
- file write as a privileged user, which gives code execution through a loaded configuration, script or library;
- file read of keys, tokens and configuration (to authn, crypto and secrets-config);
- privilege escalation from a local user to a service account or administrator;
- file replacement that defeats a verify-then-install flow (to supply-chain);

This domain often **needs**:
- local code execution or a local account, or a path that lets a remote actor place a file (from input-parsing archive and upload classes);

## Verification notes

- **E1 is usually enough** for: an explicit wide mode or ACL set in code (FP-01); a predictable temporary name without exclusive create in a shared directory used by privileged code (FP-02); a wrong drop order or an unchecked return value (FP-06); a secret on a command line or in a world-readable crash file (FP-07, FP-09); installer-set rights in the repository (FP-05). The waiver must name the API semantics used.
- **E3 is required** for: every file TOCTOU claim (FP-04), as SKILL.md section 6 says; link and junction claims whose result depends on OS or file system behaviour (FP-03); signal races (FP-09); Windows search-order and path-feature claims (FP-08, FP-10). Without T2, these are `needs-validation` with a reproduction plan.
- **Privilege gain:** a finding needs a real gain. The attacker must be less privileged than the code that acts. The same user acting on their own files is design authority.
- **Reachability:** confirm the code runs with the claimed privilege in the default install. Confirm the lower-trust actor can write the directory (check the installer, the packaging and the default umask).
- **E3 test shape:** run at the isolation level the user chose (see execution.md). Use a scratch directory, a dummy second user if available, and marker files. Force the race with a barrier. Record the observed change to the marker. Do not run privileged code on a host that you do not own.
- **Severity examples:**
  - critical – a local or remote low-privilege actor makes a root or system service write a chosen file into an executable or configuration location (FP-03, FP-05);
  - high – local privilege escalation through a setuid program or search path (FP-06, FP-08); another user's secrets readable through a wide mode (FP-01);
  - medium – a link attack that deletes or overwrites a non-critical file; a leaked descriptor to a less trusted child; a narrow-window race;
  - low – a predictable temporary name in a private directory; a stale lock that only causes a restart failure;
  - informational – a wide mode on a file that holds public data.

## Fix patterns

- **Create with the right mode.** Pass the restrictive mode or ACL in the creating call. Do not rely on umask or on a later chmod. Create secret files in a private directory.
- **Use the platform's safe temporary API.** Use exclusive create with an unpredictable name, or a private per-user or per-service directory.
- **Open once, then use the handle.** Open the file with no-follow and exclusive flags. Do the checks on the handle (stat on the descriptor). Operate relative to a directory handle. On Windows, use handle-based calls and flags that do not follow reparse points.
- **Keep privileged locations private.** Use directories that only the service or administrators can write. Do not read code or configuration from user-writable places. Quote service paths.
- **Drop completely and check.** Clear supplementary groups, set the group, set the user (all of real, effective and saved IDs), drop capabilities, and verify. Exit on any failure. Do the privileged step first and early.
- **Build the environment.** Pass an explicit, minimal environment and working directory. Set close-on-exec by default. On Windows, pass an explicit list of inheritable handles. Pass secrets by descriptor, pipe or file with a restrictive mode, not by command line.
- **Fixed search.** Start helpers by absolute path. Load libraries by full path or with a restricted search. Ignore or reset loader and interpreter variables in privileged programs.
- **Small handlers.** Set a flag in the handler and do the work in the main loop. Write files by temporary name, flush, then atomic rename. Validate leftover state on start.
- **Looks right but is not:** `access()` or an exists check before open; resolving the real path and then opening the path; a later chmod; a random suffix in a shared directory without exclusive create; dropping only the user ID; a deny-list of file names on Windows; scrubbing one variable instead of building a clean environment.

## Regression tests

- **Mode test:** after each create, assert the mode or ACL under a permissive umask and under a restrictive one.
- **Pre-created path test:** place a file, a link and a directory at the predicted temporary path. Assert that the program fails or uses another path, and does not touch the planted object.
- **Link test:** place a link or junction at each privileged write, delete and chmod target. Assert that the marker target does not change.
- **Race test:** use a hook that swaps the path between check and use. Assert that the operation fails or acts on the checked object.
- **Privilege test:** after the drop, assert real, effective and saved user and group IDs, supplementary groups and capabilities. Assert that a forced drop failure ends the program.
- **Child test:** list the descriptors, handles and environment in a child. Assert that only the expected ones appear and that the command line holds no secret.
- **Windows name set:** feed stream suffixes, short names, device names and trailing-dot names to each name check. Assert rejection.
