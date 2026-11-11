# Domain: Local IPC and Client-Side Boundaries

## Scope

- **Load when:** the code runs on a user's device and talks to other local code, or accepts input from other apps, web pages or the OS shell. Signs: Unix domain sockets, named pipes, loopback listeners, D-Bus, XPC or Mach services, COM or RPC servers, shared memory, Android components and manifests, iOS app extensions and URL handlers, custom URL schemes, protocol handlers, webviews and embedded browsers, privileged helpers and services, installers and repair paths, native messaging hosts, keychains and credential stores.
- **Covers:** authentication of local IPC peers, privileged helpers as confused deputies, exported mobile components, deep links and URL handlers, webview and embedded-browser bridges, local trigger paths for update and repair, local credential and token storage, and account switch and logout state.
- **Hand off to:**
  - `domain-filesystem-process.md` – file permissions, symlinks, temp files, privilege dropping, child process and environment handling. This file owns who may call the helper and what the helper accepts.
  - `domain-web-client.md` – DOM XSS, CORS, CSRF, postMessage and browser extension pages. This file owns the native side of the bridge and the choice of what the page may call.
  - `domain-supply-chain.md` – authenticity, signing and rollback of the update. This file owns the local code path that applies it.
  - `domain-authn.md` – OAuth redirect design, PKCE and session design. This file owns who can receive the redirect on the device.
  - `domain-crypto.md` – choice of algorithm and key handling for stored secrets. This file owns where the secret is stored and who can read it.
  - `domain-outbound-network.md` – TLS verification and certificate pinning in the client.
  - `domain-sandbox.md` – isolation of plugin code inside the app.
  - `domain-logging-privacy.md` – content of logs and telemetry.

## Invariants

Fill the placeholders from `threat-model.md`.

1. **Peer:** <helper | service | socket | component> acts only for <named peers>, identified by <OS credentials | code-signing identity | permission> that the OS supplies. A name, a path or a request field does not identify a peer.
2. **Authority:** The helper uses the rights of the caller, or it accepts only <fixed operations> on <fixed targets>. It never runs a generic command, write, or install for an unprivileged caller.
3. **Binding:** <socket | pipe | listener> is created by the intended owner, in a location and with permissions that other local users and apps cannot use to listen first or connect.
4. **Component:** Only <named apps or the OS> can start, bind to or read from <exported component>. Input from it is untrusted.
5. **Link:** A deep link or URL handler performs no sensitive action without <authenticated user confirmation>. Its parameters are untrusted data.
6. **Bridge:** A page or script loaded in a webview can call only <listed native functions>, and only when its origin is <listed origins>. Remote or user-controlled content has no bridge.
7. **Local trigger:** Only <named principals> can start update, install or repair. The privileged step uses files that unprivileged users cannot change.
8. **Storage:** <token | key | credential> is readable only by <this app and this user> through <platform store>. It is gone after logout.
9. **Account:** After an account switch or logout, no cached data, token, background task or open IPC channel keeps the rights or content of the previous account.

## Recon additions

Add these to `domain-notes.md` under "Local boundaries".

1. **Local principals.** Who else runs on the device: other OS users, other apps (trusted and untrusted), a browser, a remote desktop session, a container on the same host, malware at user level. State which the product must resist.
2. **IPC surface table.** Mechanism | name or address | created by whom | permissions or DACL or signing requirement | peer check (file:line) | operations offered.
3. **Privilege map.** Each process or service, its OS identity, and what it can do that the user cannot. Mark each place where an unprivileged input reaches a privileged process.
4. **Mobile component table.** Component type | name | exported (explicit or implied) | permission or signing check | intent filters or URL patterns | data it reads.
5. **Link and handler table.** Scheme or URL pattern | registered where | actions reachable | confirmation | parameters used.
6. **Webview table.** Webview or embedded browser | content source (bundled, remote, user) | allowed origins | native bridge functions | file and URL access settings.
7. **Local storage table.** Secret or data | where it is stored | store type | access control | backup behaviour | lifetime.
8. **Update and repair paths.** Who triggers them, what privilege applies, where files come from.
9. **Account model on the device.** Multiple accounts, profiles, shared devices, background tasks, notifications.

## Lead searches

Adapt to the platform. Language files add API names.

| Search | A hit may mean | False-hit notes |
|---|---|---|
| `socket\(.*AF_UNIX\|bind\(\|listen\(\|CreateNamedPipe\|mkfifo\|NSXPCListener\|NSMachPort\|dbus\|RegisterServiceCtrl` | A local server (LI-01) | Check the creator, the path and the access control. |
| `0\.0\.0\.0\|127\.0\.0\.1\|localhost\|INADDR_ANY\|INADDR_LOOPBACK` near `listen\|serve\|bind` | A local TCP listener (LI-01) | Loopback is reachable by every local user and by web pages. |
| `SO_PEERCRED\|getpeereid\|LOCAL_PEERCRED\|GetNamedPipeClientProcessId\|ImpersonateNamedPipeClient\|auditToken\|setCodeSigningRequirement\|SecRequirement` | Peer check (LI-01, LI-02) | A process ID alone is weak (it can be reused). Read what follows the check. |
| `SECURITY_ATTRIBUTES\|SetSecurityInfo\|chmod\(.*0?[67][67][67]\|umask\|FILE_FLAG_FIRST_PIPE_INSTANCE\|PIPE_REJECT_REMOTE_CLIENTS` | Access control on pipe or socket (LI-01) | A missing flag is a lead. Check the default security descriptor. |
| `system\(\|exec\|popen\|CreateProcess\|ShellExecute\|Process\.Start\|NSTask` in code that handles a client request | Helper runs commands for callers (LI-02) | A fixed command with fixed arguments is not a lead. |
| `android:exported\|<intent-filter\|<provider\|<receiver\|<service\|grantUriPermissions\|android:permission\|PendingIntent\|FLAG_MUTABLE\|getIntent\(\)\|startActivity\(.*getParcelableExtra` | Exported components and intent handling (LI-03) | Components with filters were exported by default on older targets. Check the target level. |
| `CFBundleURLSchemes\|applinks\|associated-domains\|application\(.*open url\|onOpenURL\|BROWSABLE\|android:scheme\|setAsDefaultProtocolClient\|HKEY_CLASSES_ROOT.*URL Protocol\|x-scheme-handler` | Link or URL handler (LI-04) | Verified app or universal links are safer than custom schemes. |
| `addJavascriptInterface\|setJavaScriptEnabled\|setAllowFileAccess\|AllowUniversalAccessFromFileURLs\|onReceivedSslError\|WKScriptMessageHandler\|evaluateJavaScript\|nodeIntegration\|contextIsolation\|webSecurity\|ipcMain\.\(handle\|on\)\|contextBridge\|shell\.openExternal\|AddHostObjectToScript\|WebMessageReceived` | Webview bridge or setting (LI-05) | Read the origin check and the list of exposed functions. |
| `Authenticode\|WinVerifyTrust\|signtool\|MSI\|msiexec\|SMJobBless\|SMAppService\|pkexec\|polkit\|sudo\|runas\|Elevate\|AuthorizationExecuteWithPrivileges` | Elevation and install paths (LI-02, LI-06) | Read what runs after elevation and where its input files are. |
| `LoadLibrary\|dlopen\|LD_LIBRARY_PATH\|RPATH\|RUNPATH\|@rpath\|DYLD_` and service paths with spaces and no quotes | Search path and load-path risks (LI-06) | Owned by filesystem-process for the mechanism. Record the privilege boundary here. |
| `SharedPreferences\|NSUserDefaults\|UserDefaults\|Keychain\|kSecAttrAccessible\|Keystore\|DPAPI\|CryptProtectData\|allowBackup\|MODE_WORLD\|localStorage\|registry.*password\|\.token\|credentials\.json` | Secret storage (LI-07) | Check the store type, the access flag and backup rules. |
| `logout\|signOut\|switchAccount\|clearCache\|removeAllCookies\|deleteDatabase\|WorkManager\|BackgroundTasks\|NSNotification` | Account state cleanup (LI-08) | Compare what logout clears with what the app stores. |

## Attack classes

### LI-01 Unauthenticated or squattable local IPC peers

- **What fails:** another local user, an unrelated app or a web page in the browser can connect to a local server, or can listen where the product expects its own server. It then sends commands or reads data.
- **Where to look:** Unix sockets (path, directory permissions, abstract namespace on Linux); named pipes (security descriptor, remote client flag, first-instance flag); loopback TCP or HTTP servers; D-Bus services and policies; XPC and Mach services; COM and RPC servers; shared memory and files used as channels; native messaging hosts; debug and remote-control ports.
- **Questions:**
  - Who creates the endpoint? Could another process create it first, in a shared directory or with a predictable name?
  - What do permissions or the descriptor allow? Does the OS supply the peer's identity and does the code use it?
  - Does a loopback server accept requests from a browser page? (CORS, DNS rebinding and Host checks belong to `domain-web-client.md` and `domain-http-protocol.md`; the question here is whether any authentication exists.)
  - Does the client check that the server is the real one before it sends secrets?
  - Does a native messaging manifest list only the intended extension origins?
- **Sad-path inputs:** a second OS user as the client; a process that created the pipe first; a web page that calls the loopback port; a request with no credential; a client under a different code-signing identity.
- **Evidence for confirmed:** the endpoint creation, its access control, the operation reachable without a peer check, and which local principal gains it. E1 is usually enough. A squatting race needs E3.
- **Not a finding:** an endpoint restricted to the same user in a user-private directory, when the threat model excludes same-user malware and the endpoint runs as that user. If the endpoint or entry point runs elevated (an elevation re-entry such as `--elevated-task <file>`, a privileged helper, a polkit action), classify the caller with [phase-recon.md "Elevation consent"](phase-recon.md#elevation-consent) instead.
- **CWE:** no single checked entry fits all cases. Name the weakness in words ("missing peer authentication on local channel", "endpoint creation without ownership check"). Add CWE-250 if the server runs with high privilege for no need.

### LI-02 Privileged helper as confused deputy

- **What fails:** a root, SYSTEM or otherwise privileged process does work for an unprivileged caller and uses its own rights without limiting the target or operation.
- **Where to look:** helper tools and services installed with elevated rights; polkit actions; macOS privileged helper tools and XPC services; Windows services and elevated broker processes; setuid programs (mechanics in `domain-filesystem-process.md`); handlers that take a path, a command, an argument list, a URL or a package from the client.
- **Questions:**
  - What operations does the helper offer? Is any generic: run a command, write a file, copy, install, set a setting?
  - How does it identify the caller: OS-supplied credentials or a field in the message? If it uses a process ID, can the process be replaced after the check?
  - Does it check the code-signing identity or the user's right to the target before it acts?
  - Does it act on a path that the caller controls, with the helper's rights?
  - Does it parse the message safely (hand off to `domain-input-parsing.md`)?
- **Sad-path inputs:** a target path that the caller cannot normally read or write; a caller from another user or another signed app; a request that carries an argument starting with `-`; a replayed request.
- **Evidence for confirmed:** the helper's entry point, the missing caller check or target limit, and a concrete privileged action on a target that the caller could not reach. Use a dummy file or value in a test. Do not escalate on a real system.
- **Not a finding:** a helper whose only operation is fixed and harmless, and which checks the caller's identity.
- **CWE:** CWE-250; CWE-78 when the helper builds a shell command from client data. The confused-deputy pattern itself: no checked entry; name it in words.

### LI-03 Exported mobile components and intent handling

- **What fails:** another app on the device starts, binds to or reads from a component that the product meant to keep private, or tricks the product into using attacker-chosen data.
- **Where to look:** Android activities, services, content providers and broadcast receivers (explicit and implied export; permission attributes; intent filters); `PendingIntent` mutability and base intents; file providers and path rules; implicit intents that carry sensitive data; code that reads a nested intent from extras and launches it; task and affinity settings; iOS app extensions, shared containers, App Group data, pasteboard use and inter-app messages.
- **Questions:**
  - Is the component exported? Does it need to be? Does it demand a permission or signature check?
  - What does the component do with extras, URIs and data? Does it open files, run queries, or start other components?
  - Does a content provider limit paths and columns, or can a caller traverse or inject?
  - Does the app send sensitive data in an implicit intent or broadcast that any app can receive?
  - Does it launch an intent that came from untrusted extras with its own rights?
- **Sad-path inputs:** a call from a different app with no permission; a URI with `..` segments; an extra holding a nested intent; a mutable pending intent with empty fields.
- **Evidence for confirmed:** the manifest entry, the handler code, and the action the caller gains. Read the manifest after merge rules, as libraries add components. E1 is usually enough.
- **Not a finding:** an exported component that must be public (the launcher activity) and that does nothing sensitive with its input.
- **CWE:** CWE-926 (improper export of Android application components); CWE-927 (use of implicit intent for sensitive communication).

### LI-04 Deep links, custom schemes and URL handlers

- **What fails:** a link from a web page, a message or another app triggers a sensitive action in the product without the user's informed consent. Or another app steals the data that a custom scheme carries.
- **Where to look:** link handlers on every platform (mobile schemes and verified links, desktop protocol registrations, shell associations, `open-url` handlers); parameters that name an action, a URL, a file, an account or a token; authentication redirect handling; command lines built from a link on desktop.
- **Questions:**
  - Which actions can a link trigger: sign in, pay, install, open a file, change a setting, load a URL in a webview?
  - Does the action need a confirmation that shows the real target?
  - Can another app register the same scheme and receive an authentication redirect? (Verified links or a loopback redirect avoid that. Flow design belongs to `domain-authn.md`.)
  - Does the handler pass link parts to a shell, a file path or a launched process (quoting, leading `-`)?
  - Does the handler resolve the link against the current account (LI-08)?
- **Sad-path inputs:** a link with an extra parameter that names an internal action; a path with traversal segments; a very long link; a link opened while locked out or signed out; a quote character in a parameter on desktop.
- **Evidence for confirmed:** the handler registration, the parameter flow, and the unconfirmed action. Test with a local test harness that calls the handler with a fixture link.
- **Not a finding:** a link that only opens a screen the user can already reach, with no state change.
- **CWE:** CWE-78 if the link reaches a shell. Handler authorisation: no checked entry; name in words ("missing authorisation in a URL scheme handler").

### LI-05 Webview and embedded-browser bridges

- **What fails:** content in a webview gets native power it should not have. Remote, injected or user-controlled content can call native functions, read local files or start processes.
- **Where to look:** webview settings for scripts, file access and mixed content; injected native objects and message handlers; Electron-style settings for node access, context isolation and web security; preload scripts; IPC handlers in the main process; calls that open external URLs or files; navigation and new-window handling; certificate error handlers; embedded engines in desktop frameworks.
- **Questions:**
  - What content loads: bundled files only, or remote and user content?
  - Which native functions can the page call? Is any generic (read file, run command, open path, fetch URL)?
  - Does the native handler check which page or frame sent the call, and the origin?
  - Can navigation leave the allowed origins and keep the bridge?
  - Does the app ignore certificate errors in the webview?
  - Can a script injected by XSS (hand off to `domain-web-client.md`) reach the bridge and thereby native code?
- **Sad-path inputs:** a sub-frame or a redirected page that calls the bridge; a `file:` URL; a link that opens a new window with the same privileges; an argument that names a path or program.
- **Evidence for confirmed:** the bridge function, the missing origin or sender check, the content source that an attacker can influence, and the native effect. The XSS or content injection that supplies the script may be a separate finding; chain them.
- **Not a finding:** a bridge function that is narrow and safe on any input, exposed only to bundled content.
- **CWE:** no checked entry fits. Name in words ("dangerous method exposed to web content", "missing sender or origin check on a bridge call"). CWE-78 if a bridge call reaches a shell.

### LI-06 Local update, install and repair paths

- **What fails:** a low-privilege local user or app makes a privileged install, update or repair step run attacker-chosen code or files.
- **Where to look:** installers and uninstallers that run with high rights; update services that stage files in user-writable directories; repair and rollback modes; service binary paths and library search paths; loaders that read libraries or plug-ins from user-writable locations; scheduled tasks and launch agents.
- **Questions:**
  - Who can start the update or repair? Does it need a prompt for credentials?
  - Where does the privileged step read its files? Can an unprivileged user change them between verification and use?
  - Does the elevated process load code from a path that an unprivileged user can write?
  - Do paths with spaces appear unquoted in service definitions?
  - Does the uninstaller delete a directory that a user can fill with links?
- **Sad-path inputs:** a replaced file in the staging directory; a library with an expected name in a writable directory; a link in the target directory of an uninstall.
- **Evidence for confirmed:** the privileged step, the writable input, and the code or file that the attacker supplies. Races between check and use need E3 (mechanics in `domain-filesystem-process.md`). Signature design belongs to `domain-supply-chain.md`.
- **Not a finding:** a per-user installer that writes only into the user's own profile and runs with the user's rights.
- **CWE:** CWE-250; CWE-829 for code loaded from an untrusted location. Search-path and link issues: use the `domain-filesystem-process.md` entries.

### LI-07 Credential stores and local secret storage

- **What fails:** a token, key or password on the device can be read by another local user, another app, a backup, or an attacker with brief device access. The product ignored the safer platform store.
- **Where to look:** key-value preferences; plain files in the profile; the registry; browser-like storage in embedded pages; keychain items and their accessibility class; hardware-backed key stores; data protection and backup flags; command-line arguments and environment variables that carry secrets; clipboard use; secrets in screenshots, task switchers and notifications.
- **Questions:**
  - Where is each secret stored, and which store type is it?
  - Who can read it: same user only, other apps, other users, backups, a device with a lock?
  - Does the accessibility class allow reading while the device is locked, or sync to other devices?
  - Does a secret appear in a process list, a log or crash data?
  - Is the secret removed at logout and at uninstall?
- **Sad-path inputs:** a second OS user; an app backup restored on another device; a process listing while the app runs; a stolen but unlocked-once device.
- **Evidence for confirmed:** the store call, the weak access setting, the secret type (never the value), and the reader. E1 is usually enough. Platform defaults by version are external: state the version assumed.
- **Not a finding:** storage of a non-sensitive preference; a token in an app-private store with default platform protection, where the threat model excludes root-level attackers.
- **CWE:** CWE-532 for secrets in logs; CWE-538 for secrets in an externally accessible file; CWE-200 (class-level) for general exposure. Weak store choice: name in words ("cleartext storage of sensitive information").

### LI-08 Account switch, logout and shared-device state

- **What fails:** after a logout or an account switch, the next user or the same device keeps access to the previous account's data, tokens, tasks or open channels.
- **Where to look:** logout and switch handlers; local databases, caches, search indexes and file stores; background jobs and push notification handlers; open sockets and long-lived IPC channels; shared helpers serving several OS users; deep links resolved against the wrong account; lock screen and notification content.
- **Questions:**
  - Does logout clear every store that holds account data, tokens or keys? List the stores first, then check each.
  - Does a queued background task run later with the old account's rights?
  - Does a helper that serves several OS users keep one cache or one identity for all?
  - Does a notification or widget show private content on a locked device?
- **Sad-path inputs:** switch accounts while a sync runs; log out and open a stale link; sign in as a second user on the same device.
- **Evidence for confirmed:** the store or task that survives, and the content or right that the next principal gains. A stale view in the same session of the same user is not a boundary failure.
- **Not a finding:** data kept on purpose and shown only to the same user after sign-in.
- **CWE:** CWE-200 (class-level) for leftover data. Leftover rights: no checked entry; name in words ("session or credential not cleared on logout").

## Variant search

When you find one local-boundary defect:
1. **Same mechanism.** List every socket, pipe, service, component or handler of the same kind and check each for the same missing check.
2. **Same helper.** List every operation the helper offers, not only the one found.
3. **Same bridge.** List every native function exposed to web content, and every webview in the app.
4. **Same store.** List every place that writes the same secret or similar secrets.
5. **Same build variants.** Compare manifests and registrations across build flavours, platforms and libraries (merged manifests add components).
6. **Same history.** If an earlier fix restricted one endpoint (phase 2.3), check its siblings.

## Chain primitives

This domain often **gives**:
- code execution or file write at higher privilege on the device (from a helper or an update path);
- tokens, keys and account data of the user (from stores and components);
- native power from web content (from a bridge);
- a way to start sensitive actions from a web page or message (from links).

This domain often **needs**:
- a local foothold: another app, another user, or a page the user visits;
- content injection into a webview (from `domain-web-client.md`);
- a file write or link race (from `domain-filesystem-process.md`);
- a victim action such as clicking a link.

## Verification notes

- **E1 is usually enough** for LI-02 (generic operation with no caller check), LI-03 (manifest and handler), LI-04, LI-05 (bridge function with no sender check) and LI-07 when the code and manifest are in the repository. The waiver must name every layer read: the manifest after merge, the registration code, and any OS-level setting that the code sets.
- **E3 is needed** for races (socket squatting, check-then-use on staged files), for pipe and socket behaviour that depends on default OS security descriptors, and for any claim about platform behaviour not in the repository. Run tests only at the isolation level in `plan.md`, with dummy files, a second dummy user or process, and no real accounts.
- **Facts usually outside the repository** make a finding `needs-validation`: OS and SDK version defaults (export defaults, keychain classes); the presence of device lock and disk encryption; whether a web page or other app is actually installed; platform store verification of links (domain association files are served by the vendor's domain); policies set by device management.
- **Reachability:** confirm that the component, handler or listener exists in the default build and platform, and that the attacker is the local principal the threat model includes. Same-user malware is often out of scope. Record the assumption.
- **Design authority:** a helper or service may do privileged work by design. The defect is that the caller can steer it beyond what the user could do. "Same-user malware is out of scope" never covers a privileged step behind a consent prompt: the attacker has the user's rights but not the user's approval. Use the (a)/(b)/(c) classes in [phase-recon.md "Elevation consent"](phase-recon.md#elevation-consent) and write the class in the finding or hardening note.
- **Severity examples:**
  - critical – any local user or any web page gains administrator or root code execution through a helper or an update path; a bridge gives remote web content code execution on the device;
  - high – another app or user reads the account's tokens or messages; a link silently performs a payment or sign-in; an exported component exposes private files;
  - medium – a squattable endpoint that leaks low-sensitivity data; a secret stored in a store that backups include;
  - low – a notification that shows content on a locked device; a stale cache for the same user;
  - informational – an exported component with no sensitive effect.

## Fix patterns

- **Use OS-supplied identity.** Check the peer with credentials from the OS (peer credentials, audit tokens, code-signing requirements, pipe client identity). Do not trust a process ID alone, a path, or a message field.
- **Create endpoints safely.** Use a private directory owned by the user, strict permissions, and first-instance flags. Reject remote clients.
- **Narrow the helper.** Offer fixed operations with typed arguments. Resolve targets to a fixed set. Act as the caller or drop rights before touching caller-chosen files.
- **Unexport by default.** Export only what must be public. Require a signature-level permission for internal components. Use explicit intents and immutable pending intents.
- **Treat links as untrusted.** Require confirmation for sensitive actions. Prefer verified links over custom schemes for authentication redirects. Never put link parts into a shell.
- **Limit the bridge.** Load only bundled content in a webview with a bridge. Expose narrow functions. Check the sender frame and origin on every call. Turn off node access and file access for remote content.
- **Protect update paths.** Stage files in a directory only the privileged service can write. Verify and use the same opened file. Load libraries from protected paths only.
- **Use platform stores.** Use the keychain, keystore or credential manager with the strictest accessibility class that works. Exclude secrets from backups. Remove them at logout.
- **Clear on logout.** Keep a list of every store, task and channel per account. Clear each, and cancel queued work.
- **Looks right but is not:** obscure socket names; an authentication token in the same world-readable file as the socket; a peer check by process name; hiding an exported component with an unguessable name; a "localhost only" listener as the only control; a bridge allow-list that matches a URL prefix; encryption with a key stored beside the data.

## Regression tests

- An **IPC peer test**: connect as a different user, a different signed app and a process that skips the handshake. Each must be refused.
- A **squatting test**: start a dummy listener on the expected name before the product. The product must refuse to use it.
- A **helper test**: call each operation with a target outside the allowed set, a caller without rights, and a replayed request. Each must be denied.
- A **manifest test** that lists exported components after merge and compares them with an approved list.
- A **link handler test** with fixture links: unknown action, traversal segment, extra parameter, signed-out state. None may change state without confirmation.
- A **bridge test**: call each bridge function from a foreign origin and from a sub-frame. Each must be refused.
- A **logout test** that creates data for account A, logs out, signs in as B, and asserts that no A data, token, task or channel remains.
- A **storage test** that scans the profile, preferences and logs for secrets after a sign-in.
