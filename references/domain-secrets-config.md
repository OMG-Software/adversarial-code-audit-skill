# Domain: Secrets and Configuration

## Scope

- **Load when:** the code loads configuration, holds secrets, or has modes and flags. Signs: config files, environment variables, command-line options, `.env` files, feature-flag clients, remote config, debug or development switches, default accounts, key and credential files, secret-manager clients, installers and example configs, container and build files, mobile or desktop apps with embedded keys.
- **Covers:** config loading and precedence; insecure defaults; feature flags that disable security; debug and development modes; hard-coded and committed secrets; secret storage, rotation and revocation; secret exposure (logs, errors, URLs, client bundles, images, history); environment-variable trust; example and template configs that ship.
- **Hand off to:**
  - `domain-obvious.md` – the first-pass literal checks. This file owns the full analysis and the verification rules for each hit.
  - `domain-crypto.md` – how a cryptographic key is generated and used (CR-06). This file owns credentials, tokens and config secrets, and where they are stored and leaked.
  - `domain-authn.md` – how a credential is checked. This file owns the existence of default and hard-coded credentials.
  - `domain-cloud-deploy.md` – secrets in infrastructure code, IAM roles and metadata-service exposure.
  - `domain-supply-chain.md` – secrets in CI workflows, signing keys and release authority.
  - `domain-logging-privacy.md` – what logs, telemetry and crash reports may hold as a policy. This file owns secrets that reach them.
  - `domain-web-client.md` – server data serialised into pages and hydration leaks. This file owns secrets and environment variables that a build step puts into client code.
  - `domain-embedded.md` – secrets in firmware images and debug ports. `domain-local-ipc.md` – OS credential stores.
  - `domain-business-logic.md` – defaults that affect workflow rules (limits, prices). This file owns defaults that affect security.
  - `domain-filesystem-process.md` – `PATH`, `LD_PRELOAD` and other variables that change how a process loads code.

## Invariants

Fill the placeholders from `threat-model.md`.

1. **No secret in artefacts:** No secret value appears in source, version-control history, container images, client bundles, packages, installers, firmware or example files that ship.
2. **Limited reach:** Only <principal> can read secret <S> at rest and in transit. It does not appear in logs, errors, URLs, process arguments, crash reports, metrics or responses.
3. **Separation and rotation:** Each environment, tenant and purpose has its own secret. A leaked secret can be revoked and replaced within <time> without a code change.
4. **Safe default:** With no configuration, or partial configuration, the product starts in a safe state or refuses to start. No default credential or fixed key exists.
5. **Production mode:** Production builds and configurations expose no debug, test or development feature. Request data cannot turn one on.
6. **No off-switch for untrusted input:** A setting that disables authentication, verification or encryption cannot be set by request data, by a less-trusted config source, or by a missing value.
7. **Precedence:** The order of config sources is documented. A lower-trust source cannot override a security setting from a higher-trust source.
8. **Parse failure:** An unknown, misspelled, malformed or mistyped security setting stops start-up. It never falls back to "off".
9. **Environment trust:** The code trusts a value from the environment, the working directory or a user-writable file only for settings that its writer may control.

## Recon additions

Add these to `domain-notes.md` under a heading "Configuration and secrets model". Keep it short.

1. **Config sources.** Table: source (built-in defaults, file, environment, command line, remote config, database, flag service, per-tenant settings) | who can write it | when read | what it overrides.
2. **Security settings.** Table: key | meaning | default | production value | behaviour when missing or invalid | file:line.
3. **Secret inventory.** Table: secret and type | where defined | storage at rest | readers | places it could leak | rotation | environments that share it. Record types and places only. Never record values.
4. **Modes.** Build types, environment names, and every switch for debug, development, test and demo behaviour. How production is selected.
5. **Shipped artefacts.** Images, packages, bundles, installers, mobile and desktop binaries, firmware. What each contains.
6. **Install-time files.** Example, sample and template configs that setup copies or that operators copy.
7. **Runtime change.** Config reload, flag changes, admin settings pages, and who can use them.

## Lead searches

Adapt the patterns to the language. Never print or copy a matched secret value into audit files.

| Search | A hit may mean | False-hit notes |
|---|---|---|
| `(password\|passwd\|pwd\|secret\|api_?key\|token\|private_?key\|credential)\w*\s*[:=]\s*["'][^"'$\{ ]{6,}` | Hard-coded secret (SCF-01) | Placeholders (`changeme`, `xxx`, `<token>`), test values and variable names are false hits. Check if the value is used. |
| `-----BEGIN [A-Z ]*PRIVATE KEY-----`; token shapes such as `AKIA[0-9A-Z]{16}`, `ghp_`, `xox[bp]-`, `sk_live_`, and three-part `eyJ…` strings | Committed key or token (SCF-01) | Public keys and test keys are false hits. |
| File names: `.env*`, `*.pem`, `*.p12`, `*.pfx`, `*.jks`, `*.keystore`, `id_rsa*`, `.netrc`, `.pgpass`, `.npmrc`, `*.tfstate`, `credentials*`, `secrets.*` | Credential file in the tree or in history (SCF-01) | Check version-control history for removed files. |
| `(log\|print\|debug\|trace\|echo\|dump)` near `config\|settings\|env\|password\|secret\|token\|header`; whole-object logging; `printenv`, `environ` dumps | Secret in logs and errors (SCF-02) | |
| Secrets in URLs: `\?(token\|key\|secret\|password)=`; command lines that carry secrets as arguments | URL or process-list exposure (SCF-02) | |
| Client-exposed env prefixes (for example `NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, `EXPO_PUBLIC_`) on secret-like names; `sourceMappingURL`; `ARG` or `--build-arg` with secrets; `COPY` of key files into images | Secret in client bundle, source map or image layer (SCF-03) | |
| `(admin\|root\|user\|test)\s*[:/,]\s*(admin\|root\|password\|changeme\|123456\|test)`; `0\.0\.0\.0`; `listen\|bind` with open hosts | Default credential or open bind (SCF-04) | Loopback bind is safe. |
| `(debug\|devel(opment)?\|verbose\|trace\|profil\w+\|pprof\|swagger\|playground\|introspection\|console\|actuator\|__debug__)` as flags, routes or build switches | Debug or dev feature (SCF-05) | Check whether the production build removes it. |
| `(skip\|disable\|no\|insecure\|allow\|bypass\|trust)_?(auth\|verify\|tls\|ssl\|cert\|signature\|check\|csrf\|validat\w*)`; feature-flag reads near auth code | Security off-switch (SCF-06) | |
| Config reads with a default: `getenv\(.*,`, `\|\|\s*["'\d]`, `\?\?`, `.get\(.*,`, `default=` | Insecure fallback or silent default (SCF-07) | |
| `HTTP_PROXY`, `http_proxy`, `NODE_ENV`, `APP_ENV`, `ENVIRONMENT`, `LD_PRELOAD`, `PATH` read by the application | Environment trust (SCF-08) | `PATH` and loader variables belong to `domain-filesystem-process.md`. |
| `(rotate\|expire\|renew\|revoke\|kms\|vault\|secret_?manager\|keyring\|keychain)` and the absence of such code | Storage and rotation (SCF-09) | |
| `\.(example\|sample\|dist\|template)$`, `docker-compose`, chart `values` files, installer scripts that copy configs | Example config that ships (SCF-10) | |

## Attack classes

### SCF-01 Hard-coded and committed secrets

- **What fails:** a secret sits in source, history or a shipped artefact, so anyone with that access holds the secret.
- **Where to look:** source constants; test fixtures that ship; example configs; scripts; CI files; infrastructure state files; docs and wiki exports; mobile, desktop and firmware binaries; version-control history (removed files, old branches, tags); vendored code.
- **Questions:**
  - What does the secret grant? Is it used as a credential, a signing key, an encryption key or a comparison value in a check?
  - Is it one value for every installation, or per installation?
  - Who can read this location: the public, customers, all staff, the repository team?
  - Is the secret still valid? (This is an external fact. Do not test it.)
  - Does the code accept the hard-coded value as a login or token, so that anyone who knows it can act?
- **Sad-path inputs:** a removed file still in history; a secret in a binary string table; a secret in a base64 or hex form; a key in a mobile app resource; a value in a comment.
- **Evidence for confirmed:** file, line and secret type; the code that uses it; the boundary it defeats. E1 is enough. Never copy the value. Never test it against a live system. If the finding depends on whether the secret is still valid, the status is `needs-validation`. State the safe check: the owner checks the provider console.
- **Not a finding:** a placeholder or test value in a test-only file that does not ship; a public key; a client identifier that is public by design; a publishable key meant for client use.
- **CWE:** CWE-798, CWE-259, CWE-321, CWE-540, CWE-260.

### SCF-02 Secrets in logs, errors, URLs and process data

- **What fails:** a secret reaches a place with a wider audience than the secret allows.
- **Where to look:** log statements that print requests, headers, configs or objects; error and exception handlers; debug endpoints that dump settings; secrets in query strings; command-line arguments; process environment dumps; crash reports; metrics labels; cache keys; temporary files.
- **Questions:**
  - Does any log call print a whole config, request, header set or credential-bearing object?
  - Do error responses include connection strings, tokens or file paths?
  - Does the code place a secret in a URL, where proxies, history and referrers keep it?
  - Does a child process get the secret as an argument, visible to other local users?
  - Does the redaction work by key name only, and miss new fields?
- **Sad-path inputs:** a failed login with a wrong password (is it logged?); a config with a bad value (is the value in the error?); an exception from a connection string; a request with an `Authorization` header in debug logging.
- **Evidence for confirmed:** the code that emits the secret, the sink, and who reads the sink. E1 is enough when the log or error path is in the repository and the secret is in scope. Policy about log content belongs to `domain-logging-privacy.md`.
- **Not a finding:** a secret that appears only in a log readable by the same principal who already holds it; logging of a masked or hashed identifier.
- **CWE:** CWE-532, CWE-209, CWE-598, CWE-215, CWE-526.

### SCF-03 Secrets in client bundles, images and shipped artefacts

- **What fails:** a build step copies a secret into something that users or the public can download.
- **Where to look:** build-time environment inlining into client code; source maps; container layers and build arguments; installers and packages; mobile and desktop resources; public storage; documentation sites built from the repository; artefact uploads in CI.
- **Questions:**
  - Which environment variables or config values does the build place into client code? Do secret names match the exposure prefix rules of the build tool?
  - Do source maps or debug symbols ship with embedded source and constants?
  - Does an image layer, build argument or cache hold a secret, even if the final layer deletes it?
  - Does the package list or installer include `.env`, key files or test fixtures?
  - Which values must be public (publishable keys), and which are secrets with the same shape?
- **Sad-path inputs:** a build with a secret in the environment; the produced bundle, map, layer or archive; a client that reads a "config" endpoint with server-only values.
- **Evidence for confirmed:** the build configuration that includes the secret and the artefact path where it lands. E1 is enough when the build rule is plain. At T2 you can build in a sandbox and scan the output. Do not publish the artefact.
- **Not a finding:** a value that is public by design; a bundle that holds only a public identifier.
- **CWE:** CWE-540, CWE-798, CWE-312.

### SCF-04 Insecure defaults

- **What fails:** the product, with no or partial configuration, runs unprotected.
- **Where to look:** default accounts and passwords; initial admin creation; open bind addresses; authentication off by default; permissive access lists; verification off by default; generated secrets that fall back to a fixed value; default tokens in agents and daemons; first-run setup that stays open.
- **Questions:**
  - What does the product do with an empty config? Does it start, and in which state?
  - Is there a default credential, key, token or secret that is the same for every install? Does setup force a change before the service accepts traffic?
  - What is the default bind address and port exposure?
  - Does first-run setup (create admin, claim device) stay open after use, or open to whoever connects first?
  - Which security setting defaults to off, permissive or "allow all"?
- **Sad-path inputs:** empty config; missing config file; unreadable file; setup page after setup; a fresh install reached over the network.
- **Evidence for confirmed:** the default value in source, the code path that uses it with no override, and the reachable state. E1 is enough. If a deployment layer outside the repository changes the default, record it as `needs-validation`.
- **Not a finding:** a default that is safe (deny, loopback, random generated value); a development-only default in a path that production cannot reach.
- **CWE:** CWE-1188, CWE-1392, CWE-798.

### SCF-05 Debug and development modes reachable in production

- **What fails:** a feature meant for developers is available to attackers.
- **Where to look:** debug flags; verbose error pages; interactive consoles; profilers and diagnostic endpoints; test or demo accounts and routes; "backdoor" login for support; remote debuggers; schema introspection and API explorers; mocks that skip real checks; mode selection by environment variable, header or query parameter.
- **Questions:**
  - How does the code decide the mode? Can request data, a cookie, a header or a user-writable file change it?
  - Does the production build remove the feature, or only hide the link?
  - What does the feature expose: source, config, secrets, state, code execution?
  - Does the mode default to development when the variable is unset?
  - Does a debug port or console bind to all interfaces?
- **Sad-path inputs:** the mode variable unset, empty or in another case; a debug header or parameter; a request to a diagnostic route; a stack trace for a malformed request.
- **Evidence for confirmed:** the mode selection, the route or code that stays active, and what it exposes. E1 is enough when the default build includes it. Whether production sets the variable is often external: then the status is `needs-validation`.
- **Not a finding:** a debug feature behind a build flag that release builds exclude (cite the build rule); a diagnostic route that needs administrator rights, where administrators may see the same data.
- **CWE:** CWE-489, CWE-215, CWE-209.

### SCF-06 Flags and settings that disable security

- **What fails:** a switch turns off authentication, verification, encryption or limits, and an attacker, a bad default or a failure can flip it.
- **Where to look:** flags named skip, disable, insecure, allow, bypass or trust; feature-flag services; per-tenant settings; admin pages that toggle controls; flags read from request data or from files that lower-trust users write; flag evaluation code on service outage.
- **Questions:**
  - Who can set this flag? Can an attacker reach any setter (a request field, a header, an environment of a child process, a shared config file)?
  - What does the code do if the flag service is unreachable or returns an error: fail open or closed?
  - Does the flag exist in release builds? Is its default safe?
  - Does a documented "temporary" flag remain in code with its unsafe path?
- **Sad-path inputs:** flag service down; flag value as string `"false"`, `"0"`, `"off"` or empty; flag in another case; a flag set per tenant by a tenant admin that affects other tenants.
- **Evidence for confirmed:** the flag read, the check it disables, and a path that sets it. E1 is enough. If only an operator can set it, record the finding as hardening.
- **Not a finding:** a flag that only an operator can set, with a safe default, for a documented test setup.
- **CWE:** CWE-15, CWE-636 (class-level; use a more specific child if one fits), CWE-1188.

### SCF-07 Config precedence, parsing and missing values

- **What fails:** a lower-trust source overrides a security setting, or a parsing error silently changes a setting.
- **Where to look:** config loaders; merge rules between files, environment, command line and defaults; per-tenant or per-user overrides; include directives; unknown-key handling; type coercion; templated config; reload code; fallback to defaults on parse error.
- **Questions:**
  - What is the order of sources? Can a source that attackers or low-trust users write override a security key?
  - Does an unknown or misspelled key get ignored? A typo in `require_tls` then leaves the default.
  - Does a string such as `"false"` become true in a truthy check? Does an empty value mean unset or off?
  - If the file is missing, unreadable or invalid, does the product start with defaults?
  - Does a config value flow into a path, command, URL or query without validation (external control of a setting)?
  - Does the config path come from the current directory or a writable location?
- **Sad-path inputs:** a misspelled key; duplicate keys; wrong type; empty string versus unset; a file that fails to parse; a config in the working directory; an override from a tenant setting.
- **Evidence for confirmed:** the loader code, the input that changes a security value, and the effect. E1 is enough. Behaviour of a third-party config library that you did not read makes the claim `needs-validation`.
- **Not a finding:** an override that only an operator can make, with the same trust as the base config.
- **CWE:** CWE-15, CWE-1188.

### SCF-08 Environment and external-source trust

- **What fails:** the code trusts a value from a source that a less-trusted party controls.
- **Where to look:** environment variables read at start or per request; proxy variables; mode variables; values from the current directory; user-writable config in home directories; values from a database or remote config service; variables set by a parent process or a CGI-style server from request headers.
- **Questions:**
  - Who sets this variable? Could a caller, a parent process, a web server or another user set it?
  - Does a request header become an environment variable of the handler?
  - Does the process run with higher privilege than the writer of the value?
  - Does a proxy variable redirect outbound traffic (hand off to `domain-outbound-network.md`)?
- **Sad-path inputs:** a variable set by the caller; a variable set to an attacker URL or path; a variable that is set in a development shell but not in production.
- **Evidence for confirmed:** the read, the writer who is not trusted, and the effect on a security decision. E1 is normally enough. Behaviour of the hosting layer is often external.
- **Not a finding:** a variable that only the administrator sets, in a service that the administrator already controls.
- **CWE:** CWE-15, CWE-526.

### SCF-09 Secret storage, rotation and revocation

- **What fails:** a secret is stored weakly, shared too widely, or cannot be replaced after exposure.
- **Where to look:** config files with plaintext secrets; file permissions; shared secrets across environments or tenants; single long-lived tokens; secret-manager use; startup code that reads secrets; rotation scripts; revocation paths; derived secrets from guessable inputs.
- **Questions:**
  - Where is the secret at rest, and who can read it?
  - Do staging and production, or two tenants, share it?
  - Can the secret change without a code change or an outage? Does the system accept two secrets during a switch?
  - After a leak, is there a way to revoke it? Does the old value stay valid?
  - Does a missing secret at start lead to a generated weak value or a default?
- **Sad-path inputs:** a secret file with wide permissions; the same secret in two environments; a rotation that leaves the old value valid; a missing secret at start.
- **Evidence for confirmed:** the storage and the reader who should not have access, or the missing rotation path with a long-lived secret that guards a real boundary. E1 is enough for plain exposure. Rotation practice outside the repository makes a claim `needs-validation`.
- **Not a finding:** a secret readable only by the service account in a single-tenant host, where the threat model excludes local administrators.
- **CWE:** CWE-522 (class-level), CWE-312, CWE-922 (class-level), CWE-324.

### SCF-10 Example, template and fixture configs that ship

- **What fails:** an example or test file with weak values becomes the real configuration.
- **Where to look:** `*.example`, `*.sample`, `*.dist` and template files; compose files and charts; installers that copy defaults; Docker images that include fixtures; documentation snippets that setup scripts use; seed data and demo accounts in migrations.
- **Questions:**
  - Does setup copy the example config as-is? Does it contain default passwords, open binds or disabled checks?
  - Does the image or package include seed users, demo data or test keys?
  - Do migrations create a default admin or test account in every environment?
  - Does the documented quick-start produce an insecure installation that operators keep?
- **Sad-path inputs:** a fresh install that follows the quick-start; a production deploy from the default compose file; a migration run on an empty database.
- **Evidence for confirmed:** the file or migration, the insecure value, and the path by which it reaches a running system. E1 is enough when the installer copies it.
- **Not a finding:** an example file that the product refuses to run with (it checks for placeholder values).
- **CWE:** CWE-1188, CWE-1392, CWE-798.

## Variant search

When you find one secrets or configuration failure:
1. **Same value.** Search the tree, history and artefacts for the same secret or the same default.
2. **Same pattern.** Search for the same flag, setting name or default idiom in other modules, services, scripts and languages.
3. **Same source.** Check every place that reads the same variable or config key, and the code of each sibling service.
4. **Same sink.** If a secret reaches one log or response, check every log call and error handler near similar objects.
5. **Same artefact type.** If one image or bundle holds a secret, scan the other build outputs and the CI artefacts.
6. **Same history.** If an earlier commit removed a secret, check that the fix rotated it and did not just delete it.

## Chain primitives

This domain often **gives**:
- valid credentials or signing keys (to authn, supply-chain and cloud chains);
- a way to impersonate the service or a user (forged tokens, fixed keys);
- debug access that exposes state, config or code execution;
- a switched-off control that unlocks another domain's flaw (verification disabled, auth disabled);
- knowledge of internal hosts, paths and versions.

This domain often **needs**:
- read access to a log, artefact, repository or response (from authz, logging-privacy or supply-chain);
- a way to set an environment variable or a config value (from filesystem-process, local-ipc or an admin interface);
- network reach to a debug port (from cloud-deploy or http-protocol).

## Verification notes

- **E1 is usually enough** for SCF-01 (secret in the tree and used as a credential), SCF-02, SCF-03 (plain build rule), SCF-04, SCF-05 (feature in the default build), SCF-06, SCF-07, SCF-09 (plain exposure) and SCF-10, when every step is in the repository.
- **E3 is rarely needed.** Use it when a claim depends on a build output (SCF-03 with a complex pipeline) or on a library parsing rule that you did not read (SCF-07). No claim in this domain depends on timing or memory layout.
- **Liveness is external.** Whether a leaked secret still works is outside the repository. Never test it. Use `needs-validation` when the impact depends on it, and name the safe check (the owner checks the provider).
- **Attacker access:** state who can read the place where the secret sits. A secret in a private repository that all contributors can read is a different risk from a secret in a public package.
- **Production selection:** decide how production is configured from files in the repository (compose files, charts, installers). If production values are outside the repository, the status is `needs-validation`.
- **Protect secrets:** record file, line and type. Never copy the value into a finding, a report or a log.
- **Severity examples:**
  - critical – a hard-coded credential or key gives unauthenticated access to all installations or to production data; debug console with code execution reachable from the network;
  - high – a secret in a public client bundle or image that grants access to backend data; a default admin account that is reachable on a fresh install; a flag request data can set to disable authentication;
  - medium – secrets in logs readable by many staff; a debug route that exposes configuration to authenticated users; a shared secret across environments;
  - low – verbose errors that reveal paths and versions; a long-lived secret with a documented manual rotation;
  - informational – a placeholder value in a shipped example that the product rejects.

## Fix patterns

- **Keep secrets out of artefacts.** Inject them at run time from a secret manager or the platform. Do not put them in source, images, build arguments or client bundles.
- **Validate configuration at start.** Use a schema with required keys, known keys only and typed values. Refuse to start on any error. Treat a missing security key as an error, not as "off".
- **Make safe the default.** Deny, loopback, TLS verification on, random per-install secrets. Generate secrets at first start. Block service traffic until setup finishes, and close setup after use.
- **Separate by environment and purpose.** One secret per environment, tenant and use. Support two active versions during rotation.
- **Rotate after exposure.** If a secret was ever committed or logged, treat it as exposed. Revoke it and issue a new one. Rewriting history is not enough.
- **Remove debug in release.** Compile it out or fail the build. Do not use a runtime request switch.
- **Fix precedence.** Let only the highest-trust source set security keys. Ignore tenant and request overrides for them.
- **Redact by allow-list.** Log named safe fields. Do not log whole objects.
- **Detect.** Run a secret scanner (for example gitleaks or trufflehog) in pre-commit and CI, and scan built artefacts.
- **Looks right but is not:** deleting the file in a new commit; adding it to the ignore list after the commit; base64 or XOR "obfuscation"; a private repository as the only control; masking a secret in logs by exact match; secret in a URL query; a secret in an image build argument; a note in the documentation to "change the default password"; hiding the debug link while the route stays active.

## Regression tests

- Start-up tests: with an empty config, a missing file, an unreadable file and a misspelled security key, the product refuses to start or runs in a safe state.
- Type tests: `"false"`, `"0"`, empty and case variants of each boolean security setting produce the documented result.
- Mode tests: in a production build, each debug and diagnostic route returns not found or denied. Request data cannot change the mode.
- Precedence tests: a tenant, request or user-writable source cannot override a security key.
- Artefact scan: in CI, scan source, history, built bundles, images and packages for secret patterns and key files. Fail the build on a hit.
- Redaction tests: log and error output for failed logins, bad configs and failed connections contains no secret value.
- Rotation test: replace the secret, and assert the old value stops working after the switch window.
- Fresh-install test: a default install has no default credential, and setup cannot be reused by a second visitor.
