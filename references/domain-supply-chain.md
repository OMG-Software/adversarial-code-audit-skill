# Domain: Supply Chain

## Scope

- **Load when:** the repository has dependency manifests or lockfiles, vendored or copied third-party code, CI or build workflows, release or packaging scripts, an update client, a plugin, extension or mod loader, or code that downloads models or datasets. Signs: `package.json`, `requirements*.txt`, `go.mod`, `Cargo.toml`, `pom.xml`, `*.gradle`, `Gemfile`, `Dockerfile`, `.github/workflows/`, `.gitlab-ci.yml`, `Jenkinsfile`, signing keystores, update manifests, plugin manifests.
- **Covers:** dependency resolution and confusion, mutable and unpinned inputs, lockfile and hash integrity, vendored code, install-time and build-time code execution, CI workflow trust and token scope, build and release authority, signing, update channels and rollback, plugin, extension and mod distribution, and model and dataset provenance.
- **Hand off to:**
  - `domain-secrets-config.md` – secret storage, rotation and loading at run time. This file owns how CI jobs expose secrets.
  - `domain-sandbox.md` – isolation of a plugin or mod at run time. This file owns how the plugin arrives and what approves it.
  - `domain-embedded.md` – device-side image verification, secure boot and OTA state. This file owns the build, signing and publishing side.
  - `domain-local-ipc.md` – the local privileged installer that applies an update, and who may trigger it. This file owns the authenticity of the update.
  - `domain-ai-llm.md` – unsafe model file formats and what happens when a model file loads. This file owns where the model came from and how it is pinned.
  - `domain-cloud-deploy.md` – container and IaC runtime privileges. This file owns image and module provenance.
  - `domain-web-client.md` – third-party scripts and SRI in pages.
  - `domain-crypto.md` – signature algorithm and key-handling errors. This file owns what the signature covers and whether the code enforces it.

## Invariants

Fill the placeholders from `threat-model.md`.

1. **Pinned input:** Every input to <build | install | release | deploy> is fixed to <exact version and content hash | commit SHA | image digest> and resolves from <named source>.
2. **Name resolution:** The name <package | image | module | action> resolves to <registry and namespace the project owns or chose>. No default order, mirror or fallback makes it resolve elsewhere.
3. **Untrusted code:** Code from <fork | pull request | third-party package | plugin> never runs with <secrets | write token | release rights>.
4. **Job scope:** Each CI job holds only the permissions and secrets it needs. A job started by untrusted input holds none that can publish, deploy or write to the repository.
5. **Event data:** Text from <issue | branch name | pull request title | commit message | artefact> never becomes code or a shell command in a workflow.
6. **Release authority:** Only <named role> using <named process> can publish <artefact>. The published artefact comes from the reviewed commit and nothing else.
7. **Update:** A client installs an update only if a signature over the payload, version and target verifies against a pinned key, and the version is not older than the installed one. Any error means no install.
8. **Plugin:** A plugin or mod loads only the code that <user | operator | reviewer> approved, identified by content hash, and a later update needs approval again.
9. **Provenance:** A model or dataset that the product loads is the one reviewed, identified by revision and hash. Loading it does not run code.

## Recon additions

Add these to `threat-model.md` under "Supply chain".

1. **Dependency sources.** Table: ecosystem | manifest and lockfile | registries and mirrors (with config file:line) | pinning (range, exact, hash) | install command in CI and in docs | scripts allowed at install.
2. **Vendored code.** Directories, submodules and pasted snippets with origin, version and local patches.
3. **Workflow inventory.** Table: workflow or pipeline | trigger | which parts of the trigger an outsider controls | permissions | secrets | runner type (hosted, self-hosted, shared) | what it checks out | what it uploads.
4. **Release pipeline.** Table: artefact | built where | signed by which key and where the key lives | published to where | who can start it | how a consumer verifies it.
5. **Update and plugin channels.** For each client that fetches code or data: URL source (constant or config), transport, signature and what it covers, rollback rule, key rotation, fallback on error.
6. **Model and dataset sources.** Host, revision pin, hash check, remote-code flags.
7. **Who can change what.** Maintainers, bots, code owners and branch protection that the repository shows. Mark outside settings as external assumptions.

## Lead searches

Adapt the patterns to the ecosystem. Language files add package-manager details.

| Search | A hit may mean | False-hit notes |
|---|---|---|
| `pull_request_target\|workflow_run\|issue_comment\|issues:\|discussion` in workflow triggers | A privileged workflow started by outsiders (SUP-06) | Safe if the job never checks out or runs outsider code and never expands outsider text. |
| `\$\{\{\s*(github\.event\|github\.head_ref\|inputs\|steps\..*outputs)` inside `run:` or `script:` blocks | Event text expanded into a script (SUP-06) | An `env:` indirection that is then quoted in the script is the safe form. |
| `ref:\s*\$\{\{.*(head\|pull_request)` near `actions/checkout`, or a CI step that fetches the merge-request source branch | Privileged job runs outsider code (SUP-06) | Check the trigger and permissions first. |
| `permissions:\s*write-all`, no `permissions:` key, `id-token:\s*write`, `contents:\s*write` | Wide token (SUP-07) | Org defaults live outside the repository. Record as external. |
| `uses:\s*[^@\s]+@(main\|master\|v?\d+(\.\d+)*)\s*$` and `image:\s*\S+:(latest\|\d+)` | Action or image fixed by a mutable ref (SUP-02) | A first-party action in the same repository is lower risk. |
| `curl\|wget\|iwr\|Invoke-WebRequest` piped to `sh\|bash\|iex\|python` | Unverified code at build time (SUP-02, SUP-03) | Safe if a hash check runs before use. |
| `--extra-index-url\|--index-url\|registry=\|\[source\|replace\s*=\|GONOSUMDB\|GOFLAGS\|GOPRIVATE\|--trusted-host\|--no-verify\|strict-ssl\s*=\s*false` | Resolution or integrity setting weakened (SUP-01, SUP-03) | Private mirrors can be correct. Read the precedence rules. |
| `postinstall\|preinstall\|prepare\|setup\.py\|build\.rs\|cmdclass\|exec-maven\|buildscript\|pre-commit\|husky\|git config core.hooksPath` | Code that runs at install or build time (SUP-05) | Read what the script does and what runs it. |
| `git+https\?://\|github:\|\.git#\|file:\.\./\|"latest"\|\^\|~\|>=\s*\d` in manifests | Unpinned or non-registry dependency (SUP-01, SUP-02) | A lockfile may fix the version. Check that it exists and that CI uses it. |
| Lockfile names in `.gitignore`, or `install` where `ci`, `--frozen-lockfile`, `--locked` or `--require-hashes` is possible | Lockfile not enforced (SUP-03) | Libraries may omit lockfiles by choice. Check the CI and release build. |
| `verify\|signature\|checksum\|sha256\|gpg\|cosign\|minisign` near download or update code, with the result unused or inside a `try` that continues | Verification absent or ignored (SUP-09) | Read the control flow after a failure. |
| `trust_remote_code\|allow_pickle\|from_pretrained\|hf_hub_download\|torch\.hub\|load_dataset` without a revision pin | Model or dataset from a mutable source (SUP-11) | A pinned local mirror may sit behind the call. |

## Attack classes

### SUP-01 Dependency confusion, typosquatting and name takeover

- **What fails:** an install resolves a package, module, image or action name to a source the project did not intend. The wrong source supplies code that runs with developer or build rights.
- **Where to look:** internal package names that also fit a public registry; resolver settings that mix a private and a public index; scoped names without a scope owner; dependencies named by a close misspelling; dependencies whose maintainer account, domain or repository was abandoned or renamed; `git` and URL dependencies; build scripts that install tools by name.
- **Questions:**
  - Is every internal name reserved or scoped on the public registry? Does the resolver config force each name to one source?
  - Does a manifest name differ by one character from a well-known package?
- **Sad-path inputs:** a public package with the internal name and a higher version; a name that a registry normalises (case, `-`, `_`); a renamed repository whose old name is free.
- **Evidence for confirmed:** the resolver configuration, the name that is not reserved, and the rule that lets a second source win. The existence of a public package is an external fact. Without it the finding is `needs-validation`. Do not publish a test package.
- **Not a finding:** a name that an enforced lockfile pins by hash to the intended source; a dependency resolved from one explicit index.
- **CWE:** CWE-829; CWE-1357 (class-level).

### SUP-02 Mutable and unpinned inputs

- **What fails:** the build takes an input that its owner can change after review. A later change reaches the build without a project commit.
- **Where to look:** version ranges and `latest`; actions or CI templates pinned to a branch or tag; base images pinned to a tag; remote `include:` templates; tools fetched during build; Git dependencies and IaC modules pinned to a branch; scripts piped into a shell.
- **Questions:**
  - Which inputs does the release build fetch? Does each have a hash or commit SHA?
  - Can the input's owner move the ref (tag, branch, `latest`)?
  - Does the input run with secrets or the release token?
- **Sad-path inputs:** a tag moved to new code; a new minor version with a changed install script.
- **Evidence for confirmed:** the mutable reference, the step that fetches it, and the privileges of that step. An upstream change is a precondition outside the repository: the finding states the exposure, not an event.
- **Not a finding:** a pin by full commit SHA or digest; a mutable ref in a job with no secrets, no write rights and no output that other jobs trust (hardening note).
- **CWE:** CWE-829; CWE-1357 (class-level).

### SUP-03 Lockfile, hash and vendored-code integrity

- **What fails:** the lockfile or hash check does not bind what is installed. Or vendored code differs from its stated source.
- **Where to look:** lockfiles that are ignored, missing or not used by CI; install commands that ignore the lockfile; resolved URLs that use plain HTTP or a host outside the registry; missing integrity fields; checks disabled by flags or variables; `replace` and override directives; submodules that follow a branch or a fork; checked-in binaries; copied code with local patches and no origin record.
- **Questions:**
  - Does CI run the strict install (`npm ci`, `--frozen-lockfile`, `--locked`, `--require-hashes`, `go mod verify`)?
  - Do manifest and lockfile agree? Can a pull request change the lockfile without a manifest change, and does review notice?
  - Does a flag turn off a checksum database or a TLS check?
  - Can you compare the vendored tree to the upstream version it names?
- **Sad-path inputs:** a lockfile entry with an odd host or hash; a manifest range that the lockfile does not satisfy; a vendored file with an unexplained change.
- **Evidence for confirmed:** the weak setting or missing check, the install path that uses it, and what an input change then reaches. For vendored code, the diff against upstream.
- **Not a finding:** a library that ships without a lockfile when its own CI uses one; an `--ignore-scripts` install in a job with no secrets.
- **CWE:** CWE-494; CWE-345 (class-level); CWE-1104 for vendored code of a project that no longer maintains it.

### SUP-04 Known-vulnerable and unmaintained dependencies

- **What fails:** shipped software or a development, build, test or release workflow uses a component whose weakness is public, or whose upkeep ended, and attacker-controlled input reaches the weak function.
- **Where to look:** lockfile versions; vendored copies; pinned base images; bundled native libraries in mobile and desktop apps; development dependencies and build-tool plugins used by CI and release workflows.
- **Questions:**
  - Does the product call the weak function with input an attacker controls?
  - Can the product update this component at all?
- **Sad-path inputs:** the input class that the advisory names, at the product's call site.
- **Evidence for confirmed:** the version, the advisory text, and the call path from entry to the weak function. A version match alone is a lead.
- **Not a finding:** a component version with no reachable vulnerable call in shipped software or development, build, test and release workflows. Absence from shipped artefacts alone does not exclude a development dependency.
- **CWE:** CWE-1395 (class-level); CWE-1104; CWE-1329 (class-level) when a fixed component has no update path.

### SUP-05 Install-time and build-time code execution

- **What fails:** code from a dependency, a plugin of the build tool or the repository runs during install, build or test, with the rights of the developer or the CI job.
- **Where to look:** package lifecycle scripts; `setup.py` and build backends; `build.rs`; build-tool plugins; code generators; git hooks and hook managers that fetch remote repositories; task runners; editor tasks that run on folder open.
- **Questions:**
  - What runs, who wrote it, and is it pinned (SUP-02)?
  - What can the process read: environment variables, credential files, cloud tokens, the signing key?
  - Is script execution off in the release and publish jobs?
- **Sad-path inputs:** a dependency version that adds a script; a script that reads the environment.
- **Evidence for confirmed:** the script, the step that runs it, and the secret or right that step holds. Read the script. Do not run it.
- **Not a finding:** a script of the project itself that a trusted maintainer reviewed, in a job without secrets.
- **CWE:** CWE-829; CWE-250 when the job holds more rights than the step needs.

### SUP-06 CI workflow injection and untrusted triggers

- **What fails:** a person outside the trusted group controls text, files or code that a privileged workflow expands, checks out or runs.
- **Where to look:** triggers that run with the base repository's secrets and write token on outsider input (`pull_request_target`, `workflow_run`, `issue_comment` on GitHub; fork merge-request pipelines with protected variables on GitLab; comment-triggered builds elsewhere); expressions in `run:` and `script:` that expand branch names, titles, bodies or commit messages; checkout of the outsider branch in a privileged job; writes to `GITHUB_ENV` or `GITHUB_PATH` from untrusted data; artefacts and caches that a privileged job reads after an unprivileged job wrote them; self-hosted runners that take jobs from public forks.
- **Questions:**
  - Which parts of the trigger does an outsider control: branch name, title, body, files, artefact content?
  - Where does that text go: into a shell, an environment file or a model prompt (hand off to `domain-ai-llm.md`)?
  - Does the job check out and run outsider code while it holds a secret or a write token?
  - Does the job read an artefact or cache that an outsider job wrote, and then trust it?
- **Sad-path inputs:** a branch name with shell metacharacters or a newline; a title that ends a quoted string; a pull request that changes a script that the privileged job later runs.
- **Evidence for confirmed:** the trigger, the expansion or checkout line, and the secret or write right of the job. Use a local rendering or a dry check of the expression, never a real run. E1 is enough when the expansion sits in a `run:` block and the trigger accepts outsider input.
- **Not a finding:** an expression expanded only from values the actor does not control (a commit SHA); an unprivileged trigger with a read-only token and no secrets.
- **CWE:** CWE-78 when the text reaches a shell; CWE-829 for checkout and run of outsider code.

### SUP-07 CI token, secret and identity scope

- **What fails:** a job holds more rights than its work needs, or a secret reaches a step that can leak it.
- **Where to look:** default token permissions; workflow-level `permissions`; long-lived cloud keys stored as CI secrets; identity federation (OIDC) whose trust policy accepts any branch, fork or workflow; third-party actions that receive secrets; `set -x`, `env` dumps and debug flags in jobs with secrets; secrets passed to pull-request builds; deploy keys with write access.
- **Questions:**
  - Does each job set its own minimal permissions?
  - Does the federation claim (subject, repository, ref, environment) restrict the cloud role to the release workflow? (The cloud-side policy is outside the repository. Record it as an external assumption.)
  - Which steps see each secret, and could a step print or send it?
- **Sad-path inputs:** a job on an outsider branch; a trust policy that matches a repository prefix.
- **Evidence for confirmed:** the job, its permissions and the secret, plus the path from an untrusted step to the secret. The cloud-side trust policy is usually external, so the finding is often `needs-validation`.
- **Not a finding:** a wide default in a repository with no outsider triggers and no secrets
- **CWE:** CWE-250; CWE-532 when a secret enters a log.

### SUP-08 Build integrity and release authority

- **What fails:** the published artefact does not come from the reviewed commit, or the wrong person or job can publish it.
- **Where to look:** release triggers (any tag, any branch, any comment); builds on developer machines; broad publish tokens; signing keys in the repository or in plain CI variables; signing steps that skip on error; artefacts uploaded before tests and signing; packages with files the repository does not have; no provenance that consumers can check.
- **Questions:**
  - Who can start the release job? Does it require a protected ref or approval?
  - Where does the signing key live, and which jobs can read it?
  - If signing fails, does the job still publish?
- **Sad-path inputs:** a tag pushed from a feature branch; a failing signing step; a release job started by a comment.
- **Evidence for confirmed:** the trigger, the missing gate or the skipped check, and the artefact that results. Branch protection and registry settings are outside the repository: mark them.
- **Not a finding:** a build that is not reproducible, with no other defect (hardening note).
- **CWE:** CWE-345 (class-level); CWE-494.

### SUP-09 Update channel authenticity, rollback and downgrade

- **What fails:** a client installs code or data that the release authority did not sign, or installs an older version that has a known flaw.
- **Where to look:** updaters for desktop, mobile, CLI, daemon and plugin hosts; manifest parsing; the code that calls the verify function; update URL selection; delta handling; key rotation; fallback on verify error; app signing configuration for Android and iOS.
- **Questions:**
  - Does the signature cover the payload, or only the manifest that points to it? Does the manifest bind the hash, size, version and target platform?
  - Does every path, including error and retry paths, enforce the verify result?
  - Is the public key pinned in the client, or does it come from the update server?
  - Does the client refuse an older version, an expired manifest, and a manifest for another product or channel?
  - Can config, an environment variable or a flag change the update URL or turn off the check? Is plain HTTP accepted?
- **Sad-path inputs:** a valid old release offered as the new one; a signed manifest with a changed payload hash; a payload with no manifest; a truncated signature; a manifest for another channel.
- **Evidence for confirmed:** the verify code, the field or step that it does not cover, and the install call that follows. Test with a local fake server and dummy keys. A race between check and install needs E3.
- **Not a finding:** an update source that an administrator sets on purpose, when the signature still applies.
- **CWE:** CWE-347; CWE-494; CWE-345 (class-level). Rollback and downgrade acceptance: no single checked CWE; name the weakness in words.

### SUP-10 Plugin, extension and mod distribution

- **What fails:** the product loads plugin, extension or mod code from a source or in a way that nobody approved, or an update changes the code after approval.
- **Where to look:** install-from-URL features; marketplace or index clients; auto-update of plugins; plugin manifests that declare permissions; plugin directories that other users or apps can write; game servers that load mod packs by name; look-alike plugin names.
- **Questions:**
  - What identifies the plugin: a name, a URL or a content hash? Does an update keep the approval?
  - Who can write to the plugin directory or the index?
  - Do a plugin's own dependencies resolve by name at install time (SUP-01)?
- **Sad-path inputs:** a plugin replaced after approval; a plugin with the name of a popular one; a manifest that asks for more permissions than the first version.
- **Evidence for confirmed:** the load path, the missing approval or binding, and who can write to the source.
- **Not a finding:** plugins that an administrator installs from a trusted local path by design, in a directory that only administrators can write.
- **CWE:** CWE-829; CWE-494.

### SUP-11 Model and dataset provenance

- **What fails:** the product downloads a model, weights or dataset from a mutable or unverified source, or loads it with a setting that runs the publisher's code.
- **Where to look:** model hub clients; download scripts; images that bake in weights; dataset loaders; flags that allow remote code.
- **Questions:**
  - Is the revision pinned to an immutable ID, and is a content hash checked?
  - Does the loader accept code from the model repository?
  - Who can change the source: the project, a third-party account, any user?
- **Sad-path inputs:** a branch moved to a new file; a model repository that adds a code file; a dataset with a changed hash.
- **Evidence for confirmed:** the fetch, the missing pin or check, and the load call. For file-format risks, use `domain-ai-llm.md`.
- **Not a finding:** a pin by revision and hash with the check enforced; a model used only in an offline script that never reaches users.
- **CWE:** CWE-494; CWE-829.

## Variant search

When you find one supply-chain defect:
1. **Same file type.** Check every workflow, pipeline and manifest for the same trigger, expansion, pin or setting.
2. **Same trust source.** List every use of the same action, template, registry, mirror, image, artefact or cache.
3. **Same secret.** List every job and step that can read the same secret.
4. **Same fetch pattern.** Search for every download-and-run and fetch-without-hash step, including in docs that users copy.
5. **Same history.** If an earlier fix pinned one input (phase 2.3), check its siblings.

## Chain primitives

This domain often **gives**:
- code execution in CI, with its secrets and tokens (leads to registry, cloud and repository write access);
- control of a released artefact that many users run;
- control of an update, plugin or model that a client trusts;
- the cloud role that a federated CI identity maps to.

This domain often **needs**:
- a way to send input to CI: a pull request, an issue, a comment, a branch name;
- a mutable upstream input or an unreserved name (external);
- cloud-side trust policies (from `domain-cloud-deploy.md`);
- a network position to alter downloads, for update attacks.

## Verification notes

- **E1 is usually enough** for SUP-06 (expansion or checkout in a privileged workflow), SUP-07 (token scope inside the workflow file), SUP-02, SUP-03, SUP-05 and SUP-09 when the verify code is in the repository and the failing step is plain control flow (a result ignored, a field not covered). The waiver must name the trigger, the permission block and every file read.
- **E3 is needed** for SUP-09 claims about races between check and install, for parser differences in manifest or archive handling, and for any claim that depends on how a package manager resolves names when its code is not in the repository.
- **Facts usually outside the repository** make a finding `needs-validation`: registry ownership of a name (SUP-01); organisation-level default token permissions and required approvals (SUP-06, SUP-07); the cloud role's trust policy for federated CI identity (SUP-07); branch and tag protection, registry publish settings and two-factor rules (SUP-08); whether upstream moved a tag (SUP-02). State the one decisive fact and a safe way to check it, such as reading the setting in the organisation console as the owner.
- **Do not touch live systems.** Do not start a workflow, publish a package, query a registry, contact an update server or call a model hub. Render config locally. Use fixtures and dummy keys.
- **Reachability:** confirm that the trigger fires on outsider input in the default configuration.
- **Design authority:** a maintainer's own push is not an attack. The attacker is an outsider, a dependency author, or a network position.
- **Severity examples:**
  - critical – an outsider's pull request or issue text runs code in a job that holds the publish token, signing key or cloud admin role; an update client installs unsigned code from a network position;
  - high – a federated CI role that any fork can assume and that can write to production; a release job that any contributor can start; an unreserved internal package name in the default resolver path;
  - medium – a mutable action ref in a job with a write token but no secrets; an updater that accepts an older signed version;
  - low – a mutable ref in a read-only job; a missing lockfile in a library;
  - informational – a build that is not reproducible.

## Fix patterns

- **Pin everything that the release uses** to a full commit SHA, image digest or content hash. Update pins by reviewed change.
- **Enforce the lockfile** with the strict install command in CI and release jobs. Fail on drift.
- **Reserve and scope names.** Put internal packages in a private scope. Configure the resolver so each name has one source.
- **Split privileged and unprivileged work.** Run outsider code in a job with a read-only token and no secrets. Pass results as data to a second job. That job does not run them.
- **Pass event text through environment variables** and quote them in the script. Never expand them into the script text.
- **Set permissions per job**, deny by default. Use short-lived federated identities bound to repository, ref and environment.
- **Publish from a protected pipeline only.** Sign in a separate step with a key that only that step can read. Publish provenance.
- **Verify updates fully.** Verify the signature over a manifest that binds hash, size, version, target and expiry. Pin the key in the client. Refuse older versions. Fail closed.
- **Bind plugin approval to a content hash.** Ask again when it changes.
- **Pin models by revision and hash.** Turn off remote code loading.
- **Looks right but is not:** pinning to a tag instead of a SHA; a lockfile that CI does not use; `--ignore-scripts` on install while the build runs the same scripts later; checking a signature on one download but installing a second download; a signature check that logs and continues; log masking as the only protection for a secret; HTTPS alone as update authentication.

## Regression tests

- A **workflow lint test** that fails on mutable refs, missing `permissions`, privileged triggers that check out outsider code, and event expressions inside `run:` blocks.
- A **lockfile test** that installs with the strict command and fails when manifest and lockfile differ.
- A **resolver test** with a fixture registry that offers the internal name at a higher version in a second index. The install must ignore it.
- **Updater tests** with a local fake server and test keys: wrong key, modified payload, modified manifest field, older version, expired manifest, missing signature, verify error. Each ends with no install.
- A **plugin test** where the code changes after approval. It must ask again.
- A **model loader test** that rejects a model with no pin or a wrong hash.
