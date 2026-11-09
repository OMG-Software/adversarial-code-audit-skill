# Phase 1 – Recon and threat model

Goal: know what the product protects, who attacks it, where attacker data enters, and which controls stand in the way. Then turn that into a list of coverage units.

Do not hunt in this phase. If you see a likely bug, write one line in `leads.md` and continue.

Outputs:
- `threat-model.md` – at most about 1,500 words. Hunters read it for every unit, so keep it dense.
- `coverage.md` – the coverage ledger.
- Domain and language selections, added to `plan.md`.

## 1.1 Inventory the repository

Record facts, each with a repository path.

1. Languages and their share of the code. At T1: `git ls-files | sed -n 's/.*\.//p' | sort | uniq -c | sort -rn | head -20`. If `cloc` or `tokei` is present, use it.
2. Build system, build targets and output binaries or packages.
3. Subsystems: top-level directories or packages and what each does.
4. Programs that run: entry points (`main`, server start-up, workers, CLIs, scheduled jobs, migrations).
5. Tests: where they are, how they run, and whether security code has tests.
6. Deployment files in the repository: container files, IaC, sample configs, default config values.
7. Documentation that states security intent: threat models, SECURITY.md, design docs, protocol specifications the code implements.
8. Vendored or generated code. Record it, and decide if it is in scope.

For a large repository, inventory per subsystem. Do not read every file now.

## 1.2 Product and assets

Write down:
- What the product does, for whom, and how it runs (service, library, CLI, app, daemon, plugin).
- **Assets**: what an attacker wants. Use this list as a prompt:
  - confidentiality: user data, other tenants' data, private messages, credentials, keys, tokens, internal topology;
  - integrity: stored data, permissions, signed or replicated state, audit logs, code and releases;
  - availability: shared service processes, queues, storage, quotas;
  - authority: acting as another user, admin, server or service;
  - money or spend: paid API calls, compute, storage.

## 1.3 Principals

List every principal from lowest to highest trust. For each, state what it can do **by design**. Typical principals:

- unauthenticated network client;
- authenticated user; user in another tenant, organisation, project or group;
- remote peer server or federated service;
- integration, bot, webhook sender, OAuth client;
- plugin or extension author;
- local user on the same host; other process on the host;
- content author whose data other users or a model will process;
- admin, operator, CI job, release signer.

A principal acting within its own design authority is not an attack. Write the design authority down so hunters can tell the difference.

## 1.4 Entry surfaces

Find every place where data from a lower-trust principal enters. For each surface record: file:line, principal, authentication required (yes / no / partial), the parser or framework that decodes it, and the first function that handles it.

Check each category:
- network listeners, routes, RPC methods, GraphQL resolvers, WebSocket handlers;
- federation or peer-to-peer endpoints, including data relayed through a peer;
- message consumers, webhooks, callbacks;
- file input: uploads, imports, archives, media, config files a user can supply;
- command-line arguments, environment variables, config, feature flags;
- local IPC: Unix sockets, named pipes, D-Bus, XPC, Binder, shared memory;
- plugins, scripts, templates, rules or expressions that users can write;
- stored data that a different principal wrote (second-order input);
- model output, if the product uses an LLM;
- time, DNS, certificates and other environment inputs that an attacker may influence.

At T1, search for registration and start-up patterns. Examples: route tables, `listen`, `bind`, `accept`, `argv`, `getenv`, handler maps, decorator names, generated stub registrations. The language file lists more patterns.

## 1.5 Trust boundaries and controls

A trust boundary is a point where data or control passes from one principal to another, or from one trust level to another.

For each boundary record:
- the two sides;
- the control that enforces it (authentication, authorization check, signature check, validation, sandbox, rate limit) with file:line;
- whether the control is **central** (one function every path must call) or **scattered** (each handler checks);
- whether the control is source-visible or **external** (proxy, gateway, identity provider, OS policy).

For each central control, note "the function everyone should call". Phase 3 searches for callers that do not call it.

## 1.6 Attacker goals

For each principal, combine it with each asset and write goals in this form:

> As **<principal>**, I want to **<action>** on **<asset>** so that **<consequence>**.

Examples:
- "As an authenticated user in organisation A, I want to download invoices of organisation B, so that I learn their customers and prices."
- "As an unauthenticated network client, I want to make the parser write past a buffer, so that I can crash or control the server process."
- "As a remote peer, I want the local node to accept a message signed by a key I do not own, so that I can impersonate another peer's users."

Use STRIDE (spoofing, tampering, repudiation, information disclosure, denial of service, elevation of privilege) only as a completeness check on each boundary. Do not list every STRIDE cell.

Rank goals by impact, then by how low the required principal is. The top goals drive unit priority and phase 5.

## 1.7 External assumptions

List the facts the security of the product depends on that are not in the repository. Examples: "the reverse proxy strips `X-Forwarded-For`", "TLS terminates before this service", "only the internal network can reach the admin interface". Phase 6 uses this list: a finding that depends on one of these facts is `needs-validation`.

## 1.8 Select domain and language files

Use the table in SKILL.md section 5. Select a file when the code has the boundary that the table names. Do not select a file only because a dependency or keyword appears.

In `plan.md`, record each selected file with the boundary that requires it (file:line). Record each excluded file with the fact that excludes it. A weak exclusion ("probably not used") is not valid. Select the file instead.

**Product-type checklist.** Use this table to find domains you may have missed. It is a checklist, not a selection rule: select each domain only when the code has its boundary, and record an exclusion for each listed domain that you do not select. A repository can be several product types; combine their rows. `obvious`, `business-logic` and `wildcard` always apply and are not listed.

| Product type | Domains to consider |
|---|---|
| Web application (server-rendered or SPA with backend) | authn, authz, injection, api, web-client, http-protocol, input-parsing, outbound-network, secrets-config, data-lifecycle, logging-privacy, abuse, concurrency, resource-exhaustion |
| Static website or CMS site | web-client, http-protocol, supply-chain, secrets-config, input-parsing (uploads), authn (admin login), injection (CMS templates and plugins) |
| Public API or SaaS backend | authn, authz, api, injection, http-protocol, outbound-network, data-lifecycle, resource-exhaustion, logging-privacy, abuse, messaging |
| Browser extension | web-client, local-ipc, authz, supply-chain, outbound-network |
| CLI tool or script collection | input-parsing, filesystem-process, injection, outbound-network, secrets-config, supply-chain |
| Library or SDK | input-parsing, memory-safety (native), crypto, injection, resource-exhaustion, concurrency |
| Network daemon or server (native) | memory-safety, input-parsing, authn, authz, resource-exhaustion, concurrency, crypto, crypto-protocols, filesystem-process |
| Federated or peer-to-peer system | federation, crypto-protocols, crypto, authz, input-parsing, resource-exhaustion, data-lifecycle, abuse |
| Desktop application | local-ipc, filesystem-process, supply-chain (updates), web-client (embedded webviews), input-parsing, secrets-config |
| Mobile application | local-ipc, authn, api, secrets-config, crypto, logging-privacy, client-trust |
| Game server, multiplayer game or mods | client-trust, sandbox, resource-exhaustion, concurrency, input-parsing, authn, abuse, supply-chain (mods) |
| Embedded firmware or IoT | embedded, memory-safety, crypto, crypto-protocols, supply-chain (OTA), input-parsing |
| Kernel module, driver or hypervisor | kernel, memory-safety, concurrency |
| Infrastructure-as-code or deployment repository | cloud-deploy, secrets-config, supply-chain, http-protocol (proxy and CDN config) |
| CI, build or release tooling | supply-chain, secrets-config, filesystem-process, injection |
| Data pipeline or ETL | input-parsing, injection, data-lifecycle, logging-privacy, messaging, secrets-config |
| AI agent or LLM application | ai-llm, sandbox (tool execution), outbound-network, authz, data-lifecycle, logging-privacy |
| Trading, payment or financial system | financial, concurrency, authn, authz, api, secrets-config, outbound-network, logging-privacy |
| Smart contracts or blockchain client | smart-contracts, financial, crypto, crypto-protocols, federation (node networking) |
| Plugin host or scripting platform | sandbox, supply-chain, authz, resource-exhaustion |

## 1.9 Use earlier runs

If earlier runs of this audit exist for the same target:
1. Read their `coverage.md` and findings.
2. Make `needs-validation`, `deferred` and `blocked` units current work with high priority.
3. For each earlier `confirmed` finding: if the relevant source is unchanged, list its fingerprint as "known" so hunters do not report it again; phase 6 still checks it. If the source changed, create a unit to re-check it.
4. An earlier `covered` unit with unchanged source gets low priority, not exclusion. A fresh pass often finds what the earlier one missed.
5. Never treat a quick or scoped earlier run as evidence that the rest of the code is safe.

## 1.10 Seed the coverage ledger

A **unit** is one combination of entry surface, trust boundary and domain. For the deep profile, also split by subsystem and lifecycle mode. For the quick profile, combine all surfaces of one domain.

Write `coverage.md` as one table. Give each unit a stable **key** built from repository names (surface path and route or function, boundary control name, domain file name). Keep the key the same across runs, so runs can be compared. Do not put line numbers in keys.

```markdown
| ID | Key | Surface | Boundary | Domain | Priority | Status | Paths read | Checks | Findings | Notes |
|----|-----|---------|----------|--------|----------|--------|------------|--------|----------|-------|
| U001 | app/api/invoices.py#GET /invoices/{id}::authz::invoice-ownership | GET /invoices/{id} | invoice ownership check | authz | 1 | planned | | | | |
```

Statuses:
- `planned` – not started.
- `in-progress` – a hunter owns it.
- `covered` – done, no candidate. Needs paths read and checks.
- `candidate` – done, at least one finding file. Needs paths read, checks and finding IDs.
- `blocked` – partly done, cannot finish. Needs paths read, checks and the blocker in Notes.
- `deferred` – not done because of budget, profile or context. Reason in Notes.
- `out-of-scope` – outside the requested scope. Keep it, so a later full run can pick it up.
- `not-applicable` – the domain does not apply to this surface. Reason in Notes.

**Priority** (1 = highest). Rank by:
1. lowest-trust principal first (unauthenticated, then remote peer, then authenticated user);
2. most valuable asset behind the boundary (keys, cross-tenant data, code execution, signed state);
3. scattered controls before central ones;
4. leads, history signals and earlier-run gaps on the unit;
5. code complexity and churn.

Break ties by key order, so two runs on the same code assign work in the same order.

Every domain and language file selected in 1.8 must have at least one unit. Every attacker goal in 1.6 must map to at least one unit.

## 1.11 `threat-model.md` layout

```markdown
# Threat model – <repo> @ <commit>

## Product and assets
## Principals and design authority
## Entry surfaces            (table: surface | file:line | principal | auth | parser)
## Trust boundaries          (table: boundary | control file:line | central/scattered | visible/external)
## Central controls          (the functions every path must call)
## Attacker goals            (ranked)
## External assumptions
## Hotspots                  (complex, high-churn or security-history files)
```
