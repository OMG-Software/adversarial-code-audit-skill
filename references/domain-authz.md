# Domain: Authorization

## Scope

- **Load when:** the code decides whether a known principal may perform an action on a resource. Signs: roles, permissions, scopes, ownership fields, membership, tenants, organisations, projects, groups, channels, ACLs, policy engines, admin routes, numeric privilege levels, sharing.
- **Covers:** function-level access, object-level access, field-level access, role and permission logic, tenant isolation at the decision point, delegation and capabilities, policy and middleware configuration, the effect of time and revocation on decisions, and disclosure through authorization behaviour.
- **Hand off to:**
  - `domain-authn.md` – how the principal is identified (sessions, tokens, credentials). Authz starts with "the principal is known"; authn owns "is the principal who it claims to be".
  - `domain-data-lifecycle.md` – isolation in derived copies (caches, search indexes, exports, backups, deletion). Authz owns the decision; data-lifecycle owns copies that bypass it.
  - `domain-federation.md` – authorization of remote servers and of events that remote servers send. Use both files for federated actions.
  - `domain-concurrency.md` – races in general. Authz keeps races that change an authorization decision (AZ-09).
  - `domain-business-logic.md` – workflow rules that are not about who may act (prices, limits, step order).

## Invariants

Fill the placeholders from `threat-model.md`.

1. **Function:** Only principals with <role or permission> can invoke <action>, on every path that performs it.
2. **Object:** A principal can <read | write | delete> <resource> only if <ownership | membership | grant> links the principal to that exact resource at decision time.
3. **Field:** A principal can read or set <field> of <resource> only if <rule>. A request cannot set fields that the server owns (owner, tenant, role, status, price, verification flags).
4. **Subject:** The principal that the decision checks is the principal that performs the action. It comes from the authenticated context, not from request data.
5. **Resource:** The resource that the decision checks is the resource that the action changes, after all resolution (aliases, names, paths, canonical IDs).
6. **Tenant:** Every read and write is limited to the principal's tenant, unless a documented cross-tenant grant exists.
7. **Escalation:** No principal can grant, or cause, a permission level higher than its own, or change its own permissions, unless the design allows it.
8. **Time:** A revoked, expired or downgraded grant stops working within the documented time, on every path, including open connections and queued work.
9. **Default:** When the policy cannot decide (error, missing rule, unknown action or role), the result is deny.

## Recon additions

Add these to `threat-model.md` under a heading "Authorization model". Keep it short; hunters copy it.

1. **Decision points.** List every place an authorization decision is made: middleware, decorators, base classes, policy-engine calls, inline `if` checks, database row filters. State central or scattered.
2. **Subject source.** For each entry surface, where does the acting principal come from? (session, token claims, mTLS identity, signed message sender, request field). Any request-field source is a lead.
3. **Resource source.** For each action, how is the target resource identified? (path parameter, body field, query, header, derived from another object). Note every place where a name, alias or path becomes an ID.
4. **Permission model.** Roles, levels, scopes and their order. Who can assign each. Default for new principals and new resources. Inheritance (organisation → project → item; folder → file; channel → message).
5. **Authorization matrix.** A table of principal type × action × resource type → allowed (yes, no, own only, same tenant). Build it from the documentation and the code. Differences are leads.
6. **Decision caching.** Where decisions or grants are cached (in memory, session, token claims, client), and how they are invalidated.
7. **Alternate paths.** Admin APIs, internal RPC, federation, import and sync, webhooks, background jobs, batch and bulk endpoints, GraphQL, WebSocket, legacy versions, file and media serving.

## Lead searches

Adapt the patterns to the language. The language file adds framework-specific decorators and annotations.

| Search | A hit may mean | False-hit notes |
|---|---|---|
| Handler registrations, compared with the list of handlers that call the central authorization function | A route without an authorization call | The check can be in middleware or a base class. Read those first. |
| `(user\|owner\|account\|tenant\|org\|project\|team\|group\|member)_?id` read from request body, query, headers or path | Subject or resource taken from the client | A resource ID from the client is normal; the question is whether a check binds it. A subject ID from the client is a strong lead. |
| `find\|get\|load\|fetch\|lookup\|select\|by_?id` with an argument from the request, not followed by an ownership or membership check before use | Object-level gap (AZ-02) | The data-layer query may filter by owner. Read the query. |
| `(is_?admin\|is_?staff\|superuser\|role\|permission\|scope\|privilege\|power_?level\|level)` in request parsing, update or deserialisation code | Field-level gap or mass assignment (AZ-04) | Read-only display is not a lead. |
| Generic update: `update(.*request\|body\|params)`, `merge`, `assign`, `setattr`, `**kwargs`, `bind`, `populate`, `from_json` into a domain object | Mass assignment (AZ-04) | An explicit allow-list or DTO with fixed fields stops it. |
| `public\|anonymous\|allow_?all\|permit_?all\|skip_?auth\|no_?auth\|@public\|AllowAnonymous\|unauthenticated` | Intentional or accidental opt-out | List each one and check that the route is public by design. |
| Comparison operators on levels or roles: `>=\|<=\|>\|<` near `level\|rank\|role\|priority` | Off-by-one or wrong direction (AZ-05) | |
| `catch\|except\|rescue\|recover\|on_error\|else` near policy or permission calls | Fail-open (AZ-11) | Read what the handler returns. |
| `TODO\|FIXME\|HACK` near `auth\|perm\|check\|owner\|admin\|role` | Known gap | |
| `cache\|memo\|lru\|ttl` near `perm\|role\|member\|grant\|acl` | Stale decision (AZ-09) | |
| `impersonat\|act_?as\|on_?behalf\|sudo\|switch_?user\|X-User\|X-Forwarded-User\|X-Remote-User` | Subject override (AZ-03) | |
| `share\|invite\|link\|token\|capability\|grant\|delegate` creation and redemption | Capability scope (AZ-10) | |

## Attack classes

### AZ-01 Missing function-level authorization

- **What fails:** a principal reaches an action that its role must not perform. Often the route checks authentication but not authorization.
- **Where to look:** admin and management routes; routes added after the authorization middleware was written; routes registered in a different router, module or plugin; debug, metrics and maintenance endpoints; internal RPC methods reachable from outside; HTTP method variants (`HEAD`, `OPTIONS`, method-override headers or parameters) that reach the same handler; GraphQL mutations and resolvers.
- **Questions:**
  - Which middleware applies to this route? Check the matching rules: prefixes, order, trailing slash, case, encoded characters, path parameters.
  - Does the handler, or something it calls, check the role for this exact action?
  - Is the route registered more than once (v1 and v2, alias path, mounted sub-application)?
- **Sad-path inputs:** a lower role; a role with a similar name; no role; a principal from another tenant; path variants (`/admin/`, `/Admin`, `/admin;x`, `//admin`, `%2Fadmin`) where the router and the authorization layer may match differently.
- **Evidence for confirmed:** the registration, the absence of a check on the full path from entry to sink, and the reachability of the route by the lower role. E1 is often enough (see verification notes).
- **Not a finding:** a route that is public by design and exposes nothing protected.
- **CWE:** CWE-862 (absent check; class-level), CWE-863 (check present but wrong; class-level), CWE-425 (direct request to an unprotected resource).

### AZ-02 Missing or wrong object-level authorization (IDOR, BOLA)

- **What fails:** the server loads a resource by an identifier the client supplies, and acts on it without checking that the principal may access that resource.
- **Where to look:** every handler that takes an ID; nested resources (`/orgs/{org}/projects/{project}/files/{file}`) where the code checks the parent but loads the child by its own ID alone; actions that take two IDs (move, copy, link, attach, invite) where only one is checked; bulk and batch endpoints; download, media and thumbnail endpoints; endpoints that accept IDs in the body, in headers or inside nested objects.
- **Questions:**
  - Does the check use the same ID that the action uses?
  - For nested resources: does the child really belong to the checked parent? (`file.project_id == project.id`)
  - For two-object actions: is the principal authorized on **both** source and destination?
  - Does a "list" endpoint filter correctly while the "get by ID" endpoint does not, or the reverse?
- **Sad-path inputs:** another principal's ID; an ID from another tenant; an ID of a deleted, archived or draft object; an ID of a different type that shares the ID space; the parent ID from one resource with the child ID from another.
- **Evidence for confirmed:** the line that loads the object, the absence of a binding check before the sink, and an action that changes or returns data of another principal. E1 is enough when the load and the sink are in the repository and no layer filters (for example no row-level security).
- **Not a finding:** the data-layer query already filters by owner or tenant; the object is public by design; IDs are capabilities by design (see AZ-10). Unguessable IDs alone do **not** make it safe: IDs leak through logs, URLs, shares and other endpoints. Record the ID entropy as a likelihood factor.
- **CWE:** CWE-639; CWE-566 when the key is a SQL primary key.

### AZ-03 Wrong subject (confused principal)

- **What fails:** the decision checks one principal while the action runs as, or for, another.
- **Where to look:** user, sender, author or actor fields in request bodies; impersonation and "act as" features; service accounts and background workers that act for users; headers that carry identity from a proxy (`X-User`, `X-Remote-User`, `X-Forwarded-User`); message envelopes where the transport sender differs from a sender field inside the payload; signed objects where the signer differs from the claimed author.
- **Questions:**
  - Where does the acting principal come from, at the decision and at the sink? Are they the same value?
  - Can the client set a field that the server later treats as the actor?
  - Does a service account check the end user's rights, or only its own?
  - Who can set the identity header? Does a trusted proxy remove client copies? (If the proxy is outside the repository, this is an external assumption.)
- **Sad-path inputs:** body actor ≠ session actor; envelope sender ≠ payload sender; identity header supplied by the client; impersonation by a role that must not impersonate; impersonation of a higher role.
- **Evidence for confirmed:** the subject source at the decision, the subject source at the sink, and the path where they differ.
- **Not a finding:** the field is ignored, or overwritten from the session before use.
- **CWE:** CWE-863; CWE-639 when the subject is a client-controlled key.

### AZ-04 Field-level authorization and mass assignment

- **What fails:** a principal reads or writes fields it must not. On write, a generic binding copies client fields into server-owned fields. On read, the response includes fields the principal must not see.
- **Where to look:** create and update handlers that bind the whole body to a model; `PATCH` handlers; serializers without an explicit field list; GraphQL input types and field resolvers; nested writes (an update of an object that also updates related objects); import endpoints; responses that return the full model.
- **Questions:**
  - Which fields can the client set? Compare with the fields the server owns: owner, tenant, role, permission, status, verification flags, counters, prices, timestamps, foreign keys.
  - Is there an allow-list, a DTO with fixed fields, or a deny-list? A deny-list misses new fields.
  - Does a nested write check authorization on the nested object?
  - Does every response field pass a read rule for the requesting principal?
- **Sad-path inputs:** extra fields with server-owned names; the same field in different case or nesting; a foreign key pointing to another tenant's object; `null` for a field that controls a check.
- **Evidence for confirmed:** the binding code, the server-owned field it reaches, and the effect (for example the principal's role changes, or a record moves to another tenant).
- **Not a finding:** the field is bound but overwritten before save; the field has no security meaning.
- **CWE:** CWE-915 (mass assignment); CWE-213 for over-exposure in responses, or a specific child of CWE-200 (class-level).

### AZ-05 Role and permission logic errors

- **What fails:** the policy compares, combines or inherits permissions wrongly.
- **Where to look:** level comparisons; role hierarchies; permission inheritance; allow and deny rule combination; wildcard permissions; default roles; "owner" special cases; code that maps external roles (IdP groups, OAuth scopes) to internal ones.
- **Questions:**
  - Is each comparison the right direction and strictness (`>=` against `>`)? What happens with equal levels?
  - What happens with negative, zero, very large, missing or non-integer levels? Can integer overflow or type coercion change the comparison?
  - When rules conflict, which wins? Is the order documented and implemented the same way?
  - Is the default for an unknown role or action deny?
  - Does a wildcard (`*`, `admin:*`) match more than intended?
- **Sad-path inputs:** equal level to the target; level just below; unknown role names; mixed-case role names; duplicate role entries; a level set to the maximum integer; a level as a string.
- **Evidence for confirmed:** the comparison or rule, the input that gives the wrong decision, and the protected action it allows.
- **Not a finding:** a difference from another product's model that the documentation intends.
- **CWE:** CWE-863; CWE-1220 when the model is too coarse to separate actions that need different rights.

### AZ-06 Privilege escalation through permission management

- **What fails:** a principal increases its own rights, or gives another principal more rights than it holds.
- **Where to look:** role assignment, invite, membership change, group join, permission edit, API-key and token creation, "promote to owner", ownership transfer, "last admin" removal, self-service settings.
- **Questions:**
  - Can a principal assign a role equal to or higher than its own?
  - Can a principal change its own role or permissions?
  - Can a principal change the rights of a principal with an equal or higher level?
  - Can a principal create a token or key with more scopes than it holds?
  - Can a principal join a group, team or channel that grants rights without approval?
  - Can removing or demoting the last admin leave the resource without control, or with control given to a default role?
- **Sad-path inputs:** target level = own level; target = self; invites that carry a role; token scopes that are a superset of own scopes.
- **Evidence for confirmed:** the management path and the resulting higher right, used once in a test or traced to the next decision point.
- **Not a finding:** escalation within a principal's documented design authority (an owner who grants admin).
- **CWE:** CWE-266 for wrong privilege assignment; CWE-269 (class-level) when no base entry fits.

### AZ-07 Tenant isolation at the decision point

- **What fails:** one tenant reads or changes another tenant's data.
- **Where to look:** tenant ID from the client; queries without a tenant filter; global unique constraints and names; shared caches keyed without tenant; background jobs and queues that lose the tenant context; cross-tenant references (attach a tenant-B object to a tenant-A resource); admin tools that cross tenants.
- **Questions:**
  - Where does the tenant come from: the authenticated context or the request?
  - Does every query on tenant data include the tenant condition? Is this enforced centrally (row-level security, scoped repository) or per query?
  - Does a job carry the tenant ID and re-check it, or trust the payload?
  - Can a reference to another tenant's object be stored and later followed?
- **Sad-path inputs:** another tenant's IDs; a tenant ID in the request that differs from the session; names that collide across tenants.
- **Evidence for confirmed:** the query or path without the tenant condition, and the cross-tenant result.
- **Not a finding:** documented cross-tenant sharing with a check.
- **CWE:** CWE-639 or CWE-863, depending on the root cause.

### AZ-08 Alternate paths to the same effect

- **What fails:** the main path checks correctly, but another path that produces the same state change does not.
- **Where to look:** for each protected effect (for example "user U becomes member of group G", "file F is deleted"), find every code path that produces it: UI API, admin API, internal RPC, federation, import and sync, restore, webhooks, scheduled jobs, batch and bulk, WebSocket, GraphQL, legacy API versions, CLI tools, migrations.
- **Questions:**
  - Does each path call the same decision function, with the same arguments?
  - Do batch paths check each item, or only the first or the container?
  - Does an import or restore path apply current authorization, or trust the imported data?
- **Sad-path inputs:** the same action through each path; a batch with one allowed and one forbidden item; an import that contains objects of another principal.
- **Evidence for confirmed:** the alternate path, the missing or weaker check, and the effect.
- **Not a finding:** a path that only a higher principal can reach, where that principal may perform the effect anyway.
- **CWE:** CWE-862 or CWE-863.

### AZ-09 Time, state and revocation

- **What fails:** a decision uses stale state, or state at the wrong time.
- **Where to look:** cached roles or memberships; tokens that embed roles or scopes; long-lived sessions, WebSocket connections and subscriptions authorized once at connect time; queued jobs that run with the rights of their creator; pending invites after the inviter loses rights; systems that authorize an object against historical state (for example the state when a record or message was created) and against current state in different places.
- **Questions:**
  - After a role is removed, which paths still allow the old action, and for how long?
  - Is a stream, subscription or open connection re-checked when membership changes?
  - Does a queued action re-check rights when it runs?
  - Is the correct point in time used? Is it the same at every check for the same action?
  - Can the check and the use be separated by a concurrent change (check-then-act)?
- **Sad-path inputs:** revoke during an open connection; demote between check and use; act with an invite created by a principal who has since lost rights; replay a request created before revocation.
- **Evidence for confirmed:** the path that uses the stale decision, and the action allowed after revocation beyond the documented window. Races need E3 (SKILL.md section 6).
- **Not a finding:** a documented, bounded propagation delay.
- **CWE:** CWE-367 for check-then-act races; CWE-613 belongs to authn (session expiry); CWE-863 for wrong-time decisions.

### AZ-10 Delegation, scopes and capabilities

- **What fails:** a delegated credential gives more than intended, or remains valid when it must not.
- **Where to look:** API keys, personal access tokens, OAuth scopes, share links, signed URLs, invite tokens, capability URLs, delegated service tokens, "on behalf of" chains.
- **Questions:**
  - Does the resource server enforce the scope on every endpoint, or only at token creation?
  - Is a share link bound to one resource, one action and an expiry? Can it reach sibling resources?
  - Is an invite token single-use and bound to the invited identity?
  - Can a delegated principal delegate again with the same or larger rights?
  - Does revoking the delegator revoke the delegation?
- **Sad-path inputs:** a token with scope A used on endpoint B; a share link for file F used on file G in the same folder; a reused invite token; a token created before the creator lost rights.
- **Evidence for confirmed:** the scope or binding check (or its absence) and the action allowed outside the grant.
- **Not a finding:** a capability that is broad by design and documented as such.
- **CWE:** CWE-863; CWE-1220 when scopes are too coarse.

### AZ-11 Policy configuration, matching and fail-open

- **What fails:** the authorization layer and the request router disagree on which rule applies, or the policy allows by default or on error.
- **Where to look:** route-pattern rules in middleware; policy files and their loading; regular expressions in rules; rule order; decorators and annotations; error handling around policy calls; feature flags that turn checks off.
- **Questions:**
  - Does the authorization layer normalise the path, method and parameters the same way as the router? (case, trailing slash, encoding, `;` parameters, duplicate slashes, `..`)
  - Is the rule set allow-list (deny unless allowed) or deny-list?
  - What does the code do when the policy engine throws, times out or returns an unknown value?
  - What happens when the policy file is missing or fails to parse?
  - Can a flag, environment variable or header turn checks off in a production build?
- **Sad-path inputs:** path variants; unknown methods; a policy that throws; an empty policy.
- **Evidence for confirmed:** the two interpretations (authorization layer and router) for the same request, or the fail-open branch and how to reach it.
- **Not a finding:** a fail-open branch that no attacker can trigger.
- **CWE:** CWE-863; for fail-open, CWE-636 ("Not Failing Securely"). CWE-636 is a class-level entry: use a more specific child if one fits.

### AZ-12 Disclosure through authorization behaviour

- **What fails:** the response to a forbidden request tells the attacker something it must not know.
- **Where to look:** different status codes or messages for "does not exist" and "not allowed"; list counts; search results that include forbidden items (even if redacted); timing differences for existing and non-existing objects; error messages that include names, owners or content.
- **Questions:**
  - Can the attacker learn that a private resource exists, its name, members or size?
  - Does that knowledge help another attack (AZ-02, chains), or reveal sensitive facts by itself?
- **Sad-path inputs:** an existing private ID and a non-existent ID, compared; IDs of deleted objects; search terms that match only forbidden items.
- **Evidence for confirmed:** the two responses and the sensitive fact they reveal.
- **Not a finding:** existence of a public resource; an oracle that reveals nothing sensitive and helps no other attack (record it as a hardening note).
- **CWE:** CWE-203.

## Variant search

When you find one authorization failure:
1. **Same function.** List every caller of the handler, model method or query that lacks the check.
2. **Same shape.** Build a table: every handler that takes the same kind of ID (or the same resource type) × whether it calls the decision function × with which arguments. Every "no" is a variant lead.
3. **Same effect.** List every path to the same protected effect (AZ-08).
4. **Same rule.** If the root cause is a policy rule or comparison, list every rule that uses the same pattern.
5. **Same history.** If an earlier fix added this check elsewhere (phase 2.3), check that the fix covers all paths.

## Chain primitives

This domain often **gives**:
- read access to objects of another principal (leaks IDs, tokens, secrets, internal URLs);
- write access to fields that other components trust (owner, role, URL, template, filename);
- membership or role in a group, team or tenant, which unlocks every check that trusts membership;
- the ability to create tokens, links or invites.

This domain often **needs**:
- an identifier of the target (from enumeration, disclosure, AZ-12, or logs);
- an authenticated session of any user (from authn);
- a race window (from concurrency).

## Verification notes

- **E1 is usually enough** for AZ-01, AZ-02, AZ-03, AZ-04, AZ-06, AZ-07 and AZ-08, when the route registration, the full path and the sink are in the repository, and no layer outside the repository makes the decision. The reproduction waiver must name every layer checked (middleware, base classes, data-layer filters, framework defaults).
- **E3 is needed** for AZ-09 claims that depend on a race, and for AZ-11 claims that depend on how a framework or proxy normalises paths when that code is not in the repository.
- **Reachability:** confirm the route is registered in the default build and configuration, and that the lower principal can reach it (not only an internal network). If network exposure is an external assumption, the finding is `needs-validation`.
- **Design authority:** check the documentation and the authorization matrix. If the action is allowed for that role by design, reject. If the documentation and code disagree, report the disagreement and state which one you used.
- **E3 test shape:** create two dummy principals (A and B) and a resource owned by B. As A, perform the action. The expected result is a deny. Record the observed result.
- **Severity examples:**
  - critical – an unauthenticated client reaches an admin action that gives control of all accounts or the server;
  - high – any user reads or changes any other user's private data (AZ-02 without limits); a user makes itself admin (AZ-06); cross-tenant write (AZ-07);
  - medium – access limited to one resource type with low sensitivity; access that needs an ID the attacker cannot easily get; a revocation gap of hours;
  - low – disclosure of the existence or name of private objects (AZ-12) with no further use;
  - informational – an oracle that only serves as a chain link.

## Fix patterns

- **Deny by default.** Every route goes through an authorization layer that denies unless a rule allows. New routes fail closed.
- **One decision function.** `authorize(subject, action, resource)` with the subject from the authenticated context and the resource loaded server-side. Call it at the last point before the effect.
- **Load, then authorize, then act on the same object.** Do not authorize an ID and then reload a different object, or authorize a name and act on a resolved ID that can differ.
- **Scope queries.** Enforce owner and tenant in the data layer (scoped repositories, row-level security), in addition to the decision function.
- **Explicit write fields.** Bind requests to DTOs or allow-lists. Never bind directly to models with server-owned fields.
- **Explicit read fields.** Serialise responses through a view per role.
- **Escalation rules.** A principal can only grant rights strictly below its own (or equal, if the design says so). A principal cannot change its own rights. Keep at least one owner.
- **Revocation.** Re-check on each streamed item or on membership-change events. Re-check rights when queued work runs. Keep token lifetimes short, or check a revocation list.
- **Batch.** Check every item, and fail the whole batch, or skip the item, according to a documented rule.
- **Looks right but is not:** hiding a button in the UI; checking in the client; relying on unguessable IDs; a deny-list of fields; checking the parent but not the child; checking at token creation but not at use; catching policy errors and continuing.

## Regression tests

- An **authorization matrix test**: for each route, each principal type in the matrix, and each expected result, a test that asserts the result. Generate it from the route table so new routes appear as untested.
- For each fixed finding, a test with two principals that asserts deny.
- For mass assignment, a test that sends each server-owned field and asserts it does not change.
- For escalation, tests for "grant own level", "grant higher level", "change own role" and "remove last owner".
- For revocation, a test that revokes during an open connection or before a queued job runs, and asserts the later action is denied.
