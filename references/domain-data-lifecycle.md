# Domain: Data lifecycle

## Scope

- **Load when:** the same data exists in more than one place or at more than one time. Signs: caches, search indexes, read replicas, materialised views, exports and reports, backups and snapshots, analytics copies, offline or device caches, blob storage with signed links, soft delete, restore and import tools, retention jobs, data migrations, multi-tenant storage.
- **Covers:** tenant and principal isolation in caches, search indexes, exports, backups and analytics copies; deletion, soft delete and restore; retention; migration defaults; derived copies after revocation; signed URLs and blob references.
- **Hand off to:**
  - `domain-authz.md` – the decision on the primary path, and caching of decisions (AZ-09). This file owns copies of the data that bypass the decision.
  - `domain-logging-privacy.md` – logs, traces, crash reports, telemetry and third-party analytics sinks.
  - `domain-messaging.md` – authenticity and replay of queue messages, and access to dead-letter stores. This file owns long-lived copies of payloads.
  - `domain-http-protocol.md` – HTTP cache keys, cache poisoning and cache deception at proxies and CDNs. This file owns application-level and data-store caches.
  - `domain-crypto.md` – key storage, rotation and destruction. This file uses key destruction only as a deletion method.
  - `domain-cloud-deploy.md` – bucket and snapshot permissions written in infrastructure code.
  - `domain-federation.md` – copies held by independent peers, and how deletion and revocation reach them.
  - `domain-concurrency.md` – races between delete, restore and read as a timing problem.
  - `domain-ai-llm.md` – context bleed in vector stores and retrieval.

## Invariants

Fill the placeholders from `threat-model.md`.

1. **Copy access:** Every copy of <data class> (cache entry, index document, export, replica, backup, analytics row, device cache) is readable only by principals who may read the source at the time of the read.
2. **Key scope:** A cache or index key includes <tenant | principal | permission set> whenever the stored value depends on it.
3. **Revocation:** When a principal loses access to <resource>, every copy stops serving it to that principal within <time>.
4. **Deletion:** When <resource> is deleted, all copies in the data map are deleted or made unreadable within <time>. No read path returns a soft-deleted record.
5. **Restore:** Restore, undelete, import and rollback apply current ownership, tenant, authorisation and retention. They do not bring back deleted data or revoked access.
6. **Retention:** Data is removed at the end of its retention period, in all stores and in backups within the documented delay.
7. **Blob reference:** A signed URL or blob reference grants access to one object, one action and one audience, for a short time. The grant ends when the source is deleted or access is revoked, within the documented delay.
8. **Export:** An export holds only the rows and fields that the requester may read when the export is built. Only the requester can download it.
9. **Migration:** A migration, default or bulk fix-up gives existing and new rows the least-privilege values. A null or default never means "visible to all".
10. **Environments:** Production data does not reach test, staging or analytics environments without masking.

## Recon additions

Add these to `domain-notes.md` under a heading "Data copy map". Keep it short; hunters copy it.

1. **Copy table.** One row for each data class. Columns: primary store | each derived copy (cache, index, replica, view, export, backup, analytics, queue payload, blob, device cache) | key or partition | access check at read | deletion path | retention | restore path.
2. **Lifecycle events.** For each event (create, share, revoke, delete, restore, export, migrate, expire), list which copies change, and how: in the same transaction, by event, by job, or never.
3. **Tenant model.** How the tenant identity reaches each store: column, schema, database, key prefix, index name, bucket path.
4. **Blob handling.** How blobs are named, who can sign access, the lifetime and scope of signed links, and whether the code de-duplicates content across tenants.
5. **Background jobs.** Export builders, indexers, backup, restore and retention jobs, migrations. Note the identity each one runs as.
6. **Soft-delete rules.** The marker, and every query layer that applies it (default scope, raw queries, views, search, exports, joins).
7. **Environment flow.** Which tools copy data between production, staging, development and analytics.

## Lead searches

| Search | A hit may mean | False-hit notes |
|---|---|---|
| `cache\.(get\|set)\|memo\|lru\|@cached\|remember\|Cache-?Key` and the key expression | Key without tenant or principal (DL-01) | A key of a global, public value is fine. |
| Cache calls inside functions that take `user\|tenant\|org\|viewer` but do not use it in the key | Cross-principal serving (DL-01) | |
| `index\|upsert\|reindex\|search\|query_?string\|suggest\|autocomplete\|facet\|aggregate` | Search document without access data, or filter after the query (DL-02) | Check where the filter is applied. |
| `export\|download\|report\|csv\|dump\|archive\|bulk` handlers and jobs | Export identity and field scope (DL-03) | Check that the job re-authorises. |
| `backup\|snapshot\|dump\|restore\|replica\|pg_dump\|mysqldump\|mongodump\|rsync` | Backup access and restore path (DL-04) | Scripts in the repository only show intent. |
| `deleted_?at\|is_?deleted\|soft_?delete\|archived\|trash\|tombstone\|paranoid` and queries that do not use them | Soft-deleted data visible on a path (DL-05) | A default scope may add the filter. Raw queries skip it. |
| `restore\|undelete\|recover\|import\|rollback\|revert\|replay` | Restore trusts old state (DL-06) | |
| `presign\|signed_?url\|sas_?token\|generate_?url\|expires\|expiry\|ttl` | Signed link scope and lifetime (DL-08) | Check the provider's semantics. |
| `bucket\|blob\|object_?key\|storage_?path\|s3\|gcs\|attachment\|upload` with a name from input or without tenant | Blob reference without owner check (DL-08) | |
| `sha\d*\|md5\|content_?hash\|dedup\|checksum` as a storage key | Cross-tenant de-duplication oracle (DL-08) | |
| `ALTER TABLE\|ADD COLUMN\|DEFAULT\|migrate\|migration\|UPDATE .* SET` in migrations | Unsafe default or bulk assignment (DL-09) | |
| `retention\|ttl\|expire\|purge\|cleanup\|vacuum\|cron` | Retention job coverage (DL-10) | List the stores the job covers. |

## Attack classes

### DL-01 Cache key missing tenant or principal

- **What fails:** a cache stores a value built for one principal or tenant, and serves it to another, because the key does not hold the scope of the value.
- **Where to look:** in-process memoisation; shared cache servers; per-request caches stored in globals or singletons; caches of query results, rendered fragments, permission-filtered lists and summaries; negative caches; caches filled by a privileged job and read by users.
- **Questions:**
  - What does the cached value depend on (tenant, principal, role, locale, filter)? Is every dependency in the key?
  - Does the cache store a value that the first caller was allowed to see, and serve it without a check to the next caller?
  - Can an attacker choose a key component that collides with another tenant's key (a separator in a name, case, encoding)?
- **Sad-path inputs:** two dummy tenants that call the same function with the same arguments; names that differ only in case or separator; a "not found" for tenant A followed by tenant B's data at the same key.
- **Evidence for confirmed:** the key expression, the value's dependency on the scope that the key omits, and a read as the second principal. E1 is enough when the key and the value are plain in the repository.
- **Not a finding:** a cache of public data; a cache that stores identifiers and checks access at read time; a cache that exists per principal by construction.
- **CWE:** CWE-524 (use of cache containing sensitive information); CWE-226 when a pooled or reused object keeps data from its previous user.

### DL-02 Search index and secondary store bypass

- **What fails:** a search index, analytics store or other secondary store returns data that the primary path would deny.
- **Where to look:** index documents that lack owner, tenant or access fields; search that filters after retrieval; suggestions, autocomplete, snippets, highlights, counts, facets and "did you mean" that use the full index; shared indexes with a tenant filter built from the request; indexing jobs with a privileged identity; analytics queries on raw tenant data.
- **Questions:**
  - Does each indexed document carry the access data needed to filter at query time?
  - Does the filter come from the authenticated context, and does the engine apply it before ranking, counting and paging?
  - Do counts, facets and suggestions use the filtered set?
  - When access changes, does the index update? How fast?
- **Sad-path inputs:** a query for a dummy term that exists only in another tenant's document; a query for a prefix; a request for the count or facets; a filter field supplied in the request.
- **Evidence for confirmed:** the indexing code, the query code without the filter, and the result that shows another principal's data, or its existence, name or count.
- **Not a finding:** an index of public content; an index per tenant that is separated by construction (name the separation).
- **CWE:** CWE-213 (exposure of sensitive information due to incompatible policies); CWE-862 (class-level; missing authorization). The primary path belongs to `domain-authz.md`.

### DL-03 Exports, reports and bulk downloads

- **What fails:** an export job or report builds a file with data or fields that the requester may not read, or delivers the file to the wrong party.
- **Where to look:** asynchronous export and report jobs; data-portability tools; cross-tenant administrative exports; download links for finished files; scheduled reports sent by e-mail; bulk API endpoints.
- **Questions:**
  - Which identity does the job run as? Does it re-check the requester's rights per row and per field when it builds the file?
  - Is the job record bound to the requester? Does the download endpoint check that binding?
  - Can the requester name the dataset, tenant, filter or columns in the request?
- **Sad-path inputs:** a job started by user A, then fetched by user B; an export request with another tenant's identifier; a column list that names a server-owned field; a link used after the requester loses access.
- **Evidence for confirmed:** the job code, the missing rights check or binding, and the file that holds data outside the requester's rights.
- **Not a finding:** an export of the requester's own data that only the requester can fetch; an administrative export by a principal that may read the data.
- **CWE:** CWE-212 (improper removal of sensitive information before storage or transfer) for fields that remain in the export; for the wrong requester, name the weakness in words and see `domain-authz.md`.

### DL-04 Backups, snapshots and restore

- **What fails:** backups hold data with weaker protection than the live store, or a restore exposes or overwrites data across tenants.
- **Where to look:** backup scripts and schedules; snapshot sharing; backup storage permissions; encryption of backups and key handling; per-tenant restore from a shared backup; restore tools and their authorisation; backups that include secrets; copies of backups in other environments.
- **Questions:**
  - Who can read the backup store? Are backups encrypted with keys that the store's readers lack?
  - Can a tenant-level restore expose or overwrite other tenants?
  - Does a restore re-run the deletions made since the backup?
- **Sad-path inputs:** a restore of one tenant from a shared snapshot; a restore after a deletion; a backup read with the application's own credential.
- **Evidence for confirmed:** the script or tool in the repository, the permission or scope it sets, and the data an unintended principal can read or change. Settings outside the repository (storage permissions, provider snapshot policy) make the finding `needs-validation`.
- **Not a finding:** operator-only backups with documented access and encryption; a backup retention longer than live data when the design documents it (record as a hardening note).
- **CWE:** name the weakness in words: exposure of backup data to an unauthorised party; CWE-459 (incomplete cleanup) when a restore leaves stale or deleted data.

### DL-05 Deletion and soft delete

- **What fails:** data that the owner or system deleted remains readable, through another path, a copy, or a reused identifier.
- **Where to look:** soft-delete flags and the queries that skip them (raw queries, views, joins, search, exports, "get by identifier", sync endpoints); delete handlers that do not cascade to blobs, thumbnails, caches, indexes, replicas, device caches and analytics; tombstones that keep content; account deletion that leaves data under a reusable name, e-mail address or identifier; delete jobs that race with writes that recreate the data.
- **Questions:**
  - For each copy in the data map, what deletes it, and when?
  - Does every read path apply the deleted marker? Which paths do not?
  - Can a new principal take the name, identifier or address of a deleted one and inherit its data, links or grants?
  - Does a tombstone hold content, or only the identifier and time?
- **Sad-path inputs:** read by identifier after delete; search for a deleted item; an export after delete; a new account with a deleted account's e-mail address or handle; a delete while a job is writing.
- **Evidence for confirmed:** the delete path, the copy that stays, the read path that returns it, and the principal who must not read it. Deleted data readable only by its own former owner is not a boundary failure unless the design says the data must be gone.
- **Not a finding:** a documented retention for legal or recovery reasons that restricts reads to an authorised role; a delete that is eventual, within the documented delay.
- **CWE:** CWE-459 (incomplete cleanup); CWE-226 for reused storage or pooled objects.

### DL-06 Restore, undelete, import and rollback re-authorisation

- **What fails:** a restore, import or rollback brings back old state without current checks. Removed access, old roles, expired shares or deleted data return.
- **Where to look:** undelete and trash restore; import from files, snapshots or another instance; rollback of configuration or data; replay of event logs to rebuild state; tools that load ownership and role fields from imported data.
- **Questions:**
  - Does the restore path call the same create and authorise functions as a new write?
  - Does it trust owner, tenant, role, visibility or sharing fields from the source data?
  - Does it bring back access that was revoked after the snapshot?
- **Sad-path inputs:** a snapshot taken before a revocation; an import file with another tenant's owner field; a restore of an item whose parent was deleted; a rollback that re-enables a removed key.
- **Evidence for confirmed:** the restore code, the trusted field or missing check, and the access or data that returns.
- **Not a finding:** a restore by a principal who may create the same state anew; a restore that applies current rules.
- **CWE:** name the weakness in words: restored state skips the current authorisation check; CWE-459 for stale remains.

### DL-07 Derived copies after revocation

- **What fails:** access to the source is revoked, but copies of the data still serve it or still show it to the former reader.
- **Where to look:** denormalised names and fields; materialised views; search indexes; caches; offline and device caches; push payloads that carry content; downloaded files and thumbnails; replicas and read models updated by events; cached member lists.
- **Questions:**
  - For each copy: what event updates it on revoke, and what is the delay?
  - Does the copy hold content, or only a reference that is checked at use?
  - Is the delay documented, and is it bounded?
- **Sad-path inputs:** revoke access, then read each copy; remove a member, then fetch a cached list, a thumbnail and a search result.
- **Evidence for confirmed:** the copy, the missing or late update, and a read by the revoked principal after the documented window. Timing claims that depend on a job schedule need E3 or `needs-validation`.
- **Not a finding:** a documented and bounded propagation delay; data that the reader already holds legitimately and cannot be recalled (record as a design note).
- **CWE:** CWE-524 when the copy is a cache; otherwise name the weakness in words: a copy outlives the access that justified it.

### DL-08 Signed URLs and blob references

- **What fails:** a signed link or a blob reference gives more access than intended, lasts too long, or lets a principal use another principal's object.
- **Where to look:** pre-signed upload and download links; signed cookies for a prefix; link expiry and scope; object names built from input; attachment of an uploaded blob identifier to a record without an ownership check; content-hash storage keys; links stored in logs, e-mails, referrer headers and browser history; links that remain valid after delete or revocation.
- **Questions:**
  - Does one link cover one object, one action and a short lifetime, or a whole prefix or bucket?
  - Is the link bound to the audience, or can anyone who sees it use it?
  - Can a principal attach a blob identifier that belongs to another principal or tenant to its own record, and then read it?
  - Does a content-hash key let one tenant learn that another tenant stores the same file?
- **Sad-path inputs:** a link for object A used for object B in the same prefix; a link used after expiry, after delete and after revoke; an upload of a known file by a second tenant; a blob identifier from another tenant in a create request.
- **Evidence for confirmed:** the signing code, the scope and lifetime it sets, and the access beyond the intended grant. The provider's signature semantics can be external; mark them.
- **Not a finding:** a capability link that is broad by design and documented, with a short lifetime and no sensitive scope.
- **CWE:** CWE-598 (use of GET request method with sensitive query strings); CWE-863 (class-level; incorrect authorization). For missing owner checks on a blob identifier, see `domain-authz.md` (AZ-02).

### DL-09 Migration and default values

- **What fails:** a schema change, default value or bulk fix-up gives existing or new data wider access than before.
- **Where to look:** migration files; new columns for owner, tenant, visibility or role with a default; scripts that assign all rows to one tenant or owner; migrations that drop row-level policies or constraints and re-create them later; code that treats null as "all"; converters from an older format.
- **Questions:**
  - What value do old rows get? Does that value widen access?
  - Does a null owner, tenant or visibility mean public, global or "no check"?
  - Is a security control (policy, constraint) absent during the migration window?
- **Sad-path inputs:** rows with null owner or tenant; rows created before and after the migration; the schema state half-way through a migration.
- **Evidence for confirmed:** the migration or default, the resulting value on existing or new rows, and the read that now succeeds for a principal who was denied before.
- **Not a finding:** a default that is restrictive; a temporary state in a migration that runs offline with no reachable service.
- **CWE:** CWE-276 (incorrect default permissions); CWE-1188 (initialization of a resource with an insecure default).

### DL-10 Retention and non-production copies

- **What fails:** data stays after its retention period in a store that a job does not cover, or production data lands in an environment with weaker controls.
- **Where to look:** retention and purge jobs and the stores each covers; time-to-live settings on caches, queues and indexes; analytics and warehouse exports; seed and "copy production" scripts; staging databases; new tables added after the purge list was written.
- **Questions:**
  - Which stores does the retention job cover? Which stores in the data map does it miss?
  - Do backups and replicas have a bounded life?
  - Do copy scripts mask personal data and secrets? Who can read the target environment?
- **Sad-path inputs:** a record older than the retention period in each store; a table added last; a staging restore from a production snapshot.
- **Evidence for confirmed:** the store, the missing coverage, the retention requirement, and the data present past the limit. For non-production copies, show the unmasked data path and the weaker control.
- **Not a finding:** a documented longer retention for a lawful reason; an environment with the same controls as production.
- **CWE:** name the weakness in words: sensitive data kept past its retention period, or copied to a less protected environment; CWE-212 when fields are not removed before transfer.

## Variant search

When you find one data-lifecycle failure:
1. **Same store.** List every reader and writer of the cache, index, bucket or table.
2. **Same key.** List every cache or index that builds its key or filter the same way.
3. **Same data class.** Check every copy in the data map for the same class.
4. **Same event.** For a revoke or delete miss, list every copy that listens to the event, and every copy that should.
5. **Same job.** List every background job that runs with the same wide identity.
6. **Same marker.** For a soft-delete miss, list every query layer that skips the marker.

## Chain primitives

This domain often **gives**:
- read access to other tenants' data without passing the main decision (a cache, index or export);
- tokens, secrets and identifiers held in backups, exports and copies;
- identity takeover through a reused name, address or identifier;
- links that outlive the grant, usable by anyone who holds them.

This domain often **needs**:
- a way to trigger an export, a search or a restore (from the API surface);
- an identifier or tenant name (from authz or disclosure);
- a revocation or deletion event (a normal action by a victim or an administrator).

## Verification notes

- **E1 is usually enough** for DL-01 (key without scope, value with scope), DL-02 (document or query without filter), DL-03 (job without re-check), DL-05 (read path without the marker), DL-06 (restore trusts fields), DL-08 (link scope set in code) and DL-09 (migration value), when every step is in the repository. The waiver names every layer checked: default scopes, row-level policies, database views, framework caching defaults.
- **E3 is required** (or `needs-validation`) when the behaviour depends on code outside the repository: a search engine's filter semantics, an object-store provider's signature rules, a managed cache, a backup service or a job scheduler. Name the exact fact and a safe local check.
- **E3 for timing claims.** A revocation delay (DL-07) or an eventual delete (DL-05) needs a measured delay with the real job or event path. Without it, use `needs-validation`.
- **E3 test shape:** create two dummy tenants A and B and a record in B. Fill every copy in the data map (cache, index, export, blob). As A, read each copy. The expected result is a deny. Then revoke or delete in B and read each copy again as the former reader. Record the observed result.
- **Design check.** Compare with the documented retention, recovery and sharing rules. A copy that the design documents, with an access rule, is not a finding.
- **Severity examples:**
  - critical – an unauthenticated read of all tenants' data through a shared cache, public export or open link;
  - high – any user reads another tenant's data through a cache, index or export (DL-01, DL-02, DL-03); a reused identifier gives a new user the data of a deleted one; restore brings back revoked administrative access;
  - medium – a revoked reader keeps access to copies for hours or days; signed links valid for a long time on sensitive data; deleted data readable through one alternate path by an authorised role;
  - low – a leak of the existence or count of private items; stale metadata after revocation;
  - informational – backups that keep data past the policy with operator-only access; a missing deletion hook for a table that holds no sensitive data.

## Fix patterns

- **Scope in the data layer.** Put tenant and principal in the key, partition, index route or schema. Enforce it centrally, not in each caller.
- **Cache references, not rights.** Store identifiers or non-sensitive values, and check access at read time. Or include a permission fingerprint in the key.
- **Filter in the query.** Apply the access filter inside the search or analytics query, before ranking, counting and paging.
- **Re-authorise exports.** Store the requester in the job. Build the file with the requester's rights. Check the requester again at download. Expire files.
- **Data-map-driven deletion.** Keep one list of all copies. Delete from each, or destroy the key (crypto-shredding). Add a test that fails when a new store has no deletion step. Keep tombstones free of content.
- **Release identifiers safely.** Do not reuse names, addresses or identifiers, or clear all links and grants on release.
- **Restore through the normal write path.** Run create and authorise functions on restored data. Ignore owner, tenant and role fields in the source.
- **Narrow, short signed links.** One object, one action, one audience, short life. Do not log them. Check ownership before attaching a blob to a record. Do not de-duplicate across tenants where existence is sensitive.
- **Safe migrations.** Default to the most restrictive value. Keep security controls active during the migration. Review null handling.
- **Mask non-production data.** Copy through a masking step.
- **Looks right but is not:** adding the tenant to the key at one call site and not the others; filtering search results after retrieval (counts and paging still leak); a deleted marker in the default scope while raw queries skip it; setting a flag as the only deletion step; hiding the item in the interface; a long time-to-live as the only revocation; encrypting every backup with one shared key; a "private" link with a long lifetime; trusting the owner field in a backup.

## Regression tests

- **Two-tenant copy test:** for each copy in the data map, create data as tenant B and read as tenant A. Assert deny. Generate the test from the data map so new copies appear as untested.
- **Search leak test:** query for a term that exists only in another tenant's data. Assert zero hits, zero count and no suggestion.
- **Export binding test:** start a job as A. Fetch as B. Assert deny. Assert that the file holds no row outside A's rights.
- **Deletion test:** delete a resource. Read it through every path in the data map (identifier, list, search, export, blob link, device sync). Assert not found.
- **Identifier reuse test:** delete an account. Create a new account with the same name or address. Assert no inherited data or grants.
- **Restore test:** revoke access, restore an old snapshot, and assert the access stays revoked.
- **Signed link test:** use a link for another object, after expiry and after delete. Assert deny.
- **Migration test:** run the migration on rows with null and legacy values. Assert no row becomes visible to a new principal.
