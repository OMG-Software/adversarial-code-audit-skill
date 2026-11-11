# Domain: Logging and privacy

## Scope

- **Load when:** the code writes logs, audit trails, metrics, traces, telemetry, crash reports or analytics events; calls error-reporting or analytics SDKs; stores or sends personal data; or uses real-time media or peer-to-peer links that expose network addresses.
- **Covers:** log injection and forging; secrets and personal data in logs, telemetry, crash reports and analytics; missing audit records for security actions (repudiation); audit-log tampering and access; data sent to third parties; retention of observability data; IP address and location leaks, including WebRTC.
- **Boundary view.** A data-exposure finding is a boundary failure: data reaches a principal or a third party that must not have it. Regulatory rules (data-protection law, payment-card rules, health-data rules) are context only. Do not state that code is or is not compliant. Do not give legal advice.
- **Hand off to:**
  - `domain-secrets-config.md` – storage, rotation and lifecycle of a secret. This file owns the code that writes a secret to a log, trace or report.
  - `domain-api.md` – error and debug text in API responses. This file owns error text that goes to logs and crash reports.
  - `domain-injection.md` – injection into queries, shells and templates. This file owns injection into log records and log viewers.
  - `domain-data-lifecycle.md` – deletion, backups, caches and exports of tenant data. This file owns observability data only.
  - `domain-authz.md` – who may call the log-viewing or audit-export endpoint. This file owns what the records contain and whether they exist.
  - `domain-web-client.md` – inclusion and integrity of third-party scripts in a browser, and referrer leaks. This file owns what an SDK sends.
  - `domain-filesystem-process.md` – file modes of log files and core dumps.
  - `domain-resource-exhaustion.md` – log volume that fills a disk.

## Invariants

Fill the placeholders from `threat-model.md`.

1. **Neutral logging:** A value from <untrusted source> cannot create, split, alter or hide a record in <log sink>, and cannot inject content into <log consumer or viewer>.
2. **Secrets:** No <secret type> (password, token, key, session identifier, recovery code, signed URL) reaches any log, trace, metric label, crash report or analytics event.
3. **Personal data:** <data class> reaches only the sinks and recipients in the data inventory, and only the listed fields.
4. **Audit completeness:** Each <security action> writes an audit record with actor, target, time and outcome. It does so on success and on denial, on every path that performs the action.
5. **Audit integrity:** The principal whose actions a log records cannot alter, delete or suppress those records, and cannot forge records in the name of another principal.
6. **Attribution:** The actor in an audit record is the authenticated principal. It does not come from request data.
7. **Third parties:** Data leaves the trust boundary only to recipients that the data inventory lists, and not when the user or operator has turned the feature off.
8. **Retention:** Observability data is deleted at the documented age. Debug detail is off in production unless an authorised operator turns it on.
9. **Network identity:** No principal learns the network address, precise location or device identifier of another principal, unless the design says so.

## Recon additions

Add these to `domain-notes.md` under a heading "Data and log inventory". Keep it short; hunters copy it.

1. **Sink table.** One row for each sink: file, standard output, system log, log shipper, metrics, traces, error tracker, analytics service, crash uploader, debug bundle. Columns: writers | fields | who can read | retention | leaves the trust boundary? | recipient.
2. **Data classes.** Secrets, personal data, user content, financial data, device and network identifiers. Mark the source of each in the code.
3. **Security actions.** List each action that needs an audit record: sign-in and failure, credential change, permission change, key or token creation, deletion, export, administrative action, configuration change, denied request.
4. **Audit store.** Where the audit records go, who can write, who can read, and who can change or delete them.
5. **Third-party code.** List each SDK, tracker, update check, font or tile service, and push or e-mail provider. Note default state (on or off), the opt-out, and the fields it sends.
6. **Network exposure.** List each feature where one principal's address, location or device identity can reach another: real-time media, peer-to-peer transfer, presence, link previews, file metadata, headers that echo addresses.
7. **Log controls.** Log levels, flags or headers that raise verbosity, and who can set them.

## Lead searches

| Search | A hit may mean | False-hit notes |
|---|---|---|
| Logging calls with request, header, body or exception objects: `(log\|logger\|print\|console\|trace\|debug\|warn\|error)\w*\(.*(req\|request\|headers\|body\|payload\|params\|args\|err\|exception)` | Secret or personal data in a log (LP-02, LP-03) | Check the fields that the object serialises. |
| Names of secrets in log arguments: `(password\|passwd\|secret\|token\|api_?key\|authorization\|cookie\|session\|bearer\|private_?key\|credential)` near a logging call | Secret in a log (LP-02) | A log of the name only, or a redacted wrapper, is safe. |
| User-controlled strings in log message format without escaping, and plain-text line formats | Log injection (LP-01) | Structured loggers with escaping stop line splitting. |
| `\\n\|\\r\|%0a\|%0d\|\\x1b\|\\u001b` handling near log writes | Presence or absence of neutralisation (LP-01) | Neutralisation at the wrong layer is a lead. |
| Security actions (the list from recon) with no call to the audit function on some path | Missing audit record (LP-04) | The record may be written by a wrapper or an event hook. |
| `audit\|activity_?log\|event_?log\|history` write calls and their storage | Audit integrity (LP-05) | Read the store's permissions and who can delete. |
| Audit write inside `try`/`catch` that ignores the error, or called after the action in a separate step | Silent loss of records (LP-04, LP-05) | A documented best-effort log may be by design. |
| `analytics\|telemetry\|tracking\|metrics\|segment\|beacon\|crash\|report\|sentry\|bugsnag\|firebase\|mixpanel\|amplitude` imports and initialisation | Third-party data flow (LP-06) | Check the default state and the fields. |
| `opt_?out\|consent\|do_?not_?track\|telemetry_?enabled\|privacy` flags | Whether the switch controls the flow (LP-06) | Find every code path that sends, not only the one that checks the flag. |
| `RTCPeerConnection\|iceServers\|iceTransportPolicy\|srflx\|candidate\|STUN\|TURN\|getifaddrs\|X-Forwarded-For\|X-Real-IP` and echoes of addresses | Address leak (LP-07) | A relay-only policy stops direct address exposure. |
| `exif\|gps\|geolocation\|latitude\|longitude\|location\|device_?id\|imei\|mac_?address\|hostname` in outputs to other users | Location or identity leak (LP-07) | Own-data display is not a leak. |
| `log_?level\|verbose\|debug` set from request, environment or flag | Excess detail in production (LP-08) | Check the default value. |
| `core\|minidump\|crash_?dump\|dump\|backtrace\|support_?bundle\|diagnostic` | Dumps with memory content (LP-09) | Check what the dump includes and who gets it. |

## Attack classes

### LP-01 Log injection and forging

- **What fails:** an untrusted value changes the meaning of a log record. The attacker adds fake records, hides real ones, or injects content into a tool that reads the log.
- **Where to look:** plain-text log lines built by string concatenation; structured logs where a value can add a field (JSON, key=value, CSV); user names, paths, headers, user agents, file names and message text written to logs; log viewers and dashboards that render records as markup; parsers and alert rules that trust a field.
- **Questions:**
  - Does the logger escape line breaks and delimiters in each value, or only in the message template?
  - Can a value add or override a field in a structured record?
  - Does a downstream tool (viewer, parser, alert rule, SIEM) trust the log content?
- **Sad-path inputs:** a value with CR, LF and the format of a real record; a value with the field delimiter and a fake key; a value with terminal escape sequences; a very long value; a value with Unicode line separators.
- **Evidence for confirmed:** the write site, the missing neutralisation, the log format, and the consumer that trusts the content (a viewer or a rule in the repository). A forged line with no trusting consumer is a hardening note.
- **Not a finding:** a structured logger that escapes each value; a log that no tool or person uses for a decision.
- **CWE:** CWE-117 (improper output neutralization for logs).

### LP-02 Secrets in logs and diagnostics

- **What fails:** a credential or key is written to a sink that principals without that credential can read.
- **Where to look:** request and response logging with headers or bodies; logging of full URLs with tokens in the query; exception messages that include connection strings or tokens; configuration dumps at start-up; command lines and environment variables in logs; query logs with bound parameters; debug logging of authentication objects; HTTP client libraries with verbose mode; trace spans that record request attributes.
- **Questions:**
  - Which sinks receive the value, and who can read each one?
  - Is the secret long-lived or single-use? Is it still valid when logged?
  - Does a redaction step run at every sink (file, trace, metric, error tracker)?
- **Sad-path inputs:** a unique dummy secret placed in every credential field, header, query parameter and body; a failed login with a password in the user-name field; an exception thrown during authentication.
- **Evidence for confirmed:** the path from the secret's entry to the log call, the sink, the principals that can read the sink, and the secret's validity. E1 is normally enough when the call is in the repository.
- **Not a finding:** a secret that appears only in a sink readable by the same principal who owns it; a value that is a public identifier; a redacted wrapper that works.
- **CWE:** CWE-532 (insertion of sensitive information into log file); CWE-209 for error text that goes to a log or report.

### LP-03 Personal data and content in logs, telemetry, crash reports and analytics

- **What fails:** personal data or user content reaches an observability sink or a vendor that must not have it, or reaches it in more detail than the purpose needs.
- **Where to look:** message bodies, e-mail addresses, phone numbers, names, precise location and device identifiers in logs; analytics events with free-text fields; URLs and screen names that include identifiers; crash reports with stack variables or memory; trace baggage and metric labels with user values; request logs with full source addresses.
- **Questions:**
  - What does the data inventory allow in this sink?
  - Does the event schema allow free text? Who fills it?
  - Is the data needed for the sink's purpose?
- **Sad-path inputs:** a user profile with recognisable dummy values (name, address, message) used in every feature; an exception thrown while handling that data; a search for a dummy term.
- **Evidence for confirmed:** the data class, the sink or recipient not allowed for it, and the path. Name the principal or third party that receives the data. State the boundary that fails.
- **Not a finding:** the user's own data shown to the same user; data the design lists for that sink; an operator-only log that the inventory allows to hold the field.
- **CWE:** CWE-359 (exposure of private personal information to an unauthorized actor); CWE-532 for log sinks; CWE-201 for data inserted into data sent to another party.

### LP-04 Missing audit records (repudiation)

- **What fails:** a security action happens and leaves no record, or the record cannot show who did what and what the result was. A principal can then deny the action.
- **Where to look:** each security action from recon; alternate paths to the same action (administrative API, internal RPC, batch, import, background job); denied requests; failed sign-ins; actions done by a service on behalf of a user; log levels that hide audit events; audit calls placed before the decision or only in the success branch; bulk actions that log the first item only.
- **Questions:**
  - For each action: does every path write a record? Does it include actor, target, time and result?
  - Is the failure or denial logged, or only the success?
  - Does a job record the user who started it, or only the service account?
- **Sad-path inputs:** a denied attempt; a bulk request with several targets; the same action through the administrative route; an action when the log sink is down.
- **Evidence for confirmed:** the action, the path with no audit write, the invariant that requires one (the audit requirement from documentation or the threat model), and what the missing record would let a principal deny.
- **Not a finding:** a low-risk action that no policy asks to record; a record written by a layer the hunter did not read. A missing log for a benign action is a hardening note.
- **CWE:** CWE-778 (insufficient logging); CWE-223 (omission of security-relevant information).

### LP-05 Audit-log integrity and access

- **What fails:** a principal alters, deletes or suppresses audit records, forges records, or reads records it must not read.
- **Where to look:** audit tables writable by the application role that acts for users; log files writable by the service user; delete or edit endpoints for log entries; rotation and clean-up jobs; actor and time fields supplied by the client; audit writes that fail open (the action proceeds without a record, against the design); viewing and export endpoints.
- **Questions:**
  - Who can write, update and delete the store? Is it append-only for the application?
  - Do the actor and time come from the server?
  - If the write fails, does the action stop or continue? What does the design require?
  - Can a low-trust principal read records about other principals?
- **Sad-path inputs:** a request that sets the actor or time field; a deletion of own records; a full disk or an unreachable sink; a rotation that drops records.
- **Evidence for confirmed:** the write or delete path available to the principal, or the field the principal controls, and the record that results. File and database permissions set at run time need E3 or a `needs-validation` verdict.
- **Not a finding:** an operator with full control who edits the log by design; a store that only a higher principal can change and who may do the action anyway.
- **CWE:** CWE-778 for records that are not kept; CWE-117 for forged content; for tampering, name the weakness in words (a principal can change or delete the audit record that covers its own actions).

### LP-06 Data sent to third parties

- **What fails:** data leaves the trust boundary to a vendor or service that the design does not list, or that the user or operator has turned off.
- **Where to look:** analytics, advertising, error-tracking, A/B-testing, push, chat-support and update-check SDKs; remote fonts, maps and tile services; link-preview fetchers; crash uploaders that start on the next launch; telemetry that is on by default.
- **Questions:**
  - Which SDKs start before consent or before sign-in?
  - What fields does each SDK collect by default? Does the application add user data?
  - Does the opt-out stop every send path, including crash and update checks?
- **Sad-path inputs:** telemetry switched off, then each feature used; a first launch before consent; a build with a different flavour or channel; an error thrown while the flag is off.
- **Evidence for confirmed:** the send site, the fields in the payload, the recipient, and the path that ignores the control or the inventory. SDK behaviour that is not in the repository needs E3 with a local capture (a stub receiver on loopback and dummy data) or becomes `needs-validation`.
- **Not a finding:** data the inventory lists for that recipient; a send that the user turned on; infrastructure traffic that carries no personal or secret data.
- **CWE:** CWE-359; CWE-201.

### LP-07 Network address and location leaks

- **What fails:** one principal learns the IP address, location, device or identity of another principal through a side channel of a feature.
- **Where to look:** real-time media and peer-to-peer links (candidate gathering that exposes local and public addresses); relay settings that do not force a relay; peer-to-peer game and file-transfer sessions; link previews and remote-content loads that make the viewer or the server fetch from the sender's chosen host; uploaded files with embedded location or device metadata served to others; echoed forwarding headers; presence and distance features.
- **Questions:**
  - Which parties can see the address or location of which other party?
  - Is the relay-only mode available and used when the design requires hiding the address?
  - Are file metadata fields removed before the file is served to others?
  - Does a remote-content load reveal the viewer's address to a host chosen by someone else?
- **Sad-path inputs:** two test clients on separate dummy networks; a call setup before the user accepts; an image with location metadata; a link that points to a host controlled by the test.
- **Evidence for confirmed:** the feature, the code that exposes or forwards the value, the recipient principal, and the design statement that the value must stay hidden. Library and browser behaviour needs E3 in a local test, or `needs-validation`.
- **Not a finding:** an address exposure that the design documents and the user accepts; a leak of the attacker's own address to itself.
- **CWE:** CWE-359; CWE-1230 (exposure of sensitive information through metadata); for other disclosures, name the weakness in words.

### LP-08 Retention and excess collection

- **What fails:** observability data lives longer than the documented period, holds more detail than needed, or is collected at a debug level in production.
- **Where to look:** log rotation and expiry settings; log-shipping and archive buckets; verbose modes switched by header, query, environment or flag; request and response capture; indefinite storage in analytics and trace stores; scrubbing jobs that cover some sinks only; data from deleted accounts that stays in logs and events.
- **Questions:**
  - What is the retention for each sink? Does the code or configuration enforce it?
  - Can a low-trust principal raise the log level or start capture?
  - Does an account or tenant deletion reach the observability sinks that hold its identifiers?
- **Sad-path inputs:** a header or parameter that turns on verbose logging; a deleted account that appears in later reports; a failed clean-up job.
- **Evidence for confirmed:** the setting or code that sets the longer lifetime or the higher detail, the contrary requirement, and for capture switches, the principal who can set them.
- **Not a finding:** retention that matches the documented period; verbose logging that only an operator can switch on.
- **CWE:** CWE-779 (logging of excessive data); CWE-532 when the extra data is sensitive.

### LP-09 Crash dumps, debug bundles and support exports

- **What fails:** a dump or bundle holds secrets or personal data from memory or state, and it goes to a reader that must not have it.
- **Where to look:** core dumps and minidumps; crash handlers that upload; support-bundle and diagnostic-export commands; debug endpoints that dump state; heap or thread dumps; configuration snapshots in bundles.
- **Questions:**
  - What does the dump include: environment, memory, request data, configuration?
  - Where does it go, and who can read it there?
  - Does the bundle tool filter secrets? Does the filter cover all files it collects?
- **Sad-path inputs:** a crash during authentication; a bundle created with a dummy secret in the configuration; a dump request from a low-trust principal.
- **Evidence for confirmed:** the dump or bundle content (shown with a dummy secret), the destination, and the reader without the right to see it.
- **Not a finding:** a local dump that only the process owner can read; an operator bundle that goes only to the operator.
- **CWE:** CWE-532 or CWE-209 depending on the destination; for a dump file readable by others, name the weakness in words and hand off to `domain-filesystem-process.md`.

## Variant search

When you find one logging or privacy failure:
1. **Same data.** Search for every log, trace, event and report that handles the same field or object.
2. **Same helper.** List every caller of the logging wrapper, serialiser or error handler that leaked the field.
3. **Same sink.** For each sink that received it, list every writer to that sink.
4. **Same action.** For a missing audit record, list every path to the same action (administrative, internal, batch, job, import).
5. **Same SDK.** For a third-party flow, list every initialisation, every event name and every opt-out check.

## Chain primitives

This domain often **gives**:
- credentials and tokens from logs, which unlock authn or authz boundaries;
- identifiers, internal URLs, host names and paths, which supply the target for other attacks;
- the ability to forge or erase records, which hides an attack and defeats response;
- network addresses of other principals, which enable targeted attacks.

This domain often **needs**:
- read access to a sink (from authz, file permissions or a vendor account);
- an input that reaches a log call (from any entry surface);
- a log consumer that trusts content (for LP-01).

## Verification notes

- **Boundary statement.** Each finding names the data, the sink or recipient, and the principal that must not have the data. If the recipient is the owner of the data, or an operator who already holds the right, reject.
- **E1 is usually enough** for LP-02, LP-03, LP-04 and LP-08 when the data path, the call and the sink are in the repository. For LP-02, check the validity of the secret (single-use and expired values lower the impact). For LP-04, the waiver names every path checked for an audit write.
- **E1 is usually enough** for LP-01 when the log format is line-based or structured in the repository and a trusting consumer is in the repository. Without a consumer, the finding is a hardening note.
- **E3 is required** (or `needs-validation`) for LP-05 claims that depend on run-time file or database permissions; for LP-06 claims that depend on what an SDK sends; and for LP-07 claims that depend on browser, media-library or operating-system behaviour. Use a stub receiver on loopback, dummy data and no live vendor traffic. Use a canary test for secrets: place a unique dummy value in every input, run the feature locally, and search every sink.
- **Do not overstate.** Personal data in an operator-only log with documented access is not a data breach. A forged log line with no consumer is not an injection into a system.
- **Severity examples:**
  - critical – a reusable administrative credential or signing key is written to a sink that any user can read;
  - high – session tokens or passwords of other users reach a log that lower-trust staff or a shared platform can read; a low-trust principal erases the audit records of its own privileged actions; personal content of users goes to an unlisted third party by default;
  - medium – personal data in a broader sink than the inventory allows; missing audit records for permission changes; address exposure to another user that the design hides;
  - low – missing audit records for low-risk actions; single-use or expired secrets in logs; excess log detail;
  - informational – a forged log line with no consumer; a full address in an operator-only log.

## Fix patterns

- **Log through a typed layer.** Use structured logging that escapes every value. Fix the field set. Never build records by concatenation.
- **Allow-list fields.** Log named fields, not whole requests, headers, bodies or exception objects. Log the secret's name or an identifier, not its value.
- **Redaction types.** Wrap secrets in a type whose string form is a fixed marker. Add a scrubber at each sink as a second layer.
- **Short-lived and scoped secrets.** Do not put credentials in URLs. Use headers and bodies that the logger does not record.
- **One audit API.** Call it from the decision function or the state-changing function, not from each handler. Record actor (from the authenticated context), target, time (server clock), action and result, for success and denial.
- **Protect the audit store.** Use an append-only store or a write-only role. Send records off the host to a store that the logged principal cannot reach. Decide in the design whether an action stops when the write fails.
- **Gate third parties.** Initialise an SDK only after consent and only when the setting allows it. Keep a list of recipients and fields. Send nothing by default if the design says so.
- **Hide addresses where required.** Force relay-only transport for media. Strip file metadata before serving. Do not echo forwarding headers.
- **Retention.** Set expiry on every sink. Keep verbose modes off by default and settable only by an authorised operator.
- **Looks right but is not:** a scrubber that cleans the message text but not structured fields; masking part of a token; redaction in the log viewer only; hashing a low-entropy value such as an e-mail address or phone number without a secret key; a stable "anonymous" identifier that joins events; audit logging only on the success branch; an audit write wrapped in a catch that ignores errors; a consent flag that the client sets and the server does not check; log level used as redaction.

## Regression tests

- **Injection test:** log a value with CR, LF, delimiters, terminal escapes and structured-field syntax. Assert that exactly one record results, with the value inside one field.
- **Canary test:** place a unique dummy secret and a unique dummy personal value in every input. Run the feature. Search every sink (files, traces, metrics, captured SDK payloads) and assert zero matches.
- **Audit coverage test:** generate a test for each security action from the list in recon. Assert one record with actor, target and result, for success and for denial, on each path.
- **Audit integrity test:** as the logged principal, try to change or delete a record and to set the actor field. Assert denial.
- **Egress test:** run with telemetry off against a local stub receiver. Assert no requests.
- **Address test:** in a local two-client setup, assert that the relay-only setting yields no direct candidates, and that served files have no location metadata.
- **Retention test:** run the expiry job on old fixtures. Assert that expired records are gone from every sink.
