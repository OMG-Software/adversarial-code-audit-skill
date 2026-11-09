# Domain: Injection

## Scope

- **Load when:** the code builds a query, command, template, expression, markup, header or document from data that a lower-trust source can influence. Signs: string concatenation or formatting into SQL, query objects built from request bodies, shell or process calls, template engines, expression languages, directory or XML queries, server-rendered HTML, email sending, report and export generators, dynamic code evaluation.
- **Covers:** SQL, NoSQL and query-DSL injection, command and argument injection, template and expression injection, server-rendered cross-site scripting (stored and reflected) with context-aware encoding, LDAP, XPath and similar query languages, email and line-protocol header injection, dynamic code evaluation, regex and pattern injection, injection into generated documents (CSV formulas, configuration, XML), second-order injection, and injection through keys and field names.
- **Hand off to:**
  - `domain-web-client.md` – DOM XSS, CSRF, CSP, cookie attributes, open redirects. Injection owns script that the server writes into HTML. Web-client owns script that browser code creates.
  - `domain-input-parsing.md` – what a value means after decoding and normalisation. Injection starts when the value reaches an interpreter.
  - `domain-filesystem-process.md` – process environment, inherited descriptors, privileges and search paths of child processes. Injection owns the flow of data into the command string or the argument list.
  - `domain-http-protocol.md` – HTTP response-header injection and response splitting at the web server or proxy.
  - `domain-logging-privacy.md` – log injection and log forging. Report the sink there.
  - `domain-sandbox.md` – containment of template and expression evaluators that must run untrusted user code by design.
  - `domain-ai-llm.md` – prompt injection.
  - `lang-*.md` – the concrete sinks, safe APIs and escaping functions of each language.

## Invariants

Fill the placeholders from `threat-model.md`.

1. **Data stays data:** Data from <source> reaches <interpreter or sink> only as a bound value, a quoted argument or an encoded text node. It never changes the structure of the command, query, template or markup.
2. **Structure is fixed:** The code fixes the structure of each query, command and template at build time. Input chooses only from a closed set of names (columns, sort orders, options, templates).
3. **Context match:** Every output encoding matches the context where the value lands (HTML body, attribute, script, style, URL, header, document format).
4. **Argument boundary:** Input cannot become an option, a sub-command or an extra argument of a program that the code starts.
5. **No input as code:** Input is never evaluated as code, an expression or a template source, unless the product is designed for that and contains it (sandbox).
6. **Typed queries:** A query object from a request has only the types and operators that the code expects. A client cannot add operators.
7. **Stored is untrusted:** Data read back from storage has the same trust as the request that stored it.
8. **Line safety:** A value written into a line-based protocol or header cannot contain line terminators or delimiters.

## Recon additions

Add a heading "Interpreter sinks" to `threat-model.md`.

| Sink kind | Location (file:line) | API or builder | Data parts (values / names / structure) | Source of each part | Safe API available and used? |
|---|---|---|---|---|---|

Then add these notes:
1. **Sink kinds.** Search for each: database queries, search and document stores, shell and process calls, template rendering, expression and rule engines, directory queries, XML and XPath, HTML output, email and message output, report and export writers, dynamic code loading.
2. **Safe wrappers.** Name the project's own query builders, escaping helpers and template settings. A wrapper is a control only after you read its body.
3. **Raw escape hatches.** List every raw-SQL, raw-HTML and raw-template feature of the frameworks in use (methods named raw, unsafe, literal, safe, trusted, no-escape).
4. **Dynamic names.** List each place where a column, table, field, sort key, header name or template name comes from input.
5. **Stored-to-sink flows.** List each value that one path stores and another path puts into a sink (names, titles, settings, templates, saved filters, webhook definitions).

## Lead searches

Adapt the patterns to the language. The language file adds concrete sinks and safe forms.

| Search | A hit may mean | False-hit notes |
|---|---|---|
| `(select\|insert\|update\|delete\|where\|order by\|limit\|from)\b.*(\+\|%s\|%\(\|\$\{\|\{\}\|\.format\|f"\|concat\|sprintf\|<<)` | Query built by string assembly (INJ-01) | Placeholders (`?`, `$1`, `:name`) bind values and are safe. Only the assembled parts matter. |
| `raw\(\|execute\(\|exec_?sql\|query\(\|cursor\.\|createQuery\|nativeQuery\|FromSql\|RawSql\|literal_?column` | Raw query escape hatch (INJ-01) | Fixed strings with no input parts are safe. |
| `order_?by\|sort(_?by)?\|group_?by\|column\|field` from request | Dynamic identifier (INJ-01, INJ-10) | An allow-list of names is the control. |
| `\$where\|\$regex\|\$ne\|\$gt\|\$expr\|\$function\|mapReduce\|query_?string\|script_?score\|painless` or request body passed whole to a find call | Operator or script injection (INJ-02) | A schema that fixes types per field stops it. |
| `system\(\|popen\|exec\w*\(\|spawn\|Runtime\.exec\|ProcessBuilder\|Process\.Start\|shell=True\|sh -c\|cmd /c\|subprocess\|backtick` | Process start (INJ-03) | An argument array with fixed program is safer. Still check for option injection. |
| Argument arrays that start with, or contain, a value from input | Option injection (INJ-03) | A `--` separator or a leading-dash check is the control. |
| `render_?template_?string\|from_?string\|Template\(\|compile\(\|Environment\(\|eval\w*\(.*template\|\{\{.*\}\}\|<%=\|\$\{.*\}` with input in the template source | Template source from input (INJ-04) | Input as template context data is normal. Input as template text is the lead. |
| `\|\s*safe\|mark_?safe\|raw\b\|v-html\|dangerouslySetInnerHTML\|innerHTML\|@Html\.Raw\|<%-\|\{\{\{\|unescape\|autoescape\s*[=:]\s*(false\|off)\|SafeString\|trust_?as` | Encoding switched off (INJ-05) | The value may be a constant or already encoded. Trace it. |
| `markdown\|sanitiz\|bleach\|DOMPurify\|allow_?tags\|whitelist` near output | Sanitiser as control (INJ-05) | Read its version, options and where it runs relative to later edits. |
| `ldap\|search_?filter\|\(&\|\(\|\|\(uid=\|distinguishedName\|xpath\|selectNodes\|evaluate\(\|xquery` | Directory or XML query (INJ-06) | Library escaping helpers are the control. |
| `mail\(\|sendmail\|smtp\|MIMEText\|setHeader\|addHeader\|Subject\|To:\|From:\|Reply-To\|Cc:\|Bcc:` with input | Email or line-protocol header (INJ-07) | Modern mail libraries reject line breaks in headers. Check the version. |
| `eval\|exec\|Function\(\|new Function\|setTimeout\(\s*['"]\|compile\|loadstring\|instance_eval\|class_eval\|import_module\|__import__\|Class\.forName\|dlopen\|reflect` with input | Dynamic code (INJ-08) | Constants and fixed lookup tables are safe. |
| `re\.compile\|new RegExp\|Regex\(\|Pattern\.compile\|preg_\|fnmatch\|glob\|LIKE\s+['"]%` with input | Pattern injection (INJ-09) | Escaped input, or a literal-match mode, is safe. |

## Attack classes

### INJ-01 SQL injection

- **What fails:** input changes the structure of a SQL statement. The attacker reads, changes or deletes data outside the intended query, or bypasses a condition.
- **Where to look:** string-built queries; search, filter and report endpoints; sort and column parameters; `LIKE` patterns; `IN (...)` lists built by joining values; dynamic table and column names; stored procedures that build dynamic SQL; batch and bulk endpoints; raw-query escape hatches in ORMs; query builders that accept a raw fragment; analytics and export code written by a different team.
- **Questions:**
  - Which parts of each statement come from input: values, identifiers, or structure (operators, clauses, limits)?
  - Does binding cover every value? Binding does not cover identifiers, sort direction, or whole clauses.
  - Is each identifier checked against a closed allow-list, not a quote-escape?
  - Does a stored procedure build SQL from its parameters? (Language file `lang-sql.md`.)
- **Sad-path inputs:** a single quote; a value that holds a quote and a comment marker; a sort name outside the allow-list; a list item with a comma; an empty list; a very long value; a number field with text; the same parameter given twice.
- **Evidence for confirmed:** the assembly line, the absence of binding or an allow-list on every path, and the sink. E1 is enough for a visible concatenation. A test on a scratch database that returns a marker row, or that makes a harmless clause take effect, is stronger.
- **Not a finding:** all input parts are bound values; the interpolated part is a constant or a server-chosen name; the string is not SQL.
- **CWE:** CWE-89.

### INJ-02 NoSQL and query-DSL injection

- **What fails:** a client supplies an object, operator or script where the code expects a plain value. The query logic then changes.
- **Where to look:** document-store and key-value queries built from request bodies or parsed query strings; search-engine query strings and scripts; graph query languages; filters passed through from an API; login and lookup queries that match on a request field; JSON bodies where a string is expected; query-string parsers that turn nested keys into objects.
- **Questions:**
  - Does the code check that each field is a string, number or boolean before it enters the query?
  - Can the client add operator keys (comparison, regex, expression, script, function)?
  - Does the server-side script or expression feature accept input text?
  - Does the whole request object go into the query call?
- **Sad-path inputs:** an object where a string is expected; an array where a scalar is expected; a field named like an operator; a regular-expression operator with a marker pattern; a null value; a boolean.
- **Evidence for confirmed:** the line that passes the client object, the missing type check, and a test showing a changed result set or a skipped condition. If the nested parsing happens in a framework outside the repository, use E3.
- **Not a finding:** a schema validator rejects non-scalar types before the query; a typed model class fixes every field.
- **CWE:** CWE-943 (class-level).

### INJ-03 Command and argument injection

- **What fails:** input reaches a shell string, or becomes an option or extra argument of a program that the code starts.
- **Where to look:** calls that run a shell with a string; string-built command lines; image, media, archive and document converters; version-control, mail and network tools that the code starts; install, update and backup scripts; CI and build scripts that use input in `run` steps; argument arrays where one element comes from input.
- **Questions:**
  - Does the code use a shell? Does the string include input? Which shell syntax would change the structure: separators, substitution, redirection, quotes, newlines, wildcards?
  - With an argument array, can an input value start with a dash and become an option? Can it contain `=` and set an option value? Is a `--` separator used?
  - On Windows, does the code build one command-line string that the program re-parses with its own rules?
  - Is the program path fixed, or does it come from input or from `PATH`? (Search paths: filesystem-process.)
- **Sad-path inputs:** a file name with a space, a semicolon and a marker word; a value that starts with a dash; a value with a newline; a value with a quote; an empty value; a name that looks like an option of the target program.
- **Evidence for confirmed:** the line that builds the command, the source of each part, and a test in which a harmless marker command or a changed option takes effect. E1 is enough for a shell string with input and no quoting. Argument-injection claims need the program's documented option behaviour.
- **Not a finding:** a fixed argument array whose elements are checked against an allow-list; a shell string with constants only.
- **CWE:** CWE-78; CWE-88. For other command-building cases, name the weakness in words.

### INJ-04 Template and expression injection

- **What fails:** input becomes the source text of a template or expression, not data inside one. The engine then evaluates attacker-chosen logic, and often reaches objects and methods of the host.
- **Where to look:** features that let users edit templates (emails, notifications, reports, pages, themes, rules); code that builds a template string by formatting input into it, then renders it; error pages that render a message as a template; expression fields in rule, filter, routing and workflow engines; framework features that evaluate expressions in annotations, configuration or headers; client-supplied "format" strings.
- **Questions:**
  - Is the template source constant, or does input enter it?
  - If users must write templates, does the engine run in a sandbox mode? What can an expression reach: objects, reflection, file access, process start? (Containment: sandbox.)
  - Does a format-string feature let input choose attributes of objects in the context?
- **Sad-path inputs:** an arithmetic expression in the engine's own syntax, where the result number appears in the output; a name of a context variable; an expression that lists attributes of a context object.
- **Evidence for confirmed:** the path from input to template source, the engine and mode, and a test showing the computed marker. A sandbox-escape claim needs E3 and belongs to sandbox.
- **Not a finding:** input is passed only as context data and the engine escapes it; the product lets trusted administrators edit templates, and the design says so.
- **CWE:** CWE-1336; CWE-917 for expression languages; CWE-94 for generated code.

### INJ-05 Server-rendered output and cross-site scripting

- **What fails:** the server writes input into HTML, script, style, URL or other markup without the encoding that the output context needs. A browser then runs attacker script in another user's session.
- **Where to look:** templates and string-built HTML; raw or "safe" output markers; error pages; search and filter echo; email HTML; PDF and report generators that use HTML; markdown or rich-text rendering; user content shown to other users or administrators; admin consoles that show logs and user-supplied names; JSON placed inside script blocks; server-built attribute and URL values.
- **Questions:**
  - Where does each value land: body text, attribute (quoted or not), URL, script, style, comment? Is the encoding correct for that context?
  - Is automatic escaping on? Which calls turn it off?
  - Does the value pass through a sanitiser? Which version and options? Does anything change the content after sanitising?
  - Is the data stored (visible to others) or reflected (victim must open a crafted link)?
- **Sad-path inputs:** a marker with angle brackets and quotes; a value placed in a quoted and in an unquoted attribute; a URL value with a script-type scheme; a name with markup in an admin view; a long value that truncates and breaks the structure.
- **Evidence for confirmed:** the line where the value enters the output, the context, the missing or wrong encoding, and a rendered response in which the marker appears unencoded. E1 is enough for raw output of unencoded input. Sanitiser bypass and browser-parsing claims need E3.
- **Not a finding:** output is auto-escaped and the context is body text; the value is only reflected to the user who sent it by a POST request that needs no victim action beyond self-attack; content-type is non-HTML and the server sends a no-sniff header. (Reflected self-only cases are hardening notes.)
- **CWE:** CWE-79; CWE-116 for wrong encoding (class-level).

### INJ-06 Directory and path-query languages

- **What fails:** input changes the structure of an LDAP filter, a distinguished name, an XPath or XQuery expression, or a similar query. The query then matches other entries or bypasses a condition.
- **Where to look:** directory-based login and lookup; address-book and group search; XML data stores and configuration queries; document selection by expression; single sign-on glue code that searches by user name.
- **Questions:**
  - Are the filter and the distinguished name escaped with different, correct rules? The two contexts need different escaping.
  - Does the query combine attributes in a way that an extra clause changes the result?
- **Sad-path inputs:** a value with parentheses, an asterisk and a backslash; a value with a quote and a bracket for XPath; an empty value; a value that contains the attribute separator.
- **Evidence for confirmed:** the assembly line, the missing escape, and a test against a local directory or XML fixture that returns a different entry.
- **Not a finding:** the library binds variables; the input is checked against a strict allow-list.
- **CWE:** CWE-90; CWE-643; CWE-91 for XML injection.

### INJ-07 Header and line-protocol injection

- **What fails:** input with line terminators or delimiters adds headers, recipients, commands or fields to a line-based message.
- **Where to look:** email sending (subject, recipient, reply-to, custom headers, body boundaries); contact forms and invite features that send mail; SMTP, IMAP, FTP and similar clients built by hand; redirect targets and cookie values written by hand; custom text protocols; configuration writers.
- **Questions:**
  - Can a value used in a header or command contain CR, LF, or other terminators? Does the library reject them, or does it pass them?
  - Can a user control recipients, such as an extra address that makes the product send mail to chosen people?
- **Sad-path inputs:** a value with an embedded line break and a marker header name; a recipient field with two addresses; a value with a null byte.
- **Evidence for confirmed:** the sink, the library behaviour (read or tested), and a captured message in a local mail sink that shows the extra header. Use a local test mail server only.
- **Not a finding:** the library rejects line breaks in header values and the pinned version is in the lockfile; the field is body text only.
- **CWE:** CWE-93; CWE-74 (class-level) for protocols with no specific entry.

### INJ-08 Dynamic code evaluation and generated code

- **What fails:** the program evaluates input as code, or writes source code, scripts or configuration from input and then runs them.
- **Where to look:** eval-style calls; dynamic loading of modules or classes by name from input; reflection that picks a method name from input; generated scripts for builds, cron or installers; user-defined formulas or rules; "calculated field" and "custom filter" features; hot-reload and plugin loaders.
- **Questions:**
  - Does any part of the evaluated text come from input, directly or via storage?
  - Is the load target chosen from a closed list, or built from input (a name that selects a class, module or method)?
  - Can the input reach the arguments of a generated script?
- **Sad-path inputs:** a name outside the closed list; a value that closes a quote in generated code; an expression that returns a marker.
- **Evidence for confirmed:** the evaluation call, the source of the text, and a marker result. E1 is enough when no sanitising step exists on any path.
- **Not a finding:** the evaluator is a sandboxed engine by design (hand off to sandbox); the name is selected from a constant map.
- **CWE:** CWE-94; CWE-95.

### INJ-09 Pattern and document-format injection

- **What fails:** input changes a pattern (regular expression, glob, `LIKE` wildcard) or a generated document (CSV, spreadsheet, configuration, XML, JSON). The consumer then reads a different structure or runs content.
- **Where to look:** search features that build a regular expression from input; allow-list matching with user-supplied patterns; export features that write user text to CSV or spreadsheets; generators of configuration files, `.env` files, INI, YAML or XML by string concatenation; JSON built by string concatenation.
- **Questions:**
  - Is input escaped as a literal before it enters the pattern? Does the language have a literal-match mode?
  - Can a pattern from input match more than intended (an anchor missing, a wildcard in an allow-list)?
  - Does an exported cell that starts with a formula marker get neutralised?
  - Does the generator quote values and escape delimiters for the target format?
- **Sad-path inputs:** a pattern with special characters; a text cell that begins with an equals sign, a plus sign, a minus sign or an at sign; a value with a newline in a configuration file; a value with a quote in a hand-built JSON.
- **Evidence for confirmed:** the writer line, the missing neutralisation, and the changed reading by the consumer. Spreadsheet formula cases need a victim who opens the file, so the severity is usually low or medium.
- **Not a finding:** a pattern from an administrator by design; a generator that uses a serialiser library for the format. (ReDoS cost: resource-exhaustion.)
- **CWE:** CWE-1236; CWE-94 for evaluated output; CWE-74 (class-level) otherwise.

### INJ-10 Second-order injection and injection through keys and field names

- **What fails:** a value that is safe when stored becomes dangerous when a different path reads it into a sink. Or a key, field name or header name from input chooses what the code reads or writes.
- **Where to look:** names, titles, settings and saved filters that are later put into queries, commands, templates or reports; background jobs that read stored text; admin screens that show user data; dynamic field mapping (`obj[key]`, `setattr`, `record.update(body)`); JSON keys that name columns or properties; header names built from input.
- **Questions:**
  - For each stored field, where is it read? Does the later reader treat it as trusted?
  - Does a job or an export run with a higher privilege than the writer?
  - Does a key from input select a column, property or attribute? Which ones can it reach?
  - Does the code encode on output, or did it only filter on input?
- **Sad-path inputs:** a marker string stored as a name, then viewed by the other consumer paths; a key named after a server-owned property; a key with special characters.
- **Evidence for confirmed:** both ends: the store and the sink, with the path between them, and the marker effect at the sink. E1 works when both ends are in the repository.
- **Not a finding:** the later sink encodes or binds the value; the key is checked against an allow-list.
- **CWE:** CWE-89, CWE-79 or the sink's own CWE, chosen by the sink. For writes to server-owned fields by key, name mass assignment in words and hand off to authz (AZ-04).

## Variant search

When you find one injection failure:
1. **Same sink API.** List every call of the same query function, builder or render function.
2. **Same builder pattern.** Search for the same string-assembly shape in other files (the same formatting call, the same concatenation).
3. **Same input.** List every sink that the same input reaches, not only the one you found.
4. **Same stored value.** For stored data, list every reader (INJ-10).

## Chain primitives

This domain often **gives**:
- read or write of the data store, including credentials, tokens and other users' data (to authn, authz and data-lifecycle);
- command execution or code execution on the server (to sandbox escape, secrets-config, cloud-deploy);
- script running in another user's session (to session theft, CSRF-style actions through web-client);
- control of mail content and recipients (to account recovery and phishing steps).

This domain often **needs**:
- a reachable input surface (from api);
- the structure of the schema or the template context (from recon and disclosure);
- a victim who views the stored value (stored XSS) or follows a link (reflected XSS).

## Verification notes

- **E1 is usually enough** for INJ-01, INJ-03, INJ-04, INJ-06, INJ-08 and INJ-10 when input reaches a sink by visible assembly with no encoding or binding on any path. This is the "query built by string concatenation" case in phase-verify.md section 6.3. The waiver must name the sink API and the paths checked.
- **E3 is required** for: sanitiser bypass and browser-parsing claims (INJ-05); claims that depend on a framework's nested-key parsing outside the repository (INJ-02); sandbox-escape claims (INJ-04); and any claim where a library's escaping behaviour decides the result and its source is not in the repository (INJ-07, INJ-06).
- **Sink semantics:** confirm the sink does what you assume. A "query" may be a key lookup. A "command" may be a log line. A "template" may be a plain string replace.
- **Framework defaults:** check the pinned version's auto-escaping, binding and header rules before you claim a missing control. Record the version.
- **Reachability:** confirm that the route or job is enabled and that the named attacker reaches the input. For stored cases, confirm who views the output.
- **E3 test shape:** use a scratch database, local mail sink or local renderer. Send a marker. Show that the marker changes structure and not only content. Never use real data stores or real mail.
- **Severity examples:**
  - critical – unauthenticated SQL, command or code injection with data-store or server control (INJ-01, INJ-03, INJ-04, INJ-08);
  - high – authenticated injection that reads other tenants' data; stored script in an administrator's session (INJ-05); query-operator bypass of a login check (INJ-02);
  - medium – stored script that reaches only low-privilege users; spreadsheet formula injection with a likely victim (INJ-09); mail header injection that sends mail to chosen recipients from the product's domain (INJ-07);
  - low – reflected script that needs a rare victim action; injection into a field that only the writer reads;
  - informational – a raw-output feature whose input is always constant today.

## Fix patterns

- **Bind values.** Use parameterised queries and prepared statements for every value. Use the query builder's typed API.
- **Allow-list structure.** Map sort keys, columns, operators and template names through a closed table. Never escape an identifier from input and use it.
- **No shell.** Start programs with an argument array and a fixed program path. Put `--` before input operands. Check that values do not start with a dash. Prefer a library call to a program call.
- **Typed query input.** Validate each request field against a schema (type and range) before it enters a query. Reject unknown operators.
- **Template source is constant.** Pass input as context data. If users must author templates, use a logic-less or sandboxed engine and a minimal context.
- **Encode at output, for the context.** Use the template engine's automatic, context-aware encoding. Keep it on. Mark a value as safe only when the code built it and encoded it. Add a content security policy as a second layer (web-client).
- **Sanitise rich text with a maintained library** at output time, with a fixed allow-list of tags and attributes and URL schemes, and no edits after sanitising.
- **Use library escapes for query languages and exports.** Use the escape or variable-binding function of the directory or XPath library. Neutralise exported cells that start with a formula marker.
- **Reject line breaks** in values for headers, recipients and protocol fields. Use a mail library that validates headers.
- **Looks right but is not:** escaping quotes only; a deny-list of keywords; stripping a bad word once (it can reappear); escaping on input and then using the value in another context; HTML-encoding a value that lands in a script or a URL; escaping a value that is used as an identifier; trusting the front end to validate; a web application firewall as the only control; quoting one shell word while the whole string still passes through a shell.

## Regression tests

- **Metacharacter table** for each sink: quote, backslash, line break, dash prefix, operator-named key, markup characters. Assert that the result is the literal value, or a clean rejection.
- **Structure test:** assert on the built query or command (for a builder, assert the statement text and the bound values separately).
- **Output test:** render each template with a marker in every context. Assert encoding per context.
- **Second-order test:** store a marker through every writer. Assert safe behaviour at every reader.
- **Type test:** send objects, arrays and operator keys for scalar fields. Assert rejection.
