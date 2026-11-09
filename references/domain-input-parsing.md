# Domain: Input Parsing

## Scope

- **Load when:** the code turns bytes, text or structured data from a lower-trust source into values that it trusts. Signs: parsers and decoders, deserialisation calls, file uploads, archive extraction, path handling, identifier comparison, length or count fields in a binary format, XML, YAML, JSON, CSV or custom wire formats, configuration files that users supply, import and restore features.
- **Covers:** parser differentials, deserialisation of untrusted data, archives, uploads, path normalisation and traversal (string level), Unicode normalisation, confusable characters and case folding in identifiers, integer and length fields, encodings and charsets, XML, YAML and other formats with code-execution or resource-loading features.
- **Hand off to:**
  - `domain-injection.md` – data that reaches an interpreter, query, shell, template or output context. Input-parsing owns "what the value means after decoding". Injection owns "what the next component does with it".
  - `domain-memory-safety.md` – memory corruption caused by a parsing defect (bounds, overflow, use-after-free). Input-parsing keeps the logic-level length and count errors (IP-07).
  - `domain-resource-exhaustion.md` – decompression bombs, entity expansion cost, deep nesting, ReDoS and parse-time cost. Input-parsing reports the missing limit as a lead only.
  - `domain-filesystem-process.md` – symlinks, hard links, junctions, permissions and file races at the extraction or upload target. Input-parsing owns the name and path as a string.
  - `domain-web-client.md` – serving uploads from the application origin, and browser content sniffing.
  - `domain-ai-llm.md` – unsafe model files (pickle-style formats), training-data and embedding poisoning. Use this file for the loader call only.

## Invariants

Fill the placeholders from `threat-model.md`.

1. **Single meaning:** Every component that reads <input> gives it the same meaning. A value that passes a check means the same thing at the use.
2. **Check after decode:** Validation runs on the final decoded and normalised form that the sink uses, not on an earlier form.
3. **Data only:** Parsing <format> from <source> creates only plain data. It never creates arbitrary objects, loads code or opens resources named by the input.
4. **Contained names:** A name or path from <source> resolves to a location inside <base directory>, after decoding, normalisation and link resolution.
5. **Bounded fields:** Every length, count, offset and size field from <source> is checked against the real data size and against a documented maximum, before it is used in arithmetic, allocation or a loop.
6. **Strict grammar:** The parser accepts only the documented grammar. It rejects duplicates, trailing data, unknown critical fields and invalid encodings.
7. **Identifier identity:** Two identifiers are the same only if the system defines them so, after one fixed normalisation and case-folding rule that all components share.
8. **Declared type:** The type, size and name of an upload are decided by the server from its own inspection, not by the client's claim.

## Recon additions

Add a heading "Parser inventory" to `threat-model.md`. Use one row for each parser or decoder that handles lower-trust input.

| Format or input | Library or hand-written | Version and configuration | Entry (file:line) | Source trust | Output used by | Second parser of the same input |
|---|---|---|---|---|---|---|

Then add these notes:
1. **Same input, two readers.** List every input that more than one component parses (proxy and application, validator and consumer, API layer and storage, signer and verifier, scanner and extractor, client and server). Each pair is a lead for IP-01.
2. **Normalisation points.** For each identifier (user name, file name, path, URL, tag, channel name, email address, key), write where it is normalised, where it is compared and where it is stored.
3. **Dynamic-type deserialisers.** List each call that can create objects of a type that the input names or implies.
4. **File-handling features.** List uploads, imports, restores, extractors, previews, thumbnailers, converters, and every place the product stores a client-supplied name.
5. **Binary formats.** List each format that has length, count or offset fields, and who wrote the reader.

## Lead searches

Adapt the patterns to the language. The language file adds the concrete deserialisers and parsers.

| Search | A hit may mean | False-hit notes |
|---|---|---|
| `deserial\|unmarshal\|unpickle\|readObject\|fromXML\|load\(s\)?\b\|decode.*object\|Marshal\|BinaryFormatter\|ObjectInputStream` | Deserialiser that can build objects (IP-02) | Safe if the call uses a plain-data mode or a strict type allow-list. Read the options. |
| `unzip\|untar\|extract\|ZipEntry\|tar.*next\|archive\|\.zip\|\.tar\|\.7z\|\.rar` | Archive extraction (IP-03) | Check the library's own path protection. Do not assume it. |
| `entry\.?name\|getName\|member\.?name\|header\.?name` joined to a destination with `join\|+\|/` | Entry name used as a path (IP-03) | A check on the result of the join is the control. Read it. |
| `upload\|multipart\|file_?name\|original_?name\|content_?type\|mime\|extension\|\.ext` | Upload handling (IP-04) | Framework temp-file handling is not a control for the final name. |
| `\.\./\|\.\.\\\|%2e\|%2f\|%5c\|normalize\|realpath\|canonical\|abspath\|startswith\|starts_with\|HasPrefix` near a path | Path check or traversal (IP-05) | A prefix check without a trailing separator is a lead. |
| `lower\(\)\|upper\(\)\|casefold\|toLowerCase\|ToLower\|normalize\|NFC\|NFKC\|NFD\|NFKD\|collat\|ilike\|COLLATE` on identifiers | Normalisation and case folding (IP-06) | Display-only use is not a lead. |
| `len\|length\|size\|count\|offset\|nbytes\|read\(.*\)` multiplied, added or used in `alloc\|new\|make\|resize\|reserve\|slice` | Length field in arithmetic (IP-07) | Checked arithmetic or a bounded type stops it. |
| `XMLParser\|DocumentBuilder\|SAXParser\|XmlReader\|libxml\|expat\|lxml\|xml\.etree\|XSLT\|DOCTYPE\|ENTITY\|XInclude\|resolve_?entities\|load_?dtd` | XML parser setup (IP-09) | Many current libraries disable external entities by default. Check the pinned version. |
| `yaml\.load\|YAML\.load\|unsafe_?load\|FullLoader\|!!\|safe_?load\|Psych` | YAML loader choice (IP-10) | A safe loader or schema mode is the control. |
| `merge\|extend\|deep_?(merge\|copy\|assign)\|__proto__\|constructor\|prototype\|setIn\|set_?path` on input objects | Key-path writes and prototype pollution (IP-10) | Key allow-lists and null-prototype maps stop it. |
| Two different libraries that parse the same format (for example two URL parsers, two JSON parsers, two mail parsers) | Parser differential (IP-01) | Same library at two sites is not a differential, unless the options differ. |

## Attack classes

### IP-01 Parser differentials

- **What fails:** two components read the same input and reach different results. A check passes on one reading. The use runs on the other reading.
- **Where to look:** a validator and a consumer that use different libraries or options; a gateway or scanner next to an application; duplicate keys, repeated fields and trailing data; non-canonical numbers; content-type labels that differ from the content; polyglot files; signature code that parses a different copy than the code that acts.
- **Questions:**
  - Which two readers see this input? What does each one do with a duplicate key, a repeated field, a comment, trailing bytes, a byte-order mark and an invalid encoding?
  - Is the checked value the same bytes as the used value? Or does the code re-serialise, re-parse or re-fetch between the check and the use?
- **Sad-path inputs:** duplicate keys with different values; the same key in different case; trailing data after the end of the document; a leading byte-order mark; an integer larger than 2^53; a number written in a non-canonical form; a file that two format readers accept.
- **Evidence for confirmed:** both parsers at file:line, the one input and the two results, and the decision that depends on the difference. A parser-differential claim needs E3 (SKILL.md section 6).
- **Not a finding:** both readers are the same library with the same options; the second reader only sees data that the first reader has already re-serialised in canonical form; the difference changes nothing that any check or use depends on.
- **CWE:** CWE-436 (Interpretation Conflict, class-level; use a more specific child if one fits).

### IP-02 Deserialisation of untrusted data

- **What fails:** a deserialiser builds objects, calls constructors or setters, or resolves types that the input chooses. The attacker steers the program into code paths the developer did not intend.
- **Where to look:** native object serialisation of a language; formats with type tags or class names in the data; message queues, caches, session stores and cookies that hold serialised objects; "import settings", "restore backup" and plugin-state features; remote procedure call layers with polymorphic types.
- **Questions:**
  - Does the data choose the type? Is there a closed allow-list of types, or a deny-list?
  - Can the attacker supply or change the bytes? Does a signature check run before the parse?
  - Does the library offer a data-only mode, and does the code use it?
- **Sad-path inputs:** a type name outside the allow-list; a known-harmless type with a side effect that leaves a marker (for example a logger call); a value of the wrong type for a typed field; a very deep nesting; a field that refers to itself.
- **Evidence for confirmed:** the attacker-reachable source, the deserialiser call and its configuration, and the type-choice by data. For a claim of code execution or another effect beyond type choice, the claim needs a reachable type with that effect in the shipped dependency set. Prove it with E3, or mark `needs-validation`.
- **Not a finding:** the data comes only from a trusted internal writer that no lower principal can influence; a signature that the attacker cannot forge covers the bytes before parsing; the loader accepts only plain data.
- **CWE:** CWE-502; CWE-843 for type confusion; CWE-1321 for key-path writes to object prototypes.

### IP-03 Archive extraction

- **What fails:** an entry in an archive writes, links or overwrites outside the extraction directory, or creates a special file, or changes permissions.
- **Where to look:** upload processors; plugin, theme, mod, package and update installers; backup restore; import tools; document formats that are archives (office documents, application packages); self-written extraction loops.
- **Questions:**
  - Is the entry name joined to the destination, then checked after the join and after normalisation, with a separator-aware containment test?
  - Does the code handle absolute paths, drive letters, `..` segments, backslashes as separators, and names that contain a null byte?
  - Does the code create symlinks, hard links, device nodes or sockets from entries? Can a later entry write through an earlier link?
- **Sad-path inputs:** an entry named with parent-directory segments; an absolute name; a name with a backslash on a POSIX target; a link entry that points outside, followed by a file entry below it; duplicate entry names; a name that is empty or `.`.
- **Evidence for confirmed:** the loop that extracts, the missing or wrong containment test, and a test archive in a scratch directory whose entry lands outside the target. E1 is enough if the join and write are in the repository and the library does no path sanitising (documented behaviour of the pinned version). Otherwise E3.
- **Not a finding:** the archive comes only from a trusted signer after verification; the library version in the lockfile rejects unsafe entries and the code sets no option that disables this.
- **CWE:** CWE-22 (and children CWE-23, CWE-36); CWE-59 for link entries; CWE-409 belongs to resource-exhaustion.

### IP-04 Upload handling

- **What fails:** the server trusts the client's file name, type, size or content, and stores or serves the file in a way that crosses a boundary.
- **Where to look:** multipart handlers; avatar, attachment, media and import endpoints; chunked and resumable upload protocols; thumbnail pipelines; code that picks behaviour from the extension or the client's content-type.
- **Questions:**
  - Who chooses the stored name? Is it generated by the server, or is it derived from the client's name?
  - Does the type decision use the client's label or the extension, or does the server inspect the content? Does the stored content-type match what the server will send later?
  - Can the file be executed or interpreted by the server (script, template, server-side include, configuration file such as a per-directory override)? Is the upload directory inside an interpreted web root?
- **Sad-path inputs:** a name with a double extension; a name with path separators; a name with a trailing dot or space; an empty name; a client type that differs from the content; a zero-byte file; a polyglot file; a chunk sequence that exceeds the total.
- **Evidence for confirmed:** the handler, the missing server-side decision, and the effect: a stored file in a location or with a type that the product later interprets. E1 is enough for server-side effects visible in the repository. Effects in a browser or a downstream scanner are external: `needs-validation`.
- **Not a finding:** the server renames the file, stores it outside any interpreted location, serves it as an attachment with a fixed safe type, and nothing else reads it.
- **CWE:** CWE-434; CWE-646 for decisions based on name or extension; CWE-22 for names used as paths.

### IP-05 Path normalisation and traversal

- **What fails:** the code builds a path from input and the result points outside the intended base, or the check and the use see different paths.
- **Where to look:** file download, static file, template include, log viewer, export and import endpoints; plugin and mod loaders; configuration includes; command-line tools that take names; code that checks a string prefix.
- **Questions:**
  - Does the code check before it decodes or normalises (validate then canonicalise)? The check must run on the final form.
  - Is the containment test separator-aware? A prefix test on `/data/files` also accepts `/data/files-private`.
  - Does the code handle backslashes, null bytes and absolute forms, which discard the base in a join?
- **Sad-path inputs:** parent-directory segments, plain and percent-encoded; an absolute path in place of a relative name; a double-encoded segment; backslash separators on a POSIX target; a name with a null byte; a name that normalises to the base itself.
- **Evidence for confirmed:** the line where input becomes a path, the check, the sink, and a test value that reads or writes a marker file outside the base in a scratch tree. E1 is enough when the check and sink are in the repository and no step depends on OS behaviour.
- **Not a finding:** a name that the code maps through an allow-list or an ID table; a base directory that holds only public data and the access is read only.
- **CWE:** CWE-22; CWE-23; CWE-36; CWE-180 when validation runs before canonicalisation; CWE-41 for path equivalence.

### IP-06 Unicode normalisation, confusables and case folding

- **What fails:** two identifiers that look the same, or that one component treats as the same, are treated as different by another. Uniqueness, ownership or authorization checks then fail.
- **Where to look:** sign-up and rename flows for user names, display names, tenant slugs, channel and room names, domain labels, email addresses, package names, file names; lookups that mix case-insensitive database collation with case-sensitive code; allow-lists and deny-lists of names; reserved-name checks; mention and handle matching.
- **Questions:**
  - Which normalisation form is used (NFC, NFD, NFKC, NFKD) at storage, at comparison and at lookup? Is it the same at every site?
  - Which case-folding rule is used? Compare simple lower-casing with full case folding. Locale-sensitive rules change results (the Turkish dotted and dotless i).
  - Does the system compare after normalisation, or does it normalise only at display?
  - Can a name differ only by confusable characters, zero-width characters, direction marks or combining marks, so it impersonates another principal?
- **Sad-path inputs:** a name with a precomposed character and the same name with a base character plus combining mark; a full-width form of an ASCII name; names that differ only in case, including the German sharp s and the dotless i; a name with a zero-width character; a name that mixes scripts.
- **Evidence for confirmed:** both comparison sites, the pair of identifiers, and the decision that differs: for example a duplicate account name, or a reserved-name bypass. This is a normalisation differential and needs E3, unless both sites are in the repository and visibly use different rules (then E1 with a waiver that names both).
- **Not a finding:** confusable names that only mislead a human reader, with no check that depends on equality (record as a hardening note); lower-case folding applied consistently at every site.
- **CWE:** CWE-176; CWE-178; CWE-180; CWE-1007 for visual confusion.

### IP-07 Integer, length and count fields

- **What fails:** a size, length, count or offset field from the input is wrong, inconsistent, negative after conversion, or overflows in arithmetic. The program then allocates, reads or loops incorrectly.
- **Where to look:** binary and framed formats; network protocols; file headers; image, audio and font readers; serialisation formats with length prefixes; pagination, quantity and range parameters; code that converts between signed, unsigned and different widths; size arithmetic before allocation.
- **Questions:**
  - Is each length checked against the remaining input before the read, and against a maximum before the allocation?
  - Is the arithmetic checked for overflow in the width that the language uses? Does a conversion truncate or change sign?
- **Sad-path inputs:** zero; one; maximum for the width; maximum plus one; negative when read as signed; an inner length that is larger than the outer length; a count that does not match the data; a length of exactly the remaining input plus one.
- **Evidence for confirmed:** the field, the arithmetic or check, and the wrong result. A logic-level effect (wrong quantity, wrong range, unbounded loop) can be E1. A claim of memory corruption needs E3 (a sanitizer run) and belongs in memory-safety.
- **Not a finding:** a field that the code checks in a later line before any use; a size bounded by a type that cannot hold the bad value.
- **CWE:** CWE-190; CWE-130; CWE-1284.

### IP-08 Encodings and charsets

- **What fails:** the decoder accepts forms that the checker did not expect, or decoding happens at the wrong time. Different layers then read different strings.
- **Where to look:** URL, percent, HTML-entity, Base64, hex and JSON-escape decoding; charset conversion between layers; legacy code pages; handling of invalid byte sequences; null bytes in strings that pass into C-style APIs; byte-order marks; mixed line endings.
- **Questions:**
  - Does any layer decode a value that an earlier layer already decoded (double decoding)?
  - Does the code check the string at the character level and then pass bytes to a native API that stops at a null byte?
- **Sad-path inputs:** a null byte inside a name; a doubly encoded separator; an overlong two-byte form of an ASCII character; a lone surrogate; an invalid sequence in the middle of a string; a Base64 value with whitespace or wrong padding.
- **Evidence for confirmed:** the two layers, the one input and the two readings, and the decision that depends on the difference. E3 is required when the claim depends on a library's decoding behaviour that is not in the repository.
- **Not a finding:** a decoder in strict mode that rejects the form; decoding that happens once, before the check.
- **CWE:** CWE-176; CWE-180; CWE-436 (class-level) for a differential.

### IP-09 XML processing

- **What fails:** the XML parser resolves external entities, loads external documents, expands entities without limit, or runs transforms that the input controls.
- **Where to look:** document import; SOAP and similar message layers; office and e-book formats; SAML and other signed XML messages; SVG processing on the server; RSS and feed readers; configuration and manifest files from users; XSLT engines; XInclude support.
- **Questions:**
  - Does the parser setup disable external general entities, external parameter entities, DTD loading and XInclude? Does the pinned library version do this by default?
  - Does the code limit entity expansion, element depth and document size?
- **Sad-path inputs:** a document that declares an external entity pointing to a marker file in the scratch directory; a document with a DTD where none is allowed; a document with nested entity definitions of small size; a document with an XInclude element.
- **Evidence for confirmed:** the parser creation and its options at file:line, the attacker-reachable input, and a test in which the marker file content or a loopback request appears. E1 is enough when the code sets unsafe options explicitly. When the result depends on library defaults, read the pinned version's documentation, or use E3.
- **Not a finding:** a parser that disables DTDs and external resolution by explicit option; a document that only trusted operators supply.
- **CWE:** CWE-611; CWE-776 (the cost aspect also belongs to resource-exhaustion).

### IP-10 Format features that load code, objects or resources

- **What fails:** a data format has a feature that goes beyond plain data. The parser applies the feature to attacker input. Examples: YAML tags that build objects, include directives in configuration formats, JSON merge helpers that write to special keys, formats with embedded scripts or macros, and template-like placeholders in "data" files.
- **Where to look:** configuration and settings loaders; import and export; plugin manifests; theme and mod packages; deep-merge and path-set utilities; "extends" and "include" keys; document formats with macros; spreadsheet and presentation parsers.
- **Questions:**
  - Does the loader call the full mode or the safe mode of the library?
  - Does the format allow references to files, URLs or other documents? Does the loader follow them?
  - Do merge and set-by-path helpers accept keys such as the prototype, constructor or class-reference names? Do they check the key against an allow-list?
- **Sad-path inputs:** a tag or type marker in a data file; an include key that points to a file in the scratch directory; an object key named after a prototype or constructor; a very large number of aliases or anchors; a key path with many segments.
- **Evidence for confirmed:** the loader call and mode, the attacker-reachable input, and a test showing the feature runs (a marker file read, a marker object created, or a polluted property seen by an unrelated object). E1 is enough for documented unsafe loader modes in a pinned dependency. Prototype-pollution impact beyond the property write depends on a reachable gadget: E3.
- **Not a finding:** the loader is the safe mode; the input is operator-only configuration with no lower-trust writer.
- **CWE:** CWE-502; CWE-1321; CWE-611 when the feature is an XML entity; CWE-94 when the result is evaluated (see injection).

## Variant search

When you find one parsing failure:
1. **Same library, same call.** List every call of the same parser, decoder or deserialiser. Compare the options at each.
2. **Same input, other readers.** List every component that reads the same input. Test each pair for IP-01.
3. **Same identifier.** List every site that compares, stores or looks up the same kind of identifier. Check the normalisation rule at each.
4. **Same format, other entry.** List every path that accepts the format.

## Chain primitives

This domain often **gives**:
- file write or file read outside a base directory (config, keys, code, templates);
- object creation or code loading through a loader (a path to execution);
- two identities that the system treats as one (account takeover or impersonation steps, with authn and authz);

This domain often **needs**:
- an interpreter, template engine or browser on the other side (from injection or web-client).

## Verification notes

- **E1 is usually enough** for: a missing containment test in a visible extraction or path join (IP-03, IP-05) when the library behaviour is documented in the pinned version; an unsafe loader mode set in code (IP-02, IP-09, IP-10); a server that trusts a client file name or type (IP-04); a logic-level length error (IP-07). The reproduction waiver must name the library version and the documented behaviour.
- **E3 is required** for: any parser differential (IP-01, IP-08); any normalisation differential that depends on library behaviour (IP-06); memory-safety effects of a length error (IP-07, with memory-safety); gadget or type-reachability claims (IP-02, IP-10); any claim that depends on OS path or file system behaviour.
- **Reachability:** check that the format is accepted in the default build and configuration, by the named attacker, and that the code path is not test-only. An upstream filter that may reject the form is an external assumption: `needs-validation`.
- **Severity examples:**
  - critical – an unauthenticated client makes the server load attacker-chosen objects or code (IP-02, IP-10), or write an arbitrary file into an executable or configuration location (IP-03, IP-05);
  - high – a low-trust user reads arbitrary files (IP-05, IP-09); an account-name collision gives access to another account (IP-06); a parser differential bypasses a security filter (IP-01);
  - medium – an upload stored with an attacker-chosen active type that needs victim interaction (IP-04); a read limited to one directory of low-sensitivity files;
  - low – a length or encoding error with a bounded logic effect; a confusable name that only misleads a reader;
  - informational – a parser feature that is unsafe but unreachable from lower-trust input today.

## Fix patterns

- **Parse once, then pass the parsed value.** Do not re-parse the raw input in a second component. Pass the typed, validated result. When two parsers are unavoidable, use one strict grammar in both and reject any input where they might differ.
- **Plain-data mode.** Use the data-only mode of each library. Use an explicit allow-list of types and fields. Prefer formats that cannot carry objects.
- **Contain paths.** Resolve the final path with the file system's own resolution, then test containment with a separator-aware comparison against the resolved base. Better: generate the stored name on the server and keep the client name only as metadata. Open files relative to a directory handle where the platform supports it.
- **Extract safely.** Write each entry through a function that rejects absolute names, parent segments, links that leave the base, special files and mode bits that grant privilege. Cap entry count, total size and ratio.
- **Own the type.** Decide the upload type from server-side inspection, store the file outside interpreted locations, and serve it with a fixed safe type and a download disposition.
- **One identifier rule.** Pick one normalisation form and one case-folding rule. Apply them at the single entry where the identifier is created or looked up, and store the folded form for uniqueness checks. Restrict the allowed scripts or character classes for names that grant identity.
- **Looks right but is not:** checking the raw string before decoding; a deny-list of `..`; stripping `../` once (the result can form a new traversal); checking the file extension only; trusting the content-type header; lower-casing in one place only; "sanitising" a name and then using the original; a prefix test with no separator; a deny-list of dangerous types in a deserialiser; scanning the archive with one tool and extracting with another.

## Regression tests

- **Differential corpus:** for each parser pair, a set of ambiguous inputs (duplicates, trailing data, odd encodings). Assert that both readers give the same result, or that the input is rejected.
- **Traversal set:** for each path-taking entry, a table of traversal forms (plain, encoded, absolute, mixed separators, null byte). Assert that each either fails or stays inside the base.
- **Archive set:** archives with unsafe names, links and duplicates. Assert that extraction fails and that no file appears outside the target.
- **Identifier set:** pairs of names that differ by case form, normalisation form and confusable characters. Assert that uniqueness and lookup treat them as the system defines.
