# Domain: AI and LLM Systems

## Scope

- **Load when:** the code builds prompts from data, calls a generative model, lets a model call tools, retrieves documents for a model, feeds model output to other code, loads model files, or trains on collected data. Signs: prompt templates, chat or completion calls, tool schemas, agent loops, vector stores, tool-server clients, memory stores, model loaders, training scripts.
- **Covers:** direct and indirect prompt injection, tool and action authority, confirmation binding, model output used as input, context bleed between users, memory poisoning, retrieval source trust, tool-server and plugin trust, unsafe model files, training-data and embedding poisoning, model theft and extraction through the API, and agent cost and loop limits.
- **Hand off to:**
  - `domain-sandbox.md` – isolation of code that an agent tool runs. This file owns whether the model can reach that tool and with what arguments.
  - `domain-outbound-network.md` – SSRF, redirects and TLS in a fetch tool. This file owns whether untrusted text can choose the URL.
  - `domain-supply-chain.md` – where a model, dataset or tool server comes from and how it is pinned.
  - `domain-injection.md` and `domain-web-client.md` – sink-side handling of model output (SQL, shell, HTML). This file owns the step where output is treated as trusted.
  - `domain-authz.md` – the permission model. This file owns whether the agent applies it for the requester.
  - `domain-resource-exhaustion.md` and `domain-abuse.md` – general spend, quotas and scraping. This file owns loop and step limits inside an agent.
  - `domain-data-lifecycle.md` and `domain-logging-privacy.md` – stored copies (indexes, caches) and prompts in logs or provider telemetry. This file owns the query-time retrieval filter.
  - `domain-input-parsing.md` – general deserialisation. This file owns model file formats.

## Invariants

Fill the placeholders from `threat-model.md`.

1. **Authority:** Text from <untrusted source> has the authority of data. It never gains the authority of an instruction, a policy or a tool grant, by any text it contains.
2. **Gate:** A model-chosen action on <tool> runs only if deterministic code checks <requester's rights> and <argument rules>. A prompt instruction is not a gate.
3. **Requester:** Every tool call acts with the rights of <the requesting principal>, never with wider rights of the agent or service.
4. **Confirmation:** A confirmation shows the exact arguments that will run, comes from <the principal>, and covers one call.
5. **Output:** Model output is untrusted input to every downstream parser, renderer, interpreter and policy. It never decides authorization.
6. **Isolation:** Context, memory, caches and retrieved content of one principal never reach another principal.
7. **Persistence:** Data that a model or untrusted content writes to memory, notes or instruction files is not loaded later as trusted instruction.
8. **Retrieval:** A retriever returns only documents that <the requester> may read, checked at query time against current permissions.
9. **Tool servers:** A tool server or plugin is pinned and approved. Its descriptions, outputs and updates are untrusted.
10. **Artefacts:** Loading a model file or checkpoint does not run code.
11. **Training:** Data that enters training, fine-tuning or a shared index has known provenance and review.
12. **Limits:** One request cannot cause unbounded model calls, tool calls, tokens or spend.

## Recon additions

Add these to `threat-model.md` under "AI components".

1. **Model calls.** Each call site: model or provider, what goes into the prompt (system text, user text, retrieved text, tool results, memory), who writes each part.
2. **Trust labels.** For each prompt part: who controls it (operator, requester, third party, other user).
3. **Tool table.** Tool | effect (read, write, send, execute, spend) | model-chosen arguments | credentials | gate in code (file:line) | confirmation.
4. **Data reach.** What private data the model sees, and which channels can carry it out: tool calls, links, images, messages.
5. **Output sinks.** Where model output goes: UI renderers, parsers, shells, queries, files, other agents, policies.
6. **Memory and instruction files.** What persists, who writes it, where it loads.
7. **Retrieval corpus.** Sources, who adds documents, how permissions are checked.
8. **Tool servers.** Source, pinning, transport, authentication, update behaviour.
9. **Artefacts and training flows.** Model files, loaders, datasets, feedback into training or indexes.
10. **Limits.** Step, token, time and spend caps.

## Lead searches

Adapt to the framework. Language files add loader and SDK names.

| Search | A hit may mean | False-hit notes |
|---|---|---|
| Prompt construction: `f".*{.*}"` or template strings near `prompt\|system\|messages\|instructions`, concatenation of request, document or web text into a prompt | Untrusted text in the prompt (AL-01) | Find the source of each variable. Constants are not leads. |
| `tools\s*=\|functions\s*=\|tool_choice\|function_call\|tool_calls\|@tool\|register_tool\|call_tool` | Tool surface (AL-02) | Read each tool body and its gate. |
| `subprocess\|os\.system\|exec\|eval\|shell\|run_command\|write_file\|delete\|send_email\|http(s)?_(get\|post)\|fetch_url\|payment\|transfer` inside a tool body | Powerful tool (AL-02) | A fixed allow-list of commands and a path jail lower the risk. |
| `confirm\|approve\|allow_?always\|auto_?approve\|yolo\|dangerously\|skip_?permission\|human_in_the_loop` | Approval logic (AL-03) | Read what the user sees and what runs. |
| `innerHTML\|dangerouslySetInnerHTML\|markdown\|render\|json\.loads\|literal_eval\|exec\|eval\|execute\(\|\.query\(` applied to model output | Output used as trusted input (AL-04) | A schema validator and an escaping renderer reduce it. |
| `cache\|lru\|memo\|session\|conversation_?id\|thread_?id\|global\|singleton` near `chat\|prompt\|history\|completion` | Shared context (AL-05) | Check that the key includes the principal. |
| `memory\|notes\|remember\|save_?(to_)?memory\|scratchpad\|AGENTS\|instructions\.md\|system_?prompt\s*=.*read\|load.*prompt` | Persistent state (AL-06) | Check who can write and what loads it. |
| `retriev\|similarity_search\|vector\|embedding\|top_k\|namespace\|filter=` | Retrieval path (AL-07) | A filter built from model text is a lead. |
| `mcp\|tool_server\|plugin\|manifest\|openapi.*tools\|npx\s\|uvx\s\|command\s*:\s*\[` in agent config | Tool server trust (AL-08) | Check pinning, transport and approval. |
| `torch\.load\|pickle\|joblib\|dill\|cloudpickle\|numpy\.load\|allow_pickle\|trust_remote_code\|load_model\|from_pretrained\|Lambda\|safe_?tensors\|weights_only` | Model loading (AL-09) | Safe formats and `weights_only` settings reduce it. Read the real call. |
| `logprobs\|top_logprobs\|return_embeddings\|temperature\|max_tokens\|model\s*=` taken from a request; public inference routes with no authentication or quota | API extraction surface (AL-11) | Check authentication and per-principal limits. |

## Attack classes

### AL-01 Direct and indirect prompt injection

- **What fails:** text from a source the attacker controls enters the prompt and steers the model. Sources include the requester, a web page, an email, a file, an issue, a retrieved chunk, a tool result, a name or a comment field. Models cannot reliably separate data from instructions.
- **Where to look:** every prompt build; every tool result that returns to the model; third-party content (web, mail, documents, tickets, code, logs); text extracted from images or audio; names and titles of other users' items.
- **Questions:**
  - Which prompt parts can a third party write? List them with the writer.
  - What is the most powerful thing the model can do after reading that text (AL-02)? What private data is in the same context?
  - Is a deterministic control between the model and each effect? Is a delimiter or a "ignore instructions" line the only defence?
- **Sad-path inputs:** instruction-like text in a document, page or field; text that mimics a system message or tool result; text split across fields; hidden text (zero-width characters, off-screen markup).
- **Evidence for confirmed:** the path from the third-party writer to the prompt, and a reachable effect with no deterministic gate (AL-02 to AL-04). Injection that reaches no effect and no private data is a hardening note.
- **Not a finding:** an injection that only changes the answer for the user who wrote the text; a model with no tools, no private data and no output sink.
- **CWE:** CWE-1427 (improper neutralization of input used for LLM prompting; added in CWE 4.15, after the offline catalogue). Pair it with the CWE of the effect (AL-02 to AL-04).

### AL-02 Tool and action authority (confused deputy)

- **What fails:** a model-chosen call runs with more rights than the requester has, or with arguments that the requester could not set. The model becomes a deputy that attackers steer through AL-01.
- **Where to look:** tool definitions and bodies; credentials that tools use (service, user or ambient); argument handling for paths, URLs, queries, commands, recipients and amounts; tools that read private data next to tools that send data out; code execution and file tools; agent-to-agent calls.
- **Questions:**
  - Which credentials does each tool use? Are they the requester's or the service's?
  - Does code validate each argument (allow-lists, path jails, URL rules, recipient rules, amount limits)? Does it check authorization for the requester?
  - Can untrusted content, private data and an outward channel meet in one session? If all three can, the agent can leak data without any other flaw.
  - Are tools that change state, send messages, spend money or run code reachable from sessions that process untrusted content?
- **Sad-path inputs:** a path outside the allowed root; a URL to an internal host; a recipient chosen by the content; a very large amount; a tool name not in the list; nested arguments.
- **Evidence for confirmed:** the tool body, the missing gate or the wide credential, the untrusted path to the context (AL-01), and the effect on a named victim or resource.
- **Not a finding:** a tool that stays within the requester's rights and authorized task, with no attacker-controlled third-party text steering the action; a powerful tool that only operators reach, by documented design. Acting on the requester's own data does not establish consent.
- **CWE:** CWE-250 where the tool runs with excess rights; CWE-78 where a tool builds a shell command from model arguments. The missing gate and the confused-deputy shape: name in words ("tool call executes with authority of the service, not of the requester").

### AL-03 Confirmation and approval binding

- **What fails:** a human or policy approval does not cover what actually runs. The user approves one thing and the system does another, or an approval stays valid too long.
- **Where to look:** approval dialogs; "always allow" and auto-approve modes; approvals stored by tool name; code between approval and execution; command policy engines.
- **Questions:**
  - Does the dialog show the real arguments, or a model-written summary?
  - Does the approval bind the exact call, principal and session, or only a tool name or prefix?
  - Can the arguments change after approval?
  - Does an allow-list for commands match whole commands, or prefixes that can be extended (`safe-cmd; other`)?
- **Sad-path inputs:** a summary that differs from the arguments; a command that begins with an approved prefix and adds more; an approval reused in another session.
- **Evidence for confirmed:** the approval code, the field that the approval does not bind, and the executed effect.
- **Not a finding:** a confirmation that is weak only for actions with no side effects.
- **CWE:** CWE-78 where a command allow-list is bypassed to reach a shell. Missing binding: name in words ("approval not bound to executed action").

### AL-04 Model output used as trusted input

- **What fails:** code treats model output as safe. A steered model then attacks a downstream component.
- **Where to look:** HTML and markdown rendering (links and auto-loaded images that carry data to attacker hosts); code, SQL, shell and template execution from model text; structured output parsed without a schema; output used as a path, URL or identifier; output that sets roles or policy; output passed to another agent.
- **Questions:**
  - What reads this output next? Does it escape, validate or sandbox it?
  - Does the rendered output load remote images or links with data in the URL? That moves data out without a tool call.
  - Does any decision (authorization, routing) depend on what the model says?
- **Sad-path inputs:** output with markup, a link with data in the query, a command, a traversal path, a role name, an extra field.
- **Evidence for confirmed:** the sink, the missing validation, and an attacker-influenced context (AL-01) that reaches the model. Link the sink-side finding from the injection or web-client file.
- **Not a finding:** model output shown as plain text to the requester only; output checked for structure, permitted values, requester authority and downstream sink rules. A strict schema alone does not make a string, path, URL or command safe.
- **CWE:** CWE-78 for output run in a shell; CWE-200 (class-level) for data that leaves through rendered links. Other sinks: use the sink's own domain file.

### AL-05 Context bleed between users and sessions

- **What fails:** one principal's prompt, history, documents or results reach another principal.
- **Where to look:** conversation stores keyed by a guessable or shared ID; response, prompt and embedding caches; system prompts that include user data; module-level variables in request handlers; shared agent workspaces; shared vector stores; batch jobs that merge requests; tool-result caches.
- **Questions:**
  - Does every key for history, cache and memory include the principal and tenant?
  - Can a request name another principal's conversation ID?
  - Does a cache return an answer built from another principal's private context?
- **Sad-path inputs:** another user's thread ID; two parallel requests; a cached query that differs only by principal.
- **Evidence for confirmed:** the key or shared object, the missing principal binding, and the data of another principal that appears. Use two dummy principals and a mocked model.
- **Not a finding:** a cache of public results.
- **CWE:** CWE-200 (class-level). The root cause (cache or store key without principal) may fit authorization CWEs listed in `domain-authz.md`.

### AL-06 Memory and persistent-instruction poisoning

- **What fails:** untrusted content writes to a store that later loads as trusted instruction, so one injection becomes permanent or spreads across sessions and users.
- **Where to look:** long-term memory; notes and summaries; instruction and rules files that the agent can edit or that a repository supplies; agent-created scheduled tasks or settings; shared team memory.
- **Questions:**
  - Who or what writes to memory? Does the model decide alone, from untrusted content?
  - Where does the saved text load: as a trusted rule, or as data?
  - Can the agent edit its own instruction files, tool config or permissions?
- **Sad-path inputs:** a page that asks the agent to "remember" a rule; a summary that carries an injected line.
- **Evidence for confirmed:** the write path from untrusted content, the load path as trusted text, and the changed behaviour in a later session. Use a mocked model that writes the line.
- **Not a finding:** memory that stores only user-approved facts and loads as plain data.
- **CWE:** no close CWE entry. Weakness in words: untrusted content persisted into trusted instruction store.

### AL-07 Retrieval source trust and retrieval authorization

- **What fails:** the retriever returns documents the requester may not read, or ingests content from sources that attackers can write to.
- **Where to look:** ingestion pipelines; connectors to mail, chat, drives and wikis; vector store queries and filters; filters built from request or model text; permission data stored at index time; upload endpoints that feed a shared corpus.
- **Questions:**
  - Is permission checked at query time against current rights, or only copied at index time?
  - Can the requester or the model change the filter logic through a filter value?
  - Can a low-trust user add text that a high-trust user's session will retrieve?
- **Sad-path inputs:** a document revoked after indexing; a filter value with extra operators; a query that matches a private document; an uploaded file with injected instructions.
- **Evidence for confirmed:** the query code, the missing or stale permission check, and a document the requester could not otherwise read.
- **Not a finding:** a corpus of public content only.
- **CWE:** CWE-200 (class-level). Missing retrieval authorization: name in words ("retrieval returns documents without checking requester's rights").

### AL-08 Tool-server, plugin and MCP-style trust

- **What fails:** the product trusts a tool server or plugin more than it should. Tool descriptions, results or updates steer the model or run code.
- **Where to look:** agent configuration that lists tool servers; servers started by a command from config or from a repository; tool descriptions and schemas that go into the prompt; server updates after approval; name clashes between servers; token forwarding; credential scopes given to servers.
- **Questions:**
  - Who wrote the server, and is its code or version pinned (hand off to `domain-supply-chain.md`)?
  - Are tool descriptions treated as untrusted text? Can a description change after approval without a new approval?
  - Does the client pass a token with a wider audience than the server needs?
  - Does project-level config start a server automatically when a repository opens?
- **Sad-path inputs:** a description that holds instructions; a tool that changes its schema on update; a config file from a cloned repository.
- **Evidence for confirmed:** the config or client code, the missing approval or pinning, and the effect (command start, token leak, steering). Do not start real servers.
- **Not a finding:** a pinned, approved first-party server with narrow scopes.
- **CWE:** CWE-829 for loading tool code from an untrusted source. Description steering and token passthrough: name in words.

### AL-09 Unsafe model files and loaders

- **What fails:** loading a model file, checkpoint or pipeline runs code or reads files that the file's author chose.
- **Where to look:** loaders for formats built on object serialisation (pickle-style, including checkpoints and joblib files); array loaders with pickle enabled; formats that embed custom layers or code; flags that allow code from a model repository; upload endpoints for user models; resume-from-checkpoint paths in shared directories.
- **Questions:**
  - Does the loader accept a data-only format, or use a safe-load option?
  - Who can supply or replace the file: the operator, a user, a hub, a shared directory?
- **Sad-path inputs:** a checkpoint from a user; a model directory with an extra code file; a file whose extension hides another format.
- **Evidence for confirmed:** the loader call with unsafe settings and the path from an untrusted file source. Do not load a hostile file. Reading the call and the source is enough.
- **Not a finding:** loading a file that only the operator can supply from a trusted, pinned source.
- **CWE:** CWE-829 for code in a model repository; CWE-494 for download without integrity check. Unsafe object deserialisation: use the entry in `domain-input-parsing.md`.

### AL-10 Training-data, fine-tuning and embedding poisoning

- **What fails:** low-trust data enters training, fine-tuning, preference data or a shared index, and changes behaviour for others (a backdoor, a bias, a planted answer, a planted instruction).
- **Where to look:** feedback and ratings that feed training; uploaded or scraped data; user documents that enter a shared index; annotation pipelines; automatic retraining jobs.
- **Questions:**
  - Who can add data? Is there review and provenance?
  - Can one contributor affect results for other users or tenants?
  - Can an attacker place content that a later retrieval returns for a chosen query?
- **Sad-path inputs:** many consistent samples from one account; a rare trigger phrase paired with a chosen output.
- **Evidence for confirmed:** the write path from a low-trust principal to the training or index data, and the absence of review. Proof of changed model behaviour is rarely possible from the repository, so the finding is often `needs-validation`.
- **Not a finding:** training only on vetted sources; per-tenant models that serve one tenant.
- **CWE:** CWE-1357 (class-level) for reliance on untrusted data sources; otherwise name in words ("training data from untrusted contributors without validation").

### AL-11 Extraction, theft and runaway cost

- **What fails:** an attacker copies the model, its weights or its private prompt, or rebuilds the model from API answers. Or one request makes an agent run unbounded model calls or tool calls, or sets parameters that should be fixed.
- **Where to look:** inference endpoints and their authentication; per-principal quotas; responses that return log-probabilities or embeddings; weight files in public storage; secrets inside system prompts; agent loops and retries; agent-to-agent calls; request fields that set model, token limit or tool settings.
- **Questions:**
  - Can an unauthenticated client call the model? Is there a per-principal limit?
  - Does the system prompt hold a secret or private data? Anything in a prompt can leak. Product text alone is not a secret.
  - Is there a hard cap in code on steps, tokens and cost per request and principal?
  - Can injected content cause a loop or fan-out? Which inference parameters can the requester set?
- **Sad-path inputs:** very many queries from one account; a request for probabilities; a task that never completes; a tool that always answers "try again"; two agents that call each other.
- **Evidence for confirmed:** the open route, the exposed detail or the missing cap, and the asset or cost that results. Measure the effect with a mocked model. A secret inside a prompt is a finding on its own (never copy the value). Provider spend caps are external.
- **Not a finding:** a public model by design; a loop with a hard cap.
- **CWE:** CWE-200 (class-level) for exposed internals; CWE-538 for weights in an externally accessible file. Unbounded loops: name in words ("unbounded resource use by agent loop"); see `domain-resource-exhaustion.md`.

## Variant search

When you find one AI defect:
1. **Same tool.** List every agent and session that can call the tool, and the context each reads.
2. **Same shape.** Check the gate of every tool with the same kind of argument (path, URL, recipient, command).
3. **Same prompt part.** List every place where the same untrusted source enters a prompt.
4. **Same store.** List every cache, memory, index and history store, and check the key for the principal.

## Chain primitives

This domain often **gives**:
- actions with the service's authority, steered by text an attacker can place;
- private data of the requester or of other users, through outputs, links or tool calls;
- persistent influence (memory, instruction files, shared indexes);
- code execution on the host (loaders, command tools, tool servers).

This domain often **needs**:
- a way to place text in the model's context: a document, page, message, tool result or name field;
- a powerful tool or an output sink (from this domain, `domain-sandbox.md` or `domain-outbound-network.md`);
- victim activity, such as a user asking the agent to read a page.

## Verification notes

- **Treat the model as an attacker-influenced component.** Model behaviour is not a control and is not stable. Do not claim that "the model will refuse" or "the model will comply". The finding rests on one property: if the model emits this call or output, nothing in code stops the effect.
- **E1 is usually enough** for AL-02, AL-03, AL-04, AL-05, AL-07 and AL-08 when three facts are in the repository: untrusted text reaches the context, the tool or sink exists, and no code gate lies between the model's output and the effect. The waiver states that the model's emission is assumed possible, and names every gate checked (validators, path jails, permission checks, approval code, output encoders).
- **Prove it with a mocked model.** Use a local fixture: a fake model that returns a fixed tool call or output, a fake tool backend or a temporary directory, and dummy principals. Assert the effect or the denial. Never call a real model API, real tools, real mail, real payment or real hosts. Whether a real model obeys is external runtime behaviour.
- **Claims that are `needs-validation`:** that a specific model follows a specific injection; that poisoning changes behaviour; that a provider setting (retention, filter, spend cap) exists.
- **E3** is needed for races between approval and execution (AL-03), and for loader behaviour (AL-09) when the loader code is not in the repository.
- **Reachability:** confirm that the tool is registered in the default configuration and that the attacker can place text in the context.
- **Design authority:** an agent that acts for its own user, on that user's data, with that user's rights and no third-party text in context, crosses no boundary.
- **Severity examples:**
  - critical – third-party text in context can make an agent with shell or payment tools act with service authority, with no gate; an unsafe loader on a user-supplied model file in a shared service;
  - high – injection reaches another user's private data and an outward channel; context or cache bleed between users; retrieval of documents the requester cannot read;
  - medium – injection that changes state within the requester's own rights without consent; approval that does not bind the arguments; a tool server loaded from unpinned config;
  - low – a leaked prompt that holds product text only; a large but finite loop cap;
  - informational – injection with no reachable effect.

## Fix patterns

- **Gate in code.** Put deterministic checks between the model and every effect. Check the requester's rights, validate arguments with allow-lists, and jail paths and URLs.
- **Act as the requester.** Use the requester's token or a downscoped token for each tool call. Never use the service's ambient rights.
- **Break the three-way meeting.** Do not let one session combine untrusted content, private data and an outward channel. Split the work across sessions, or require approval for outward actions.
- **Confirm the real call.** Show the exact arguments. Bind the approval to the call, the principal and the session. Match whole commands, not prefixes.
- **Treat output as untrusted.** Validate against a schema. Escape on render. Block auto-loaded remote images and links built from model text. Never let output decide authorization.
- **Key everything by principal.** Include tenant and principal in history, cache, memory and index keys. Filter retrieval at query time.
- **Keep memory and training as controlled data.** Mark where text came from. Never load third-party text as instruction. Review writes to instruction files and training data, and record provenance.
- **Pin and approve tool servers.** Re-approve on any schema or description change. Give each server a narrow token.
- **Load safe formats.** Use data-only model formats and disable code loading. Open untrusted files in a restricted process.
- **Cap everything.** Set hard limits for steps, tokens, time and spend per request and per principal.
- **Looks right but is not:** a system prompt that says "never follow instructions in documents"; delimiters around untrusted text; a classifier as the only filter; asking the model to check its own output; a confirmation that shows a model-written summary; a per-user namespace chosen by the model.

## Regression tests

- A **mocked-model injection test**: a fake model returns a harmful tool call after reading a fixture document. The gate must deny, with no side effect in a temporary directory or fake backend.
- A **tool argument test** per tool: path outside the root, internal URL, foreign recipient, large amount. Each must be denied.
- An **authority test** with two dummy principals: a call for A must not read or change B's data.
- An **approval test**: change the arguments after approval, reuse the approval in a second session, and extend an approved command prefix. Each must be refused.
- An **output sink test**: feed output with markup, a data-carrying link, a path with traversal and an extra field. The renderer and parsers must neutralise or reject each.
- A **context isolation test**: two principals share a cache, history and index. Neither may see the other's content.
- A **loader and memory test**: an unsafe file format is refused. A fixture document that asks to save a rule creates no loaded instruction.
- A **loop test** with a fake model that never stops. The agent must end at the cap.
