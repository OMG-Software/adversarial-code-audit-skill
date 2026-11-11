# Domain: Cloud and Deployment

## Scope

- **Load when:** the repository holds infrastructure-as-code, container definitions, cluster manifests, serverless configuration or deployment descriptors. Signs: `*.tf`, `*.tfvars`, CloudFormation or ARM or Bicep templates, Pulumi or CDK programs, `Dockerfile`, `docker-compose*.yml`, Kubernetes manifests, Helm charts, Kustomize overlays, `serverless.yml`, function manifests, policy files, Ansible playbooks.
- **Covers:** IAM and role design, public and shared storage, network exposure of internal and admin services, container privileges and mounts, Kubernetes RBAC and admission, serverless permissions and event sources, secrets in infrastructure code and state, and metadata service and workload identity exposure.
- **Hand off to:**
  - `domain-secrets-config.md` – how an application stores, loads and rotates its secrets. This file owns secrets that infrastructure code writes into manifests, state and images.
  - `domain-http-protocol.md` – web server, proxy and CDN rules inside the request path. This file owns whether the service is reachable at all and from where.
  - `domain-supply-chain.md` – provenance of images, modules and charts, and CI deploy identities. This file owns what the deployed workload may do.
  - `domain-outbound-network.md` – the SSRF code path that reaches a metadata endpoint. This file owns whether the endpoint is reachable and what its credentials allow.
  - `domain-messaging.md` – authentication of the producers on a queue or topic. This file owns who the resource policy lets publish.
  - `domain-data-lifecycle.md` – backups, snapshots and copies of tenant data. This file owns who can read the storage that holds them.
  - `domain-logging-privacy.md` – content of logs. This file owns whether audit logging is on and who can read or change it.

## Invariants

Fill the placeholders from `threat-model.md`.

1. **Least privilege:** The identity <role | service account | function | pod> can perform only <named actions> on <named resources>.
2. **Trust:** Only <named principals> can assume or impersonate <identity>, and only under <conditions: account, repository, branch, namespace>.
3. **Storage:** <bucket | volume | snapshot | registry | database> is readable and writable only by <named principals>. No anonymous or all-authenticated access exists.
4. **Exposure:** <admin | metrics | debug | datastore | control-plane> interface is reachable only from <named network and principals>.
5. **Container:** The workload runs as <non-root user> with <no extra capabilities>, no host mounts and no access to the container runtime socket, unless <documented reason>.
6. **Cluster:** A workload cannot read secrets, execute in other pods or change policy outside its namespace and role.
7. **Admission:** Every workload that enters <cluster | namespace> passes <policy>. If the policy engine fails, the workload is rejected.
8. **Event source:** Only <named publisher> can invoke <function | queue consumer>, and the invoker's identity is checked.
9. **Secrets in code:** No secret value is in infrastructure code, state, rendered output, image layers or build arguments.
10. **Credentials of the platform:** A workload cannot obtain credentials of a broader identity through the metadata service or the identity-federation binding.

## Recon additions

Add these to `domain-notes.md` under "Deployment model".

1. **Identity table.** Identity | who can assume it (trust policy file:line) | permissions (file:line) | attached to which workload.
2. **Exposure table.** Interface | port | bind address | listener type (public, internal, cluster-only) | auth in front | file:line. Include control-plane and datastore ports.
3. **Storage and data stores.** Resource | access policy | public-access settings | encryption and logging | what data it holds.
4. **Workload table.** Workload | user | capabilities | host mounts | privileged flags | network policy | service account.
5. **Cluster policy.** RBAC bindings, admission policies and their failure mode, namespace exemptions, default service accounts.
6. **Event sources and triggers.** Function or consumer | trigger | who may publish or invoke.
7. **State and secrets.** Where infrastructure state lives, who can read it, and which variables and outputs hold secrets.
8. **Environments.** How development, staging and production differ in the files. Shared roles or shared state across environments are leads.
9. **External assumptions.** The deployed account, organisation policies, network layout and platform defaults that the repository does not show.

## Lead searches

Adapt to the template language. Language files add rendering commands.

| Search | A hit may mean | False-hit notes |
|---|---|---|
| `"Action"\s*:\s*"\*"\|actions\s*=\s*\["\*"\]\|"Resource"\s*:\s*"\*"\|verbs:\s*\[?\s*["']?\*\|roles/(owner\|editor)\|Owner\|Contributor` | Wildcard permission (CD-01, CD-05) | A wildcard on a resource type with no data may be fine. Read the action list. |
| `"Principal"\s*:\s*("\*"\|\{\s*"AWS"\s*:\s*"\*")\|allUsers\|allAuthenticatedUsers\|principals?\s*=.*\*\|AuthLevel.*(anonymous\|none)\|authorization_type\s*=\s*"NONE"` | Public principal (CD-02, CD-06) | A `Condition` block can restrict it. Read the whole statement. |
| `0\.0\.0\.0/0\|::/0\|0\.0\.0\.0:\|"\*"` in ingress rules, firewall rules and bind addresses | Open ingress or wide bind (CD-03) | Ports 80 and 443 behind an authenticated front are normal. |
| `type:\s*(LoadBalancer\|NodePort)\|hostNetwork\|publicly_accessible\s*=\s*true\|public_ip\|associate_public` | Service or data store on a public path (CD-03) | An internal load balancer annotation changes the result. |
| `privileged:\s*true\|allowPrivilegeEscalation:\s*true\|hostPID\|hostIPC\|hostNetwork\|hostPath\|docker\.sock\|cap_add\|SYS_ADMIN\|NET_ADMIN\|seccomp.*[Uu]nconfined` | Container breakout surface (CD-04) | Node agents and CSI drivers may need some. Check the workload's job. |
| `runAsUser:\s*0\|runAsNonRoot:\s*false`, a `Dockerfile` with no `USER`, `ADD http`, `COPY \. ` | Root container or wide copy (CD-04, CD-07) | A later `USER` line or a security context may fix it. |
| `ClusterRoleBinding\|cluster-admin\|system:masters\|escalate\|impersonate\|bind\b\|pods/exec\|secrets` in RBAC rules; `automountServiceAccountToken` | RBAC overreach (CD-05) | Read the subject: a default service account is worse than a named one. |
| `failurePolicy:\s*Ignore\|namespaceSelector\|exempt\|enforce.*(warn\|audit)\|pod-security\.kubernetes\.io` | Admission that fails open or skips namespaces (CD-05) | A warn label next to an enforce label is normal. |
| `password\|secret\|token\|api_?key\|private_?key\|connection_?string` in `.tf`, `.tfvars`, values files, templates, `user_data`, `environment:` blocks, and a committed `*.tfstate` | Secret in code or state (CD-07) | Placeholders, references to a secret manager and test values are not leads. Never copy the value. |
| `169\.254\.169\.254\|metadata\.google\.internal\|IMDS\|http_tokens\s*=\s*"optional"\|hop_limit\|iam\.gke\.io/gcp-service-account\|eks\.amazonaws\.com/role-arn\|azure\.workload\.identity` | Metadata or workload identity config (CD-08) | A required token setting and a low hop limit are good. |
| `event_source\|trigger\|topic_policy\|queue_policy\|aws:SourceArn\|source_arn\|invoker\|function_url` | Event source policy (CD-06) | A source condition limits the publisher. |
| `ref=main\|ref=master\|source\s*=\s*"git::\|latest\|skip_final_snapshot\|deletion_protection\s*=\s*false\|enable_logging\s*=\s*false` | Mutable module or disabled protection (CD-09) | Disabled protection in a throw-away environment is a hardening note. |

## Attack classes

### CD-01 IAM overreach and weak trust

- **What fails:** an identity can do more than its work needs, or a principal that should not assume it can assume it. A small flaw in a workload then becomes control of the account or project.
- **Where to look:** policy documents; role and trust definitions; service accounts and managed identities; cross-account and cross-project grants; identity-federation bindings for CI and workloads; permission to create or change identities and policies; role assignments at wide scope (account, subscription, project, organisation).
- **Questions:**
  - Do action and resource lists use wildcards? Is there a condition that narrows them?
  - Who can assume this role? Does the trust policy name a specific account, repository, branch, namespace or service account?
  - Can the identity grant itself more rights, pass a stronger role to a new resource, or edit its own policy?
  - Do several workloads share one identity, so that the widest need sets the rights of all?
- **Sad-path inputs:** a trust principal that is a whole account or `*`; a federation subject that matches a prefix; a role passed to a function that the caller creates.
- **Evidence for confirmed:** the policy statement, the trust statement, and the workload or principal that reaches the right. State the concrete action it allows, such as reading all secrets or creating new admin roles. The deployed account may differ from the template: see verification notes.
- **Not a finding:** a wildcard on a harmless read action; a broad role in a throw-away environment that holds no real data and shares nothing with production.
- **CWE:** CWE-250 for workloads that run with more rights than needed. Over-wide policy statements and weak trust: no single checked entry; name the weakness in words ("overly permissive policy", "missing trust restriction").

### CD-02 Public or weakly protected storage and data stores

- **What fails:** a bucket, blob container, disk snapshot, image registry, database or cache is open to the internet or to every authenticated cloud user. Data leaks or an attacker writes content that the product later trusts.
- **Where to look:** storage resources and their ACLs, policies and public-access blocks; static-site buckets; shared snapshots and images; database and cache network settings and authentication flags; signed-URL generation; registries; backup targets; log buckets.
- **Questions:**
  - Does the policy allow an anonymous or all-authenticated principal to read, list or write?
  - Does a block on public access exist and apply to this resource?
  - Does the resource hold private data, secrets, state files, backups or build artefacts?
  - Does a data store listen on a public address, or lack authentication?
  - Can the public write path change content that a deploy or a client later trusts (a script, an update, a template)?
- **Sad-path inputs:** list access without read access; write access to a prefix that another service reads; a snapshot or image shared with all accounts.
- **Evidence for confirmed:** the resource, the policy or ACL that grants public access, and the kind of data it holds. Public data by design is not a finding. Account-level blocks are external, so a finding is often `needs-validation`.
- **Not a finding:** a bucket that serves public assets by design and holds nothing else; a public registry for public images.
- **CWE:** CWE-538 where the exposed file holds sensitive data; CWE-200 (class-level) for the disclosure. The cause (public ACL or policy) has no single checked entry; name it in words.

### CD-03 Network exposure of internal and admin services

- **What fails:** a service meant for operators or for other services is reachable from untrusted networks, or without authentication.
- **Where to look:** security groups and firewall rules; load balancer and ingress definitions; Kubernetes `Service` types; ports published in compose files; bind addresses of daemons; management planes (dashboards, API servers, runtime sockets, metrics, debug and profiling ports, message brokers, datastores); ingress rules that route to admin paths; private-endpoint settings.
- **Questions:**
  - Which source ranges can reach each port? Does a rule open `0.0.0.0/0` for a non-public port?
  - Does the service require authentication, or does it rely on the network alone?
  - Does the default network policy deny traffic between workloads, or allow all?
  - Does an ingress annotation or rule skip the authentication layer for some paths?
  - Can a workload reach the control plane or datastore of another tenant or environment?
- **Sad-path inputs:** a port open to all sources; an admin path routed through a public ingress; a listener bound to all interfaces inside a container with a published port.
- **Evidence for confirmed:** the rule or listener, its reach, and the unauthenticated or weakly authenticated function behind it. Cloud firewalls and organisation policies outside the repository can change the reach: mark them.
- **Not a finding:** a public port for the public service itself; a wide rule on a network that has no route from outside.
- **CWE:** CWE-1327 (binding to an unrestricted IP address); CWE-306 (missing authentication for critical function).

### CD-04 Container privileges, mounts and capabilities

- **What fails:** a process inside a container can reach the host, the container runtime or other workloads, so a bug in one container becomes control of the node.
- **Where to look:** privileged flags; added capabilities; host namespaces and host paths; the container runtime socket mounted into a container; device mounts; root user; writable root file system; disabled seccomp or AppArmor profiles; Dockerfile `USER`, `ARG` and `COPY` lines; compose files; build contexts.
- **Questions:**
  - Does the workload need each privilege, capability and mount? What is the job of the workload?
  - Does a mounted runtime socket or host path give the container control of the host?
  - Does the image copy the whole build context, including `.env`, key files and history?
  - Does the image bake in secrets through `ARG`, `ENV` or a layer?
- **Sad-path inputs:** a pod spec that sets `privileged: true`; a host path of `/` or the runtime directory; a Dockerfile that copies the repository root.
- **Evidence for confirmed:** the setting, the workload that has it, and a plausible route from a flaw in the workload to the host. For a flaw that does not exist in the workload, record a hardening note unless the privilege has no reason.
- **Not a finding:** a privileged node agent that must manage devices, with a documented reason and no other exposure.
- **CWE:** CWE-250; CWE-538 for a secret baked into an image layer that is distributed.

### CD-05 Kubernetes RBAC and admission

- **What fails:** a workload or user in the cluster can read secrets, run commands in other pods, create privileged pods or change policy. Or the admission layer lets bad workloads in.
- **Where to look:** `Role`, `ClusterRole` and their bindings; subjects that are default or group service accounts; rules with `secrets`, `pods/exec`, `create pods`, `escalate`, `bind`, `impersonate`; service account token mounting; operators and controllers with cluster-wide rights; admission webhooks and policies; Pod Security labels; namespace exemptions; Helm default values.
- **Questions:**
  - Which subject holds each binding? What can it do on `secrets` and `pods`?
  - Can a subject that can create pods choose any service account or privileged settings?
  - Does the workload need the service account token mounted?
  - Does the admission policy deny by default? What happens when the webhook is down or times out (`failurePolicy`)?
  - Which namespaces are exempt, and can a workload move into one?
- **Sad-path inputs:** a pod created in an exempt namespace; a webhook that times out; a binding to the group of all authenticated users.
- **Evidence for confirmed:** the binding, the rule it grants, the subject, and the next step that the right allows. Cluster-side state (existing bindings, live admission config) is external: mark it.
- **Not a finding:** an operator with broad rights that its function requires and that no workload can abuse.
- **CWE:** CWE-250. Roles too coarse to separate duties: name in words ("insufficient granularity of access control").

### CD-06 Serverless permissions and event sources

- **What fails:** a function runs with a role wider than its code needs, or anyone can invoke it or feed it events.
- **Where to look:** function roles; function URLs and API gateway routes without an authoriser; resource-based policies on functions, queues and topics; event source mappings; cross-account layers; scheduled triggers; environment variables that hold secrets; timeouts and memory limits.
- **Questions:**
  - Does the function share a role with other functions?
  - Does the invocation policy name a specific source, or any principal?
  - Does the route require authentication? Does the code then check the caller's identity (hand off to `domain-authn.md`)?
  - Does the function trust event content from a queue or bucket that others can write to?
- **Sad-path inputs:** an event from a different account or bucket; a route called with no credentials; an event that carries a path or URL that the function acts on.
- **Evidence for confirmed:** the resource policy or route definition, the function's role, and the action the function can then take. Platform-level defaults are external.
- **Not a finding:** a public function that serves public content only, with a narrow role.
- **CWE:** CWE-250. Open invocation and open event source: name in words ("missing restriction on who can invoke").

### CD-07 Secrets in infrastructure code, state and rendered output

- **What fails:** a secret value sits in a file, state, output, image or log that more people or systems can read than should hold the secret.
- **Where to look:** variable defaults; `.tfvars`; Helm values; Kubernetes `Secret` manifests (base64 is not encryption); compose `environment:` blocks; `user_data` and startup scripts; CI-rendered templates; infrastructure state files in the repository or in a shared bucket; outputs not marked sensitive; Dockerfile `ARG` and `ENV`.
- **Questions:**
  - Is the value real, or a placeholder or test value? (Record the file, line and secret type. Never copy the value.)
  - Who can read the repository, the state backend and the rendered output?
  - Does the value still work? That is an external fact. Treat the secret as exposed and recommend rotation.
  - Does an output or log print the value?
- **Sad-path inputs:** a default that works in production; a state file with plain-text values; a Helm value that ends up in a config map.
- **Evidence for confirmed:** the file and line, the secret type, and the audience that can read the place. E1 is enough.
- **Not a finding:** a reference to a secret manager; a documented dummy value used only in local development.
- **CWE:** CWE-538 for a secret in an externally accessible file; CWE-532 for a secret in a log; CWE-200 (class-level) otherwise. Hard-coded credentials: no checked entry; name in words.

### CD-08 Metadata service and workload identity exposure

- **What fails:** a workload can obtain credentials of the node or of a broader identity. A flaw in the workload (for example an SSRF) then becomes cloud access.
- **Where to look:** instance metadata settings (version, token requirement, hop limit); network policy for the metadata address; node roles; workload identity bindings (service account to cloud identity); host networking; pods that share a node with sensitive workloads; shared identities.
- **Questions:**
  - Can a pod reach the metadata address? Does it get node credentials or its own?
  - Does the metadata service require a session token? Is the hop limit low enough to stop containers?
  - Does the binding name one service account in one namespace, or a whole namespace or cluster?
  - What does the reachable identity allow (CD-01)?
- **Sad-path inputs:** a request to the link-local metadata address from a pod; a binding that matches any service account.
- **Evidence for confirmed:** the metadata setting or missing policy, the identity it yields, and its rights. The SSRF path to reach it belongs to `domain-outbound-network.md`; link both findings in chains. Without such a path, record a hardening note.
- **Not a finding:** metadata access that the workload needs, with a narrow role.
- **CWE:** CWE-250 for excess rights of the reachable identity. The metadata exposure itself: name in words.

### CD-09 Weak defaults, disabled protections and module trust

- **What fails:** a template or module is insecure unless the caller sets a flag, or it turns off a protection that matters for the data it holds.
- **Where to look:** module variables with unsafe defaults; encryption, logging, versioning and deletion protection flags; minimum TLS settings; plain-HTTP listeners; shared state or roles across environments; modules pulled from a mutable ref.
- **Questions:**
  - Does the unsafe default reach production, or does each caller set the flag?
  - Does the disabled protection remove the only control for a real asset?
  - Do development and production share a role, state backend or network?
- **Sad-path inputs:** a caller that omits an optional variable; production built from a development variable file.
- **Evidence for confirmed:** the default, the caller that uses it, and the exposure that results. A missing hardening flag with no exposure is a hardening note.
- **Not a finding:** disabled deletion protection in a throw-away environment; a plain-HTTP listener that only redirects.
- **CWE:** CWE-1188.

## Variant search

When you find one deployment defect:
1. **Same resource type.** List every resource of that type in all files and environments, and check each for the same setting.
2. **Same module or chart.** Find every caller of the module or chart, and the values each caller passes.
3. **Same identity.** List every workload that uses the identity, role or service account.
4. **Same policy shape.** Search for the same wildcard, principal or condition pattern in other policies.
5. **Same environment gap.** Compare the same resource across development, staging and production files.
6. **Same history.** If a fix narrowed one policy (phase 2.3), check its siblings.

## Chain primitives

This domain often **gives**:
- cloud credentials and a role, which unlock storage, secrets and other services;
- a path to the node or to other tenants from one container;
- read or write of storage that applications trust (artefacts, templates, state);
- reach to internal services, datastores and admin planes.

This domain often **needs**:
- a flaw in a workload that reaches the platform (SSRF, command execution, file read) from other domains;
- a network position or an account in the cluster or cloud project;
- CI deploy identities (from `domain-supply-chain.md`).

## Verification notes

- **E1 is usually enough** for CD-04, CD-07 and for CD-01 when the statement and the workload binding are both in the repository. The waiver names every file that sets the value, including overlays, variable files and module defaults.
- **Render before you judge.** The final value of a setting comes from variables, overlays and module defaults. Render locally with tools that need no cloud access, such as Helm and Kustomize template rendering, `docker compose config`, or reading the module and variable files by hand. Do not run commands that call a cloud API, plan or apply infrastructure, or talk to a cluster. If a render would need credentials, read the files instead.
- **Facts usually outside the repository** make a finding `needs-validation`: the deployed state (drift from the code); organisation-level policies and public-access blocks (CD-02); cloud firewalls, peering and routes (CD-03); live cluster bindings and admission configuration (CD-05); platform defaults for metadata settings (CD-08); whether a template is used for production at all. State the one decisive fact and a safe check, such as asking the owner to read the setting in the console.
- **E3** needs a local test. Use it rarely, for example a policy engine unit test that evaluates a policy file against a sample request with offline tools. Never test against a live account or cluster.
- **Reachability:** confirm that the file is part of the deployed path (referenced by a root module, chart or pipeline), and that the attacker has the starting position the finding claims.
- **Design authority:** check the stated purpose of the workload. A node agent, a build runner or an operator may need rights that an application does not.
- **Severity examples:**
  - critical – an anonymous principal can read or write storage that holds production data or deployable code; a public admin plane gives control of the cluster or account;
  - high – a workload role that gives administrator rights to a workload that handles untrusted input; a federated trust that any fork can use; a runtime socket mounted in an internet-facing container;
  - medium – a broad role on an internal-only workload; an admission policy that fails open on webhook timeout;
  - low – a missing network policy between low-value workloads; an unneeded service account token mount;
  - informational – a disabled protection in a throw-away environment.

## Fix patterns

- **Least privilege by default.** Give each workload its own identity. List actions and resources. Add conditions for source, account and tag.
- **Narrow trust.** Name the exact account, repository, branch, namespace and service account in each trust or federation binding.
- **Block public access** at the account or organisation level, and again at each resource. Allow public access only for named public-asset resources.
- **Deny by default on the network.** Open only the ports and sources that the design lists. Put admin interfaces on private networks or behind an authenticating proxy.
- **Harden the container.** Run as non-root. Drop all capabilities and add back only the needed ones. Use a read-only root file system. Never mount the runtime socket. Never copy the build context blindly: use an ignore file.
- **Control the cluster.** Bind roles to named service accounts. Turn off token mounting by default. Enforce admission policy with fail-closed behaviour and few exemptions.
- **Authenticate event sources.** Use resource policies that name the publisher and its account.
- **Keep secrets out of code.** Reference a secret manager. Mark outputs sensitive. Keep state in a restricted, encrypted backend. Rotate any secret that reached a repository.
- **Require metadata tokens** and limit hops. Bind workload identity to one service account.
- **Looks right but is not:** a security group that is open on a "private" subnet with a public route; encrypting a bucket that is public; base64 in a Kubernetes secret; a deny rule for one path next to an allow rule for all; `readOnlyRootFilesystem` with a privileged flag; a wildcard policy with a "do not use" comment; an admission policy in audit mode only.

## Regression tests

- A **policy lint test** in CI that fails on wildcard actions, wildcard principals, open ingress on non-public ports, privileged containers, root users and host mounts. Run it on rendered output, not only on templates.
- A **render test** that renders every environment and compares key settings (public access, logging, network rules) with an expected table.
- A **trust-policy test** that evaluates the policy offline against sample principals (right repository and branch; wrong branch; fork) and expects only the first to pass.
- An **RBAC test** that lists what each service account can do and fails when it can read secrets or exec into pods without a recorded reason.
- An **admission test** with sample manifests (privileged, host path, root, no limits) that expects rejection, and a test that expects rejection when the policy engine is unavailable.
- A **secret scan** on the repository, rendered output and state files.
