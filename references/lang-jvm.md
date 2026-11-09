# Language: JVM (Java and Kotlin)

## Scope
- Covers: Java 8 to 21+, Kotlin on the JVM (1.9 and 2.x), Android app code where it differs. Scala and Groovy appear only as notes.
- Common frameworks: Spring Framework, Spring Boot, Spring Security, Spring Data, Jakarta EE (Servlet, JAX-RS, JPA, JMS; namespace `javax.*` before Jakarta EE 9, `jakarta.*` after), Ktor, Hibernate, MyBatis, Jackson, Android SDK.

## Entry points
Find where external input enters. Search for these.

- **Process start:** `static void main`, `fun main`, `@SpringBootApplication`, picocli `@Command`, `args` handling.
- **Spring MVC and WebFlux:** `@RestController`, `@Controller`, `@(Request|Get|Post|Put|Delete|Patch)Mapping`, `@RequestBody`, `@RequestParam`, `@PathVariable`, `@RequestHeader`, `@ModelAttribute`, `RouterFunction`, `@MessageMapping` (STOMP), `@ControllerAdvice`.
- **Jakarta EE and servlets:** `@Path` with `@GET`/`@POST`, `@QueryParam`, `@PathParam`, `@WebServlet`, `@WebFilter`, `doGet`, `doPost`, `@ServerEndpoint`, `web.xml` (`servlet-mapping`, `security-constraint`).
- **Ktor:** `routing {`, `call.receive`, `call.parameters`.
- **Consumers and schedulers:** `@KafkaListener`, `@RabbitListener`, `@JmsListener`, `@MessageDriven`, `@Scheduled`, `@EventListener`.
- **Remote interfaces:** `UnicastRemoteObject`, `Registry`, JMX flags (`com.sun.management.jmxremote`), Actuator endpoints.
- **Android:** `AndroidManifest.xml` components with `android:exported` or an `<intent-filter>`, `ContentProvider`, `BroadcastReceiver`, `getIntent()`, `Intent.getData`, `@JavascriptInterface`. Hand off to `local-ipc`.
- **Authorization registration:** `SecurityFilterChain`, `authorizeHttpRequests`, `requestMatchers`, `@PreAuthorize`, `@Secured`, `@RolesAllowed`, `@EnableMethodSecurity`. Compare this list with the handler list.

## Sinks by domain

| Domain | Dangerous API or pattern | Safer alternative | Notes |
|---|---|---|---|
| `injection` | `Statement.executeQuery(String)`, string-built `JdbcTemplate`, `createQuery`, `createNativeQuery`, `@Query(nativeQuery = true)` with concatenation, MyBatis `${}` | `PreparedStatement`, named parameters, MyBatis `#{}` | Table, column and `ORDER BY` names cannot be parameters. Use an allow-list. |
| `injection` | `Runtime.exec(String)`, `ProcessBuilder("sh", "-c", s)` | `ProcessBuilder(List)` with fixed program | `exec(String)` splits on spaces and uses no shell. Argument injection still works. |
| `injection` | `SpelExpressionParser` with `StandardEvaluationContext`, OGNL, MVEL, `javax.el`/`jakarta.el` `ExpressionFactory`, Thymeleaf preprocessing `__${...}__`, a view name built from input, `GroovyShell.evaluate` | `SimpleEvaluationContext`, fixed templates | Expression language reaches arbitrary classes. |
| `injection` | `DirContext.search(name, "(uid=" + u + ")", ...)`, `XPath.evaluate` with concatenation | `search(name, filterExpr, Object[] args, ctl)`, `XPathVariableResolver` | LDAP and XPath. |
| `input-parsing` | `ObjectInputStream.readObject`, `XMLDecoder`, `XStream.fromXML`, Kryo and Hessian on untrusted bytes | JSON or protobuf with a fixed schema, `ObjectInputFilter` | See the deserialisation section. |
| `input-parsing` | `DocumentBuilderFactory`, `SAXParserFactory`, `XMLInputFactory`, `TransformerFactory`, `SchemaFactory` with defaults | `disallow-doctype-decl` feature, `XMLConstants.ACCESS_EXTERNAL_DTD` set to `""`, `XMLInputFactory.SUPPORT_DTD` false | Factory defaults allow external entities. |
| `input-parsing` | `ZipInputStream` plus `new File(dir, entry.getName())`, `getOriginalFilename()`, `getSubmittedFileName()` | Resolve, `normalize()`, then `Path.startsWith(base)` | See the string trap below. |
| `filesystem-process` | `new File("/tmp/" + name)`, `File.exists()` then open, `Files.setPosixFilePermissions` after create | `Files.createTempFile`, `Files.createFile(p, PosixFilePermissions.asFileAttribute(...))`, `StandardOpenOption.CREATE_NEW`, `LinkOption.NOFOLLOW_LINKS` | `Files.createTemp*` uses owner-only permissions on POSIX. |
| `filesystem-process` | `ProcessBuilder.environment()`, `inheritIO()`, `System.loadLibrary` with a writable path | Clear the environment map, fixed absolute paths | |
| `outbound-network` | `new URL(s).openConnection()`, `RestTemplate`, `WebClient`, OkHttp, Apache HttpClient with a URL from input | Allow-list host, resolve once, connect to that address | `HttpURLConnection` and OkHttp follow redirects by default. `java.net.http.HttpClient` does not (`Redirect.NEVER`). |
| `outbound-network` | `TrustManager` with empty `checkServerTrusted`, `HostnameVerifier` returning true, `NoopHostnameVerifier`, `TrustAllStrategy`, `TrustSelfSignedStrategy` | Default trust manager, pinned trust store | A raw `SSLSocket` does not check the host name unless `SSLParameters.setEndpointIdentificationAlgorithm("HTTPS")` is set. |
| `outbound-network` | `InitialContext.lookup(userString)` | Fixed names | JNDI lookup can load remote objects. |
| `crypto` | `Cipher.getInstance("AES")` (SunJCE gives ECB), `AES/CBC` without MAC, `MessageDigest` MD5 or SHA-1, `java.util.Random`, `Math.random`, `new SecureRandom(fixedSeed)` | `AES/GCM/NoPadding` with a fresh 12-byte nonce, `SecureRandom` | Check `Signature.verify` result is used. |
| `crypto` | `Arrays.equals`, `String.equals` on MACs or tokens | `MessageDigest.isEqual` | |
| `authn` | `NoOpPasswordEncoder`, JWT `decode` without verify (for example java-jwt `JWT.decode`), `csrf(...disable)` on cookie sessions | `DelegatingPasswordEncoder`, `JWT.require(alg).build().verify(t)` | |
| `authz` | `permitAll()`, `anyRequest().permitAll()`, `@PreAuthorize` without `@EnableMethodSecurity`, `web.xml` `http-method` list | Deny by default, `anyRequest().authenticated()` | `hasRole("X")` checks authority `ROLE_X`. |
| `api` | Binding request to entity: `@ModelAttribute Entity`, `@RequestBody Entity`, Spring Data REST auto-export | DTO with fixed fields, `@InitBinder` `setAllowedFields` | Mass assignment. |
| `web-client` | Thymeleaf `th:utext`, JSP `${x}` without `<c:out>`, `response.getWriter().write(x)`, `@CrossOrigin("*")` with credentials, `sendRedirect(x)`, `redirect:` + input | `th:text`, `fn:escapeXml`, `HtmlUtils.htmlEscape` | |
| `http-protocol` | `getHeader("Host")`, `X-Forwarded-*`, `ForwardedHeaderFilter` without trusted proxy, `server.forward-headers-strategy` | Configure the trusted proxy | |
| `messaging` | JMS `ObjectMessage.getObject`, ActiveMQ `setTrustAllPackages`, Spring Kafka `spring.json.trusted.packages=*`, AMQP Java-serialised bodies | Fixed-schema converters, narrow package lists | |
| `memory-safety` | `sun.misc.Unsafe`, JNI `native`, `java.lang.foreign` (final in Java 22), `ByteBuffer.allocateDirect`, JNA | Pure Java | Java bounds checks stop at these edges. |
| `resource-exhaustion` | `Pattern.compile(input)`, `readAllBytes()`, `Executors.newCachedThreadPool()`, unbounded queues, Jackson without limits | `Pattern.quote`, size caps, bounded pools | Jackson `StreamReadConstraints` exists from 2.15. Spring multipart defaults are 1 MB per file and 10 MB per request. |
| `secrets-config` | `application-*.properties` passwords, `management.endpoints.web.exposure.include=*`, `spring.h2.console.enabled`, `server.error.include-stacktrace` | Environment or secret store, minimal exposure | |
| `logging-privacy` | `printStackTrace()`, `logger.info(obj)` with Lombok `@Data`/`@ToString`, `CommonsRequestLoggingFilter` with headers, `spring.jpa.show-sql` | `@ToString.Exclude`, redaction | Log4j 2 before 2.15.0 resolves JNDI lookups in logged messages by default; related fixes continued to 2.17.1. Check the pinned version. |
| `data-lifecycle` | `@Cacheable` key without tenant or principal, Hibernate `@Filter` not enabled per session, `@Where` | Tenant in the key, central filter | Hibernate 6.3 adds `@SQLRestriction`. |
| `sandbox` | `SecurityManager`, `ScriptEngine`, GraalVM `Context.newBuilder().allowAllAccess(true)`, `URLClassLoader` on writable paths, `GroovyShell` | Polyglot with minimal `HostAccess`, process isolation | `SecurityManager` is deprecated for removal (Java 17) and permanently disabled (Java 24). It is not a boundary. |
| `local-ipc` | `addJavascriptInterface`, `setAllowFileAccess(true)`, mutable `PendingIntent`, `exported="true"`, `usesCleartextTraffic` | Exported only when needed, permission on component | |
| `financial` | `double` or `float` money, `new BigDecimal(double)`, `BigDecimal.equals` | `BigDecimal.valueOf`, `compareTo`, explicit `RoundingMode` | |
| `supply-chain` | Maven `LATEST`/`RELEASE`/ranges, `SNAPSHOT`, Gradle `1.+`, `http` repositories, `exec` plugins | Lockfile, `verification-metadata.xml`, `distributionSha256Sum` | Maven 3.8.1+ blocks `http` mirrors by default. |

## Language traps

- **Reference equality.** `==` on `String` or `Integer` compares references. `Integer` caches -128 to 127.
  - Wrong: `if (role == "admin")`. Right: `"admin".equals(role)`.
- **Path prefix on strings.** `"/data-evil/x".startsWith("/data")` is true.
  - Wrong: `file.getPath().startsWith(base)`. Right: `p.toRealPath().startsWith(baseReal)` on `Path` objects (compares components). Check symlinks too.
- **Silent overflow.** `int` arithmetic wraps. `Math.abs(Integer.MIN_VALUE)` stays negative. `hashCode() % n` can be negative.
  - Wrong: `int total = qty * price;`. Right: `Math.multiplyExact(qty, price)`, `Math.floorMod(h, n)`.
- **Narrowing and sign.** `(int) longValue` truncates. `byte` is signed.
  - Wrong: `int b = bytes[i];`. Right: `bytes[i] & 0xFF`.
- **Locale.** `toLowerCase()` uses the default locale (Turkish dotless i).
  - Wrong: `name.toLowerCase().equals("admin")`. Right: `name.toLowerCase(Locale.ROOT)`.
- **Default charset.** `new String(bytes)` and `getBytes()` use the platform charset before Java 18. Java 18 and later default to UTF-8.
- **URL equality.** `URL.equals` and `URL.hashCode` may resolve host names. Use `URI`.
  - Wrong: `Set<URL> allowed`. Right: `Set<URI>` with a normalised host.
- **`BigDecimal.equals`** compares scale. `new BigDecimal("2.0").equals(new BigDecimal("2.00"))` is false. Use `compareTo`.
- **Fail-open handlers.** `catch (Exception e) { return true; }` in a check. A `return` in `finally` hides exceptions.
- **Kotlin null and equality.** Platform types (`String!`) from Java can be null. `!!` throws. `==` is `equals`; `===` is identity. String templates build SQL: `"... WHERE id = $id"`.
- **Kotlin `copy` and `toString`.** A data class prints every field, including secrets.
- **Spring proxies.** `@PreAuthorize`, `@Transactional` and `@Async` act through proxies. A call inside the same class, a `private` method or a `final` class skips them.
- **Scala.** `scala.sys.process` with a string runs split text. Slick `#$x` splices raw SQL, `$x` binds.
- **Groovy.** `"cmd".execute()` runs a command. A GString passed directly to `groovy.sql.Sql` binds parameters. Assigning it to a `String` first makes it plain text.

## Deserialisation and reflection

- **Java serialisation.** `ObjectInputStream.readObject` on untrusted bytes can run code through classes already on the classpath. Also check `readObject`, `readResolve`, `Externalizable`, RMI, JMX, JMS `ObjectMessage`, HTTP session stores, cache stores and "remember me" cookies.
  - Control: `ObjectInputFilter` (Java 9+, backported to 8u121) set per stream or with `-Djdk.serialFilter`. Java 17 adds filter factories. Use an allow-list.
- **Other byte formats.** `java.beans.XMLDecoder` executes method calls. Kryo should use `setRegistrationRequired(true)`. Configure XStream with `addPermission`/`allowTypes`.
- **Jackson polymorphism.** `enableDefaultTyping()`, `activateDefaultTyping` with a permissive validator, `@JsonTypeInfo(use = Id.CLASS)` or `Id.MINIMAL_CLASS` on fields typed `Object`. Control: `BasicPolymorphicTypeValidator` with an allow-list. Fastjson `autoType` is the same class of risk.
- **YAML.** SnakeYAML before 2.0 builds arbitrary types from tags in `new Yaml().load(...)`. Use `SafeConstructor`. Check the pinned version.
- **Reflection with input.** `Class.forName(s)`, `ClassLoader.loadClass`, `Method.invoke`, `MethodHandles`, `ServiceLoader`, `URLClassLoader`, `defineClass`, JNDI `lookup`. Commons BeanUtils `populate` and Spring `DataBinder` follow property paths such as `class.classLoader`. Spring Framework before 5.3.18 (5.2.20 on the older line) had a binder path gap. Check the version.
- **Script engines.** `ScriptEngineManager` (Nashorn removed in Java 15), `GroovyShell`, `Eval.me`, Spring `SpelExpressionParser`, JShell.
- **Safe by schema.** `kotlinx.serialization` with registered subclasses and Jackson with concrete target classes do not instantiate arbitrary types.

## Concurrency

- **Shared singletons.** Spring beans and servlets are single instances. Instance fields hold data of every request.
  - Wrong: `private User current;` in a controller. Right: pass the value as a parameter.
- **Check-then-act.** `if (!map.containsKey(k)) map.put(k, v)` races. Use `putIfAbsent` or `computeIfAbsent`. For database state use a unique constraint or `UPDATE ... WHERE`.
- **Thread locals.** `ThreadLocal`, `SecurityContextHolder`, MDC values and `RequestContextHolder` do not cross to `@Async`, executors or reactive chains. Pooled threads can keep the previous user. Use `DelegatingSecurityContextExecutor` or `ReactiveSecurityContextHolder`. The strategy `MODE_INHERITABLETHREADLOCAL` copies context to new child threads.
- **`@Transactional` limits.** The default isolation is the database default. Self-invocation skips the proxy. Checked exceptions do not roll back by default.
- **Not thread-safe.** `SimpleDateFormat`, `DecimalFormat`, a shared `Random` for tokens, JPA `EntityManager` across threads.
- **Cancellation.** `Future.cancel(true)` only interrupts. Swallowing `InterruptedException` hides cancellation. In Kotlin coroutines, `catch (e: Exception)` catches `CancellationException` and can leave partial state. `GlobalScope` outlives the request.
- **Virtual threads (Java 21).** Thread locals still work but cost memory. A `synchronized` block can pin the carrier thread (fixed in Java 24).

## Build and runtime settings

- **Debug and management.** `-agentlib:jdwp=...address=*:PORT` opens a debugger on all interfaces. `-Dcom.sun.management.jmxremote.authenticate=false` and `.ssl=false` open JMX.
- **JNDI codebases.** `com.sun.jndi.ldap.object.trustURLCodebase` defaults to false since 8u191. `com.sun.jndi.rmi.object.trustURLCodebase` defaults to false since 8u121. Setting either to true is a lead.
- **Serialisation filter.** `-Djdk.serialFilter` absent means no filter.
- **Module encapsulation.** `--add-opens` and `--add-exports` undo encapsulation. List each one.
- **TLS.** `jdk.tls.disabledAlgorithms` in `java.security`, `jdk.tls.client.protocols`, `-Djavax.net.debug` (can log handshake data).
- **Spring Boot.** `management.endpoints.web.exposure.include` (only `health` is exposed over HTTP by default), `spring.profiles.active`, `server.error.include-stacktrace`, `server.error.include-message`, `spring.jpa.open-in-view` (default true), `spring.mvc.hiddenmethod.filter.enabled` (default false since 2.2), `spring.h2.console.enabled`, `spring.devtools.*`, `spring.security.user.password` (a random password is logged when none is set), `server.servlet.session.cookie.secure|http-only|same-site` (`same-site` from 2.6), `spring.mvc.pathmatch.matching-strategy` (default `path_pattern_parser` since 2.6).
- **Spring Framework 6.** Trailing-slash matching is off by default. Older versions match `/admin/` to `/admin` rules differently from filters. Check the version when a rule uses exact paths.
- **Servlet containers.** `web.xml` `security-constraint` that lists some `http-method` values leaves the other methods open. Tomcat `DefaultServlet` with `readonly=false` allows PUT. Check `listings`.
- **Android.** `android:debuggable`, `android:allowBackup`, `android:usesCleartextTraffic`, network security config `cleartextTrafficPermitted` and `<certificates src="user"/>`.
- **Compiler.** `-Xlint:all -Werror`, Kotlin `allWarningsAsErrors`. Suppressions: `@SuppressWarnings`, `@SuppressFBWarnings`.

## Tools

Run only tools that are installed. This section agrees with `phase-leads.md` section 2.1 (JVM: spotbugs with find-sec-bugs). Tools after the first row are extra.

| Tool | Offline-safe command | Notes |
|---|---|---|
| spotbugs + find-sec-bugs | `spotbugs -textui -pluginList <findsecbugs-plugin.jar> -effort:max -low -html <classes-dir> > out.html` | Works on compiled classes. Build with `mvn -o -q compile` or `./gradlew --offline compileJava`. The Maven plugin form needs the plugin in the local repository. |
| Maven or Gradle | `mvn -o dependency:tree`, `./gradlew --offline dependencies` | Lists pinned versions. A wrapper may try to download its distribution. Check `distributionUrl` first. |
| PMD | `pmd check -d src -R category/java/security.xml -f text` | PMD 7 syntax. PMD 6 uses `pmd -d`. |
| Semgrep | `semgrep --config ./local-rules --metrics=off src` | Never `--config auto`. |
| detekt (Kotlin) | `detekt --input src` | Rule sets vary. Use as lead source. |
| Jazzer | `@FuzzTest` in a JUnit test | Only if already a dependency. |
| Test runner | `mvn -o -q test -Dtest=Class#method`, `./gradlew --offline test --tests 'pkg.Class.method'` | Test code is target code. See `execution.md`. |

OWASP dependency-check needs a database from the network. Do not use it without permission. Use lockfile versions as leads.

## Lead searches

| Regex | Meaning | False-hit notes |
|---|---|---|
| `ObjectInputStream\|readObject\(\|XMLDecoder\|XStream\|Kryo\|Hessian` | Byte-level deserialisation | Check whether input is trusted and whether an `ObjectInputFilter` is set. |
| `enableDefaultTyping\|activateDefaultTyping\|JsonTypeInfo\.Id\.(MINIMAL_)?CLASS\|autoType` | Polymorphic JSON | A strict validator makes it safe. |
| `Runtime\.getRuntime\(\)\.exec\|new ProcessBuilder\|"\s*\.execute\(\)` | Process start | Fixed argument lists are fine. |
| `createStatement\(\)\|createQuery\(.*\+\|createNativeQuery\(.*\+\|nativeQuery\s*=\s*true\|\$\{` | SQL by concatenation | `${}` is a risk in MyBatis XML only. |
| `SpelExpressionParser\|StandardEvaluationContext\|ExpressionFactory\|Ognl\.\|MVEL\|GroovyShell\|ScriptEngine` | Expression and script evaluation | Constant expressions are fine. |
| `DocumentBuilderFactory\|SAXParserFactory\|XMLInputFactory\|TransformerFactory\|SchemaFactory` | XML parser creation | Look for `disallow-doctype-decl` or `ACCESS_EXTERNAL` nearby. |
| `TrustManager\|HostnameVerifier\|NoopHostnameVerifier\|TrustAllStrategy\|checkServerTrusted` | TLS checks weakened | Test code only is a hardening note. |
| `\.lookup\(\|InitialContext\|Class\.forName\|loadClass\|\.invoke\(\|URLClassLoader\|defineClass` | JNDI and reflection | Constant names are fine. |
| `Cipher\.getInstance\("(AES\|DES\|RSA)"\|/ECB/\|"MD5"\|"SHA-?1"\|new Random\(\|Math\.random\|ThreadLocalRandom` | Weak crypto or randomness | Check use: tokens and keys matter, jitter does not. |
| `csrf.*disable\|permitAll\|@CrossOrigin\|allowCredentials\|setAllowedFields\|@PreAuthorize\|@Secured\|@RolesAllowed` | Authorization map | Compare to the handler list. |
| `ZipEntry\|ZipInputStream\|getCanonicalPath\|getOriginalFilename\|getSubmittedFileName` | Path escape from names | A `startsWith` check on `Path` objects after `normalize` is correct. |
| `exposure\.include\|show-sql\|h2\.console\|include-stacktrace\|devtools` | Unsafe Spring settings | Check the profile that sets it. |
| `exported="true"\|addJavascriptInterface\|usesCleartextTraffic\|allowBackup\|debuggable` | Android exposure | Hand off to `local-ipc`. |
| `catch\s*\((Exception\|Throwable)[^)]*\)\s*\{[^}]*return (true\|null)` | Fail-open handler | Use a multi-line search. |
| `sun\.misc\.Unsafe\|System\.loadLibrary\|\bnative\b` | Memory-safety edge | |
| `ThreadLocal\|@Async\|newCachedThreadPool\|SimpleDateFormat` | Context loss or shared state | |
| `@SuppressWarnings\|@SuppressFBWarnings\|NOSONAR` | Silenced tool | Strong lead. Read the reason. |

## Verification notes

- **Smallest harness.** One JUnit test that calls the method with hostile input. Avoid starting the whole Spring context. When you need filters, use `@WebMvcTest` with Spring Security test support. `MockMvcBuilders.standaloneSetup` skips the security filter chain and gives false allows.
- **SQL.** Use an in-memory H2 or SQLite database with a dummy table. Assert that a canary row stays unchanged.
- **XML.** Parse a document with a DOCTYPE that points to a temp file with dummy content. Assert the content does not appear.
- **Java deserialisation.** Use a canary class whose `readObject` sets a static flag. Never build a gadget chain. Whether a real chain exists depends on the classpath and needs E3 or stays `needs-validation`.
- **Authorization.** Two dummy principals A and B, a resource owned by B, and a call as A. Expect deny.
- **False positives.** A `PreparedStatement` with a constant table name. An ORM filter in the data layer. A security annotation on an interface or a parent class. A fixed `ProcessBuilder` list. A `SecurityFilterChain` that matches in an earlier chain.
- **Needs E3.** Races, framework path matching and normalisation, Jackson or SnakeYAML behaviour that depends on the library version, and any claim that a gadget chain is reachable.
