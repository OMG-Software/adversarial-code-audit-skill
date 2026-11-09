# Language: .NET (C#)

## Scope
- Covers: C# 8 to 13 on .NET Framework 4.x, .NET Core 3.1 and .NET 5 to 9. F# and VB.NET follow the same runtime rules.
- Common frameworks: ASP.NET Core (MVC, Razor Pages, minimal APIs, SignalR, gRPC, Blazor Server and WebAssembly), ASP.NET (System.Web) on .NET Framework, Entity Framework Core, Dapper, WCF, Azure Functions, WinForms, WPF, MAUI, Unity scripting (Mono and IL2CPP) where it differs.

## Entry points
- **Process start:** `static void Main`, `Program.cs` with `WebApplication.CreateBuilder`, `Startup.Configure`, `Global.asax`, `System.CommandLine`, `args`.
- **ASP.NET Core routes:** `app.Map(Get|Post|Put|Delete|Patch)`, `MapGroup`, `MapControllers`, `MapRazorPages`, `MapHub<`, `MapGrpcService<`, `MapBlazorHub`, `MapFallback`, `[ApiController]`, `[Http(Get|Post|Put|Delete|Patch)]`, `[Route]`, `[FromBody]`, `[FromQuery]`, `[FromRoute]`, `[FromHeader]`, `[FromForm]`.
- **Real-time and RPC:** public methods of a `Hub` class, gRPC service classes, `[ServiceContract]`/`[OperationContract]` (WCF), `[WebMethod]`, `IHttpHandler`.
- **Blazor:** `@page`, `[Parameter]`, `[JSInvokable]`, `@code`. Blazor Server runs component code on the server for every UI event.
- **Background input:** `BackgroundService`, `IHostedService`, `ServiceBusProcessor`, MassTransit `IConsumer<`, Azure Functions `[Function]`/`[FunctionName]` with `HttpTrigger` (check `AuthorizationLevel.Anonymous`).
- **Desktop and games:** `Application.Run`, URI scheme handlers, `NamedPipeServerStream`, `WndProc`, Unity `MonoBehaviour` callbacks, and network attributes such as Mirror `[Command]` or Netcode `[ServerRpc]`. Hand off to `client-trust` and `local-ipc`.
- **Authorization registration:** `[Authorize]`, `[AllowAnonymous]`, `RequireAuthorization`, `FallbackPolicy`, `UseAuthentication`, `UseAuthorization`. Compare with the route list.

## Sinks by domain

| Domain | Dangerous API or pattern | Safer alternative | Notes |
|---|---|---|---|
| `injection` | `SqlCommand` with concatenated or interpolated text, `FromSqlRaw($"...")`, `ExecuteSqlRaw($"...")`, Dapper with built strings | `SqlParameter`, `FromSql($"...")` and `FromSqlInterpolated` (EF Core 7+ `FromSql` binds interpolation), Dapper parameters | Identifiers cannot be parameters. |
| `injection` | `Process.Start(string)`, `ProcessStartInfo.Arguments` built from input, `cmd.exe /c` | `ProcessStartInfo.ArgumentList` (.NET Core 2.1+), fixed file name | `UseShellExecute` defaults to true on .NET Framework and false on .NET Core and later. |
| `injection` | `CSharpScript.EvaluateAsync`, `DataTable.Compute`, `DataColumn.Expression`, `DataView.RowFilter`, System.Linq.Dynamic.Core `Where(string)` | Typed lambdas | String expressions reach methods and properties. |
| `injection` | `Html.Raw`, `new HtmlString(x)`, Blazor `MarkupString`, `Content(x, "text/html")` | Razor default encoding | |
| `injection` | `DirectorySearcher.Filter` concatenation, `XPathNavigator.Select` concatenation, `new Regex(userInput)` | Escape filter values, `Regex.Escape`, `matchTimeout` | |
| `input-parsing` | `BinaryFormatter`, `SoapFormatter`, `NetDataContractSerializer`, `LosFormatter`, `ObjectStateFormatter`, `JavaScriptSerializer` with a type resolver | `System.Text.Json` with fixed types | See the deserialisation section. |
| `input-parsing` | `XmlTextReader` (DTD parsing on by default), `XmlDocument` with a resolver, `XslCompiledTransform` with `EnableScript` | `XmlReaderSettings` with `DtdProcessing.Prohibit`, `XmlResolver = null` | `XmlReader.Create` prohibits DTDs by default. |
| `input-parsing` | `Path.Combine(base, input)`, `ZipArchiveEntry.ExtractToFile(path)`, `IFormFile.FileName` | `Path.GetFullPath`, then check the prefix with a trailing separator | `Path.Combine` drops `base` when `input` is rooted. |
| `filesystem-process` | `File.Exists` then open, `Path.GetTempPath()` plus a guessed name, `File.SetUnixFileMode` after create | `FileMode.CreateNew`, `FileStreamOptions.UnixCreateMode` (.NET 7+), `Directory.CreateDirectory(path, UnixFileMode)` | Check `FileInfo.LinkTarget` (.NET 6+) for links. |
| `filesystem-process` | `Assembly.LoadFrom`, `Assembly.LoadFile`, `NativeLibrary.Load`, `DllImport` without search paths | `DefaultDllImportSearchPaths`, absolute paths | DLL search order on Windows. |
| `outbound-network` | `HttpClient` with a URL from input, `new Uri(base, input)`, `AllowAutoRedirect` default true | Allow-list host, resolve once, `AllowAutoRedirect = false` | An absolute `input` replaces `base`. |
| `outbound-network` | `ServerCertificateCustomValidationCallback` returning true, `DangerousAcceptAnyServerCertificateValidator`, `ServicePointManager.ServerCertificateValidationCallback`, `RemoteCertificateValidationCallback` returning true, ignored `X509Chain.Build` result | Default validation, pinned thumbprint check that also checks the chain | On Linux and macOS, `HttpClient` reads `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY`. |
| `crypto` | `MD5`, `SHA1`, `DES`, `TripleDES`, `RC2`, ECB or CBC without MAC, `System.Random`, `Random.Shared`, `Guid.NewGuid()` for secrets, `Rfc2898DeriveBytes` constructors | `AesGcm`, `RandomNumberGenerator`, `Rfc2898DeriveBytes.Pbkdf2` (.NET 6+) | `Aes.Create()` defaults to CBC. |
| `crypto` | `==`, `SequenceEqual`, `string.Equals` on MACs or tokens | `CryptographicOperations.FixedTimeEquals` | |
| `authn` | `TokenValidationParameters` with `ValidateIssuer`, `ValidateAudience`, `ValidateLifetime`, `ValidateIssuerSigningKey` false, `RequireSignedTokens = false`, custom `SignatureValidator`, `ReadJwtToken` without `ValidateToken`; `PasswordSignInAsync` with `lockoutOnFailure: false` | Validate all four, `lockoutOnFailure: true` | `ClockSkew` defaults to 5 minutes. |
| `authz` | `[AllowAnonymous]` on a route inside a protected group, missing `FallbackPolicy`, `[Authorize(Roles = "A,B")]` | `RequireAuthorization()` on groups, fallback policy that requires a user | A comma list in `Roles` means OR. Stacked `[Authorize]` attributes mean AND. |
| `api` | Model binding to an entity, `TryUpdateModelAsync` without include list | DTO, `[Bind]`, `[BindNever]` | Overposting. |
| `web-client` | `AddCors` with `SetIsOriginAllowed(_ => true).AllowCredentials()`, `Redirect(url)`, `[IgnoreAntiforgeryToken]` | `LocalRedirect`, `Url.IsLocalUrl`, antiforgery on every cookie-based mutation | `AllowAnyOrigin` with credentials throws. The callback form is the bypass. MVC controllers do not validate antiforgery tokens unless you add the filter. Razor Pages do. |
| `http-protocol` | `UseForwardedHeaders` with cleared `KnownProxies` and `KnownNetworks`, `AllowedHosts` of `*` (template default), `Request.Host` in links | Set known proxies and hosts | |
| `messaging` | SignalR `Groups.AddToGroupAsync` with a client-chosen name, `Clients.All` for private data, a hub without `[Authorize]`, token in query string | Server-derived group names | SignalR checks authorization at connect, not per call, unless you add it. |
| `memory-safety` | `unsafe`, `fixed`, `stackalloc`, `Marshal.*`, `Unsafe.*`, `MemoryMarshal`, `DllImport`, `LibraryImport`, `BinaryReader` length then `new byte[len]` | Safe `Span<T>`, bounds-checked reads | Needs `AllowUnsafeBlocks` for `unsafe`. |
| `resource-exhaustion` | `Regex` without timeout, unbounded `Task.Run`, `Stream.CopyTo`, Json.NET deep input | `matchTimeout`, `RegexOptions.NonBacktracking` (.NET 7+), size caps | System.Text.Json `MaxDepth` defaults to 64. Json.NET before 13.0.1 had no default depth limit. Kestrel `MaxRequestBodySize` defaults to about 30 MB. `FormOptions.MultipartBodyLengthLimit` defaults to 128 MB. |
| `secrets-config` | `appsettings*.json`, `web.config` (`customErrors Off`, `compilation debug="true"`, fixed `machineKey`, `trace enabled`), `UseDeveloperExceptionPage` outside Development, Swagger in production | User secrets (development only), environment, key vault | `ASPNETCORE_ENVIRONMENT` defaults to Production. Configuration order: JSON, then environment, then command line. |
| `logging-privacy` | `EnableSensitiveDataLogging()`, logging of models or `Exception.ToString()` to clients, `UseHttpLogging` with extra headers | Redaction, `ProblemDetails` without detail | HTTP logging redacts headers that are not allow-listed. |
| `data-lifecycle` | `IgnoreQueryFilters()`, `IMemoryCache` or output cache keys without tenant, `[ResponseCache]` on private data | Tenant in key, `Vary` on identity | EF global query filters via `HasQueryFilter`. |
| `sandbox` | `AssemblyLoadContext` for plugins, Roslyn scripting, `Assembly.Load(bytes)` for mods, `Type.GetType(name)` | Process isolation | .NET Core has no partial-trust sandbox. Code Access Security is gone. |
| `local-ipc` | WCF `SecurityMode.None`, named pipes without `PipeSecurity`, WebView2 `AddHostObjectToScript`, `Process.Start(url)` with `UseShellExecute` | Authenticated channels, fixed host objects | |
| `client-trust` | Unity `PlayerPrefs` for state, Mirror `[Command(requiresAuthority = false)]`, Netcode `[ServerRpc(RequireOwnership = false)]` | Server validates every action | |
| `financial` | `double` or `float` money, `Math.Round` default (banker's rounding) | `decimal`, explicit `MidpointRounding` | |
| `supply-chain` | `Version="*"`, ranges, `nuget.config` with several sources and no `packageSourceMapping` (NuGet 6.0+), `http` sources, MSBuild `Exec`, pre- and post-build events, `Directory.Build.props` | `packages.lock.json` with `--locked-mode`, source mapping | Analyzers and source generators run at build. |

## Language traps

- **Culture-sensitive strings.** `StartsWith(string)`, `IndexOf(string)` and `Compare` use the current culture. Under ICU they can ignore zero-width characters.
  - Wrong: `path.StartsWith(prefix)`. Right: `path.StartsWith(prefix, StringComparison.Ordinal)`.
- **Case conversion.** `ToLower()` uses the current culture. Use `ToLowerInvariant()` or an ordinal-ignore-case comparison.
- **Unchecked arithmetic.** `int` overflow wraps. `Math.Abs(int.MinValue)` throws. `(int)longValue` truncates.
  - Wrong: `var n = a * b;`. Right: `checked(a * b)`, or set `<CheckForOverflowUnderflow>true</CheckForOverflowUnderflow>`.
- **`Path.Combine` with a rooted second part.**
  - Wrong: `Path.Combine(root, name)`. Right: `var full = Path.GetFullPath(Path.Combine(root, name)); if (!full.StartsWith(rootFull + Path.DirectorySeparatorChar, StringComparison.Ordinal)) throw ...;`
- **Null-conditional fail-open.** Nullable annotations are hints. `?.` yields null.
  - Wrong: `if (user?.Role != "Banned") Allow();` (null user passes). Right: `if (user is null || user.Role == "Banned") Deny();`
- **Enum range.** `(Role)99` is a valid cast. Use `Enum.IsDefined` or a switch with a default deny.
- **Regex `\d`** matches any Unicode digit. Use `[0-9]` or `RegexOptions.ECMAScript`. `$` matches before a final newline.
- **Reference equality.** `==` on `byte[]` compares references. Use `SequenceEqual` (non-secret) or `FixedTimeEquals` (secret).
- **`Uri` quirks.** `new Uri(base, rel)` returns `rel` when it is absolute. On Unix, `Uri.TryCreate("/x", UriKind.RelativeOrAbsolute, ...)` can treat `/x` as an absolute file path.
- **Time.** `DateTime.Now` and `Kind` confuse local and UTC. Use `DateTimeOffset.UtcNow` or `TimeProvider` (.NET 8).
- **Async.** `async void` exceptions end the process. Unobserved task exceptions vanish. Fire-and-forget work loses the request scope.
- **Deferred queries.** `IEnumerable` runs later. A scope or `DbContext` can be gone, or a filter can run after `AsEnumerable()` in memory.

## Deserialisation and reflection

- **Binary and type-carrying formats.** `BinaryFormatter`, `SoapFormatter`, `NetDataContractSerializer`, `LosFormatter`, `ObjectStateFormatter` (ViewState). `BinaryFormatter` is obsolete (SYSLIB0011) and throws by default from .NET 9. On .NET 5 to 8 the switch `EnableUnsafeBinaryFormatterSerialization` re-enables it. Any such switch is a lead.
- **Type names from data.** Json.NET `TypeNameHandling` other than `None` (also `Auto`, `All`, `Objects`, `Arrays`) without an allow-listing `ISerializationBinder`. `DataContractSerializer` or `XmlSerializer` with a type taken from input. `JavaScriptSerializer` with `SimpleTypeResolver`. `System.Text.Json` does not read type names unless you use `[JsonDerivedType]` (.NET 7+) with fixed derived types.
- **ViewState.** On .NET Framework, `enableViewStateMac="false"` or a known `machineKey` lets an attacker forge ViewState.
- **Reflection with input.** `Type.GetType(name)`, `Activator.CreateInstance`, `Assembly.Load*`, `MethodInfo.Invoke`, `Expression.Compile`, `dynamic`, `CSharpScript`, `Reflection.Emit`, plugin folders loaded with `AssemblyLoadContext.LoadFromAssemblyPath`.
- **Unity.** Save files read with `BinaryFormatter`, mod DLLs loaded with `Assembly.Load`. `JsonUtility` reads fixed fields only.
- **Code analysis rules.** CA2300 to CA2362 cover insecure deserialisers. See Tools.

## Concurrency

- **Locks and async.** You cannot `await` inside `lock`. Use `SemaphoreSlim`. A forgotten release deadlocks.
- **Shared state.** `static` mutable fields in controllers or services. `ConcurrentDictionary.GetOrAdd` may run the factory more than once. Check-then-act on `ContainsKey` races.
- **DI lifetimes.** A singleton that holds a scoped service keeps one user's data for all users. `ValidateScopes` is on by default only in the Development environment. A `DbContext` is not thread-safe.
- **Context flow.** `HttpContext` is not thread-safe. Do not store it in a field. `AsyncLocal<T>` flows into child tasks, including detached work.
- **Blazor Server.** Scoped services live per circuit. Static state is shared by all users.
- **Cancellation.** `RequestAborted` can cancel an operation half way. Wrap multi-step state changes in a transaction. `Task.WhenAll` can leave some tasks done.
- **Database races.** Use `[ConcurrencyCheck]` or a row version and handle `DbUpdateConcurrencyException`. Use a unique index for check-then-insert.
- **Unity.** Unity APIs run on the main thread. Coroutines resume later and may see removed objects.

## Build and runtime settings

- **Project file.** `<Nullable>`, `<TreatWarningsAsErrors>`, `<AnalysisLevel>`, `<AnalysisMode>`, `<EnableNETAnalyzers>`, `<CheckForOverflowUnderflow>`, `<AllowUnsafeBlocks>`, `<EnableUnsafeBinaryFormatterSerialization>`, `<InvariantGlobalization>`, `<RestorePackagesWithLockFile>`.
- **Analyzer severity.** `.editorconfig` entries `dotnet_diagnostic.CAxxxx.severity = none` hide rules. Search for them.
- **ASP.NET Core.** `ASPNETCORE_ENVIRONMENT`, `ASPNETCORE_URLS` (`http://*:` or `0.0.0.0` binds all interfaces), `AllowedHosts: "*"`, `UseHsts` only outside Development, `UseHttpsRedirection`, Kestrel `AddServerHeader`, `AddDatabaseDeveloperPageExceptionFilter`, auth cookie `SecurePolicy` default `SameAsRequest`, antiforgery and CORS order in the pipeline, `UseAuthentication` before `UseAuthorization`.
- **.NET Framework.** `web.config` `<authentication><forms requireSSL="false">`, `<httpCookies httpOnlyCookies>`, `<compilation debug="true">`, `<customErrors mode="Off">`, `<machineKey>`, `<trace enabled="true">`. `ServicePointManager.SecurityProtocol` forced to old TLS versions.
- **Unity.** Development builds, script debugging and `Application.logMessageReceived` output to files.

## Tools

Run only tools that are installed. This section agrees with `phase-leads.md` section 2.1: the multi-language row (Semgrep with local rules, `--metrics=off`) applies. The other tools are extra.

| Tool | Offline-safe command | Notes |
|---|---|---|
| Roslyn analyzers (built in) | `dotnet build --no-restore -p:AnalysisMode=All -p:EnableNETAnalyzers=true -v:minimal` | Needs packages in the local cache. `AnalysisMode=All` is noisy; group by rule. Security rules: CA2300 to CA2362 (deserialisers), CA3001 (SQL), CA3006 (process), CA3075 (DTD), CA5350 and CA5351 (weak crypto), CA5359 (certificate validation off). The taint rules CA3001 to CA3012 are off by default. Enable them in `.editorconfig`. |
| `dotnet format` | `dotnet format analyzers --verify-no-changes --no-restore` | Reports; does not need to write. |
| Security Code Scan | Analyzer package, if already in the lockfile | Third-party. Do not install. |
| Semgrep | `semgrep --config ./local-rules --metrics=off src` | Never `--config auto`. |
| Package list | `dotnet list package` and the lockfile | `--vulnerable` needs the network. |
| Test runner | `dotnet test --no-restore --filter "FullyQualifiedName~Name"` | Test code is target code. See `execution.md`. |
| SharpFuzz | Harness in a test project | Only if already a dependency. |

## Lead searches

| Regex | Meaning | False-hit notes |
|---|---|---|
| `BinaryFormatter\|SoapFormatter\|NetDataContractSerializer\|LosFormatter\|ObjectStateFormatter\|TypeNameHandling\|SimpleTypeResolver` | Type-carrying deserialisation | `TypeNameHandling.None` is safe. |
| `FromSqlRaw\|ExecuteSqlRaw\|new SqlCommand\|CommandText\s*=\|\.Query<.*\$"` | SQL built from strings | Constant text is fine. |
| `Process\.Start\|ProcessStartInfo\|UseShellExecute\s*=\s*true\|cmd(\.exe)?\s+/c` | Process start | `ArgumentList` with fixed program is fine. |
| `Html\.Raw\|MarkupString\|HtmlString\|Content\(.*text/html` | Raw HTML output | Check the source of the value. |
| `CSharpScript\|DataTable\.Compute\|\.Expression\s*=\|RowFilter\|Dynamic\.Core\|Type\.GetType\|Activator\.CreateInstance\|Assembly\.Load` | Dynamic code and reflection | Constant type names are fine. |
| `ServerCertificateCustomValidationCallback\|DangerousAcceptAnyServerCertificateValidator\|ServerCertificateValidationCallback\|RemoteCertificateValidationCallback` | TLS validation | Check that the delegate does not return true for all. |
| `Validate(Issuer\|Audience\|Lifetime\|IssuerSigningKey)\s*=\s*false\|RequireSignedTokens\s*=\s*false\|ReadJwtToken\|ReadToken` | Token checks weakened | `ReadJwtToken` for display after validation is fine. |
| `AllowAnonymous\|IgnoreAntiforgeryToken\|AuthorizationLevel\.Anonymous\|SetIsOriginAllowed\|AllowAnyOrigin\|FallbackPolicy` | Authorization and CORS map | Compare with the route list. |
| `Path\.Combine\|ZipArchiveEntry\|ExtractToFile\|\.FileName\b` | Path escape | A full-path prefix check nearby makes it safe. |
| `new Random\(\|Random\.Shared\|Guid\.NewGuid\|MD5\|SHA1\|TripleDES\|DES\b\|ECB` | Weak crypto or randomness | Non-security use is fine. |
| `unsafe\b\|stackalloc\|Marshal\.\|DllImport\|LibraryImport\|Unsafe\.` | Memory-safety edge | |
| `EnableSensitiveDataLogging\|UseDeveloperExceptionPage\|UseSwagger\|AllowedHosts\|customErrors\|machineKey\|KnownProxies` | Config exposure | Check the environment guard. |
| `#pragma warning disable\|SuppressMessage\|dotnet_diagnostic\.\w+\.severity\s*=\s*none` | Silenced analyser | Strong lead. |
| `async void\|static .* Dictionary<\|\.Result\b\|GetAwaiter\(\)\.GetResult` | Async and shared-state traps | |

## Verification notes

- **Smallest harness.** An xUnit test that calls the method or controller action with hostile input. For routes and filters, use `WebApplicationFactory<Program>` (package `Microsoft.AspNetCore.Mvc.Testing`). It runs in memory and opens no network port. It also runs the application's start-up code and hosted services. Treat that as target code.
- **Authorization.** Add a test authentication handler with two dummy principals. Call the route as A on B's resource. Expect deny.
- **SQL.** Use SQLite in-memory (`Data Source=:memory:`) or the EF Core SQLite provider. Assert that a canary row is unchanged. Note that dialect differences can change the result.
- **Deserialisation.** Use a canary type with a static flag set in a constructor or setter. Assert it is not created. Do not build a gadget chain.
- **Path checks.** Test with a rooted name, `..` segments, mixed separators, and on Windows reserved names and alternate data streams.
- **False positives.** A fallback policy or a group-level `RequireAuthorization` that covers the route. `FromSqlRaw` with constant text. `[AllowAnonymous]` on login and health routes. A resolver or binder that allow-lists types. Warnings in generated code.
- **Needs E3.** Races, culture-dependent string behaviour (it depends on ICU or NLS and the invariant-globalization setting), middleware order effects, and any claim about default behaviour that changes between .NET versions.
