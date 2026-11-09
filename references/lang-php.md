# Language: PHP

## Scope

- Covers: PHP 7.4 to 8.4. Version-dependent behaviour carries the version. PHP-FPM, Apache `mod_php`, CLI, and long-running runtimes (Swoole, OpenSwoole, RoadRunner, FrankenPHP worker mode, Laravel Octane).
- Common frameworks: plain PHP scripts, Laravel, Symfony (with Doctrine and Twig), WordPress plugins and themes.
- In plain PHP, every `.php` file under the web root is an entry point, unless the server sends all requests to a front controller.

## Entry points

- **Superglobals.** `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, `$_FILES`, `$_SERVER`, `$_ENV`, `$GLOBALS`. In `$_SERVER`, the client controls `HTTP_*`, `REQUEST_URI`, `QUERY_STRING`, `PATH_INFO`, `PHP_SELF`, `HTTP_HOST`. Other sources: `php://input`, `getallheaders()`, `$argv`, `STDIN`, `file_get_contents($url)`.
- **Plain PHP.** List every `.php` file in the document root. Check which ones the server really exposes. A file with only functions and classes still runs its top-level code when someone requests it. Look for `include`, `require` and autoloaders that user values reach.
- **Laravel.** Routes: `routes/web.php`, `routes/api.php`, `routes/channels.php`, `routes/console.php`. Patterns: `Route::get(`, `post(`, `put(`, `patch(`, `delete(`, `match(`, `any(`, `resource(`, `apiResource(`, `group(`, `->middleware(`, `->withoutMiddleware(`. Input: `$request->input(`, `->all()`, `->query(`, `->only(`, `->validated()`, `->file(`, `->header(`. Other entries: Artisan commands (`handle`), queue jobs (`ShouldQueue`), event listeners, Livewire components (public properties are client-writable and public methods are callable), broadcast channels.
- **Symfony.** Attributes `#[Route(` and annotations `@Route(`; `config/routes.yaml`; controllers that extend `AbstractController`; `#[IsGranted(`; `security.yaml` `access_control`; `Request $request` arguments; `#[MapRequestPayload]` (6.3+); console commands (`execute`); Messenger handlers (`#[AsMessageHandler]`).
- **WordPress.** `add_action('wp_ajax_...')` (logged-in users) and `add_action('wp_ajax_nopriv_...')` (everyone); `admin_post_` and `admin_post_nopriv_`; `register_rest_route(` with its `permission_callback`; `add_shortcode(`; hooks on `init`, `admin_init`, `template_redirect`, `parse_request`; direct requests to plugin files (guard: `defined('ABSPATH') || exit;`). `admin_init` also runs for unauthenticated `admin-ajax.php` requests, so it is not an authorization point.
- **Exported code.** Public methods of a library; `__invoke`, `__call` and `__get` magic methods that route input to code.

## Sinks by domain

| Domain | Dangerous API or pattern | Safer alternative | Notes |
|---|---|---|---|
| injection | `mysqli_query`, `PDO::query`, `exec` with concatenated SQL; Laravel `DB::raw`, `whereRaw`, `selectRaw`, `orderByRaw`, `havingRaw`, `DB::unprepared`; Doctrine `createQuery` or `createNativeQuery` with concatenation; `$wpdb->query` without `prepare` | Prepared statements; bindings; `$wpdb->prepare`; query builder | Column, table and `ORDER BY` names cannot be bound. Check `orderBy($request->sort)`. |
| injection | `system`, `exec`, `shell_exec`, `passthru`, `popen`, `proc_open` (string form), backticks; Symfony `Process::fromShellCommandline` | `proc_open` with an array (7.4+); Symfony `new Process([...])`; `escapeshellarg` | `escapeshellcmd` does not stop argument injection. Add `--`. |
| injection | `echo $_GET[...]`; Blade `{!! !!}`; Twig `\|raw`, `autoescape false`, `createTemplate($user)`; `Blade::render($user)`; WordPress output without `esc_html`, `esc_attr`, `esc_url`, `esc_js`, `wp_kses_post` | Blade `{{ }}`; Twig autoescape; `htmlspecialchars($s, ENT_QUOTES, 'UTF-8')` | `htmlspecialchars` escapes single quotes by default only from PHP 8.1. Before that, pass `ENT_QUOTES`. `esc_attr` is for attribute context only. |
| injection | `mail($to, $subject, $msg, $headers)` with input in headers or the fifth argument | A mail library; strip CR and LF | `header()` refuses more than one header per call. |
| input-parsing | `unserialize`, `simplexml_load_string`, `DOMDocument::loadXML` with `LIBXML_NOENT` or `LIBXML_DTDLOAD`, `yaml_parse`, `parse_str`, `extract`, `$$var` | `json_decode`; no entity flags; `parse_str` with a result array | `extract($_POST)` overwrites local variables. |
| input-parsing | `include`/`require` with a user value; `file_get_contents`, `fopen`, `readfile`, `file_put_contents` with a user path; `basename` misuse; `$_FILES['f']['name']` and `['type']` | Allow-list of names; `realpath` then prefix check on a trailing separator; generated file names; `finfo` for the type | Name and type are client-controlled. Extensions `.php`, `.phtml`, `.phar` and a `.htaccess` upload can run code on some servers. |
| input-parsing | Stream wrappers: `php://filter`, `data://`, `phar://`, `file://`, `expect://` | Reject `://` in paths | `phar://` triggered unserialisation of metadata before PHP 8.0. |
| filesystem-process | `tempnam` in shared directories, `mkdir($d, 0777)`, `chmod(..., 0777)`, `umask(0)`, `file_exists` then `fopen`, `symlink` | `tempnam` then open at once; `0700`/`0600`; `fopen($p, 'x')` | `open_basedir` limits paths but does not stop races. |
| outbound-network | `file_get_contents($url)`, `curl_exec`, `fopen($url)`, Guzzle, Symfony HttpClient with a user URL; `CURLOPT_SSL_VERIFYPEER => false`; Guzzle `verify => false`; stream context `verify_peer => false` | Host allow-list; check the address after DNS; Symfony `NoPrivateNetworkHttpClient`; WordPress `wp_safe_remote_get`, `wp_http_validate_url` | `CURLOPT_FOLLOWLOCATION` and Guzzle `allow_redirects` follow redirects. Limit protocols with `CURLOPT_PROTOCOLS`. `allow_url_fopen` is on by default. |
| api | `Model::create($request->all())`, `fill($request->all())`, `$guarded = []`, `Model::unguard()`, `forceFill`; Symfony serializer `denormalize` without groups; WordPress `update_option($_POST[...])` | `$fillable`, `$request->validated()`, DTOs, serializer groups | Livewire public properties accept client values unless `#[Locked]`. |
| web-client | `header("Location: " . $_GET['u'])`, `wp_redirect($user)`, Laravel `redirect($request->next)`, CSRF exceptions, `Access-Control-Allow-Origin` set from `Origin` | `wp_safe_redirect`; allow-list; Symfony `UrlHelper` checks | Laravel 11: `validateCsrfTokens(except: [...])`; before: `VerifyCsrfToken::$except`. WordPress nonces prove intent, not capability. |
| authn | `==` on tokens, `md5` or `sha1` passwords, `session_start` without `session_regenerate_id(true)` after login, `session.use_strict_mode` off | `password_hash`, `password_verify`, `hash_equals($known, $user)` | `password_needs_rehash` for upgrades. |
| authz | `Model::find($request->id)` with no owner scope; routes without `can:` or policy; `access_control` gaps; WordPress `wp_ajax_*` without `current_user_can`; `register_rest_route` with `permission_callback => '__return_true'` or none | `Gate::authorize`, policies, scoped relations (`$user->posts()->findOrFail`), `#[IsGranted]` | Nonce checks are not authorization. Symfony `access_control` is a regex, first match wins. |
| crypto | `rand`, `mt_rand`, `uniqid`, `md5`, `sha1`, `crypt`, `openssl_encrypt` with ECB or fixed IV, `openssl_decrypt` with no MAC, `==` for MACs | `random_bytes`, `random_int`, `sodium_*`, `hash_hmac` with `hash_equals`, AEAD | `mcrypt` is removed since 7.2. |
| messaging | Webhook route with no signature check, or `==` on the signature | `hash_hmac('sha256', $rawBody, $key)` and `hash_equals`; `file_get_contents('php://input')` | Verify the raw body, not decoded input. |
| concurrency | Check-then-act on rows or files; `firstOrCreate` without a unique index; long-running worker with static state | `DB::transaction` with `lockForUpdate()`, `Cache::lock`, unique keys, `flock` | See "Concurrency". |
| resource-exhaustion | `preg_*` with nested quantifiers; unbounded `file_get_contents`; `max_input_vars`; user-set `LIMIT`; `unserialize` of large data; `set_time_limit(0)` | Size caps; `pcre.backtrack_limit`; pagination caps | A failed `preg_match` returns `false`. |
| secrets-config | `.env` or `wp-config.php` in the web root or in a backup file; `APP_DEBUG=true`; `APP_KEY` committed; default WordPress salts | Keep config outside the document root | See "Build and runtime settings". |
| logging-privacy | `error_log(print_r($_POST, true))`, `Log::info($request->all())`, `display_errors` on, Laravel debug pages | Log named fields; `display_errors=0` | Debug pages show environment values. |
| data-lifecycle | Cache keys with no tenant; `Storage` public disk; `storage:link`; soft deletes with global scopes bypassed (`withTrashed`) | Tenant in key; private disk plus signed URLs | |
| supply-chain | `composer.json` scripts (`post-install-cmd`, `post-update-cmd`); VCS repositories; unpinned versions; plugin updates from custom servers | `composer.lock` with hashes; `composer install --no-scripts` | WordPress plugin update servers are a supply-chain channel. |
| sandbox | `eval`, `assert($string)` (PHP before 8), `create_function` (removed in 8.0), Twig sandbox off, Smarty `{php}` | No dynamic code; Twig `SandboxExtension` | |
| ai-llm | `eval` of model output; `unserialize` of cached model data; tools that call `exec` | Validate structured output | |
| financial | `float` for money; `round()`; `intval` of a price string | Integer minor units; `bcmath` or a money library | `bcadd` takes strings. |
| abuse | Rate limits keyed on `REMOTE_ADDR` behind a proxy; Laravel `throttle` on some routes only | Per-account limits; trusted proxies set | |
| http-protocol | `$_SERVER['HTTP_HOST']` in URLs and emails; Laravel `TrustProxies` with `'*'`; Symfony `trusted_proxies` missing | Fixed app URL (`APP_URL`); trusted proxy list | Host header poisoning in reset links is a classic. |
| local-ipc, memory-safety | PHP extensions, `FFI::cdef`, `ffi.enable`; sockets | Review the native side | The default `ffi.enable=preload` limits FFI to the CLI and preloaded code. |
| business-logic, federation, client-trust, embedded, kernel, cloud-deploy, smart-contracts | Not specific to PHP | Use the domain file | |

## Language traps

- **Loose comparison.** `==` converts strings that look like numbers. `"0e123" == "0e456"` is true, because both are the number 0. `"1e3" == "1000"` is true. With `md5` output that begins `0e` and digits, two hashes compare equal. Before PHP 8.0, `0 == "abc"` is true. PHP 8.0 and later compare a number with a non-numeric string as strings, so it is false.
  - Wrong: `if (md5($a) == md5($b))` or `if ($token == $_GET['t'])`.
  - Right: `hash_equals($known, $user)`, or `===` for non-secret values.
- **`in_array` and `array_search`.** They compare loosely unless the third argument is `true`. `switch` and `match`: `switch` is loose; `match` is strict.
  - Right: `in_array($x, $list, true)`.
- **Arrays from input.** `?a[]=1` makes `$_GET['a']` an array. PHP 8 throws `TypeError` for arrays passed to string functions. PHP 7 emitted a warning and went on, and `strcmp([], "x")` returned `null`, which `== 0` accepts.
  - Right: `if (!is_string($_GET['a'] ?? null)) { reject(); }`.
- **`strpos` returns 0.** `if (strpos($path, "admin"))` is false at position 0.
  - Right: `str_contains` (8.0+) or `!== false`.
- **`empty` and `isset`.** `empty("0")` is true. `isset($x)` is false for `null`.
- **Numeric strings.** `is_numeric(" 1")` is true; trailing whitespace is also numeric from PHP 8.0. `"1e5"` is numeric. `intval("12abc")` is `12`. Integer overflow converts to `float`. `json_decode` of a big integer gives a `float` unless `JSON_BIGINT_AS_STRING` is set.
- **Regex errors.** `preg_match` returns `false` on error (for example backtrack limit). `if (preg_match($bad, $in)) { reject }` then lets the input through.
  - Right: compare the result with `=== 1` and `=== 0` and treat `false` as reject. In a pattern, `$` also matches before a final newline. Use the `D` modifier or `\z`.
- **Bytes and Unicode.** `strlen`, `substr`, `strtolower` and `strtoupper` work on bytes. A multi-byte character can be cut. Use `mb_*` with an explicit `'UTF-8'`. `strtolower` followed locale rules before PHP 8.2. Validate after normalisation (`Normalizer::normalize`, `intl`), and check `mb_check_encoding`.
- **Validation functions.** `filter_var($u, FILTER_VALIDATE_URL)` accepts `javascript://x%0aalert(1)` and other schemes. It checks syntax, not safety. `parse_url` and `curl` can disagree on the host. `FILTER_VALIDATE_EMAIL` accepts some odd forms.
- **Magic quotes in WordPress.** WordPress adds slashes to `$_GET`, `$_POST`, `$_COOKIE` and `$_SERVER`. Use `wp_unslash()` before sanitising. `sanitize_text_field` is not SQL or attribute escaping.
- **Variable variables.** `$$name`, `extract`, and `parse_str($s)` (no result array, removed in 8.0) overwrite variables.
- **`declare(strict_types=1)`.** It applies per file, to calls made from that file only. Without it, PHP coerces scalar types, for example the string `"5"` to the integer 5.
- **Path functions.** `realpath` returns `false` for a missing path. `basename` returns only the last path part. It cannot protect a path built from several parts. Null bytes in paths raise an error from PHP 8.

## Deserialisation and reflection

- **`unserialize`.** It creates objects and calls magic methods (`__wakeup`, `__unserialize`, `__destruct`, `__toString`, `__call`). Any class loaded by the autoloader is a possible gadget. Use `unserialize($s, ['allowed_classes' => false])` (PHP 7.0+) or a short list. `unserialize_max_depth` (7.4+) limits depth. Prefer `json_decode`.
- **Where `unserialize` hides.** Cookies, cache and queue payloads, session data, database columns, `maybe_unserialize` and `get_option` in WordPress (stored options are unserialised), `Phar` metadata (`phar://` on PHP before 8.0), Laravel `decrypt()` and `Crypt::decrypt` (they unserialise by default; a leaked `APP_KEY` becomes object injection; `decryptString` does not unserialise).
- **Sessions.** A mismatch of `session.serialize_handler` (`php`, `php_serialize`) between code paths can corrupt session data.
- **YAML.** Symfony `Yaml::parse` with `Yaml::PARSE_OBJECT` builds objects. The `yaml` extension with `yaml.decode_php` enabled decodes PHP objects from tags.
- **Code from strings.** `eval`, `assert($string)` (PHP before 8.0), `create_function` (removed in 8.0), `preg_replace` with the `/e` modifier (removed in 7.0), `include` of uploaded or generated files, `call_user_func($user)`, `$f = $_GET['f']; $f()`, `array_map($user, ...)`, `usort($a, $user)`.
- **Reflection.** `new $class`, `$obj->$method()`, `ReflectionClass`, `ReflectionMethod::invoke`, `class_exists($user)` (it runs the autoloader), `$$name`. A user-chosen class or method name selects code. Allow-list the names.
- **Templates.** Twig `createTemplate`, `template_from_string`, and `Blade::render` with user text are template injection.

## Concurrency

- **Per-request model.** PHP-FPM and `mod_php` share nothing between requests. Races come from the database, the filesystem, the cache and the session.
- **Check-then-act.** Two requests can pass the same check.
  - Wrong: `if ($wallet->balance >= $cost) { $wallet->balance -= $cost; $wallet->save(); }`.
  - Right: `DB::transaction` with `lockForUpdate()`, or one statement (`UPDATE ... WHERE balance >= ?`), or `increment`/`decrement`.
- **Laravel tools.** `lockForUpdate()`, `sharedLock()`, `Cache::lock`, `Cache::add`, `RateLimiter`, `ShouldBeUnique` jobs. `firstOrCreate` and `updateOrCreate` are racy without a unique index. Jobs can run twice (`$tries`, retries): check idempotency.
- **Session locking.** The default file session handler locks the session until `session_write_close()`. A second request with the same session waits. Other handlers may not lock, which allows lost updates and double use.
- **Long-running runtimes.** In Swoole, RoadRunner, FrankenPHP worker mode and Octane, `static` properties, singletons and globals live across requests. Request or user data kept in them leaks to the next request. Octane's own guidance warns about this.
- **Files.** `flock` is advisory. `file_exists` then `fopen` is a race.
- **Shutdown.** `ignore_user_abort`, `register_shutdown_function` and `set_time_limit` change what runs after the client leaves. A half-finished operation can stay.
- **Threads.** The `parallel` and `pcntl` extensions are rare. Review them as shared-state code.

## Build and runtime settings

- **php.ini.**
  - `display_errors` (on in php.ini-development); `log_errors`; `expose_php`.
  - `allow_url_fopen` (default on); `allow_url_include` (default off); `open_basedir`; `disable_functions`.
  - `session.use_strict_mode` (default 0, so session fixation is easier); `session.cookie_httponly`; `session.cookie_secure`; `session.cookie_samesite`; `session.use_only_cookies`; `session.use_trans_sid`.
  - `upload_max_filesize`; `post_max_size`; `max_input_vars` (default 1000); `max_execution_time`; `memory_limit`; `pcre.backtrack_limit`.
  - `zend.assertions` (set `-1` in production); `unserialize_max_depth`; `auto_prepend_file`; `cgi.fix_pathinfo`; `.user.ini` (per-directory overrides, if `user_ini.filename` is set).
- **Laravel.** `APP_DEBUG=true` and `APP_ENV` (debug pages show environment values and source); `APP_KEY` (signs and encrypts cookies and sessions); `SESSION_SECURE_COOKIE`; `SESSION_SAME_SITE`; `config/cors.php` (`allowed_origins`, `supports_credentials`); `TrustProxies` (`'*'`); the web root must be `public/`; `.env` must not be reachable.
- **Symfony.** `APP_ENV=dev` and `APP_DEBUG` in production; `/_profiler` and `/_wdt` reachable; `APP_SECRET`; `framework.trusted_proxies` and `trusted_headers`; `framework.http_method_override`; `security.yaml` `access_control` order; `password_hashers`.
- **WordPress.** `WP_DEBUG`, `WP_DEBUG_DISPLAY`, `WP_DEBUG_LOG` (a public `debug.log`); `DISALLOW_FILE_EDIT`, `DISALLOW_FILE_MODS`; salts and keys left at the sample text; `xmlrpc.php` enabled; REST user listing (`/wp-json/wp/v2/users`); backups of `wp-config.php` in the web root.
- **Web server.** Uploads directories that run PHP; `.htaccess` overrides (`AllowOverride`). Hand off to `http-protocol`.

## Tools

Use only installed tools. Do not install. `phase-leads.md` section 2.1 has no PHP row; the tools below are extra and used if present. Record each one as section 2.1 requires. Binaries in the target's `vendor/bin` are target code, and PHPStan and Psalm load the project's autoloader and bootstrap files: run them only at the isolation level the user chose ([execution.md](execution.md) section 1). `php -l` and an installed `phpcs` with your own standard are T1.

| Tool | Command | Notes |
|---|---|---|
| `php -l` | `php -l FILE` | Syntax check. Does not run the file. |
| `phpstan` | `vendor/bin/phpstan analyse --no-progress SRC` | Type and logic errors. Set a rule level. |
| `psalm` | `vendor/bin/psalm --taint-analysis --no-cache` | Taint analysis traces input to sinks. |
| `phpcs` | `vendor/bin/phpcs --standard=WordPress SRC` | The WordPress standard has `WordPress.Security.*` sniffs (escaping, nonces, input). |
| `semgrep` | `semgrep --config LOCAL_RULES_DIR --metrics=off --disable-version-check SRC` | Local rules only. Never `--config auto`. |
| `composer audit` | Needs the advisory service. | Do not run without permission. Read `composer.lock` and list versions as leads. |
| Route listing | `php artisan route:list --json`; `php bin/console debug:router` | These boot the application and run target code. Use an approved isolation level. |
| Tests | `vendor/bin/phpunit --filter NAME` | Runs target code. See `execution.md`. |
| Fuzzing | `php-fuzzer` (if present) | For parsers. |

## Lead searches

| Regex | Meaning | False-hit notes |
|---|---|---|
| `\bunserialize\(\|maybe_unserialize\(\|decrypt\(` | Object injection | Safe with `allowed_classes => false` and a trusted source. `decrypt(` is only a lead in Laravel. |
| `\b(eval\|assert\|create_function\|call_user_func(_array)?\|extract)\(` | Dynamic code or variable overwrite | Constant arguments are safe. |
| `\b(system\|exec\|shell_exec\|passthru\|popen\|proc_open)\(` | Process creation (also search for the backtick operator) | Fixed commands are safe. |
| `(mysqli_query\|->query\|->exec)\(\s*["'][^"']*["']\s*\.\|DB::(raw\|unprepared)\|(where\|select\|orderBy\|having)Raw\(` | SQL built from text | Prepared statements use `?` or named bindings. |
| `\$wpdb->(query\|get_results\|get_var\|get_row)\(\s*["'$]` | WordPress SQL call whose argument is not `prepare(` | Constant SQL is safe. |
| `(include\|require)(_once)?\s*\(?\s*\$` | File inclusion from a variable | Check the source of the variable. |
| `\$_(GET\|POST\|REQUEST\|COOKIE\|SERVER\|FILES)\[` | Raw input | Follow each to a sink. |
| `echo\s+\$_\|\{!!\|\|\s*raw\|autoescape\s+false` | Unescaped output | Escaped by `esc_*` is safe. |
| `in_array\([^,]+,[^,)]+\)\|==\s*\$_(GET\|POST\|REQUEST)\|md5\(.*\)\s*==` | Loose comparison | Safe if both sides are known types. |
| `wp_ajax_nopriv_\|admin_post_nopriv_\|__return_true\|register_rest_route` | WordPress public entry | Check `permission_callback` and `current_user_can`. |
| `check_ajax_referer\|wp_verify_nonce\|check_admin_referer` | Nonce check | A nonce does not give authorization. |
| `\$guarded\s*=\s*\[\s*\]\|::unguard\(\|->all\(\)\)\|forceFill\(` | Mass assignment | `$fillable` or `validated()` stops it. |
| `CURLOPT_SSL_VERIFYPEER\|verify_peer\|'verify'\s*=>\s*false\|CURLOPT_FOLLOWLOCATION` | TLS or redirect setting | Test code only. |
| `file_get_contents\(\s*\$\|curl_setopt\([^,]+,\s*CURLOPT_URL,\s*\$` | URL fetch from variable | Check allow-list. |
| `move_uploaded_file\|\$_FILES\[` | Upload | Check name, type, destination, execution. |
| `\b(rand\|mt_rand\|uniqid\|md5\|sha1)\(` | Weak RNG or hash | Matters near tokens, passwords, reset links. |
| `APP_DEBUG\s*=\s*true\|WP_DEBUG'?,\s*true\|display_errors` | Debug on | Check production config. |
| `header\(\s*["']Location:.*\$\|wp_redirect\(\s*\$\|redirect\(\s*\$request` | Open redirect | An allow-list stops it. |
| `HTTP_HOST\|X-Forwarded-` | Host trust | Check use in links and emails. |
| `@\$\|error_reporting\(0\)\|// ?(TODO\|FIXME).*(auth\|check)` | Silenced error or known gap | Read why. |

## Verification notes

- **Smallest test shape.** One PHPUnit test method with one assertion. Laravel: `$this->actingAs($userA)->getJson('/x')->assertForbidden()` (feature tests with `RefreshDatabase` and SQLite in memory). Symfony: `WebTestCase` and `static::createClient()`. WordPress: `WP_UnitTestCase`, or call the handler function with `$_POST` set and capture `wp_die` through `WPDieException`. Plain PHP: `include` a function file in a test, never the page script.
- **Authorization.** Create a resource for B. As A, request it. Assert 403 or 404 and assert the data is unchanged.
- **Loose comparison.** Call the check with `"0e1"` and `"0e2"` hash-like strings, `0`, `"abc"`, `[]`, `null`. State the PHP version, because PHP 8 changed `0 == "abc"`.
- **`unserialize`.** Define a test class with a `__destruct` that sets a static flag. Pass its serialised form to the code. Assert the flag. Use a harmless flag. Never run a shell command.
- **Mass assignment.** Post a server-owned field (`is_admin`, `role`). Reload the model. Assert it did not change.
- **SQL.** Use SQLite in memory. Pass a value with a quote. Assert the query returns what the safe path returns, and that an extra row does not appear.
- **Regex.** Test the pattern with `"abc\n"`. Test an error case with a long input and a low `pcre.backtrack_limit` set by `ini_set`.
- **False positives.** `$_GET` read after a framework validator; `unserialize` with `allowed_classes => false`; `eval` or `exec` on constants; `rand` for UI; `md5` for cache keys; `echo` of a value escaped by a helper you have read; `wp_ajax_nopriv_` for a public feature with no sensitive effect; nonce checks plus `current_user_can`; Laravel `$request->all()` passed to a model with a `$fillable` list.
- **E3 needed for:** races; behaviour that depends on the PHP version or `php.ini`; gadget chains that depend on installed packages; web-server execution of uploads; WordPress hook order.
- **E1 is often enough for:** a `wp_ajax_nopriv_` or REST route that writes data with no capability check; `$guarded = []` with `->all()`; a SQL string built from `$_GET`; a committed `APP_KEY`. List every layer you read in the waiver.
