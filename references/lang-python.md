# Language: Python

## Scope

- Covers: CPython 3.9 to 3.13 (3.13 free-threaded builds noted where they differ), web services, command-line scripts, workers, data pipelines and machine-learning code.
- Common frameworks: Django (with Django REST framework), Flask, FastAPI (with Starlette and Pydantic), aiohttp, Celery. Libraries: `requests`, `httpx`, `PyYAML`, `Jinja2`, pandas, NumPy, PyTorch.
- Domain files hold the attack logic. This file tells you where input enters, which calls are dangerous, and which language traps break an invariant.

## Entry points

Find every place where attacker data enters. Then give each one a coverage unit.

- **Django.** Routes are in `urls.py`: `path(`, `re_path(`, `include(`, `urlpatterns`. Handlers are functions or `View` subclasses. Django REST framework adds `@api_view`, `APIView`, `ViewSet`, and `router.register(`. Read `MIDDLEWARE` in settings, because it sets the order of checks. Other entries: Channels consumers (`AsyncWebsocketConsumer`, `receive`), `BaseCommand.handle`, signal receivers, admin classes (`ModelAdmin`).
- **Flask.** `@app.route(`, `@bp.route(`, `@app.get(` (Flask 2.0 and later), `app.add_url_rule(`, `register_blueprint(`, `before_request`. Input objects: `request.args`, `.form`, `.json`, `.get_json()`, `.files`, `.headers`, `.cookies`, `.view_args`, `.data`.
- **FastAPI and Starlette.** `@app.get(`, `@router.post(`, `APIRouter(`, `include_router(`, `app.mount(`, `@app.websocket(`. Check `Depends(` and `Security(` on each route and on each router (`dependencies=[...]`). Pydantic models define the body shape.
- **aiohttp.** `web.RouteTableDef`, `@routes.get(`, `app.add_routes(`, `app.router.add_get(`.
- **Workers and consumers.** Celery `@app.task`, `@shared_task`; message libraries (`pika`, `kafka`, `redis` subscribers); `asyncio.start_server`, `socketserver`, `http.server`.
- **Scripts.** `if __name__ == "__main__"`, `sys.argv`, `argparse`, `click`, `typer`, `input(`, `os.environ`, `sys.stdin`, files and paths given as arguments.
- **Data and ML code.** Any loader of a file, URL or model name: `pd.read_*`, `torch.load`, `joblib.load`, `numpy.load`, `from_pretrained(`. Treat the file as input.
- **Exported functions.** A library has no routes. Its public functions and classes (`__all__`, top-level names) are the entry surface.

## Sinks by domain

| Domain | Dangerous API or pattern | Safer alternative | Notes |
|---|---|---|---|
| injection | `cursor.execute(f"...")`, `%` or `.format` in SQL, Django `.raw(`, `.extra(`, `RawSQL(`, SQLAlchemy `text(f"...")` | Parameters: `execute(sql, params)`, ORM filters | Column and table names cannot be parameters. Check `order_by(user_input)`. |
| injection | `Template(user_text)`, `render_template_string(user_text)`, `Environment().from_string(user_text)`, `mark_safe(`, `\|safe`, `Markup(`, `autoescape` off | Fixed templates; autoescape on; `escape()` | `jinja2.Environment()` has autoescape off by default. Flask turns it on for HTML and XML template names only. |
| injection | `str.format(user_text)` on a format string the client controls | `string.Template`; fixed format strings | `"{0.__class__}".format(obj)` reads attributes. F-strings are not open to this. |
| input-parsing | `pickle`, `yaml.load`, `marshal`, `shelve`; `xml.etree`, `xml.dom.minidom`, `xml.sax`; `zipfile`, `tarfile` extraction | `json`; `yaml.safe_load`; `defusedxml`; `tarfile` with `filter="data"` | The standard XML parsers allow entity expansion bombs. See "Deserialisation and reflection". |
| input-parsing | `os.path.join(base, user)`, `open(user_path)`, `send_file(user_path)`, `startswith(base)` | `Path(base, user).resolve().is_relative_to(base_resolved)` (3.9+); `send_from_directory` | `os.path.join("/a", "/etc/x")` returns `/etc/x`. Resolve symlinks before the check, then open the resolved path. |
| filesystem-process | `subprocess.*(shell=True)`, `os.system`, `os.popen`, `tempfile.mktemp`, `os.chmod(0o777)`, `open(path, "w")` on shared paths | Argument lists; `tempfile.mkstemp`, `NamedTemporaryFile`, `mkdtemp`; `open(path, "x")` | Add `--` before user values that could begin with `-`. `PYTHONPATH` and the working directory change what `import` loads. |
| outbound-network | `requests.get(user_url)`, `urllib.request.urlopen`, `httpx`, `aiohttp`; `verify=False`; `ssl._create_unverified_context` | Allow-list of hosts; resolve then check the address; `ssl.create_default_context()` | `urlopen` also accepts `file:` URLs. `requests` has no default timeout and follows redirects. `trust_env` reads proxy variables. |
| api | `Model(**request.data)`, `fields = "__all__"`, `setattr(obj, k, v)` in a loop, `**body.model_dump()` | Explicit serializer or Pydantic model with fixed fields | Pydantic ignores extra fields by default (v1 and v2). A model that has server-owned fields still binds them. |
| web-client | `@csrf_exempt`, `HttpResponseRedirect(request.GET["next"])`, `set_cookie` without flags, `CORS_ALLOW_ALL_ORIGINS` | `url_has_allowed_host_and_scheme` (Django 3.0+) | Server-rendered XSS belongs to `injection`. |
| authn | `jwt.decode(..., options={"verify_signature": False})`, `algorithms` missing, `==` on tokens, `session` in a signed cookie that holds trust | `hmac.compare_digest`; fixed `algorithms=[...]` | Check Flask `session` contents: the cookie is signed, not encrypted. |
| authz | `Model.objects.get(pk=request_value)`, `AllowAny`, empty `permission_classes`, router-level `Depends` missing on one route | `get_queryset` scoped to the principal; `get_object_or_404(qs.filter(owner=user))` | Django REST framework default permission is `AllowAny` unless settings change it. |
| crypto | `random.*`, `hashlib.md5`, `hashlib.sha1`, `AES.MODE_ECB`, `uuid.uuid1`, `==` compare of MACs | `secrets`, `hmac.compare_digest`, `hashlib.scrypt` or a password library, an AEAD cipher | `hashlib.md5(usedforsecurity=False)` (3.9+) marks a non-security use. |
| crypto-protocols | Signing `json.dumps(obj)` output without fixed key order or separators | `sort_keys=True` and fixed separators; sign the exact bytes sent | The verifier must hash the same bytes. |
| messaging | Celery with `accept_content` that includes `pickle`; webhook handler without signature check; consumer that trusts message fields | JSON serializer; `hmac.compare_digest` over the raw body | Read the raw body before the framework parses it. |
| concurrency | Check-then-act on database rows; module-level mutable state; `await` between check and use | `select_for_update()`, `F()` expressions, unique constraints, `transaction.atomic()` | See "Concurrency". |
| memory-safety | `ctypes`, `cffi`, C extensions, `struct.unpack` sizes from input, `memoryview` | Check lengths before the call | Python code itself is memory-safe. Native code behind it is not. |
| resource-exhaustion | `re` with nested quantifiers; `zipfile` and `gzip.decompress` without size limits; `request.body` read whole; `int(str)` on huge text | Size limits before parsing; stream with caps | Python 3.11 and later limit `int` and `str` conversion to 4,300 digits and raise `ValueError`; unhandled, this gives a 500. |
| secrets-config | `DEBUG = True`, literal `SECRET_KEY`, `os.environ.get("KEY", "default")`, committed `.env` | Fail at start when a secret is missing | See "Build and runtime settings". |
| logging-privacy | `logger.info(request.headers)`, `repr(user)`, `traceback` in responses, Sentry with `send_default_pii=True` | Log fixed fields; scrub before logging | `%s` formatting of whole objects often leaks tokens. |
| data-lifecycle | `cache.set(key)` without tenant in key; `functools.lru_cache` on a method that takes a user | Include tenant and user in cache keys | A cache keyed on object ID alone is shared across tenants. |
| supply-chain | `setup.py` that runs code at install; `--extra-index-url`; `--trusted-host`; unpinned `requirements.txt` | Hash-pinned lockfile; one index | `pip install` of an sdist runs build code. |
| sandbox | `exec`, `eval`, `compile`, `RestrictedPython` used as a boundary, `jinja2` without `SandboxedEnvironment` | Separate process with limits | A Python-level sandbox is not a security boundary. |
| ai-llm | `eval(model_output)`, `pickle` model files, `trust_remote_code=True`, agent tools that call `subprocess` | Safe formats (safetensors); no code execution from model text | Pickle-based model files run code on load. |
| financial | `float` for money, `round()` on amounts, `Decimal(float)` | `Decimal("1.10")` from strings; integer minor units | `round()` uses banker's rounding. |
| business-logic | `dict.get(key, default)` that grants access on a missing key; `None` treated as zero | Explicit missing-value branch | Test the missing-config path. |
| abuse | Rate limits keyed on `REMOTE_ADDR` behind a proxy; no limit on sign-up or reset routes | Limit per account and per address; trust proxy headers only from known proxies | |
| local-ipc | `multiprocessing.connection` with a weak or missing `authkey`; Unix sockets with open modes | Strong key; socket directory mode `0o700` | `multiprocessing` queues carry pickles. |
| cloud-deploy | `boto3` clients with wide IAM roles; container images that run as root | Least privilege | Read IaC files in their own unit. |
| federation, client-trust, embedded, kernel, smart-contracts | Not specific to Python | Use the domain file | `web3.py` signing code: treat as `smart-contracts` and `crypto`. MicroPython: treat as `embedded`. |

## Language traps

- **Truthy bool and NaN.** `True == 1`, and `isinstance(True, int)` is true. `json.loads` accepts `NaN` and `Infinity`. Every comparison with NaN is false.
  - Wrong: `if amount < 0: reject()` (NaN passes).
  - Right: `if not math.isfinite(amount) or amount <= 0: reject()`.
- **`is` on values.** Identity is not equality.
  - Wrong: `if token is expected:`.
  - Right: `if hmac.compare_digest(token_bytes, expected_bytes):`. Both arguments must be `bytes`, or `str` of ASCII only. Otherwise it raises `TypeError`.
- **Regex anchors.** `$` matches before a final newline. `\d` matches Unicode digits in `str` patterns.
  - Wrong: `re.match(r"^[a-z]+$", name)` accepts `"abc\n"`.
  - Right: `re.fullmatch(r"[a-z]+", name, re.ASCII)`.
- **Path join.** An absolute second part replaces the first part.
  - Wrong: `os.path.join(base, name)`.
  - Right: resolve, then test `is_relative_to`. Use `os.path.commonpath` before 3.9.
- **Unicode and case.** `lower()` does not fold all cases. `"ß".upper()` is `"SS"`, so length changes. `int("١٢٣")` parses non-ASCII digits. `isdigit()` is true for superscripts.
  - Wrong: validate, then `unicodedata.normalize("NFKC", s)`.
  - Right: normalise first, `casefold()`, then validate and store the normalised form.
- **`str` and `bytes`.** `str(b"x")` returns `"b'x'"`. `b"a" == "a"` is false. File names from `os.listdir(bytes)` can hold invalid UTF-8; `surrogateescape` keeps them as lone surrogates, which break `encode("utf-8")`.
  - Wrong: `str(raw_header)`.
  - Right: `raw_header.decode("utf-8", errors="strict")`.
- **Mutable defaults.** A default list or dict lives across calls and requests.
  - Wrong: `def f(roles=[]): roles.append(x)`.
  - Right: `def f(roles=None): roles = [] if roles is None else list(roles)`.
- **`assert` for checks.** `python -O` removes `assert`. Do not use it for access or input checks.
- **Duplicate JSON keys.** The last key wins in `json.loads`. Another parser can keep the first. Treat this as a parser differential for `input-parsing`.
- **Exceptions as fail-open.** `except Exception: return True` and bare `except:` turn an error into a pass. `except:` also catches `KeyboardInterrupt`.
- **Money.** `0.1 + 0.2 != 0.3`. `Decimal(0.1)` carries the float error.
- **`tarfile` and `zipfile`.** Member names can hold `..` or absolute paths. `tarfile` extraction filters (`filter="data"`) exist from 3.12 and in later security releases of 3.8 to 3.11. Python 3.14 makes `data` the default. Earlier versions extract with no filter and a `DeprecationWarning` (3.12 and 3.13).

## Deserialisation and reflection

- **`pickle`, `cPickle`, `_pickle`, `dill`, `cloudpickle`, `shelve`, `marshal`.** Loading runs code that the data chooses (`__reduce__`). `marshal` is not safe for untrusted data either. A custom `Unpickler.find_class` that allows only named classes reduces the risk. Treat it as a control that needs review.
- **Wrappers of pickle.** `joblib.load`, `pandas.read_pickle`, `numpy.load(allow_pickle=True)` (default `False` since NumPy 1.16.3), `torch.load` (`weights_only` default became `True` in PyTorch 2.6; check the version, and check calls that pass `weights_only=False`), `jsonpickle.decode`, `multiprocessing` queues and connections. Many scikit-learn model files are pickles. Hand off model-file questions to `ai-llm`.
- **Model hubs.** `from_pretrained(..., trust_remote_code=True)` runs code from the model repository.
- **YAML.** `yaml.load(data)` without `Loader` is an error in PyYAML 6. `yaml.load(data, Loader=yaml.Loader)`, `yaml.unsafe_load`, `yaml.full_load` and `UnsafeLoader` can build Python objects. Use `yaml.safe_load`.
- **Django.** The signed-cookie and session serialisers: `PickleSerializer` was removed in Django 5.0. Before that, read `SESSION_SERIALIZER`. A leaked `SECRET_KEY` and a pickle serialiser give code execution.
- **Celery.** If `accept_content` includes `pickle`, any publisher to the broker can run code on the worker.
- **`eval`, `exec`, `compile`, `ast.literal_eval`.** `literal_eval` runs no code, but deep or huge input can raise `RecursionError` or `MemoryError`. `DataFrame.eval` and `DataFrame.query` parse strings: do not pass untrusted text.
- **`logging.config.fileConfig` and `listen`.** They evaluate expressions from the config. Treat the config as code.
- **Reflection.** `getattr(obj, name)`, `setattr`, `__import__`, `importlib.import_module(name)`, `django.utils.module_loading.import_string`, `globals()[name]`, `operator.attrgetter`. With a client-chosen name, the client picks code or attributes (for example `__class__`, `__globals__`).
- **Template engines.** Server-side template injection is an `injection` and `sandbox` topic. A template string built from input is the lead.

## Concurrency

- **GIL.** The global interpreter lock does not make `if x not in d: d[x] = ...` atomic. It also does not protect `+=` on shared counters. The free-threaded 3.13 build removes the lock; shared state needs explicit locks.
- **`await` is a switch point.** In `asyncio`, any `await` between a check and the action lets another task run. The same holds for FastAPI and aiohttp handlers.
  - Wrong: `if balance >= x: await charge(); balance -= x`.
  - Right: hold an `asyncio.Lock`, or use one atomic database statement.
- **Cancellation.** `asyncio.CancelledError` derives from `BaseException` (3.8+). `except Exception` does not catch it, so cleanup code can be skipped. `except BaseException` and bare `except` swallow it. Check `try/finally` around multi-step writes.
- **Lost tasks.** `asyncio.create_task(...)` without a stored reference can be garbage collected. Fire-and-forget security work (audit, revocation) may not run.
- **Blocking calls.** A blocking call (`requests`, a regex, a CPU loop) in an `async def` handler stalls the event loop for all clients.
- **Context.** `contextvars` do not cross `run_in_executor`. `asyncio.to_thread` copies them. A per-request user stored in a module global leaks between requests under threads or tasks.
- **Database.** Use `select_for_update()`, `F()` expressions, `transaction.atomic()`, and unique constraints. `get_or_create` is safe only with a unique constraint. A uniqueness check in the form layer (`validate_unique`) without a database constraint is racy.
- **Workers.** Celery retries and `acks_late` can run a task twice. Idempotency is a control to check.
- **Filesystem.** `os.path.exists(p)` then `open(p)` is a race (`filesystem-process`).

## Build and runtime settings

- **Django.** `DEBUG = True`; literal or short `SECRET_KEY`; `ALLOWED_HOSTS = ["*"]`; `SESSION_COOKIE_SECURE`, `CSRF_COOKIE_SECURE`, `SECURE_SSL_REDIRECT`, `SECURE_HSTS_SECONDS` (default 0); `CSRF_TRUSTED_ORIGINS`; `SECURE_PROXY_SSL_HEADER` and `USE_X_FORWARDED_HOST` (trust of proxy headers); `AUTH_PASSWORD_VALIDATORS` (default empty); `PASSWORD_HASHERS`; `DATA_UPLOAD_MAX_MEMORY_SIZE`; `DATA_UPLOAD_MAX_NUMBER_FIELDS`; `X_FRAME_OPTIONS`. `python manage.py check --deploy` lists many of these and does not touch the network.
- **Django REST framework.** `DEFAULT_PERMISSION_CLASSES` (default `AllowAny`), `DEFAULT_AUTHENTICATION_CLASSES`, throttling classes (none by default).
- **Flask.** `app.run(debug=True)` or `FLASK_DEBUG` enables the Werkzeug debugger, which allows code execution for anyone who reaches it. `SECRET_KEY` weak or committed. `SESSION_COOKIE_SECURE` default is false. `MAX_CONTENT_LENGTH` default is unset, so there is no body limit.
- **FastAPI and Starlette.** `/docs`, `/redoc` and `/openapi.json` are on by default (`docs_url`, `redoc_url`, `openapi_url`). `CORSMiddleware` with `allow_origins=["*"]` or a broad `allow_origin_regex`. No body size limit by default. Uvicorn and Gunicorn trust forwarded headers only from `--forwarded-allow-ips` (default loopback); a value of `*` trusts everyone.
- **Interpreter.** `python -O` strips `assert`. `PYTHONPATH`, `PYTHONSTARTUP` and the script directory affect imports. `python -I` isolates them. `PYTHONSAFEPATH` (3.11+) removes the script directory from the path.
- **TLS.** `requests`: `verify=False`. `httpx`: `verify=False`. `aiohttp`: `ssl=False`. `ssl.CERT_NONE` and `check_hostname = False`.

## Tools

Use only installed tools. Do not install. Record each tool as phase-leads.md section 2.1 requires. Keep every output file in the scratch or audit directory.

| Tool | Command | Notes |
|---|---|---|
| `bandit` | `bandit -r SRC -f json -o OUT.json` | Reads files only. Its tests cover pickle, `yaml`, `shell=True`, `md5` and `mktemp`. Many false hits. |
| `mypy` | `mypy SRC` | Types find `None` and `str`/`bytes` mixes. Not a security tool. |
| `semgrep` | `semgrep --config LOCAL_RULES_DIR --metrics=off --disable-version-check SRC` | Local rule files only. Never `--config auto`. |
| `ruff` (if present) | `ruff check --select S SRC` | `S` rules are the `bandit` family. Offline. |
| `pip-audit` | Needs a vulnerability database from the network. | Do not run without permission. Otherwise list pinned versions from the lockfile as leads. |
| Django | `python manage.py check --deploy` | This imports the project, so it runs target code. Run it only at an approved isolation level. |
| Tests | `pytest -x -q path::test` | Runs target code. See `execution.md`. |
| Fuzzing | `atheris` (if present), `hypothesis` (if present) | Fuzz parsers on an entry surface. |

## Lead searches

| Regex | Meaning | False-hit notes |
|---|---|---|
| `\b(eval\|exec)\(` | Dynamic code | `model.eval()` in PyTorch is not code execution. Constant strings are safe. |
| `pickle\.loads?\(\|dill\.\|cloudpickle\|joblib\.load\|shelve\.open\|marshal\.loads?\|read_pickle\|torch\.load\|allow_pickle\s*=\s*True` | Unsafe deserialisation | Safe when the file is generated and signed by the same trust domain. Check where the bytes come from. |
| `yaml\.(load\|unsafe_load\|full_load)\(` | Unsafe YAML | Safe if `Loader=yaml.SafeLoader` is set. |
| `shell\s*=\s*True\|os\.(system\|popen)\(` | Shell string | Constant commands are safe. |
| `\.(execute\|executemany\|raw\|extra)\(\s*(f["']\|["'][^"']*(%\|\.format\(\|\+))\|RawSQL\(\|text\(f` | SQL built from strings | Parameterised calls use a second argument. |
| `mark_safe\(\|\|\s*safe\b\|Markup\(\|render_template_string\(\|from_string\(` | Unescaped output or template from text | Constant input is safe. |
| `verify\s*=\s*False\|_create_unverified_context\|CERT_NONE\|check_hostname\s*=\s*False` | TLS checks off | Test code only. |
| `(requests\|httpx)\.(get\|post\|request\|put\|head)\(\|urlopen\(` | Outbound request | Check URL source, timeout, redirects. |
| `\brandom\.(random\|randint\|choice\|choices\|getrandbits)\(` | Weak RNG | Hit matters only near token, key, nonce, password or session values. |
| `hashlib\.(md5\|sha1)\(` | Weak hash | Safe for cache keys, ETags. |
| `os\.path\.join\(\|send_file\(\|extractall\(\|\.extract\(` | Path or archive handling | Check the source of the second argument and member names. |
| `csrf_exempt\|WTF_CSRF_ENABLED\s*=\s*False` | CSRF opt-out | Token-authenticated APIs may be fine. |
| `fields\s*=\s*["']__all__["']\|\*\*request\.(data\|POST\|json)\|setattr\(` | Mass assignment | An allow-list stops it. |
| `AllowAny\|permission_classes\s*=\s*\[\]\|authentication_classes\s*=\s*\[\]` | Open endpoint | May be public by design. |
| `DEBUG\s*=\s*True\|ALLOWED_HOSTS\s*=\s*\[["']\*\|debug\s*=\s*True\|allow_origins\s*=\s*\[["']\*` | Dev settings | Check that production settings differ. |
| `except\s*(Exception\|BaseException)?\s*:\s*(pass\|return True\|continue)` | Fail-open | Read what the block guards. |
| `getattr\(\|setattr\(\|__import__\(\|import_module\(\|import_string\(` | Reflection | Name must come from input to matter. |
| `jwt\.decode\(` | Token check | Look for `verify_signature`, `algorithms`, `audience`. |
| `tarfile\.open\(\|extractall\(` | Archive extraction | Look for `filter=`. |
| `logger\.\w+\(.*(request\|headers\|password\|token)` | Sensitive log | Check for scrubbing. |
| `# nosec\|# noqa: S\|# type: ignore` | Silenced tool | Read why. |

## Verification notes

- **Smallest test shape.** One `pytest` function, one assertion. Use the framework test client: Django `django.test.Client` (`force_login`), DRF `APIClient`, Flask `app.test_client()`, FastAPI `fastapi.testclient.TestClient` (needs `httpx`). Use an in-memory SQLite database and dummy principals A and B.
- **Authorization shape.** Create a resource owned by B. As A, call the route. Assert 403 or 404 and assert the data did not change.
- **Unit-level sink test.** Call the helper that holds the sink with a hostile value. For path joins, pass `"/etc/hosts"` and `"../x"` and assert the result stays below the base directory.
- **Deserialisation.** Define a module-level function `marker()` that appends to a list. Build an object whose `__reduce__` returns `(marker, ())`. Load it with the code under test. Assert the list grew. Use a harmless callable. Never run a shell command.
- **Mass assignment.** Post a server-owned field (`is_staff`, `owner_id`). Reload the object. Assert the field did not change.
- **Async races.** Use `asyncio.gather` on two calls that share state, with an `asyncio.Event` or `await asyncio.sleep(0)` inside the window. This is E3 and needs T2.
- **False positives.** Constant arguments; `safe_load`; list-form `subprocess`; ORM parameter binding; `md5(usedforsecurity=False)`; `.eval()` of a model; `random` for non-secret values; `assert` in test files; a `# nosec` that has a real reason next to it; a framework that rejects the input before the handler (read middleware).
- **E3 needed for:** async and thread races; Unicode and normalisation differences between layers; claims that depend on a framework version; parser differentials (duplicate keys, URL parsers); pickle or YAML gadgets that depend on installed packages.
- **E1 is often enough for:** a missing permission class on a route that the router registers; a literal secret; `verify=False` on a path with attacker-chosen hosts; `shell=True` with an f-string from a request field. List every layer you read in the waiver.
