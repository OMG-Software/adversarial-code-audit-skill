# Language: Ruby

## Scope

- Covers: Ruby 2.7 to 3.4 (MRI/CRuby). Version-dependent behaviour carries the version. Other runtimes (JRuby, TruffleRuby) differ in threads and native extensions.
- Common frameworks: Rails (6.1 to 8.x, including Action Cable, Active Storage, Active Job), Sinatra, Rack (and Rack middleware), Grape, GraphQL-Ruby, Devise, Pundit, CanCanCan, Sidekiq.
- Ruby has no memory-safety problems in plain code. Native extensions, `Fiddle` and the `ffi` gem do. Hand those to `memory-safety`.

## Entry points

- **Rails routes.** `config/routes.rb`: `get`, `post`, `put`, `patch`, `delete`, `match` (check `via: :all`), `resources`, `resource`, `namespace`, `scope`, `member`, `collection`, `concern`, `root`, `mount` (mounted Rack apps such as `Sidekiq::Web`, Action Cable, engines). Also `draw` for split route files. Dynamic segments such as `*path` and `(:format)` widen the match.
- **Rails controllers.** Public methods of classes under `app/controllers` are actions if a route reaches them. Input: `params`, `request.headers`, `cookies`, `request.body`. Filters: `before_action`, `skip_before_action`, `around_action`, with `only:` and `except:` lists. `skip_forgery_protection` and `protect_from_forgery with: :null_session` change CSRF handling. `ActionController::API` has no CSRF layer.
- **Strong parameters.** `params.require(...).permit(...)`, `params.permit!`, `params.to_unsafe_h`. Each one decides what the model sees.
- **Action Cable.** `app/channels/*`: `subscribed`, `receive`, and every public method of a channel class. A client can call any public method with `perform`. Check `connect` in `ApplicationCable::Connection` for authentication and each action for authorization.
- **Other Rails entries.** Active Job `perform`, Action Mailbox, Active Storage routes (signed blob IDs), rake tasks, `rails runner`, Turbo Streams, GraphQL-Ruby `field`, `resolve`, `authorized?`.
- **Sinatra.** `get '/x' do`, `post`, `put`, `delete`, `before do`, `helpers`, `Sinatra::Base` subclasses, `params`, `request`, `settings`. Classic style puts routes at top level.
- **Rack.** `config.ru`: `run`, `use`, `map`. An app is any object with `call(env)`. Input: `env['PATH_INFO']`, `env['QUERY_STRING']`, `env['HTTP_*']`, `env['rack.input']`.
- **Grape.** `get`, `post`, `params do requires ... end`, `namespace`, `before`.
- **Workers.** Sidekiq `perform` (arguments are JSON), `Resque`, `Delayed::Job` (jobs are stored as YAML), message-queue consumers.
- **Scripts.** `ARGV`, `OptionParser`, `gets`, `$stdin`, `ENV`, `File.read(ARGV[0])`.
- **Exported code.** A gem's public classes and methods are its entry surface.

## Sinks by domain

| Domain | Dangerous API or pattern | Safer alternative | Notes |
|---|---|---|---|
| injection | `where("a = '#{x}'")`, `find_by_sql`, `connection.execute`, `exists?("...")`, `update_all("...")`, `joins("...")`, `group`/`having`/`select`/`from` with strings, `Arel.sql(user)` | `where(a: x)`, `where("a = ?", x)`, `sanitize_sql_array` | `order(user)` and `pluck(user)` raise for unknown raw strings from Rails 6.1, but `Arel.sql` removes that check. Column names cannot be bound. |
| injection | Backticks, `%x()`, `system("cmd #{x}")`, `exec`, `spawn`, `IO.popen(string)`, `Open3.capture2(string)`, `Kernel#open(user)` | Argument arrays: `system("cmd", arg)`, `Open3.capture2("cmd", arg)` | `open("\|cmd")` runs a command. It warns from Ruby 3.3. `URI.open` and `File.open` do not. Add `--` before user values. |
| injection | `html_safe`, `raw`, `<%==`, `sanitize` with broad options, `content_tag` with user attribute names, `link_to` with a user URL, `render inline:`, `render file:`, `render template:` with a user value, `ERB.new(user).result` | Default ERB escaping (`<%=`); `sanitize` with a tag list; URL scheme allow-list | `ERB.new` alone does not escape. `link_to` accepts `javascript:` URLs. |
| input-parsing | `Marshal.load`, `YAML.unsafe_load`, `Oj.load` (default object mode), `JSON.load`, `Nokogiri::XML` with `NOENT` or `DTDLOAD`, `REXML` | `JSON.parse`, `Psych.safe_load`, `Oj.safe_load`, Nokogiri defaults | See "Deserialisation and reflection". |
| input-parsing | `File.read(user)`, `send_file(user)`, `send_data(File.read(user))`, `Dir.glob(user)`, `File.join(base, user)`, `Pathname#join(user)`, `File.expand_path(user)`; `Zip::File` entry names; `params[:file].original_filename` | Resolve with `File.realpath`, then check the prefix with a trailing separator; generated file names | `Pathname("/base").join("/etc")` returns `/etc`. `File.join` keeps both parts (`/base/etc`). `File.expand_path("~name")` expands to a home directory. |
| filesystem-process | `Tempfile` in shared paths with fixed names, `File.open(p, 'w')` in `/tmp`, `FileUtils.chmod 0777`, `File.umask`, `FileUtils.rm_rf(user)`, `Process.setuid` order | `Tempfile.create`, `Dir.mktmpdir`, `File::CREAT\|File::EXCL`, `0600`/`0700` | `ENV['PATH']` and `RUBYOPT`, `RUBYLIB` change what a child runs. |
| outbound-network | `Net::HTTP.get(URI(user))`, `URI.open`, Faraday, HTTParty, RestClient, Typhoeus; `verify_mode = OpenSSL::SSL::VERIFY_NONE`; `ssl: { verify: false }` | Host allow-list; check the resolved address; default verification | `Net::HTTP` does not follow redirects by itself. Faraday and HTTParty may. Active Storage and link-preview gems fetch URLs. |
| api | `Model.new(params)`, `update(params)`, `params.permit!`, `to_unsafe_h`, `config.action_controller.permit_all_parameters = true`, `accepts_nested_attributes_for` with `allow_destroy`, `render json: @record` | `permit` lists; serializers with a field list | `as_json` returns all columns, including `password_digest` and tokens. A `permit` list that holds `:role`, `:admin` or a foreign key is a lead. |
| web-client | `skip_forgery_protection`, `protect_from_forgery with: :null_session` on cookie-authenticated routes, `redirect_to params[:url]`, `rack-cors` with `origins '*'`, cookies without flags | `allow_other_host: false` | Rails 7.0 defaults (`load_defaults 7.0`) raise on open redirects. Check `config.action_controller.raise_on_open_redirects`. |
| authn | `==` on tokens, `Digest::MD5` or `SHA256` for passwords, `rand`, `Random.rand` for tokens, `session[:user_id]` set without `reset_session` | `has_secure_password` (bcrypt), `SecureRandom`, `ActiveSupport::SecurityUtils.secure_compare`, `Rack::Utils.secure_compare` | Devise settings: `stretches`, `paranoid`, `maximum_attempts`, `pepper`. |
| authz | `Model.find(params[:id])` with no owner scope; `before_action ..., only: [...]` that misses a new action; `skip_before_action`; Pundit without `verify_authorized`; CanCanCan without `load_and_authorize_resource`; `unscoped`, `default_scope` removed | `current_user.records.find(params[:id])`; `after_action :verify_authorized`; `policy_scope` | An `only:` list fails open when you add an action. An `except:` list fails open too for new actions. |
| crypto | `Digest::MD5`, `Digest::SHA1`, `OpenSSL::Cipher` in ECB or without a tag, fixed IV, `rand`, `==` for MACs | `SecureRandom`, AES-GCM with `auth_tag`, `ActiveSupport::MessageEncryptor`, `OpenSSL::KDF` | `MessageVerifier` signs and does not encrypt. |
| crypto-protocols | Signing `to_json` output with unstable key order | Fixed field order; sign the bytes you send | Ruby hashes keep insertion order. |
| messaging | Webhook action without a signature check; `request.body.read` after `params` parsed the body; Sidekiq Web mounted without auth | Verify HMAC over the raw body with `secure_compare` | `request.body.rewind` before a second read. |
| concurrency | Check-then-update on records; class-level state; `\|\|=` memoisation in shared objects | `with_lock`, `lock!`, `lock_version`, unique indexes | See "Concurrency". |
| resource-exhaustion | `Regexp.new(user)`, nested quantifiers, `Zlib::Inflate` without limits, unpaged `.all`, `params[:per_page]` without a cap, `JSON.parse` without `max_nesting` | `Regexp.timeout=` (3.2+); caps on page size | Ruby 3.2 and later memoise most regex matches, which lowers ReDoS risk, but not for all patterns (back-references). |
| secrets-config | `config/master.key` or `.env` committed, `secrets.yml`, `ENV['X'] \|\| 'default'`, `config.consider_all_requests_local = true` in production | `ENV.fetch('X')` (raises when missing); `config.require_master_key` | See "Build and runtime settings". |
| logging-privacy | `Rails.logger.info(params)`, `inspect` on records, missing `filter_parameters`, SQL logs at debug level, Sentry or Bugsnag with personal data | `config.filter_parameters`; log named fields | Filtered keys match by substring or regex. |
| data-lifecycle | `Rails.cache.fetch(key)` without tenant, fragment caches (`cache @item`) shared across users, soft-delete scopes (`discard`, `paranoia`), Active Storage blob URLs | Tenant and user in keys; signed, expiring URLs | A fragment cache is keyed by the object, not by the viewer. |
| supply-chain | `Gemfile` with `git:` or `github:` sources, several global `source` lines, gems with `extensions` (`extconf.rb` runs at install), unfrozen bundle | Block-scoped sources; `bundle config set frozen true`; `Gemfile.lock` with checksums | Install-time code runs with the installer's rights. |
| sandbox | `eval`, `instance_eval`, `class_eval`, `binding`, `ERB`, `Ractor` as a boundary | Liquid templates; separate process | `$SAFE` was removed in Ruby 3.0. Ruby has no in-process sandbox. |
| ai-llm | `eval` of model output; `Marshal.load` of cached model data | Validate structured output | |
| financial | `Float` for money, `round` on floats, `to_f` on price strings | `BigDecimal("1.10")`, integer cents, `Money` types | `"abc".to_f` is `0.0`. |
| abuse | `Rack::Attack` keyed on `req.ip` behind a proxy; no throttle on login or reset routes | Throttle per account and per address | |
| http-protocol | `request.host` and `X-Forwarded-Host` in links and mail; `url_for(host: params[:h])`; `Rack::Sendfile` with a trusted `X-Sendfile-Type` | `config.hosts`; `default_url_options` | `request.remote_ip` depends on `trusted_proxies`. |
| local-ipc | `DRb.start_service` without an ACL, `Marshal` over sockets | `DRb::ACL`; JSON | DRb exposes objects and unmarshals data from peers. |
| business-logic, federation, client-trust, embedded, kernel, cloud-deploy, smart-contracts | Not specific to Ruby | Use the domain file | |

## Language traps

- **Truthiness.** Only `nil` and `false` are false. `0`, `""` and `[]` are true. Request parameters are strings, so `"false"` is true.
  - Wrong: `if params[:skip_check]`.
  - Right: `if params[:skip_check] == 'true'`, or cast with `ActiveModel::Type::Boolean`.
- **Regex anchors.** `^` and `$` match at every line. `"x\nevil" =~ /^[a-z]+$/` matches.
  - Wrong: `/^[a-z0-9]+$/`.
  - Right: `/\A[a-z0-9]+\z/`. Rails raises `ArgumentError` for `validates_format_of` with `^`/`$` unless `multiline: true` is set. A `case` with an unanchored `when /admin/` is a lead.
- **Parameter types.** `params[:x]` can be a `String`, an `Array` (`x[]=1`) or a hash (`x[a]=1`). JSON bodies add numbers, `true` and `nil`.
  - Wrong: `params[:name].strip` (a 500 on an array), `params[:id] == 1`.
  - Right: `params[:name].to_s`, `params.require(:name)` with a type check.
- **Nil in finders.** A missing parameter becomes `nil`. `find_by(token: params[:token])` then matches a row whose `token` is `NULL`.
  - Right: `return head :bad_request if params[:token].blank?` before the lookup.
- **Conversion.** `"12abc".to_i` is `12`. `nil.to_i` is `0`. `Integer("12abc")` raises. `"abc".to_f` is `0.0`. A failed parse that turns into `0` can mean "no limit" or "free".
- **`File.join` and `Pathname#join`.** See the path row above. `File.expand_path` resolves `..` and expands `~`.
- **Dynamic dispatch.** `send(params[:m])` calls private methods. `public_send` does not. Both let a client pick the method name. `constantize` and `const_get` let a client pick a class.
- **Equality.** `==`, `eql?`, `equal?` and `===` differ. `case x when Foo` uses `===`. `Array#include?` uses `==`. `==` on strings is not constant time.
- **Unicode.** `String#downcase` and `casecmp?` are Unicode-aware from Ruby 2.4. `length` counts characters, `bytesize` counts bytes: check the one that the column or protocol limits. `unicode_normalize` exists (2.2+); normalise before you validate or compare. A string with an invalid encoding raises `ArgumentError` in `=~`; check `valid_encoding?`.
- **Mutable constants.** A constant string or hash that code mutates (`<<`, `merge!`) is shared by all requests. Use `# frozen_string_literal: true` and `.freeze`.
- **Format strings.** `format(user_string, ...)` and `String#%` with a client format can raise or read hash keys. Use fixed formats.
- **Time.** `Time.now` is local time. Compare in UTC. `Time.parse` accepts many forms.
- **Error swallowing.** `rescue => e` followed by `nil` or `true`, and `rescue Exception`, turn an error into a pass. A modifier `rescue` (`x = f rescue true`) hides errors.

## Deserialisation and reflection

- **`Marshal.load`.** It builds objects of any loaded class. Data from a client, cache or queue leads to code execution through gadget classes. Do not load data that an untrusted party can write. Older Rack cookie sessions (`Rack::Session::Cookie`) and Rails cookies with `cookies_serializer = :marshal` or `:hybrid` unmarshal after a signature check; a leaked `secret_key_base` makes this exploitable. New Rails apps use `:json`.
- **YAML.** Psych 4 (Ruby 3.1 and later) makes `YAML.load` safe by default. Before that, `YAML.load` is unsafe. `YAML.unsafe_load` is unsafe in every version. Use `Psych.safe_load(str, permitted_classes: [], aliases: false)`. `Delayed::Job` stores jobs as YAML and loads them in the worker: write access to the jobs table means code execution.
- **JSON and Oj.** `JSON.parse` is safe. `JSON.load` is meant for trusted data. `Oj.load` in object mode (the default) can build objects. Use `Oj.safe_load` or set `mode: :strict`.
- **XML.** Nokogiri does not load external entities by default. The options `NOENT` and `DTDLOAD` enable them. REXML has entity expansion limits; check the version.
- **Code from strings.** `eval`, `instance_eval(string)`, `class_eval(string)`, `module_eval(string)`, `binding.eval`, `ERB.new(string).result`, `Kernel#open("|...")`, `Kernel#exec`.
- **Reflection.** `send`, `public_send`, `method(name).call`, `const_get`, `constantize`, `safe_constantize`, `instance_variable_get`, `define_method`, `Object.const_get(params[:type])` (polymorphic types). Allow-list the names.
- **Rails polymorphic types.** `params[:commentable_type].constantize.find(params[:id])` lets the client choose any model class.
- **`DRb`.** Remote objects and `Marshal` over the wire. Treat any reachable `DRb` service as remote code execution.
- **Job systems.** Sidekiq arguments are JSON. Active Job uses GlobalID; a forged GlobalID selects a record class. Check the job's own authorization.

## Concurrency

- **GVL.** CRuby's global VM lock does not make read-modify-write sequences atomic. Threads switch between lines. Puma runs several threads per process. Unicorn runs processes.
- **Check-then-act.**
  - Wrong: `if wallet.balance >= cost; wallet.update(balance: wallet.balance - cost); end`.
  - Right: `wallet.with_lock { ... }`, or `Wallet.where("balance >= ?", cost).update_all(...)`, or optimistic locking with `lock_version` (it raises `ActiveRecord::StaleObjectError`).
- **Uniqueness.** `validates_uniqueness_of` is racy without a unique index (the Rails guide says so). `find_or_create_by` is racy for the same reason. `create_or_find_by` (Rails 6.0+) relies on the index.
- **Shared state.** Class variables (`@@x`), class-level instance variables, constants and `||=` memoisation on shared objects are shared by all threads. `Thread.current[:x]` is fiber-local, not thread-local. `ActiveSupport::CurrentAttributes` resets per request in Rails. In your own threads or jobs, reset it.
- **Callbacks.** `after_save` runs before the commit. A job queued there can run before the data exists, or run for a rolled-back change. `after_commit` runs after.
- **`Timeout.timeout`.** It raises in arbitrary lines of the block. It can interrupt cleanup and leave state half-written. Do not use it around security-relevant multi-step writes.
- **Retries.** Sidekiq and Active Job retry failed jobs. A job that sends money, mail or grants rights needs an idempotency key.
- **Fibers and Ractors.** Fiber schedulers (Ruby 3.0+; for example Falcon) share objects across fibers. Ractors isolate objects but are not a security boundary.
- **Filesystem.** `File.exist?` then `File.open` is a race (`filesystem-process`).

## Build and runtime settings

- **Rails environments.** `config.consider_all_requests_local = true` shows detailed error pages. Keep it false in production. `config.action_dispatch.show_exceptions`. `config.log_level`. `config.eager_load`.
- **Transport and cookies.** `config.force_ssl` (also sets secure cookies and HSTS). `config.assume_ssl` (Rails 7.1+) for TLS ended at a proxy. `config.session_store :cookie_store, key:, secure:, httponly:, same_site:`. `config.action_dispatch.cookies_same_site_protection` (default `:lax`).
- **Secrets.** `secret_key_base` signs and encrypts cookies: leaking it breaks sessions and, with Marshal cookies, gives code execution. `config/credentials.yml.enc` is safe if `config/master.key` stays out of the repository. `config.require_master_key = true`.
- **Hosts and proxies.** `config.hosts` (Rails 6.0+) guards against DNS rebinding and Host header abuse. It is empty by default in production, so every host is accepted. `config.action_dispatch.trusted_proxies` controls `request.remote_ip`.
- **Parameters.** `config.action_controller.permit_all_parameters` (keep false). `config.action_controller.action_on_unpermitted_parameters` (`:raise` is stricter than `:log`). `config.filter_parameters` for logs.
- **CSRF.** `config.action_controller.allow_forgery_protection` is false in the test environment by default. `forgery_protection_origin_check`. API-only apps skip CSRF; check that no cookie authentication remains.
- **Headers.** `config/initializers/content_security_policy.rb`; `config.action_dispatch.default_headers`.
- **Static files.** `config.public_file_server.enabled`. Everything in `public/` is served.
- **Sinatra.** `set :protection` (Rack::Protection), `set :sessions` and `session_secret`, `set :show_exceptions`, `set :environment`, `set :public_folder`, `set :bind`.
- **Rack.** `Rack::Static`, `Rack::Directory` and `Rack::Sendfile` expose files. `Rack::Session::Cookie` needs a strong `secret`.
- **Interpreter.** `RUBYOPT` and `RUBYLIB` change what loads. `-W` and `$DEBUG` change warnings and output. `$SAFE` is gone since Ruby 3.0.
- **Bundler.** A frozen bundle (`bundle config set frozen true`) stops lockfile changes at install.

## Tools

Use only installed tools. Do not install. Record each tool as `phase-leads.md` section 2.1 requires. That table has no Ruby row. The tools below are extra and used if present.

| Tool | Command | Notes |
|---|---|---|
| `brakeman` | `brakeman -q --no-pager -f json -o OUT.json APP_DIR` | Static analyser for Rails. Reads files only. Exit code is non-zero when it finds warnings. |
| `rubocop` | `rubocop --only Security,Rails/OutputSafety SRC` | A `require:` in the project's `.rubocop.yml` loads target code: check it first, or use your own config (`-c`). Cops include `Security/Eval`, `Security/MarshalLoad`, `Security/YAMLLoad`, `Security/Open`, `Security/JSONLoad`. |
| `bundler-audit` | `bundle-audit check` | Uses a local copy of the advisory database. Do not run `update` or `--update` without permission (network). Otherwise list pinned versions from `Gemfile.lock` as leads. |
| `semgrep` | `semgrep --config LOCAL_RULES_DIR --metrics=off --disable-version-check SRC` | Local rules only. Never `--config auto`. |
| Syntax | `ruby -wc FILE` | Checks syntax. Does not run the file. |
| Route listing | `bin/rails routes` | Boots the application and runs target code. Use an approved isolation level. |
| Tests | `bundle exec rspec FILE:LINE`; `bundle exec ruby -Itest FILE -n /NAME/`; `bin/rails test FILE` | Run target code. See `execution.md`. |
| Fuzzing | `ruzzy` (if present) | For parsers and native extensions. |

## Lead searches

| Regex | Meaning | False-hit notes |
|---|---|---|
| `\b(eval\|instance_eval\|class_eval\|module_eval)\b` | Dynamic code | Block form (`instance_eval do`) is safe. |
| `Marshal\.load\|YAML\.(load\|unsafe_load)\|Oj\.load\|JSON\.load` | Unsafe deserialisation | Safe with a trusted source or `safe_load`. |
| `\.(send\|public_send\|constantize\|safe_constantize\|const_get)\(` | Reflection | Names must come from input to matter. |
| `%x\(\|\bsystem\(\|\bexec\(\|\bspawn\(\|IO\.popen\|Open3\.` | Process creation (also search for backticks, which have no safe regex here) | Argument-array forms are safe. |
| `\bopen\(` | `Kernel#open` | `File.open` and `URI.open` are different calls. Check for a bare `open(`. |
| `(where\|find_by_sql\|exists\?\|update_all\|joins\|having\|group\|select\|from\|order\|pluck)\(\s*"[^"]*#\{` | SQL with interpolation | Interpolated constants are safe. |
| `Arel\.sql\(` | Raw SQL fragment | Check the argument source. |
| `html_safe\|\braw\b\|<%==\|render\s+(inline\|file\|template):` | Unescaped output or render from text | Constant strings are safe. |
| `permit!\|to_unsafe_h\|permit_all_parameters\|\.permit\(.*:(role\|admin\|is_admin\|owner_id\|user_id\|tenant_id)` | Mass assignment | Read what the model does with the field. |
| `skip_before_action\|skip_forgery_protection\|null_session\|only:\s*\[` | Filter gap | Check each action under the filter. |
| `\.find\(params\|\.find_by\w*\(\s*\w+:\s*params` | Lookup by client value | Check owner scope and `nil` handling. |
| `redirect_to\s+params\|allow_other_host:\s*true` | Open redirect | Safe with an allow-list. |
| `VERIFY_NONE\|verify:\s*false\|ssl_verify` | TLS checks off | Test code only. |
| `(Net::HTTP\|URI\.open\|Faraday\|HTTParty\|RestClient)[^\n]*(params\|url)` | Outbound request | Check allow-list and redirects. |
| `rand\(\|Random\.rand\|Digest::(MD5\|SHA1)` | Weak RNG or hash | Matters near tokens and passwords. |
| `==\s*.*(token\|secret\|signature\|digest)` | Non-constant-time compare | Matters for secrets. |
| `\^.*\$\|validates?_format_of\|format:\s*/` | Regex anchors | `^`/`$` are line anchors. |
| `consider_all_requests_local\|master\.key\|secret_key_base\|ENV\[["'][A-Z_]+["']\]\s*\|\|` | Config and secrets | Check production values. |
| `mount\s+\w+::Web\|DRb\.start_service` | Exposed admin or RPC | Check authentication. |
| `rescue\s*(=>\s*\w+)?\s*$\|rescue\s+Exception\|rescue\s*nil` | Swallowed error | Read what follows. |
| `# rubocop:disable\|# nosec\|brakeman:ignore\|TODO.*(auth\|check)` | Silenced check | Read why. |

## Verification notes

- **Smallest test shape.** One RSpec example or Minitest test with one assertion. Rails: a request spec or `ActionDispatch::IntegrationTest` (`post`, `get`, then assert on `response`). Sinatra and Rack: `Rack::Test::Methods` with `get '/x'`. Use dummy principals A and B and the test database.
- **Authorization.** Create a record for B. Sign in as A. Request it. Assert 403, 404 or a redirect, and assert that the record is unchanged.
- **Mass assignment.** Post a server-owned field (`role`, `admin`, `user_id`). Reload the record. Assert it did not change.
- **Nil finder.** Send the request without the parameter. Assert that no record with a `NULL` column is returned.
- **Regex anchors.** Test the pattern with `"ok\nbad"`.
- **Deserialisation.** Define a test class whose `marshal_load` or `init_with` sets a class-level flag. Load a dump of it with the code under test. Assert the flag. Use a harmless flag. Never run a shell command.
- **Path checks.** Pass `"../x"`, `"/etc/hosts"` and `"~root"`. Assert that the resolved path stays under the base.
- **Races.** Run two threads against the same record. Release both from a `Queue` so they enter the window together. Use a database that supports row locks. This is E3 and needs T2.
- **False positives.** Interpolated constants in SQL; `html_safe` on literals; `send` with a fixed symbol; `YAML.load` on Psych 4 or later; `permit` lists that hold harmless fields; `skip_forgery_protection` on token-only API controllers; `eval` in build or generator code that reads no input; Brakeman warnings on code that is not reachable from a route.
- **E3 needed for:** races; behaviour that depends on the Rails, Rack or Psych version; ReDoS timing; Active Storage and proxy interactions; Action Cable connection flows.
- **E1 is often enough for:** a controller action with no authorization call and a sensitive effect (after you read every filter and base class); `permit!` on a model with a role field; SQL built with `#{params[...]}`; a committed `master.key`. List every layer you read in the waiver.
