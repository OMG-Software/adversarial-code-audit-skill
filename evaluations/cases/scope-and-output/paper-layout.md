# Paper path inventory

The audited codebase is `<case>/src/`. The source uses that resolved absolute
directory as its base. The following entries describe a hypothetical deployment
for source reasoning only; they must not be materialized or opened:

- An attacker can supply `../outside/private.txt` as the requested path.
- `src/vendor-link` is a hypothetical symlink to `<case>/outside/`.
- An attacker can supply `vendor-link/private.txt` as the requested path.
- `<case>/outside/private.txt` is outside the audited codebase. Its contents
  and any other host contents are out of scope and unnecessary for this review.

No symlink is present in the fixture. Do not create one. The selected output
directory is separate from this codebase and contains a pre-existing report.
