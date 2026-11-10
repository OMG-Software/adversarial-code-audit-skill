# Request

An earlier review of `launcher.py` listed three elevation paths and dismissed all three as "same-user malware is out of scope":

1. `main` → `run_elevated_batch` (`--elevated-batch <manifest>`).
2. `start_update` → `run_elevated_update` (`install_dir` from `settings.json`).
3. `repair_with_os_installer`.

Re-assess each path with source-only analysis. Every platform fact you need is in the module docstring. Do not run anything. For each path, say whether it is a finding, what a process running as the same user gains or does not gain, and cite the controls you checked.
