"""Tests for audit_run.py. Run: python -m unittest discover -s scripts -p "test_*.py"."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import audit_run  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
DASH = "–"

CONFIRMED = f"""# Any user can export another tenant's invoices

## Header

- fingerprint: authz.invoice-export.missing-tenant-check
- status: confirmed
- evidence-level: E1
- domain: authz
- root-cause-at: app/export.py#export_invoices
- cwe: CWE-639
- coverage-units: U002
- found-by: hunter-1
- verified-by: verifier-1
- source-ref: abc1234
- first-seen: this run

## Summary

An authenticated user of tenant A reads the invoices of tenant B through the CSV export.

## Regression origin

none

## Attacker

- principal: authenticated user in tenant A
- starting capability: can call the export route

## Path

1. entry {DASH} `app/routes.py:12` {DASH} `export()` {DASH} tenant id comes from the query
2. sink {DASH} `app/export.py:30` {DASH} `export_invoices()` {DASH} query runs without a tenant filter

## Control

- intended control: tenant filter, absent
- why it fails: missing on this path
- other controls checked: middleware at app/auth.py:8 authenticates only

## Conditions

- attacker has an account {DASH} source-visible

## Impact

- victim or resource: tenant B invoices
- result: read of all invoice rows
- not claimed: no write shown

## Evidence

- read: app/routes.py:1-40, app/export.py:1-60
- tools: none
- reproduction: none
- proof test: text only, not run

## Reproduction waiver

- deterministic steps: every step is plain code in the repository
- runtime dependencies checked: none needed
- what reproduction would add: shows the wrong-tenant rows in a local test
- recommended confirmation: one test with two tenants

## Disprove attempts

1. checked elsewhere {DASH} read app/auth.py:1-30 {DASH} finding-not-disproved

## Severity

- likelihood: high {DASH} any account
- impact: high {DASH} cross-tenant read
- overall: high {DASH} same as impact
- confidence: 85 {DASH} short path

## Blocker

none

## Rejection

none

## Resolution

none

## Fix

- invariant: an export returns rows of the caller's tenant only
- change: filter by the session tenant at app/export.py:30
- regression test: two tenants, assert deny
- variants: searched: none found
"""

NEEDS_VALIDATION = (
    CONFIRMED.replace("authz.invoice-export.missing-tenant-check", "http.admin-allowlist.forwarded-header")
    .replace("- status: confirmed", "- status: needs-validation")
    .replace("app/export.py#export_invoices", "app/admin.py#client_ip")
    .replace(f"- likelihood: high {DASH} any account", "- likelihood: none")
    .replace(f"- impact: high {DASH} cross-tenant read", "- impact: none")
    .replace(f"- overall: high {DASH} same as impact", "- overall: none")
    .replace(f"- confidence: 85 {DASH} short path", "- confidence: none")
    .replace(
        "## Blocker\n\nnone",
        "## Blocker\n\n- missing fact: does the proxy remove the client's header?\n"
        "- why not observable: outside the repository\n- safe check: owner reads the proxy rule",
    )
)

REJECTED = (
    NEEDS_VALIDATION.replace("http.admin-allowlist.forwarded-header", "authz.note-read.missing-check")
    .replace("- status: needs-validation", "- status: rejected")
    .replace("app/admin.py#client_ip", "app/notes.py#read_note")
    .replace("## Rejection\n\nnone", "## Rejection\n\n- reason: tenant_gate at app/auth.py:20 denies first")
)

COVERAGE = """# Coverage

| ID | Key | Surface | Boundary | Domain | Priority | Status | Paths read | Checks | Findings | Notes |
|----|-----|---------|----------|--------|----------|--------|------------|--------|----------|-------|
| U001 | k1 | GET /notes | tenant gate | authz | 1 | covered | app/notes.py:1-40, app/auth.py:1-30 | ownership holds | | |
| U002 | k2 | GET /export | tenant filter | authz | 1 | candidate | `app/export.py:1-60` | export path: candidate | F-authz.invoice-export.missing-tenant-check | |
| U003 | k3 | admin | ip allow-list | http-protocol | 2 | deferred | | | | quick profile |
"""

LEADS = """# Leads

## Tools run
| Tool | Version | Command | Result | Notes |
|------|---------|---------|--------|-------|
| bandit | absent | | | absent |

## Leads
| ID | Source | Location | Hypothesis | Unit | Status |
|----|--------|----------|------------|------|--------|
| L001 | pattern | app/export.py:30 | no tenant filter | U002 | traced |
"""

REPORT = (
    "# Report\n\nauthz.invoice-export.missing-tenant-check\nhttp.admin-allowlist.forwarded-header\n"
    "authz.note-read.missing-check\n\n" + audit_run.FINAL_SENTENCE + ". Further or deeper runs may find more.\n\n"
    "Consistency check: passed\n"
)


def make_run(directory, confirmed=CONFIRMED):
    run = Path(directory)
    (run / "findings").mkdir()
    files = {
        "plan.md": "# Audit plan\n",
        "coverage.md": COVERAGE,
        "leads.md": LEADS,
        "REPORT.md": REPORT,
        "findings/F-authz.invoice-export.missing-tenant-check.md": confirmed,
        "findings/F-http.admin-allowlist.forwarded-header.md": NEEDS_VALIDATION,
        "findings/F-authz.note-read.missing-check.md": REJECTED,
    }
    for name, text in files.items():
        (run / name).write_text(text, encoding="utf-8", newline="\n")
    return run


class AuditRunTest(unittest.TestCase):
    def test_clean_run_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            errors, warnings, summary = audit_run.check_run(make_run(directory))
        self.assertEqual(errors, [])
        self.assertEqual(warnings, [])
        self.assertIn("Findings: 3 (proposed 0, confirmed 1, needs-validation 1, rejected 1, fixed 0)", summary)
        self.assertIn("Confirmed by evidence level: E1 1, E2 0, E3 0", summary)
        self.assertIn("Units: 3 (covered 1, candidate 1, deferred 1)", summary)

    def test_rule_violations_are_errors(self):
        cases = {
            "must not have a severity": NEEDS_VALIDATION.replace("- impact: none", "- impact: high"),
            "needs a reproduction waiver": CONFIRMED.replace(
                "- deterministic steps: every step is plain code in the repository", "- deterministic steps: none"
            ),
            "overall severity is above impact": CONFIRMED.replace(
                f"- overall: high {DASH} same as impact", "- overall: critical"
            ),
            "needs E3 to be confirmed": CONFIRMED.replace("- domain: authz", "- domain: memory-safety"),
            "one entry step and one sink step": CONFIRMED.replace(f"2. sink {DASH}", f"2. step {DASH}"),
            "no disprove attempts": CONFIRMED.replace(
                f"1. checked elsewhere {DASH} read app/auth.py:1-30 {DASH} finding-not-disproved", "none"
            ),
        }
        for expected, text in cases.items():
            with self.subTest(expected), tempfile.TemporaryDirectory() as directory:
                run = make_run(directory)
                name = "F-http.admin-allowlist.forwarded-header.md" if "needs-validation" in text else (
                    "F-authz.invoice-export.missing-tenant-check.md"
                )
                (run / "findings" / name).write_text(text, encoding="utf-8", newline="\n")
                errors, _, _ = audit_run.check_run(run)
                self.assertTrue(any(expected in e for e in errors), errors)

    def test_ledger_and_report_violations(self):
        with tempfile.TemporaryDirectory() as directory:
            run = make_run(directory)
            (run / "coverage.md").write_text(
                COVERAGE.replace("| covered | app/notes.py:1-40, app/auth.py:1-30 |", "| covered | |")
                .replace("F-authz.invoice-export.missing-tenant-check", "F-authz.other.thing"),
                encoding="utf-8",
            )
            (run / "REPORT.md").write_text("# Report\n", encoding="utf-8")
            errors, _, _ = audit_run.check_run(run)
        joined = "\n".join(errors)
        self.assertIn("U001 is 'covered' but 'paths read' is empty", joined)
        self.assertIn("cites F-authz.other.thing, which has no finding file", joined)
        self.assertIn("does not appear in the report", joined)
        self.assertIn("fixed coverage sentence is missing", joined)

    def test_duplicate_root_cause_is_a_warning(self):
        with tempfile.TemporaryDirectory() as directory:
            run = make_run(directory)
            twin = CONFIRMED.replace("authz.invoice-export.missing-tenant-check", "api.export.idor")
            (run / "findings" / "F-api.export.idor.md").write_text(twin, encoding="utf-8")
            (run / "REPORT.md").write_text(REPORT + "api.export.idor\n", encoding="utf-8")
            errors, warnings, _ = audit_run.check_run(run)
        self.assertEqual(errors, [])
        self.assertTrue(any("same root-cause-at 'app/export.py#export_invoices'" in w for w in warnings), warnings)

    def test_stats_counts_files_read(self):
        with tempfile.TemporaryDirectory() as directory:
            run = make_run(directory)
            listing = run / "files.txt"
            listing.write_text("app/notes.py\napp/auth.py\napp/export.py\napp/routes.py\napp/admin.py\n", encoding="utf-8")
            lines = audit_run.file_stats(run, listing, 50)
        self.assertEqual(lines[:3], ["In-scope files: 5", "Read at least once: 4 (80.0%)", "Unread: 1"])
        self.assertEqual(lines[3].strip(), "app/admin.py")

    def test_export_writes_json_and_sarif(self):
        with tempfile.TemporaryDirectory() as directory:
            run = make_run(directory)
            audit_run.export(run, overwrite=False)
            with self.assertRaises(SystemExit):
                audit_run.export(run, overwrite=False)
            findings = json.loads((run / "findings.json").read_text(encoding="utf-8"))
            sarif = json.loads((run / "findings.sarif").read_text(encoding="utf-8"))
        self.assertEqual(len(findings), 3)
        first = next(f for f in findings if f["status"] == "confirmed")
        self.assertEqual(first["path"][1], {
            "kind": "sink", "file": "app/export.py", "line": 30,
            "scope": "export_invoices()", "description": "query runs without a tenant filter",
        })
        results = sarif["runs"][0]["results"]
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual([r["level"] for r in results], ["error", "note"])
        self.assertEqual(results[1]["properties"]["status"], "needs-validation")
        self.assertEqual(results[0]["locations"][0]["physicalLocation"]["region"]["startLine"], 30)
        self.assertEqual(len(results[0]["codeFlows"][0]["threadFlows"][0]["locations"]), 2)
        self.assertEqual(len(sarif["runs"][0]["tool"]["driver"]["rules"]), 2)

    def test_parser_matches_the_shipped_template(self):
        """The template and the checker must agree on every section and field name."""
        finding = audit_run.parse_finding(ROOT / "assets" / "finding-template.md")
        self.assertEqual(sorted(audit_run.SECTIONS), finding["sections"])
        for key in audit_run.CORE_HEADER + audit_run.NEWER_HEADER:
            self.assertIn(key, finding)
        self.assertEqual([s["kind"] for s in finding["path"]], ["entry", "step", "sink"])
        self.assertEqual(sorted(finding["severity"]), ["confidence", "impact", "likelihood", "overall"])
        self.assertEqual(sorted(finding["blocker"]), ["missing-fact", "safe-check", "why-not-observable"])
        self.assertEqual(sorted(finding["resolution"]), ["checked", "fixed-by"])
        self.assertIn("deterministic-steps", finding["reproduction-waiver"])
        self.assertIn("variants", finding["fix"])


if __name__ == "__main__":
    unittest.main()
