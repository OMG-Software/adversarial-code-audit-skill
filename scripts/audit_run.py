#!/usr/bin/env python3
"""Check, measure and export one audit run directory of the adversarial-code-audit skill.

Reads the audit's own Markdown files as data. Never reads or runs the audited target.
Standard library only; Python 3.10 or later.

    audit_run.py check  <run-directory>
    audit_run.py stats  <run-directory> --files <list of in-scope repository paths>
    audit_run.py export <run-directory> [--overwrite]
"""

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

STATUSES = ("proposed", "confirmed", "needs-validation", "rejected", "fixed")
LEVELS = ("informational", "low", "medium", "high", "critical")
LIKELIHOODS = ("low", "medium", "high")
EVIDENCE = ("E1", "E2", "E3")
UNIT_STATUSES = (
    "planned", "in-progress", "covered", "candidate", "blocked",
    "deferred", "out-of-scope", "not-applicable",
)
CORE_HEADER = (
    "fingerprint", "status", "evidence-level", "domain", "cwe",
    "coverage-units", "found-by", "verified-by", "source-ref",
)
NEWER_HEADER = ("root-cause-at", "first-seen")
SECTIONS = (
    "Header", "Summary", "Regression origin", "Attacker", "Path", "Control",
    "Conditions", "Impact", "Evidence", "Reproduction waiver", "Disprove attempts",
    "Severity", "Blocker", "Rejection", "Resolution", "Fix",
)
FINAL_SENTENCE = "This audit does not show that the code has no other vulnerabilities"
SEPARATOR = re.compile(r"\s+[–—-]\s+")
FIELD = re.compile(r"^- ([A-Za-z][A-Za-z -]{0,40}?):\s*(.*)$")
FENCE = re.compile(r"^\s*(`{3,}|~{3,})")


def blank(value):
    """True for an empty field, "none", "n/a" or a template placeholder left unfilled."""
    if value is None:
        return True
    text = value.strip().strip("\"'`").strip()
    return text.lower() in ("", "none", "n/a") or bool(re.fullmatch(r"<[^<>]*>", text))


def key_of(label):
    return re.sub(r"\s+", "-", label.strip().lower())


def split_sections(text):
    """Return (title, {section name: [lines]}), ignoring headings inside code fences."""
    title, sections, current, fence = "", {}, None, None
    for line in text.splitlines():
        marker = FENCE.match(line)
        if marker:
            token = marker.group(1)
            if fence is None:
                fence = token[0]
            elif token[0] == fence:
                fence = None
        elif fence is None:
            if line.startswith("# ") and not title:
                title = line[2:].strip()
                continue
            if line.startswith("## "):
                current = line[3:].strip()
                sections[current] = []
                continue
        if current is not None:
            sections[current].append(line)
    return title, sections


def parse_section(lines):
    """Return ({field: value}, [list items], plain text) for one section body."""
    fields, items, text, last = {}, [], [], None
    for line in lines:
        field = FIELD.match(line)
        numbered = re.match(r"^\d+\.\s+(.*)$", line)
        if field:
            last = key_of(field.group(1))
            fields[last] = field.group(2).strip()
            items.append(line[2:].strip())
        elif numbered or line.startswith("- "):
            last = None
            items.append(numbered.group(1).strip() if numbered else line[2:].strip())
        elif last is not None and line.strip():
            fields[last] = (fields[last] + "\n" + line.rstrip()).strip()
        elif line.strip():
            text.append(line.strip())
    return fields, items, " ".join(text)


def parse_step(item):
    parts = SEPARATOR.split(item, maxsplit=3)
    parts += [""] * (4 - len(parts))
    kind, location, scope, description = (p.strip().strip("`") for p in parts)
    match = re.match(r"^(.*?):(\d+)", location)
    file_name = (match.group(1) if match else location).replace("\\", "/")
    return {
        "kind": kind.lower(),
        "file": "" if blank(file_name) else file_name,
        "line": int(match.group(2)) if match else None,
        "scope": scope,
        "description": description,
    }


def parse_finding(path):
    title, raw = split_sections(path.read_text(encoding="utf-8-sig"))
    parsed = {name: parse_section(lines) for name, lines in raw.items()}

    def fields(name):
        return parsed.get(name, ({}, [], ""))[0]

    def items(name):
        return parsed.get(name, ({}, [], ""))[1]

    finding = {"file": path.name, "title": title, "sections": sorted(raw)}
    header = fields("Header")
    finding.update({key: header[key] for key in CORE_HEADER + NEWER_HEADER if key in header})
    finding["summary"] = parsed.get("Summary", ({}, [], ""))[2]
    finding["regression-origin"] = parsed.get("Regression origin", ({}, [], ""))[2]
    finding["attacker"] = fields("Attacker")
    finding["path"] = [parse_step(i) for i in items("Path") if SEPARATOR.search(i)]
    finding["control"] = fields("Control")
    finding["conditions"] = [i for i in items("Conditions") if not blank(i)]
    finding["impact"] = fields("Impact")
    finding["evidence"] = fields("Evidence")
    finding["reproduction-waiver"] = fields("Reproduction waiver")
    finding["disprove-attempts"] = [i for i in items("Disprove attempts") if not blank(i)]
    finding["severity"] = fields("Severity")
    finding["blocker"] = fields("Blocker")
    finding["rejection"] = fields("Rejection")
    finding["resolution"] = fields("Resolution")
    finding["fix"] = fields("Fix")
    return finding


def level_of(value, allowed):
    match = re.match(r"[a-z-]+", (value or "").strip().lower())
    return match.group(0) if match and match.group(0) in allowed else None


def confidence_of(finding):
    match = re.match(r"\d+", (finding["severity"].get("confidence") or "").strip())
    return int(match.group(0)) if match else None


def name_of(finding):
    """The fingerprint, or the file name without F- and .md when the header has none."""
    return (finding.get("fingerprint") or "").strip() or finding["file"][2:-3]


def load_findings(run):
    directory = run / "findings"
    return [parse_finding(p) for p in sorted(directory.glob("F-*.md"))] if directory.is_dir() else []


def read_tables(path):
    """Return every Markdown table in a file as a list of {header: cell} rows."""
    tables, header = [], None
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        if not line.strip().startswith("|"):
            header = None
            continue
        cells = [c.strip() for c in re.split(r"(?<!\\)\|", line.strip().strip("|"))]
        if header is None:
            header = [c.lower() for c in cells]
            tables.append([])
        elif all(re.fullmatch(r":?-{2,}:?", c) for c in cells if c) and not tables[-1]:
            continue
        else:
            tables[-1].append(dict(zip(header, cells)))
    return tables


def table_with(path, *columns):
    if not path.is_file():
        return None
    for table in read_tables(path):
        if table and all(c in table[0] for c in columns):
            return table
    return []


def check_finding(f, errors, warnings):
    name = f["file"]

    def error(message):
        errors.append(f"findings/{name}: {message}")

    def warn(message):
        warnings.append(f"findings/{name}: {message}")

    for section in SECTIONS:
        if section not in f["sections"] and section not in ("Resolution",):
            error(f"section '{section}' is missing")
    for key in CORE_HEADER:
        if key not in f:
            error(f"header field '{key}' is missing")
    for key in NEWER_HEADER:
        if blank(f.get(key)):
            warn(f"header field '{key}' is empty (required since skill version 0.11.0)")

    status = (f.get("status") or "").strip()
    if status not in STATUSES:
        error(f"status '{status}' is not one of {', '.join(STATUSES)}")
        return
    fingerprint = (f.get("fingerprint") or "").strip()
    if not re.fullmatch(r"[a-z0-9]+(?:[.-][a-z0-9]+)*", fingerprint):
        error("fingerprint must use lowercase letters, digits, hyphens and dots only")
    elif name != f"F-{fingerprint}.md":
        error(f"file name does not match the fingerprint (expected F-{fingerprint}.md)")
    evidence = (f.get("evidence-level") or "").strip()
    if evidence not in EVIDENCE:
        (error if status == "confirmed" else warn)(f"evidence-level '{evidence}' is not E1, E2 or E3")

    severity = f["severity"]
    if status == "confirmed":
        impact = level_of(severity.get("impact"), LEVELS)
        overall = level_of(severity.get("overall"), LEVELS)
        if level_of(severity.get("likelihood"), LIKELIHOODS) is None:
            error("confirmed finding needs a likelihood of low, medium or high")
        if impact is None or overall is None:
            error("confirmed finding needs an impact and an overall severity")
        elif LEVELS.index(overall) > LEVELS.index(impact):
            error("overall severity is above impact")
        confidence = confidence_of(f)
        if confidence is None or confidence > 100:
            error("confirmed finding needs a confidence from 0 to 100")
        if evidence == "E3":
            if blank(f["evidence"].get("reproduction")):
                error("E3 needs a completed reproduction in the Evidence section")
        elif blank(f["reproduction-waiver"].get("deterministic-steps")):
            error("confirmed at E1 or E2 needs a reproduction waiver")
        if evidence in ("E1", "E2") and (f.get("domain") or "").strip() == "memory-safety":
            error("a memory-safety finding needs E3 to be confirmed")
        if not f["disprove-attempts"]:
            error("confirmed finding has no disprove attempts")
    elif any(not blank(v) for v in severity.values()):
        error(f"a {status} finding must not have a severity")

    if status == "needs-validation":
        if blank(f["blocker"].get("missing-fact")) or blank(f["blocker"].get("safe-check")):
            error("needs-validation finding needs a missing fact and a safe check")
    if status == "rejected" and blank(f["rejection"].get("reason")):
        error("rejected finding needs a rejection reason")
    if status == "fixed" and blank(f["resolution"].get("fixed-by")):
        error("fixed finding needs 'fixed-by' in the Resolution section")
    if status != "proposed":
        if blank(f.get("verified-by")):
            error(f"a {status} finding needs 'verified-by'")
        elif (f.get("verified-by") or "").strip() == (f.get("found-by") or "").strip():
            warn("verified-by equals found-by: the verifier must not be the hunter")

    if status != "rejected":
        kinds = [step["kind"] for step in f["path"]]
        if "entry" not in kinds or "sink" not in kinds:
            error("path needs at least one entry step and one sink step")
        for number, step in enumerate(f["path"], 1):
            if not step["file"]:
                error(f"path step {number} has no file")
            elif step["line"] is None:
                warn(f"path step {number} has no line number")
        contract = (
            ("attacker", "principal"), ("control", "why-it-fails"),
            ("impact", "result"), ("evidence", "read"),
        )
        for section, key in contract:
            if blank(f[section].get(key)):
                error(f"contract field '{key}' in {section.capitalize()} is empty")
        if blank(f["fix"].get("variants")):
            warn("no variant search recorded in Fix")


def check_run(run):
    """Return (errors, warnings, summary lines) for one run directory."""
    errors, warnings, summary = [], [], []
    if not (run / "plan.md").is_file():
        errors.append("plan.md is missing")
    findings = load_findings(run)
    for f in findings:
        check_finding(f, errors, warnings)

    by_status = Counter((f.get("status") or "").strip() for f in findings)
    confirmed = [f for f in findings if (f.get("status") or "").strip() == "confirmed"]
    summary.append("Findings: %d (%s)" % (len(findings), ", ".join(f"{s} {by_status[s]}" for s in STATUSES)))
    by_evidence = Counter((f.get("evidence-level") or "").strip() for f in confirmed)
    summary.append("Confirmed by evidence level: " + ", ".join(f"{e} {by_evidence[e]}" for e in EVIDENCE))
    by_severity = Counter(level_of(f["severity"].get("overall"), LEVELS) for f in confirmed)
    summary.append("Confirmed by overall severity: " + ", ".join(f"{s} {by_severity[s]}" for s in reversed(LEVELS)))

    places = {}
    for f in findings:
        place = (f.get("root-cause-at") or "").strip()
        if (f.get("status") or "").strip() != "rejected" and not blank(place):
            places.setdefault(place, []).append(f["file"])
    for place, names in sorted(places.items()):
        if len(names) > 1:
            warnings.append(f"same root-cause-at '{place}' in {', '.join(names)}: merge if the same control fails")

    names = {f["file"][:-3] for f in findings}
    units = table_with(run / "coverage.md", "id", "status")
    if units is None:
        summary.append("Units: no coverage.md (expected only in Focused mode)")
    else:
        seen = Counter(row.get("id", "") for row in units)
        for unit, count in seen.items():
            if count > 1:
                errors.append(f"coverage.md: unit ID '{unit}' appears {count} times")
        for row in units:
            unit, status = row.get("id", "?"), row.get("status", "")
            if status not in UNIT_STATUSES:
                errors.append(f"coverage.md: {unit} has status '{status}'")
                continue
            needs = {
                "covered": ("paths read", "checks"),
                "candidate": ("paths read", "checks", "findings"),
                "blocked": ("paths read", "checks", "notes"),
                "deferred": ("notes",),
                "not-applicable": ("notes",),
            }.get(status, ())
            for column in needs:
                if not row.get(column, "").strip():
                    errors.append(f"coverage.md: {unit} is '{status}' but '{column}' is empty")
            for cited in re.findall(r"F-[a-z0-9][a-z0-9.-]*[a-z0-9]", row.get("findings", "")):
                if cited not in names:
                    errors.append(f"coverage.md: {unit} cites {cited}, which has no finding file")
        by_unit = Counter(row.get("status", "") for row in units)
        summary.append("Units: %d (%s)" % (len(units), ", ".join(f"{s} {by_unit[s]}" for s in UNIT_STATUSES if by_unit[s])))
        open_units = by_unit["planned"] + by_unit["in-progress"]
        if open_units:
            warnings.append(f"coverage.md: {open_units} units are still planned or in-progress")

    leads = table_with(run / "leads.md", "id", "hypothesis", "status")
    if leads:
        by_lead = Counter(row.get("status", "").split()[0] if row.get("status") else "" for row in leads)
        summary.append("Leads: %d (%s)" % (len(leads), ", ".join(f"{s} {n}" for s, n in sorted(by_lead.items()))))
        if by_lead["open"]:
            warnings.append(f"leads.md: {by_lead['open']} leads are still open")

    report = run / "REPORT.md"
    if report.is_file():
        text = report.read_text(encoding="utf-8-sig")
        for f in findings:
            fingerprint = (f.get("fingerprint") or "").strip()
            if fingerprint and fingerprint not in text:
                target = warnings if (f.get("status") or "").strip() == "rejected" else errors
                target.append(f"REPORT.md: finding {fingerprint} does not appear in the report")
        if units is not None and FINAL_SENTENCE not in text:
            errors.append("REPORT.md: the fixed coverage sentence is missing (phase-report.md section 9)")
        if "Consistency check:" not in text:
            warnings.append("REPORT.md: the 'Consistency check:' line is missing")
    else:
        summary.append("REPORT.md: not written yet")
    return errors, warnings, summary


def tokens_in(text):
    for token in re.split(r"[\s,;()\[\]<>|]+", text):
        token = re.sub(r":[\dL,–-]+$", "", token.strip("`'\"*.")).replace("\\", "/")
        if token:
            yield token[2:] if token.startswith("./") else token


def file_stats(run, list_path, limit):
    wanted = [line.strip().replace("\\", "/") for line in Path(list_path).read_text(encoding="utf-8-sig").splitlines()]
    wanted = [w[2:] if w.startswith("./") else w for w in wanted if w]
    in_scope = set(wanted)
    read = set()
    for row in table_with(run / "coverage.md", "id", "status") or []:
        read.update(t for t in tokens_in(row.get("paths read", "")) if t in in_scope)
    for f in load_findings(run):
        read.update(step["file"] for step in f["path"] if step["file"] in in_scope)
        read.update(t for t in tokens_in(f["evidence"].get("read", "")) if t in in_scope)
    unread = sorted(in_scope - read)
    share = 100.0 * len(read) / len(in_scope) if in_scope else 0.0
    lines = [f"In-scope files: {len(in_scope)}", f"Read at least once: {len(read)} ({share:.1f}%)", f"Unread: {len(unread)}"]
    lines += [f"  {name}" for name in unread[:limit]]
    if len(unread) > limit:
        lines.append(f"  ... and {len(unread) - limit} more")
    return lines


def skill_version():
    skill = Path(__file__).resolve().parent.parent / "SKILL.md"
    if skill.is_file():
        match = re.search(r'^\s*version:\s*"?([^"\n]+?)"?\s*$', skill.read_text(encoding="utf-8-sig"), re.M)
        if match:
            return match.group(1)
    return "unknown"


def physical(step):
    location = {"artifactLocation": {"uri": step["file"], "uriBaseId": "%SRCROOT%"}}
    if step["line"]:
        location["region"] = {"startLine": step["line"]}
    return {"physicalLocation": location}


def to_sarif(findings):
    rules, results = [], []
    for f in findings:
        status = (f.get("status") or "").strip()
        if status not in ("confirmed", "needs-validation"):
            continue
        overall = level_of(f["severity"].get("overall"), LEVELS)
        level = "note"
        if status == "confirmed":
            level = {"critical": "error", "high": "error", "medium": "warning"}.get(overall, "note")
        tags = [t for t in ((f.get("cwe") or "").strip(), (f.get("domain") or "").strip()) if not blank(t)]
        name = name_of(f)
        rules.append({
            "id": name,
            "shortDescription": {"text": f["title"] or name},
            "properties": {"tags": tags},
        })
        steps = [s for s in f["path"] if s["file"]]
        sinks = [s for s in steps if s["kind"] == "sink"] or steps[-1:]
        result = {
            "ruleId": name,
            "ruleIndex": len(rules) - 1,
            "level": level,
            "message": {"text": f["summary"] or f["title"] or name},
            "locations": [physical(s) for s in sinks[-1:]],
            "partialFingerprints": {"rootCause/v1": name},
            "properties": {
                "status": status,
                "evidence-level": (f.get("evidence-level") or "").strip(),
                "likelihood": level_of(f["severity"].get("likelihood"), LIKELIHOODS),
                "impact": level_of(f["severity"].get("impact"), LEVELS),
                "overall": overall,
                "confidence": confidence_of(f),
            },
        }
        if steps:
            flow = [dict(location=dict(physical(s), message={"text": f"{s['kind']}: {s['description']}".strip(": ")})) for s in steps]
            result["codeFlows"] = [{"threadFlows": [{"locations": flow}]}]
        results.append(result)
    driver = {"name": "adversarial-code-audit", "version": skill_version(), "rules": rules}
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": driver}, "results": results}],
    }


def export(run, overwrite):
    findings = load_findings(run)
    outputs = {
        run / "findings.json": [{k: v for k, v in f.items() if k not in ("file", "sections")} for f in findings],
        run / "findings.sarif": to_sarif(findings),
    }
    existing = [p.name for p in outputs if p.exists()]
    if existing and not overwrite:
        raise SystemExit(f"refusing to overwrite {', '.join(existing)}: pass --overwrite if this run created them")
    for path, data in outputs.items():
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    return [f"Wrote {p.name}" for p in outputs] + [
        f"findings.json: {len(findings)} findings; findings.sarif: {len(outputs[run / 'findings.sarif']['runs'][0]['results'])} results"
    ]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("check", "stats", "export"):
        sub = commands.add_parser(name)
        sub.add_argument("run", type=Path, help="the run directory that holds plan.md and findings/")
        if name == "stats":
            sub.add_argument("--files", required=True, help="text file with one in-scope repository path per line")
            sub.add_argument("--limit", type=int, default=50, help="how many unread files to print")
        if name == "export":
            sub.add_argument("--overwrite", action="store_true", help="replace findings.json and findings.sarif")
    args = parser.parse_args(argv)
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    if not args.run.is_dir():
        raise SystemExit(f"{args.run} is not a directory")
    if args.command == "check":
        errors, warnings, summary = check_run(args.run)
        print("\n".join(summary))
        for label, messages in (("WARNING", warnings), ("ERROR", errors)):
            for message in messages:
                print(f"{label}: {message}")
        print(f"Check: {'failed' if errors else 'passed'} ({len(errors)} errors, {len(warnings)} warnings)")
        return 1 if errors else 0
    if args.command == "stats":
        print("\n".join(file_stats(args.run, args.files, args.limit)))
        return 0
    print("\n".join(export(args.run, args.overwrite)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
