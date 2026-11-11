#!/usr/bin/env python3
"""Validate this skill's metadata, local Markdown links and reference-file structure.

Requires PyYAML. Checks package structure only, not security-audit quality.
"""

import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

import yaml


def prose(text):
    """Exclude fenced and inline code before inspecting Markdown links."""
    result = []
    fence = None
    for line in text.splitlines():
        marker = re.match(r"^\s*(`{3,}|~{3,})(.*)$", line)
        if marker:
            token, suffix = marker.groups()
            if fence is None:
                fence = token
            elif token[0] == fence[0] and len(token) >= len(fence) and not suffix.strip():
                fence = None
            continue
        if fence is None:
            result.append(re.sub(r"(`+).*?\1", "", line))
    return "\n".join(result)


def anchors(text):
    result = set()
    counts = {}
    # Keep inline heading text when computing GitHub-style anchors.
    fence = None
    for line in text.splitlines():
        marker = re.match(r"^\s*(`{3,}|~{3,})(.*)$", line)
        if marker:
            token, suffix = marker.groups()
            if fence is None:
                fence = token
            elif token[0] == fence[0] and len(token) >= len(fence) and not suffix.strip():
                fence = None
            continue
        heading = re.match(r"^#{1,6}\s+(.+?)\s*#*\s*$", line)
        if fence is not None or heading is None:
            continue
        slug = re.sub(r"[^\w\-\s]", "", heading.group(1).lower()).replace(" ", "-")
        count = counts.get(slug, 0)
        counts[slug] = count + 1
        result.add(f"{slug}-{count}" if count else slug)
    return result


DOMAIN_SECTIONS = [
    "Scope", "Invariants", "Recon additions", "Lead searches", "Attack classes",
    "Variant search", "Chain primitives", "Verification notes", "Fix patterns", "Regression tests",
]
LANGUAGE_SECTIONS = [
    "Scope", "Entry points", "Sinks by domain", "Language traps", "Deserialisation and reflection",
    "Concurrency", "Build and runtime settings", "Tools", "Lead searches", "Verification notes",
]


def second_level_headings(text):
    result = []
    fence = None
    for line in text.splitlines():
        marker = re.match(r"^\s*(`{3,}|~{3,})", line)
        if marker:
            fence = None if fence == marker.group(1)[0] else (fence or marker.group(1)[0])
        elif fence is None and line.startswith("## "):
            result.append(line[3:].strip())
    return result


def reference_errors(root, skill_text):
    """SKILL.md section 5 tells the agent to read named sections of these files, so their shape is a contract."""
    errors = []
    references = root / "references"
    for prefix, expected in (("domain-", DOMAIN_SECTIONS), ("lang-", LANGUAGE_SECTIONS)):
        listed = set(re.findall(r"references/(" + prefix + r"[a-z0-9-]+\.md)", skill_text))
        for document in sorted(references.glob(prefix + "*.md")):
            if document.name not in listed:
                errors.append(f"references/{document.name}: not listed in SKILL.md section 5")
            found = second_level_headings(document.read_text(encoding="utf-8-sig"))
            if found != expected:
                errors.append(f"references/{document.name}: sections differ from the standard ten: {found}")
    recon = references / "phase-recon.md"
    if recon.is_file():
        table = re.search(r"^\| Product type \|.*?(?=^\s*$)", recon.read_text(encoding="utf-8-sig"), re.M | re.S)
        for row in (table.group(0).splitlines()[2:] if table else []):
            cells = [cell.strip() for cell in row.strip().strip("|").split("|")]
            for name in re.sub(r"\([^)]*\)", "", cells[1] if len(cells) > 1 else "").split(","):
                if name.strip() and not (references / f"domain-{name.strip()}.md").is_file():
                    errors.append(f"references/phase-recon.md: product row '{cells[0]}' names unknown domain '{name.strip()}'")
    return errors


def validate(root):
    root = Path(root).resolve()
    errors = []
    skill = root / "SKILL.md"
    if not skill.is_file():
        return ["SKILL.md is missing"]
    text = skill.read_text(encoding="utf-8-sig")
    frontmatter = re.match(r"\A---\r?\n(.*?)\r?\n---(?:\r?\n|$)", text, re.S)
    if not frontmatter:
        return ["SKILL.md: missing YAML frontmatter"]
    try:
        data = yaml.safe_load(frontmatter.group(1))
    except yaml.YAMLError as exc:
        return [f"SKILL.md: invalid YAML: {exc}"]
    if not isinstance(data, dict):
        return ["SKILL.md: frontmatter must be a mapping"]
    allowed = {"name", "description", "license", "compatibility", "metadata", "allowed-tools"}
    for key in data.keys() - allowed:
        errors.append(f"SKILL.md: unsupported frontmatter field {key!r}")
    name = data.get("name")
    if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name) or len(name) > 64:
        errors.append("SKILL.md: name must use lowercase letters, digits and single hyphens, at most 64 characters")
    for key, limit in (("description", 1024), ("compatibility", 500)):
        value = data.get(key)
        if key == "compatibility" and key not in data:
            continue
        if not isinstance(value, str) or not value.strip() or len(value) > limit:
            errors.append(f"SKILL.md: {key} must be a nonempty string, at most {limit} characters")
    metadata = data.get("metadata", {})
    if not isinstance(metadata, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in metadata.items()):
        errors.append("SKILL.md: metadata keys and values must be strings")
    for key in ("license", "allowed-tools"):
        if key in data and not isinstance(data[key], str):
            errors.append(f"SKILL.md: {key} must be a string")

    markdown = [skill, root / "README.md"]
    for directory in ("references", "assets", "evaluations"):
        markdown.extend((root / directory).rglob("*.md"))
    for document in markdown:
        if not document.is_file():
            continue
        content = prose(document.read_text(encoding="utf-8-sig"))
        for match in re.finditer(r"\[[^\]\n]+\]\(([^)\n]+)\)", content):
            destination = match.group(1).strip()
            # This package uses inline links with no optional title.
            if destination.startswith("<") and destination.endswith(">"):
                destination = destination[1:-1]
            parts = urlsplit(destination)
            if parts.scheme or parts.netloc:
                continue
            target = (document.parent / unquote(parts.path)).resolve() if parts.path else document
            label = f"{document.relative_to(root)}: {destination}"
            if not target.is_relative_to(root):
                errors.append(f"{label}: link leaves the package")
            elif not target.is_file():
                errors.append(f"{label}: missing file")
            elif parts.fragment and target.suffix.lower() == ".md":
                if unquote(parts.fragment) not in anchors(target.read_text(encoding="utf-8-sig")):
                    errors.append(f"{label}: missing heading anchor")
    errors.extend(reference_errors(root, text))
    return errors


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python scripts/validate_skill.py <skill-directory>", file=sys.stderr)
        sys.exit(2)
    problems = validate(sys.argv[1])
    for problem in problems:
        print(problem, file=sys.stderr)
    if not problems:
        print("Skill metadata, local Markdown links and reference structure: passed")
    sys.exit(1 if problems else 0)
