#!/usr/bin/env python3
"""
validate_skills.py — repo validation for the reverse-engineering skill.

Zero dependencies (no PyYAML): parses the simple YAML frontmatter manually.
Run from the repository root:

    python .github/scripts/validate_skills.py

Checks:
    1. Every skills/*/SKILL.md exists, with valid frontmatter:
       - name: kebab-case, <= 64 chars, matches folder name
       - description: non-empty, <= 1024 chars, no XML tags
    2. Bundled-file references inside SKILL.md exist on disk.
    3. .claude-plugin/plugin.json and marketplace.json are valid JSON
       with the required fields.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
RESERVED_NAMES = {"anthropic", "claude"}

errors: list[str] = []


def fail(message: str) -> None:
    errors.append(message)
    print(f"FAIL  {message}")


def ok(message: str) -> None:
    print(f"ok    {message}")


def parse_frontmatter(text: str) -> dict[str, str]:
    """Extract top-level scalar keys from YAML frontmatter (no dependencies)."""
    if not text.startswith("---"):
        return {}
    end = text.find("\n---", 3)
    if end == -1:
        return {}
    fields: dict[str, str] = {}
    for line in text[3:end].strip().splitlines():
        if line and not line[0].isspace() and ":" in line:
            key, _, value = line.partition(":")
            fields[key.strip()] = value.strip()
    return fields


def validate_skill(skill_dir: Path) -> None:
    skill_md = skill_dir / "SKILL.md"
    if not skill_md.is_file():
        fail(f"{skill_dir}: missing SKILL.md")
        return

    text = skill_md.read_text(encoding="utf-8")
    fields = parse_frontmatter(text)

    name = fields.get("name", "")
    if not name:
        fail(f"{skill_md}: frontmatter missing 'name'")
    elif not re.fullmatch(r"[a-z0-9-]{1,64}", name):
        fail(f"{skill_md}: name '{name}' must be kebab-case, <= 64 chars")
    elif any(word in name for word in RESERVED_NAMES):
        fail(f"{skill_md}: name '{name}' uses a reserved word")
    elif name != skill_dir.name:
        fail(f"{skill_md}: name '{name}' does not match folder '{skill_dir.name}'")
    else:
        ok(f"{skill_md}: name '{name}'")

    description = fields.get("description", "")
    if not description:
        fail(f"{skill_md}: frontmatter missing 'description'")
    elif len(description) > 1024:
        fail(f"{skill_md}: description too long ({len(description)} > 1024 chars)")
    elif "<" in description or ">" in description:
        fail(f"{skill_md}: description must not contain XML tags")
    else:
        ok(f"{skill_md}: description ({len(description)} chars)")

    body_lines = text.splitlines()
    if len(body_lines) > 500:
        fail(f"{skill_md}: body is {len(body_lines)} lines; keep it under 500, move detail to references/")
    else:
        ok(f"{skill_md}: {len(body_lines)} lines")

    for ref in sorted(set(re.findall(r"(?:references|scripts|assets)/[\w.\-]+", text))):
        target = skill_dir / ref
        if target.is_file():
            ok(f"{skill_md}: bundled file exists: {ref}")
        else:
            fail(f"{skill_md}: references missing file: {ref}")


def validate_json(path: Path, required: list[str]) -> None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"{path}: invalid JSON ({exc})")
        return
    for key in required:
        if key not in data:
            fail(f"{path}: missing required field '{key}'")
        else:
            ok(f"{path}: has '{key}'")


def main() -> int:
    skills_root = ROOT / "skills"
    skill_dirs = sorted(d for d in skills_root.iterdir() if d.is_dir()) if skills_root.is_dir() else []
    if not skill_dirs:
        fail("no skills found under skills/")
    for skill_dir in skill_dirs:
        validate_skill(skill_dir)

    validate_json(ROOT / ".claude-plugin" / "plugin.json", ["name", "description"])
    validate_json(ROOT / ".claude-plugin" / "marketplace.json", ["name", "owner", "plugins"])

    print()
    if errors:
        print(f"{len(errors)} problem(s) found.")
        return 1
    print("All checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
