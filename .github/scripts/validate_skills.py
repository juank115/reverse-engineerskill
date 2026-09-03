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
       - metadata.version: semantic version
    2. Explicit Markdown links to bundled resources resolve inside the skill,
       and every bundled file is linked from SKILL.md.
    3. Claude plugin and marketplace manifests contain required fields.
    4. Skill, plugin, and marketplace versions are identical.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parent.parent.parent
RESERVED_NAMES = {"anthropic", "claude"}
BUNDLED_DIRS = ("references", "scripts", "assets")
SEMVER_RE = re.compile(
    r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)
MARKDOWN_LINK_RE = re.compile(
    r"!?\[[^\]]*\]\(\s*(?:<(?P<angled>[^>]+)>|(?P<plain>[^\s)]+))"
)

errors: list[str] = []


def fail(message: str) -> None:
    errors.append(message)
    print(f"FAIL  {message}")


def ok(message: str) -> None:
    print(f"ok    {message}")


def frontmatter_block(text: str) -> str:
    """Return YAML frontmatter contents, or an empty string when malformed."""
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return ""
    try:
        end = lines.index("---", 1)
    except ValueError:
        return ""
    return "\n".join(lines[1:end])


def parse_frontmatter(text: str) -> dict[str, str]:
    """Extract top-level scalar keys from YAML frontmatter (no dependencies)."""
    fields: dict[str, str] = {}
    for line in frontmatter_block(text).splitlines():
        if line and not line[0].isspace() and ":" in line:
            key, _, value = line.partition(":")
            fields[key.strip()] = value.strip()
    return fields


def parse_metadata_version(text: str) -> str:
    """Extract metadata.version from the skill's simple YAML frontmatter."""
    in_metadata = False
    for line in frontmatter_block(text).splitlines():
        if line.strip() == "metadata:" and not line[0].isspace():
            in_metadata = True
            continue
        if in_metadata and line and not line[0].isspace():
            break
        if in_metadata:
            match = re.fullmatch(r"\s+version:\s*([^\s#]+)\s*(?:#.*)?", line)
            if match:
                return match.group(1)
    return ""


def markdown_bundled_links(text: str) -> set[str]:
    """Return only explicit Markdown links into bundled resource directories."""
    links = set()
    prefixes = tuple(
        f"{name}{separator}" for name in BUNDLED_DIRS for separator in ("/", "\\")
    )
    for match in MARKDOWN_LINK_RE.finditer(text):
        destination = match.group("angled") or match.group("plain") or ""
        destination = destination.split("#", 1)[0]
        if destination.startswith(prefixes):
            links.add(destination)
    return links


def bundled_files(skill_dir: Path) -> set[str]:
    """Return maintained bundled files, ignoring generated Python cache files."""
    files = set()
    for dirname in BUNDLED_DIRS:
        root = skill_dir / dirname
        if not root.is_dir():
            continue
        for path in root.rglob("*"):
            if not path.is_file() or "__pycache__" in path.parts or path.suffix == ".pyc":
                continue
            files.add(path.relative_to(skill_dir).as_posix())
    return files


def validate_bundled_resources(skill_dir: Path, text: str) -> None:
    """Validate explicit links and ensure every shipped resource is discoverable."""
    linked = markdown_bundled_links(text)
    for ref in sorted(linked):
        if "\\" in ref:
            fail(f"{skill_dir / 'SKILL.md'}: bundled link must use forward slashes: {ref}")
            continue
        posix_path = PurePosixPath(ref)
        if posix_path.is_absolute() or ".." in posix_path.parts:
            fail(f"{skill_dir / 'SKILL.md'}: bundled link escapes the skill: {ref}")
            continue
        target = skill_dir.joinpath(*posix_path.parts)
        if target.is_file():
            ok(f"{skill_dir / 'SKILL.md'}: bundled file exists: {ref}")
        else:
            fail(f"{skill_dir / 'SKILL.md'}: bundled link targets missing file: {ref}")

    unlisted = bundled_files(skill_dir) - linked
    for ref in sorted(unlisted):
        fail(
            f"{skill_dir / 'SKILL.md'}: bundled file is not linked with Markdown: {ref}"
        )


def validate_skill(skill_dir: Path) -> tuple[str, str] | None:
    skill_md = skill_dir / "SKILL.md"
    if not skill_md.is_file():
        fail(f"{skill_dir}: missing SKILL.md")
        return None

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

    version = parse_metadata_version(text)
    if not version:
        fail(f"{skill_md}: frontmatter missing 'metadata.version'")
    elif not SEMVER_RE.fullmatch(version):
        fail(f"{skill_md}: metadata.version '{version}' is not semantic versioning")
    else:
        ok(f"{skill_md}: metadata.version '{version}'")

    body_lines = text.splitlines()
    if len(body_lines) > 500:
        fail(f"{skill_md}: body is {len(body_lines)} lines; keep it under 500, move detail to references/")
    else:
        ok(f"{skill_md}: {len(body_lines)} lines")

    validate_bundled_resources(skill_dir, text)
    return (name, version) if name and version else None


def validate_json(path: Path, required: list[str]) -> dict | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"{path}: invalid JSON ({exc})")
        return None
    if not isinstance(data, dict):
        fail(f"{path}: top-level JSON value must be an object")
        return None
    for key in required:
        if key not in data:
            fail(f"{path}: missing required field '{key}'")
        else:
            ok(f"{path}: has '{key}'")
    return data


def validate_version_symmetry(
    skill_versions: dict[str, str], plugin: dict | None, marketplace: dict | None
) -> None:
    """Match plugin identity inside the catalog, then require version symmetry."""
    if plugin is None or marketplace is None:
        return

    plugin_name = plugin.get("name")
    plugin_version = plugin.get("version")
    versions_are_valid = True
    if not isinstance(plugin_version, str) or not SEMVER_RE.fullmatch(plugin_version):
        fail(f"plugin.json: version '{plugin_version}' is missing or invalid")
        versions_are_valid = False

    entries = marketplace.get("plugins")
    if not isinstance(entries, list):
        fail("marketplace.json: 'plugins' must be a list")
        return
    matching = [entry for entry in entries if isinstance(entry, dict) and entry.get("name") == plugin_name]
    if len(matching) != 1:
        fail(f"marketplace.json: expected exactly one plugin named '{plugin_name}'")
        return
    marketplace_version = matching[0].get("version")
    if not isinstance(marketplace_version, str) or not SEMVER_RE.fullmatch(marketplace_version):
        fail(f"marketplace.json: version '{marketplace_version}' is missing or invalid")
        versions_are_valid = False

    skill_version = skill_versions.get(str(plugin_name))
    if not skill_version:
        fail(f"plugin.json: no skill named '{plugin_name}' to compare versions")
        return

    if not versions_are_valid:
        return

    versions = {
        "SKILL.md": skill_version,
        "plugin.json": plugin_version,
        "marketplace.json": marketplace_version,
    }
    if len(set(versions.values())) != 1:
        fail("version mismatch: " + ", ".join(f"{source}={value}" for source, value in versions.items()))
    else:
        ok(f"version symmetry: all manifests use {skill_version}")


def main() -> int:
    errors.clear()
    skills_root = ROOT / "skills"
    skill_dirs = sorted(d for d in skills_root.iterdir() if d.is_dir()) if skills_root.is_dir() else []
    if not skill_dirs:
        fail("no skills found under skills/")

    skill_versions = {}
    for skill_dir in skill_dirs:
        identity = validate_skill(skill_dir)
        if identity:
            skill_versions[identity[0]] = identity[1]

    plugin = validate_json(
        ROOT / ".claude-plugin" / "plugin.json",
        ["name", "description", "version"],
    )
    marketplace = validate_json(
        ROOT / ".claude-plugin" / "marketplace.json",
        ["name", "owner", "plugins"],
    )
    validate_version_symmetry(skill_versions, plugin, marketplace)

    print()
    if errors:
        print(f"{len(errors)} problem(s) found.")
        return 1
    print("All checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
