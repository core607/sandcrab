#!/usr/bin/env python3
"""Offline checks for the repository's document and agent instruction surface."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
POINTER = "Read [AGENTS.md](AGENTS.md) for repository instructions.\n"
LINK = re.compile(r'\[[^\]\n]*\]\(\s*(<[^>\n]+>|[^\s()]*(?:\([^\n()]*\)[^\s()]*)*)(?:\s+["\'][^\n]*?["\'])?\s*\)')
REFERENCE = re.compile(r'^ {0,3}\[([^\]\n]+)\]:\s*(<[^>\n]+>|\S+)', re.MULTILINE)
REFERENCE_USE = re.compile(r'\[([^\]\n]+)\]\[([^\]\n]*)\]')


def repository_files(root: Path) -> set[str]:
    result = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=root, check=True, stdout=subprocess.PIPE,
    )
    return {name for name in result.stdout.decode("utf-8").split("\0") if name}


def prose(text: str) -> str:
    """Retain prose line numbers while ignoring fenced code examples."""
    lines = []
    fence = None
    for line in text.splitlines():
        marker = re.match(r"^ {0,3}(`{3,}|~{3,})(.*)$", line)
        if fence:
            if marker and marker[1][0] == fence[0] and len(marker[1]) >= len(fence) and not marker[2].strip():
                fence = None
            lines.append("")
        elif marker:
            fence = marker[1]
            lines.append("")
        else:
            lines.append(line)
    return "\n".join(lines)


def anchors(text: str) -> set[str]:
    result = set()
    counts: dict[str, int] = {}
    for line in prose(text).splitlines():
        heading = re.match(r"^ {0,3}#{1,6}\s+(.+?)(?:\s+#+)?\s*$", line)
        if heading:
            label = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", heading[1])
            label = re.sub(r"<[^>]*>", "", label).lower()
            label = re.sub(r"[^\w\- ]", "", label).replace(" ", "-")
            number = counts.get(label, 0)
            counts[label] = number + 1
            result.add(f"{label}-{number}" if number else label)
        result.update(re.findall(r'<a\s+(?:id|name)=["\']([^"\']+)["\']', line))
    return result


def link_errors(root: Path, files: set[str]) -> list[str]:
    errors = []
    for name in sorted(files):
        source = root / name
        if not name.endswith(".md") or name.startswith("notes/archived/") or not source.is_file():
            continue
        text = re.sub(r"(`+).*?\1", "", prose(source.read_text(encoding="utf-8")))
        refs = {match[1].strip().casefold(): match[2] for match in REFERENCE.finditer(text)}
        targets = [(match.start(), match[1]) for match in LINK.finditer(text)]
        targets += [(match.start(), match[2]) for match in REFERENCE.finditer(text)]
        for match in REFERENCE_USE.finditer(text):
            key = (match[2] or match[1]).strip().casefold()
            if key not in refs:
                errors.append(f"{name}: undefined link reference [{key}]")
        for offset, raw in targets:
            location = f"{name}:{text.count(chr(10), 0, offset) + 1}"
            target = urlsplit(raw.strip("<>"))
            if target.scheme in {"http", "https", "mailto"}:
                continue
            if target.scheme or target.netloc:
                errors.append(f"{location}: unsupported link '{raw}'")
                continue
            path = (source.parent / unquote(target.path)).resolve() if target.path else source
            try:
                relative = path.relative_to(root).as_posix()
            except ValueError:
                errors.append(f"{location}: link leaves repository '{raw}'")
                continue
            present = relative in files or any(item.startswith(relative.rstrip("/") + "/") for item in files)
            if not present or not path.exists():
                errors.append(f"{location}: missing local target '{raw}'")
            elif target.fragment and path.suffix == ".md" and path.is_file():
                if unquote(target.fragment) not in anchors(path.read_text(encoding="utf-8")):
                    errors.append(f"{location}: missing heading '{raw}'")
    return errors


def skill_sources(root: Path) -> dict[str, str]:
    """Validate the supported single-line frontmatter before generating any file."""
    sources = {}
    directories = sorted((root / ".agents/skills").iterdir())
    if not directories:
        raise ValueError(".agents/skills: no source skills")
    for directory in directories:
        path = directory / "SKILL.md"
        if not directory.is_dir() or not path.is_file():
            raise ValueError(f"{directory.relative_to(root)}: missing SKILL.md")
        text = path.read_text(encoding="utf-8")
        block = re.match(r"\A---\n(.*?)\n---\n", text, re.DOTALL)
        if not block:
            raise ValueError(f"{path.relative_to(root)}: missing frontmatter")
        metadata = {}
        for line in block[1].splitlines():
            key, separator, value = line.partition(":")
            if not separator or key not in {"name", "description"} or key in metadata or not value.strip():
                raise ValueError(f"{path.relative_to(root)}: expected unique name and description fields")
            metadata[key] = value.strip()
        if metadata.keys() != {"name", "description"} or metadata["name"] != directory.name or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", directory.name):
            raise ValueError(f"{path.relative_to(root)}: name must match directory and description must be present")
        description = metadata["description"]
        if ": " in description or " #" in description or description.startswith(tuple("|>'\"[{&*!")):
            raise ValueError(f"{path.relative_to(root)}: description must be a plain single-line YAML scalar")
        sources[directory.name] = description
    return sources


def skill_stub(name: str, description: str) -> str:
    return (
        f"---\nname: {name}\ndescription: {description}\n---\n\n"
        f"Generated from [.agents/skills/{name}/SKILL.md](../../../.agents/skills/{name}/SKILL.md) "
        "by `python3 scripts/sync-claude-skills.py`; do not edit. Read that file and follow it exactly.\n"
    )


def stub_errors(root: Path, sources: dict[str, str]) -> list[str]:
    errors = []
    for name, description in sources.items():
        path = root / ".claude/skills" / name / "SKILL.md"
        if not path.is_file() or path.read_text(encoding="utf-8") != skill_stub(name, description):
            errors.append(f".claude/skills/{name}/SKILL.md: missing or stale; run python3 scripts/sync-claude-skills.py")
    directory = root / ".claude/skills"
    if directory.exists():
        for entry in directory.iterdir():
            if entry.name not in sources:
                errors.append(f"{entry.relative_to(root)}: orphan stub; remove it with its source")
    return errors


def check(root: Path) -> list[str]:
    root = root.resolve()
    errors = link_errors(root, repository_files(root))
    missing = [name for name in ("AGENTS.md", "CLAUDE.md", ".gitignore") if not (root / name).is_file()]
    errors.extend(f"{name}: required file missing" for name in missing)
    if missing:
        return errors
    if (root / "CLAUDE.md").read_text(encoding="utf-8") != POINTER:
        errors.append("CLAUDE.md: keep only the AGENTS.md pointer")
    if (root / ".gitignore").read_text(encoding="utf-8").splitlines()[:1] != [".env"]:
        errors.append(".gitignore: first line must be .env")
    try:
        sources = skill_sources(root)
        inventory = set(re.findall(r"\.agents/skills/([a-z0-9-]+)/SKILL\.md", (root / "AGENTS.md").read_text(encoding="utf-8")))
        if inventory != sources.keys():
            errors.append("AGENTS.md: skill inventory differs from .agents/skills")
        errors.extend(stub_errors(root, sources))
    except (OSError, ValueError) as error:
        errors.append(str(error))
    return errors


def main() -> int:
    try:
        errors = check(ROOT)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        errors = [str(error)]
    if errors:
        print("\n".join(errors))
        return 1
    print("Repository documents, links and skills verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
