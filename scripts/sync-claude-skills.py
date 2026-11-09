#!/usr/bin/env python3
"""Generate Claude discovery pointers from the authoritative agent skills."""

import argparse

from repo_check import ROOT, skill_sources, skill_stub, stub_errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify without writing")
    args = parser.parse_args()
    try:
        sources = skill_sources(ROOT)
        if not args.check:
            for name, description in sources.items():
                path = ROOT / ".claude/skills" / name / "SKILL.md"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(skill_stub(name, description), encoding="utf-8", newline="\n")
        errors = stub_errors(ROOT, sources)
    except (OSError, ValueError) as error:
        errors = [str(error)]
    if errors:
        print("\n".join(errors))
        return 1
    print(f"{'Verified' if args.check else 'Generated'} {len(sources)} Claude skill stubs.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
