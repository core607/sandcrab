"""Run a native SDK README in an empty project on a prepared Linux service host."""
import argparse
from pathlib import Path
import re
import shlex
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("readme", type=Path)
    parser.add_argument("--package", type=Path, help="Install a candidate distribution in place of the registry package")
    args = parser.parse_args()
    text = args.readme.read_text(encoding="utf-8")
    section = text.split("## Run your first session\n", 1)[1].split("\n## ", 1)[0]
    setup, example, run = re.findall(r"^```(\w+)\n(.*?)^```$", section, re.MULTILINE | re.DOTALL)
    language = example[0]
    filename, package_prefix = {"python": ("example.py", "sandcrab=="), "ts": ("example.mts", "sandcrab@")}[language]
    if setup[0] != "sh" or run[0] != "sh":
        raise ValueError("Expected setup and run commands around the example")
    installed = False
    with tempfile.TemporaryDirectory(prefix="sandcrab-example-") as directory:
        for line in setup[1].splitlines():
            command = shlex.split(line)
            if command[-1].startswith(package_prefix):
                version = command[-1].removeprefix(package_prefix)
                if args.package:
                    candidate = args.package.resolve(strict=True)
                    expected = f"sandcrab-{version}" + ("-py3-none-any.whl" if language == "python" else ".tgz")
                    if candidate.name != expected:
                        raise ValueError(f"README requests {expected}, got {candidate.name}")
                    command[-1] = str(candidate)
                installed = True
            subprocess.run(command, cwd=directory, check=True)
        if not installed:
            raise ValueError("The README did not install the SDK")
        (Path(directory) / filename).write_text(example[1], encoding="utf-8")
        output = subprocess.check_output(shlex.split(run[1]), cwd=directory, text=True)
        if output != "42\n":
            raise ValueError(f"{filename} printed {output!r}, expected 42")
        print(f"{filename}: {output.strip()}")


if __name__ == "__main__":
    main()
