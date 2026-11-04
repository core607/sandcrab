#!/usr/bin/env bash
# A standalone consumer: create a small Python project and test it in one retained shell.
set -euo pipefail
socket=${SANDCRAB_SOCKET:-/var/lib/sandcrab/runtime/control.sock}
binary=${SANDCRAB_BIN:-/var/lib/sandcrab-release/sandcrab}
profile=${SANDCRAB_PROFILE:-default}
created=$("$binary" session open --socket "$socket" --profile "$profile")
id=$(printf '%s' "$created" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
cleanup() {
    "$binary" session close --socket "$socket" "$id" &&
        "$binary" session forget --socket "$socket" "$id"
}
trap cleanup EXIT
"$binary" session exec --socket "$socket" "$id" -- '
mkdir project
cd project
export PROJECT=calculator
printf "def add(a,b): return a+b\n" > calc.py
printf "import unittest\nfrom calc import add\nclass Check(unittest.TestCase):\n def test_add(self): self.assertEqual(5, add(2,3))\n" > test_calc.py
'
"$binary" session exec --socket "$socket" "$id" -- '
test "$PROJECT" = calculator && python3 -B -m unittest
'
