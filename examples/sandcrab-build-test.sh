#!/usr/bin/env bash
# A standalone consumer: create a small Python project and test it in one retained shell.
set -euo pipefail
: "${SANDCRAB_SOCKET:?Set SANDCRAB_SOCKET to the native service socket}"
binary=${SANDCRAB_BIN:-sandcrab}
profile=${SANDCRAB_PROFILE:-python}
created=$("$binary" session open --socket "$SANDCRAB_SOCKET" --profile "$profile")
id=$(printf '%s' "$created" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
cleanup() {
    "$binary" session close --socket "$SANDCRAB_SOCKET" "$id" &&
        "$binary" session forget --socket "$SANDCRAB_SOCKET" "$id"
}
trap cleanup EXIT
"$binary" session exec --socket "$SANDCRAB_SOCKET" "$id" -- '
mkdir project
cd project
export PROJECT=calculator
printf "def add(a,b): return a+b\n" > calc.py
printf "import unittest\nfrom calc import add\nclass Check(unittest.TestCase):\n def test_add(self): self.assertEqual(5, add(2,3))\n" > test_calc.py
'
"$binary" session exec --socket "$SANDCRAB_SOCKET" "$id" -- '
test "$PROJECT" = calculator && python3 -B -m unittest
'
