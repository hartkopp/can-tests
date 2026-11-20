#!/bin/sh
# SPDX-License-Identifier: (GPL-2.0-only OR BSD-3-Clause)
#
# gen_testcases.sh - create TESTCASES.md from the test case tables
#
# The test programs are the single source for the test case catalog:
# every test case carries its checked behaviour, the code reference and
# notes about deviations from ISO 15765-2 (see 'make doc').

cd "$(dirname "$0")" || exit 1

cat <<EOF
# CAN_ISOTP functional test cases

Generated with \`make doc\` from the test case tables of the test programs.
Do not edit manually.

Each test case lists

- **Behaviour**: the checked behaviour of the CAN_ISOTP implementation
  (input for the specification derived from the code),
- **Code**: the implementation parts (patched net/can/isotp/*.c),
- **ISO 15765-2**: \`DEVIATION\` notes (behaviour differs from ISO 15765-2,
  shown as \`# DEVIATION\` in the test output), \`DEVIATION (if observed)\`
  notes (the test case checks the ISO behaviour and reports the deviation
  only when it is observed) and \`REVIEW\` notes (needs a check against the
  ISO 15765-2 text or is implementation specific),
- **Flags**: \`slow\` (runs into 1 s protocol timeouts, skipped with -q),
  \`timing\` (checks timing with a tolerance).

Parameterized test cases with the same behaviour are grouped.

EOF

for s in api tx rx xl e2e timing; do
	./tst-isotp-$s -m || exit 1
done
