#!/usr/bin/env python3
"""Record a property whose process died before it could report a result.

    crash_record.py <out.json> <suite> <property> <reason> <log> [expectation] [issue]

A sanitized DuckDB aborts on undefined behaviour, so a crash is a finding in its
own right; it is written in the same shape as a fuzzing_check() row so triage
does not need to special-case it.
"""
import json
import sys

out, suite, prop, reason, log = sys.argv[1:6]
expectation = sys.argv[6] if len(sys.argv) > 6 else "pass"
issue = sys.argv[7] if len(sys.argv) > 7 else ""

# A probe for a still-open upstream bug is expected to blow up: report it as the
# known failure it is rather than as a new finding.
status = "known_fail" if expectation == "known_fail" else "crash"

try:
    with open(log, errors="replace") as handle:
        tail = "".join(handle.readlines()[-120:])
except OSError:
    tail = ""

json.dump(
    [
        {
            "suite": suite,
            "property": prop,
            "status": status,
            "issue": issue or None,
            "cases": 0,
            "shrinks": 0,
            "error": f"the property process {reason}",
            "counterexample": tail,
            "reproduce": "",
            "runtime_seconds": 0.0,
        }
    ],
    open(out, "w"),
    indent=1,
)
