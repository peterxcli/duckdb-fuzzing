#!/usr/bin/env python3
"""Attach sanitizer diagnostics to a property result that otherwise passed.

    annotate_sanitizer.py <result.json> <log> [expectation]

UBSan reports undefined behaviour without necessarily falsifying the property
that triggered it, so a clean `pass` can still hide a real bug. Rows with
diagnostics are re-stamped as `sanitizer` so triage treats them as findings.
"""
import json
import re
import sys

result_path, log_path = sys.argv[1:3]
expectation = sys.argv[3] if len(sys.argv) > 3 else "pass"

PATTERN = re.compile(r"(runtime error:|ERROR: AddressSanitizer|ERROR: LeakSanitizer)")

try:
    with open(log_path, errors="replace") as handle:
        log = handle.read()
except OSError:
    sys.exit(0)

diagnostics = [line.strip() for line in log.splitlines() if PATTERN.search(line)]
if not diagnostics:
    sys.exit(0)

# Keep the report bounded: the same site usually fires many times.
unique, seen = [], set()
for line in diagnostics:
    if line not in seen:
        seen.add(line)
        unique.append(line)

with open(result_path) as handle:
    rows = json.load(handle)

for row in rows:
    # Diagnostics from a probe for an open upstream bug are the bug, not news.
    row["status"] = "known_fail" if expectation == "known_fail" else "sanitizer"
    detail = "\n".join(unique[:20])
    row["error"] = ((row.get("error") or "") + "\n" + detail).strip()
    if len(unique) > 20:
        row["error"] += f"\n... and {len(unique) - 20} more distinct diagnostics"

with open(result_path, "w") as handle:
    json.dump(rows, handle, indent=1)
