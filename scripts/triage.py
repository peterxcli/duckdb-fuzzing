#!/usr/bin/env python3
"""Turn property-run results into a report and one GitHub issue per new finding.

    scripts/triage.py --results out/ --duckdb-sha <sha> [--repo owner/name]
                      [--summary report.md] [--file-issues]

Statuses come from fuzzing_check():

  pass        the property held
  fail        the property was falsified -> a finding
  crash       the property's process died before reporting -> a finding
  sanitizer   the property passed but ASan/UBSan reported a diagnostic -> a finding
  known_fail  a probe for an open upstream issue failed, as expected
  fixed       a probe for an open upstream issue passed -> the fix landed
  gave_up     too many generated cases were discarded
  skipped     a required extension was unavailable

Issues are opened only for `fail` and `crash`, and are deduplicated on a stable
fingerprint (suite + property) carried in the issue body, so a finding that
reproduces every night stays a single issue.
"""

import argparse
import json
import os
import pathlib
import subprocess
import sys

FINDING_STATUSES = ("fail", "crash", "sanitizer")
MARKER = "fuzzing-fingerprint"
LABEL = "property-failure"


def run_gh(args, check=True):
    result = subprocess.run(
        ["gh", *args], capture_output=True, text=True, check=False
    )
    if check and result.returncode != 0:
        raise RuntimeError(f"gh {' '.join(args)} failed: {result.stderr.strip()}")
    return result


def load_results(results_dir):
    rows = []
    for path in sorted(pathlib.Path(results_dir).glob("*.json")):
        try:
            content = json.loads(path.read_text())
        except json.JSONDecodeError as error:
            print(f"warning: {path} is not valid JSON ({error})", file=sys.stderr)
            continue
        rows.extend(content)
    return rows


def fingerprint(row):
    return f"{row['suite']}/{row['property']}"


def truncate(text, limit=4000):
    if text is None:
        return ""
    text = str(text)
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... [truncated, {len(text) - limit} more characters]"


def sql_string(value):
    """A single-quoted SQL string literal."""
    return "'" + str(value).replace("'", "''") + "'"


def reproduce_sql(row):
    """The exact fuzzing_check() call that replays this property run."""
    args = [sql_string(row["suite"]), f"property => {sql_string(row['property'])}"]
    for pair in (row.get("reproduce") or "").split():
        if "=" not in pair:
            continue
        key, _, value = pair.partition("=")
        args.append(f"{key} => {value}")
    return f"SELECT * FROM fuzzing_check({', '.join(args)});"


def issue_body(row, duckdb_sha, run_url):
    lines = [
        f"A property in the `{row['suite']}` suite reported `{row['status']}` against DuckDB "
        f"[`{duckdb_sha[:10]}`](https://github.com/duckdb/duckdb/commit/{duckdb_sha}).",
        "",
        f"**Property:** `{row['property']}`",
        f"**Cases before failure:** {row.get('cases', 0)}",
        f"**Shrink steps:** {row.get('shrinks', 0)}",
        "",
        "### Failure",
        "```",
        truncate(row.get("error")) or "(no message)",
        "```",
    ]
    if row.get("counterexample"):
        lines += ["", "### Shrunk counterexample", "```", truncate(row["counterexample"]), "```"]
    if row.get("reproduce"):
        lines += [
            "",
            "### Reproduce",
            "```sql",
            f"-- against DuckDB {duckdb_sha[:10]} built with FORCE_ASSERT + ASan/UBSan",
            reproduce_sql(row),
            "```",
        ]
    if run_url:
        lines += ["", f"[Nightly run]({run_url})"]
    lines += [
        "",
        "---",
        f"<!-- {MARKER}: {fingerprint(row)} -->",
        "_Opened automatically by the nightly property run. "
        "Confirm and minimise before filing upstream at duckdb/duckdb._",
    ]
    return "\n".join(lines)


def existing_issues(repo):
    """Map fingerprint -> issue number for open auto-filed issues."""
    result = run_gh(
        [
            "issue", "list", "--repo", repo, "--state", "open",
            "--label", LABEL, "--limit", "200",
            "--json", "number,body",
        ]
    )
    found = {}
    for issue in json.loads(result.stdout or "[]"):
        body = issue.get("body") or ""
        marker = f"<!-- {MARKER}: "
        if marker in body:
            value = body.split(marker, 1)[1].split(" -->", 1)[0].strip()
            found[value] = issue["number"]
    return found


def ensure_label(repo):
    run_gh(
        ["label", "create", LABEL, "--repo", repo, "--color", "d73a4a",
         "--description", "Found by the nightly property run"],
        check=False,
    )


def file_issues(findings, repo, duckdb_sha, run_url):
    ensure_label(repo)
    known = existing_issues(repo)
    opened, updated = [], []
    for row in findings:
        key = fingerprint(row)
        title = f"[{row['suite']}] {row['property']}"
        if key in known:
            number = known[key]
            run_gh([
                "issue", "comment", str(number), "--repo", repo,
                "--body", f"Still failing against DuckDB `{duckdb_sha[:10]}`."
                          + (f"\n\n[Nightly run]({run_url})" if run_url else ""),
            ])
            updated.append((number, title))
            continue
        result = run_gh([
            "issue", "create", "--repo", repo, "--title", title[:250],
            "--label", LABEL, "--body", issue_body(row, duckdb_sha, run_url),
        ])
        opened.append((result.stdout.strip(), title))
    return opened, updated


def write_summary(path, rows, duckdb_sha, opened, updated):
    by_status = {}
    for row in rows:
        by_status.setdefault(row["status"], []).append(row)

    out = [
        "# Nightly property run",
        "",
        f"DuckDB `{duckdb_sha[:10]}` "
        f"([upstream](https://github.com/duckdb/duckdb/commit/{duckdb_sha}))",
        "",
        "| status | count |",
        "|---|---|",
    ]
    for status in ("pass", "fail", "crash", "sanitizer", "known_fail", "fixed", "gave_up", "skipped"):
        if status in by_status:
            out.append(f"| `{status}` | {len(by_status[status])} |")
    out.append("")

    findings = [row for row in rows if row["status"] in FINDING_STATUSES]
    if findings:
        out += ["## Findings", ""]
        for row in findings:
            out.append(f"### `{row['suite']}` — {row['property']}")
            out += ["", "```", truncate(row.get("error"), 1500) or "(no message)", "```", ""]
            if row.get("counterexample"):
                out += ["<details><summary>counterexample</summary>", "", "```",
                        truncate(row["counterexample"], 1500), "```", "", "</details>", ""]

    if by_status.get("fixed"):
        out += ["## Fixed upstream", "",
                "These probes track open upstream issues but now pass — the fix has landed "
                "and the guard can be retired:", ""]
        for row in by_status["fixed"]:
            out.append(f"- `{row['suite']}` — {row['property']} ({row.get('issue') or 'no issue'})")
        out.append("")

    if by_status.get("known_fail"):
        out += ["## Known failures (expected)", ""]
        for row in by_status["known_fail"]:
            out.append(f"- {row.get('issue') or '(no issue)'} — {row['property']}")
        out.append("")

    if opened or updated:
        out += ["## Issues", ""]
        for url, title in opened:
            out.append(f"- opened {url} — {title}")
        for number, title in updated:
            out.append(f"- updated #{number} — {title}")
        out.append("")

    text = "\n".join(out)
    if path:
        pathlib.Path(path).write_text(text)
    return text


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", required=True, help="directory of per-suite JSON results")
    parser.add_argument("--duckdb-sha", required=True)
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", ""))
    parser.add_argument("--summary", default="", help="write the markdown report here")
    parser.add_argument("--run-url", default="")
    parser.add_argument("--file-issues", action="store_true",
                        help="open/update a GitHub issue per finding")
    args = parser.parse_args()

    rows = load_results(args.results)
    if not rows:
        print("error: no results found; the run produced nothing", file=sys.stderr)
        return 2

    findings = [row for row in rows if row["status"] in FINDING_STATUSES]

    opened, updated = [], []
    if findings and args.file_issues:
        if not args.repo:
            print("error: --file-issues needs --repo or GITHUB_REPOSITORY", file=sys.stderr)
            return 2
        opened, updated = file_issues(findings, args.repo, args.duckdb_sha, args.run_url)

    print(write_summary(args.summary, rows, args.duckdb_sha, opened, updated))

    # A new finding fails the job; expected known failures do not.
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
