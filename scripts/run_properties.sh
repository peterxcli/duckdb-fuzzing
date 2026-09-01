#!/usr/bin/env bash
# Run every registered property against a built DuckDB and collect the results
# as JSON.
#
#   scripts/run_properties.sh <duckdb-binary> <output-dir> [max_success]
#
# Each property runs in its own DuckDB process. DuckDB's sanitized builds use
# -fno-sanitize-recover=all, so a property that trips undefined behaviour takes
# the whole process down with it -- which is exactly the kind of finding we are
# hunting for. Isolating properties means such a crash is attributed to the one
# property that caused it instead of hiding the results of everything that would
# have run after it.
set -uo pipefail

DUCKDB=${1:?usage: run_properties.sh <duckdb-binary> <output-dir> [max_success]}
OUT_DIR=${2:?usage: run_properties.sh <duckdb-binary> <output-dir> [max_success]}
MAX_SUCCESS=${3:-200}
# Bound a single property so a pathological shrink cannot hang the whole run.
PROPERTY_TIMEOUT=${PROPERTY_TIMEOUT:-1200}

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

mkdir -p "$OUT_DIR"

export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0}"
export UBSAN_OPTIONS="${UBSAN_OPTIONS:-print_stacktrace=1}"

# Property names contain spaces, parentheses and $, so the fields need a
# separator that cannot appear in them. It also must not be IFS whitespace:
# `read` collapses runs of whitespace separators, which would silently shift the
# fields of every property that has no issue attached.
readonly SEP=$'\x1f'
mapfile -t PROPERTIES < <(
	"$DUCKDB" -noheader -list -separator "$SEP" \
		-c "SELECT suite, expectation, coalesce(issue, ''), property FROM fuzzing_properties()" 2>/dev/null
)
if [ ${#PROPERTIES[@]} -eq 0 ]; then
	echo "error: no properties registered; is the fuzzing extension linked in?" >&2
	exit 1
fi

echo "Running ${#PROPERTIES[@]} properties at max_success=$MAX_SUCCESS"

status=0
index=0
for entry in "${PROPERTIES[@]}"; do
	IFS="$SEP" read -r suite expectation issue property <<<"$entry"
	index=$((index + 1))
	if [ -z "$property" ] || [ -z "$suite" ]; then
		echo "error: could not parse property list entry: $(printf '%q' "$entry")" >&2
		exit 1
	fi
	slug=$(printf '%04d-%s' "$index" "$suite")
	json="$OUT_DIR/$slug.json"
	log="$OUT_DIR/$slug.log"
	rm -f "$json"

	# Double single quotes: SQL string escaping.
	sql_suite=${suite//\'/\'\'}
	sql_property=${property//\'/\'\'}

	timeout --signal=KILL "$PROPERTY_TIMEOUT" "$DUCKDB" -c "
		COPY (
			SELECT * FROM fuzzing_check('$sql_suite',
			                            property => '$sql_property',
			                            max_success => $MAX_SUCCESS)
		) TO '$json' (FORMAT JSON, ARRAY true);
	" >"$log" 2>&1
	rc=$?

	if [ -s "$json" ]; then
		# A property can pass and still trip recoverable sanitizer diagnostics.
		if grep -qE "runtime error:|ERROR: AddressSanitizer|ERROR: LeakSanitizer" "$log"; then
			printf '  %-10s %s -- sanitizer diagnostics\n' "$suite" "$property"
			python3 "$SCRIPT_DIR/annotate_sanitizer.py" "$json" "$log" "$expectation"
			[ "$expectation" = "known_fail" ] || status=1
		fi
		continue
	fi

	# No results: the process died before it could report. That is a finding.
	reason="exited with status $rc"
	[ $rc -eq 137 ] && reason="timed out after ${PROPERTY_TIMEOUT}s"
	printf '  %-10s %s -- CRASHED (%s)\n' "$suite" "$property" "$reason"
	python3 "$SCRIPT_DIR/crash_record.py" \
		"$json" "$suite" "$property" "$reason" "$log" "$expectation" "$issue"
	# A probe for an open upstream issue is *meant* to blow up; that is not news.
	[ "$expectation" = "known_fail" ] || status=1
done

echo "Wrote $(ls -1 "$OUT_DIR"/*.json 2>/dev/null | wc -l) result files to $OUT_DIR"
exit $status
