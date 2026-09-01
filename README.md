# duckdb-fuzzing

A DuckDB extension that carries a [RapidCheck](https://github.com/emil-e/rapidcheck) property-based test
suite and exposes it to SQL, so DuckDB can be bug-hunted from inside a running DuckDB:

```sql
LOAD fuzzing;
SELECT * FROM fuzzing_check('strings', max_success => 1000);
```

Instead of fixed inputs, each property states something that must hold for *every* value — "any value must
survive `CAST(v AS VARCHAR)` and back", "`LIKE` must agree with a 40-line reference matcher", "integer
arithmetic must error exactly when the `__int128` result is out of range" — and RapidCheck runs it against
hundreds of generated inputs, shrinking any failure to a minimal counterexample.

Ported from [peterxcli/duckdb#4](https://github.com/peterxcli/duckdb/pull/4), which ran the same properties
as a standalone Catch2 binary. The suite has found 12 bugs so far; see [docs/FINDINGS.md](docs/FINDINGS.md).

## SQL interface

### `fuzzing_check([suite], ...)`

Runs properties and returns one row each. With no argument it runs everything.

| named parameter | default | meaning |
|---|---|---|
| `max_success` | 100 | generated cases required before a property passes |
| `max_size` | 100 | upper bound on generated value size |
| `max_discard_ratio` | 10 | allowed `RC_PRE` discards per successful case |
| `noshrink` | false | skip shrinking — faster surveys, larger counterexamples |
| `seed` | random | RapidCheck seed; reported back in `reproduce` |
| `property` | — | run only the property with this exact name |

Columns: `suite`, `property`, `status`, `issue`, `cases`, `shrinks`, `error`, `counterexample`,
`reproduce`, `runtime_seconds`.

`status` is one of:

| status | meaning |
|---|---|
| `pass` | the property held for every generated case |
| `fail` | the property was falsified — **a finding** |
| `sanitizer` | the property passed but ASan/UBSan reported a diagnostic — **a finding** (added by the nightly runner, not by `fuzzing_check` itself) |
| `crash` | the property's process died before reporting — **a finding** (likewise) |
| `known_fail` | a probe for a still-open upstream issue failed, as expected |
| `fixed` | a probe for an open upstream issue *passed* — the fix landed, retire the guard |
| `gave_up` | too many generated cases were discarded to conclude anything |
| `skipped` | a required extension (e.g. `json`) was not loaded |

### `fuzzing_properties()`

Lists every registered property without running it: `suite`, `property`, `issue`, `expectation`,
`deterministic`, `requires_extension`.

## Suites

| suite | contents |
|---|---|
| `roundtrip` | value → VARCHAR / SQL literal / JSON / table → value |
| `strings` | LIKE/ILIKE vs a reference matcher; substring/split/pad/trim/translate/distance vs oracles |
| `lists` | list_sort/contains/position/distinct/slice/resize/concat, range/generate_series |
| `arithmetic` | integer/HUGEINT/DECIMAL vs `__int128` oracles — overflow must error exactly when out of range |
| `datetime` | date parts vs independent civil-calendar algorithms, epoch round trips, strftime/strptime |
| `storage` | persistent round trip across every `force_compression`, incl. update/delete + checkpoint + reopen |
| `known` | deterministic probes for each bug in [docs/FINDINGS.md](docs/FINDINGS.md) |

## Building

The properties exercise DuckDB's internal C++ API, which moves quickly, so the extension tracks
**upstream `main`** rather than a stable release. Bug hunting wants assertions and sanitizers on:

```bash
cmake -G Ninja \
  -DDUCKDB_EXTENSION_CONFIGS="$PWD/extension_config.cmake" \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DFORCE_ASSERT=1 -DENABLE_SANITIZER=1 -DENABLE_UBSAN=1 \
  -DBUILD_UNITTESTS=0 -DBUILD_SHELL=1 \
  -S duckdb -B build/relassert
cmake --build build/relassert
```

`make release` builds without them, which is faster but finds strictly less (finding #2 in
`docs/FINDINGS.md` is undefined behaviour that only UBSan sees).

RapidCheck is fetched with `FetchContent`; pass `-DRAPIDCHECK_SOURCE_DIR=/path/to/rapidcheck` to use a
local checkout.

## Running

```bash
# everything, default 100 cases per property
./build/relassert/duckdb -c "SELECT * FROM fuzzing_check()"

# a hunting session: more cases, no shrinking, only the failures
./build/relassert/duckdb -c "
  SELECT property, error, counterexample, reproduce
  FROM fuzzing_check(max_success => 5000, noshrink => true)
  WHERE status = 'fail'"

# replay a specific failure
./build/relassert/duckdb -c "
  SELECT * FROM fuzzing_check('strings', seed => 4570269180443172881)"

# has an open upstream bug been fixed?
./build/relassert/duckdb -c "
  SELECT property, issue FROM fuzzing_check('known') WHERE status = 'fixed'"
```

The SQL smoke tests run with `make test`.

## Nightly run

[`.github/workflows/NightlyPropertyRun.yml`](.github/workflows/NightlyPropertyRun.yml) syncs the `duckdb`
submodule to upstream `main` every night, rebuilds with assertions + ASan/UBSan, runs every suite, and
opens **one GitHub issue per new finding** in this repository (deduplicated on `suite/property`, so a
finding that reproduces every night stays a single issue).

```
scripts/run_properties.sh <duckdb-binary> <out-dir> [max_success]   # one process per property -> JSON
scripts/triage.py --results out/ --duckdb-sha <sha> --file-issues   # JSON -> report + issues
```

**Every property runs in its own DuckDB process.** DuckDB's sanitized builds use
`-fno-sanitize-recover=all`, so a property that trips undefined behaviour takes the process down with it —
which is exactly the kind of finding worth having. Isolation attributes the crash to the one property that
caused it instead of losing every result that would have come after. (Today that matters: the probe for
duckdb/duckdb#25107 aborts the process on every run.)

A property whose process dies is recorded as `crash`; one that passes while UBSan/ASan printed a
diagnostic is recorded as `sanitizer`. Both are findings — unless the property is a `FUZZING_KNOWN_FAIL`
probe, in which case blowing up is the expected outcome and no issue is filed.

Issues filed here are a **triage queue**, not upstream reports. Confirm and minimise a finding before
filing it at [duckdb/duckdb](https://github.com/duckdb/duckdb/issues); `docs/FINDINGS.md` tracks which
findings have been filed and what became of them.

## Adding a property

```cpp
FUZZING_PROPERTY("lists", "list_reverse is an involution") {
	auto type = *GenSortableType(1);
	auto values = *GenValues(type, 0.1);
	auto input = Value::LIST(type, values);
	PROP_ASSERT_VALUES_EQUAL(db.Scalar("SELECT list_reverse(list_reverse($1))", {input}), input);
}
```

`db` is a `PropDB` shared by every generated case of that property. Other registration macros:
`FUZZING_PROPERTY_REQUIRES(suite, name, extension)`, `FUZZING_REGRESSION(suite, name, issue)` for a bug
fixed upstream, and `FUZZING_KNOWN_FAIL(suite, name, issue)` for one still open — the latter flips to
`fixed` once upstream lands the fix.

Gotchas:
- `RC_PRE`/`RC_ASSERT` use expression decomposition, which silences `||`/`&&` short-circuiting — compute
  the condition into a `bool` first.
- Prefer an *independent oracle* (a small reference implementation) over comparing DuckDB with itself;
  where that is impossible, comparing two DuckDB code paths (constant vs parameterized, stored vs
  computed) still finds inconsistencies.
- `duckdb::vector` bounds-checks `back()`/`operator[]` and throws `InternalException` — do not index
  blindly in test code.
