// Deterministic probes for bugs found by the property suite.
//
// FUZZING_REGRESSION  - the bug is fixed upstream; a failure is a regression.
// FUZZING_KNOWN_FAIL  - the bug is still open upstream; the probe is expected
//                       to fail, and starts reporting "fixed" once it passes.
#include "fuzzing_property.hpp"

using namespace duckdb_fuzzing;

namespace {

Value RequireScalar(PropDB &db, const string &sql) {
	auto result = db.Query(sql);
	if (result->HasError()) {
		RC_FAIL("Query failed: " + sql + "\n" + result->GetError());
	}
	if (result->RowCount() != 1 || result->ColumnCount() != 1) {
		RC_FAIL("Query did not return a single value: " + sql);
	}
	return result->GetValue(0, 0);
}

Value RequireScalar(PropDB &db, const string &sql, vector<Value> parameters) {
	auto result = db.Query(sql, std::move(parameters));
	if (result->HasError()) {
		RC_FAIL("Query failed: " + sql + "\n" + result->GetError());
	}
	auto &materialized = result->Cast<MaterializedQueryResult>();
	if (materialized.RowCount() != 1 || materialized.ColumnCount() != 1) {
		RC_FAIL("Query did not return a single value: " + sql);
	}
	return materialized.GetValue(0, 0);
}

//! The query must fail, and the failure must not invalidate the database.
void RequireRecoverableError(PropDB &db, const string &sql) {
	auto result = db.Query(sql);
	if (!result->HasError()) {
		RC_FAIL("Expected an error from: " + sql);
	}
	auto health = db.Query("SELECT 42");
	if (health->HasError()) {
		RC_FAIL("Database was invalidated by: " + sql + "\nFollow-up query error: " + health->GetError());
	}
	RC_ASSERT(health->GetValue(0, 0) == Value::INTEGER(42));
}

void RequireSQLLiteralRoundTrip(PropDB &db, const Value &expected) {
	auto literal = expected.ToSQLString();
	RC_LOG() << "SQL literal: " << literal << std::endl;
	auto actual = RequireScalar(db, "SELECT " + literal);
	RC_ASSERT(actual.type() == expected.type());
	RC_ASSERT(Value::NotDistinctFrom(actual, expected));
}

} // namespace

//===--------------------------------------------------------------------===//
// Fixed upstream
//===--------------------------------------------------------------------===//
FUZZING_REGRESSION("known", "last_day maximum-date failure is recoverable", "duckdb/duckdb#24973") {
	RequireRecoverableError(db, "SELECT last_day(DATE '5881580-07-10')");
}

FUZZING_REGRESSION("known", "TIMETZ preserves an offset-seconds field", "duckdb/duckdb#24987") {
	auto rendered = RequireScalar(db, "SELECT '12:00:00-05:00:59'::TIMETZ::VARCHAR");
	RC_ASSERT(rendered == Value("12:00:00-05:00:59"));
}

FUZZING_REGRESSION("known", "ToSQLString quotes STRUCT field names", "duckdb/duckdb#24975") {
	RequireSQLLiteralRoundTrip(db, Value::STRUCT({{"k'", Value::INTEGER(42)}}));
}

FUZZING_REGRESSION("known", "ToSQLString renders BIT as a typed literal", "duckdb/duckdb#24975") {
	RequireSQLLiteralRoundTrip(db, Value::BIT("10"));
}

FUZZING_REGRESSION("known", "ToSQLString retains every UNION member", "duckdb/duckdb#24975") {
	child_list_t<LogicalType> members = {{"a", LogicalType::INTEGER}, {"b", LogicalType::VARCHAR}};
	RequireSQLLiteralRoundTrip(db, Value::UNION(members, 1, Value("x")));
}

FUZZING_REGRESSION_REQUIRES("known", "JSON to DECIMAL preserves precision", "duckdb/duckdb#24989", "json") {
	auto actual = RequireScalar(db, "SELECT '883406386745030.3'::JSON::DECIMAL(16,1)");
	auto expected = Value::DECIMAL(int64_t(8834063867450303LL), 16, 1);
	RC_ASSERT(actual == expected);
}

//===--------------------------------------------------------------------===//
// Open upstream
//===--------------------------------------------------------------------===//
FUZZING_KNOWN_FAIL("known", "minimum-date week truncation avoids signed overflow", "duckdb/duckdb#25107") {
	RequireRecoverableError(db, "SELECT date_trunc('week', DATE '5877642-06-25 (BC)')");
}

FUZZING_KNOWN_FAIL("known", "list_sort uses normalized INTERVAL ordering", "duckdb/duckdb#25108") {
	auto sorted = RequireScalar(db, "SELECT list_sort([INTERVAL '31 days', INTERVAL '1 month'])");
	RC_ASSERT(sorted.type().id() == LogicalTypeId::LIST);
	auto &values = ListValue::GetChildren(sorted);
	RC_ASSERT(values.size() == 2);

	auto first = values[0].GetValue<interval_t>();
	auto second = values[1].GetValue<interval_t>();
	RC_ASSERT(first.months == 1);
	RC_ASSERT(first.days == 0);
	RC_ASSERT(first.micros == 0);
	RC_ASSERT(second.months == 0);
	RC_ASSERT(second.days == 31);
	RC_ASSERT(second.micros == 0);
}

FUZZING_KNOWN_FAIL("known", "maximum-microsecond INTERVAL text round-trips", "duckdb/duckdb#25109") {
	auto actual =
	    RequireScalar(db, "SELECT CAST(CAST(to_microseconds(9223372036854775807) AS VARCHAR) AS INTERVAL)");
	auto interval = actual.GetValue<interval_t>();
	RC_ASSERT(interval.months == 0);
	RC_ASSERT(interval.days == 0);
	RC_ASSERT(interval.micros == NumericLimits<int64_t>::Maximum());
}

FUZZING_KNOWN_FAIL("known", "week parts work at the minimum date", "duckdb/duckdb#25110") {
	auto result = db.Query("SELECT weekofyear(d), isoyear(d), yearweek(d) "
	                       "FROM (SELECT DATE '5877642-06-25 (BC)' AS d)");
	if (result->HasError()) {
		RC_FAIL("Query failed: " + result->GetError());
	}
	RC_ASSERT(result->RowCount() == 1);
	RC_ASSERT(result->ColumnCount() == 3);
	RC_ASSERT(result->GetValue(0, 0) == Value::BIGINT(26));
	RC_ASSERT(result->GetValue(1, 0) == Value::BIGINT(-5877641));
	RC_ASSERT(result->GetValue(2, 0) == Value::BIGINT(-587764126));
}

FUZZING_KNOWN_FAIL("known", "list_sort accepts API-created ENUM labels with NUL", "duckdb/duckdb#25111") {
	Vector labels(LogicalType::VARCHAR, 3);
	labels.SetValue(0, Value("a"));
	labels.SetValue(1, Value(string(1, '\0')));
	labels.SetValue(2, Value("b"));
	auto enum_type = LogicalType::ENUM(labels, 3);

	auto input =
	    Value::LIST(enum_type, {Value::ENUM(2, enum_type), Value::ENUM(0, enum_type), Value::ENUM(1, enum_type)});
	auto sorted = RequireScalar(db, "SELECT list_sort($1)", {input});
	RC_ASSERT(sorted.type() == input.type());
	auto &values = ListValue::GetChildren(sorted);
	RC_ASSERT(values.size() == 3);
	RC_ASSERT(values[0].GetValue<uint32_t>() == 0);
	RC_ASSERT(values[1].GetValue<uint32_t>() == 1);
	RC_ASSERT(values[2].GetValue<uint32_t>() == 2);
}

FUZZING_KNOWN_FAIL("known", "integer minimum modulo negative one is zero", "duckdb/duckdb#25112") {
	auto actual = RequireScalar(db, "SELECT (-32768)::SMALLINT % (-1)::SMALLINT");
	RC_ASSERT(actual == Value::SMALLINT(0));
}

FUZZING_KNOWN_FAIL("known", "string distances count Unicode code points", "duckdb/duckdb#25113") {
	auto result = db.Query("SELECT levenshtein('中', 'a'), damerau_levenshtein('中', 'a'), hamming('中', 'a')");
	if (result->HasError()) {
		RC_FAIL("Query failed: " + result->GetError());
	}
	RC_ASSERT(result->RowCount() == 1);
	RC_ASSERT(result->ColumnCount() == 3);
	RC_ASSERT(result->GetValue(0, 0) == Value::BIGINT(1));
	RC_ASSERT(result->GetValue(1, 0) == Value::BIGINT(1));
	RC_ASSERT(result->GetValue(2, 0) == Value::BIGINT(1));
}

FUZZING_PROPERTY_FILE(known_issues)
