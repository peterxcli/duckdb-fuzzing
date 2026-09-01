#define DUCKDB_EXTENSION_MAIN

#include "fuzzing_extension.hpp"

#include "property_runner.hpp"

#include "duckdb.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/function/table_function.hpp"

namespace duckdb_fuzzing {

// Referenced from LoadInternal so the linker keeps every property translation
// unit; see FUZZING_PROPERTY_FILE in fuzzing_property.hpp.
FUZZING_DECLARE_PROPERTY_FILE(arithmetic);
FUZZING_DECLARE_PROPERTY_FILE(datetime);
FUZZING_DECLARE_PROPERTY_FILE(known_issues);
FUZZING_DECLARE_PROPERTY_FILE(lists);
FUZZING_DECLARE_PROPERTY_FILE(roundtrip);
FUZZING_DECLARE_PROPERTY_FILE(storage);
FUZZING_DECLARE_PROPERTY_FILE(strings);

//! Every anchor returns 0, so this always returns 0 - but the calls are what
//! force the linker to keep the translation units.
static int TouchPropertyFiles() {
	return FuzzingPropertyFile_arithmetic() + FuzzingPropertyFile_datetime() + FuzzingPropertyFile_known_issues() +
	       FuzzingPropertyFile_lists() + FuzzingPropertyFile_roundtrip() + FuzzingPropertyFile_storage() +
	       FuzzingPropertyFile_strings();
}

} // namespace duckdb_fuzzing

namespace duckdb {

using duckdb_fuzzing::PropertyCase;
using duckdb_fuzzing::PropertyRegistry;
using duckdb_fuzzing::PropertyRunOptions;
using duckdb_fuzzing::PropertyRunResult;
using duckdb_fuzzing::PropertyStatus;
using duckdb_fuzzing::PropertyStatusName;

static string FuzzingVersionString() {
#ifdef EXT_VERSION_FUZZING
	return EXT_VERSION_FUZZING;
#else
	return "development";
#endif
}

static void FuzzingVersionFunction(DataChunk &input, ExpressionState &state, Vector &result) {
	result.Reference(Value(FuzzingVersionString()), count_t(input.size()));
}

//===--------------------------------------------------------------------===//
// fuzzing_check()
//===--------------------------------------------------------------------===//
// Runs the registered RapidCheck properties and returns one row per property.
//
//   SELECT * FROM fuzzing_check();
//   SELECT * FROM fuzzing_check('strings', max_success => 1000);
//   SELECT * FROM fuzzing_check(seed => 4570269180443172881);
struct FuzzingCheckBindData : public TableFunctionData {
	vector<const PropertyCase *> properties;
	PropertyRunOptions options;
};

struct FuzzingCheckState : public GlobalTableFunctionState {
	idx_t offset = 0;

	// The properties run one after another, and a single property can take a
	// long time; keeping this single-threaded keeps the output ordered and the
	// progress predictable.
	idx_t MaxThreads() const override {
		return 1;
	}
};

static unique_ptr<FunctionData> FuzzingCheckBind(ClientContext &context, TableFunctionBindInput &input,
                                                 vector<LogicalType> &return_types, vector<Identifier> &names) {
	auto result = make_uniq<FuzzingCheckBindData>();

	string suite_filter;
	if (!input.inputs.empty() && !input.inputs[0].IsNull()) {
		suite_filter = StringValue::Get(input.inputs[0]);
	}
	string property_filter;

	for (auto &entry : input.named_parameters) {
		auto key = StringUtil::Lower(entry.first.GetIdentifierName());
		if (entry.second.IsNull()) {
			throw BinderException("fuzzing_check: parameter '%s' cannot be NULL", key);
		}
		if (key == "max_success") {
			result->options.max_success = entry.second.GetValue<uint32_t>();
		} else if (key == "max_size") {
			result->options.max_size = entry.second.GetValue<uint32_t>();
		} else if (key == "max_discard_ratio") {
			result->options.max_discard_ratio = entry.second.GetValue<uint32_t>();
		} else if (key == "noshrink") {
			result->options.no_shrink = BooleanValue::Get(entry.second);
		} else if (key == "seed") {
			result->options.seed = entry.second.GetValue<uint64_t>();
		} else if (key == "property") {
			property_filter = StringValue::Get(entry.second);
		} else {
			throw BinderException("fuzzing_check: unknown parameter '%s'", key);
		}
	}
	if (result->options.max_success == 0) {
		throw BinderException("fuzzing_check: max_success must be greater than zero");
	}

	for (auto &property : PropertyRegistry::All()) {
		if (!suite_filter.empty() && property.suite != suite_filter) {
			continue;
		}
		if (!property_filter.empty() && property.name != property_filter) {
			continue;
		}
		result->properties.push_back(&property);
	}
	if (result->properties.empty()) {
		if (!property_filter.empty()) {
			throw BinderException("fuzzing_check: no property named '%s'%s", property_filter,
			                      suite_filter.empty() ? "" : " in suite '" + suite_filter + "'");
		}
		auto suites = StringUtil::Join(PropertyRegistry::Suites(), ", ");
		throw BinderException("fuzzing_check: no properties match suite '%s' (available: %s)", suite_filter, suites);
	}

	names = {"suite", "property", "status", "issue", "cases",        "shrinks",
	         "error", "counterexample", "reproduce", "runtime_seconds"};
	return_types = {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR,
	                LogicalType::UBIGINT, LogicalType::UBIGINT, LogicalType::VARCHAR, LogicalType::VARCHAR,
	                LogicalType::VARCHAR, LogicalType::DOUBLE};
	return std::move(result);
}

static unique_ptr<GlobalTableFunctionState> FuzzingCheckInit(ClientContext &context, TableFunctionInitInput &input) {
	return make_uniq<FuzzingCheckState>();
}

static Value NullableString(const string &value) {
	return value.empty() ? Value(LogicalType::VARCHAR) : Value(value);
}

static void FuzzingCheckFunction(ClientContext &context, TableFunctionInput &data, DataChunk &output) {
	auto &bind_data = data.bind_data->Cast<FuzzingCheckBindData>();
	auto &state = data.global_state->Cast<FuzzingCheckState>();

	idx_t count = 0;
	while (count < STANDARD_VECTOR_SIZE && state.offset < bind_data.properties.size()) {
		// Properties are slow; check for cancellation between each one.
		context.InterruptCheck();
		auto result = duckdb_fuzzing::RunProperty(*bind_data.properties[state.offset], bind_data.options);
		state.offset++;

		output.SetValue(0, count, Value(result.suite));
		output.SetValue(1, count, Value(result.name));
		output.SetValue(2, count, Value(PropertyStatusName(result.status)));
		output.SetValue(3, count, NullableString(result.issue));
		output.SetValue(4, count, Value::UBIGINT(result.cases));
		output.SetValue(5, count, Value::UBIGINT(result.shrinks));
		output.SetValue(6, count, NullableString(result.description));
		output.SetValue(7, count, NullableString(result.counterexample));
		output.SetValue(8, count, Value(result.reproduce));
		output.SetValue(9, count, Value::DOUBLE(result.seconds));
		count++;
	}
	output.SetCardinality(count);
}

//===--------------------------------------------------------------------===//
// fuzzing_properties()
//===--------------------------------------------------------------------===//
// Lists the registered properties without running them.
struct FuzzingPropertiesState : public GlobalTableFunctionState {
	idx_t offset = 0;

	idx_t MaxThreads() const override {
		return 1;
	}
};

static unique_ptr<FunctionData> FuzzingPropertiesBind(ClientContext &context, TableFunctionBindInput &input,
                                                      vector<LogicalType> &return_types, vector<Identifier> &names) {
	names = {"suite", "property", "issue", "expectation", "deterministic", "requires_extension"};
	return_types = {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR,
	                LogicalType::VARCHAR, LogicalType::BOOLEAN, LogicalType::VARCHAR};
	return nullptr;
}

static unique_ptr<GlobalTableFunctionState> FuzzingPropertiesInit(ClientContext &context,
                                                                  TableFunctionInitInput &input) {
	return make_uniq<FuzzingPropertiesState>();
}

static void FuzzingPropertiesFunction(ClientContext &context, TableFunctionInput &data, DataChunk &output) {
	auto &state = data.global_state->Cast<FuzzingPropertiesState>();
	auto &properties = PropertyRegistry::All();

	idx_t count = 0;
	while (count < STANDARD_VECTOR_SIZE && state.offset < properties.size()) {
		auto &property = properties[state.offset++];
		output.SetValue(0, count, Value(property.suite));
		output.SetValue(1, count, Value(property.name));
		output.SetValue(2, count, NullableString(property.issue));
		output.SetValue(
		    3, count,
		    Value(property.expectation == duckdb_fuzzing::PropertyExpectation::KNOWN_FAIL ? "known_fail" : "pass"));
		output.SetValue(4, count, Value::BOOLEAN(property.deterministic));
		output.SetValue(5, count, NullableString(property.requires_extension));
		count++;
	}
	output.SetCardinality(count);
}

static void LoadInternal(ExtensionLoader &loader) {
	// Touch the anchors so no linker can decide the property files are unused.
	if (duckdb_fuzzing::TouchPropertyFiles() != 0) {
		throw InternalException("fuzzing: property link anchors were dropped");
	}

	loader.RegisterFunction(ScalarFunction("fuzzing_version", {}, LogicalType::VARCHAR, FuzzingVersionFunction));

	TableFunctionSet check_set("fuzzing_check");
	for (auto &arguments : vector<vector<LogicalType>> {{}, {LogicalType::VARCHAR}}) {
		TableFunction check(arguments, FuzzingCheckFunction, FuzzingCheckBind, FuzzingCheckInit);
		check.named_parameters["max_success"] = LogicalType::UINTEGER;
		check.named_parameters["max_size"] = LogicalType::UINTEGER;
		check.named_parameters["max_discard_ratio"] = LogicalType::UINTEGER;
		check.named_parameters["noshrink"] = LogicalType::BOOLEAN;
		check.named_parameters["seed"] = LogicalType::UBIGINT;
		check.named_parameters["property"] = LogicalType::VARCHAR;
		check_set.AddFunction(std::move(check));
	}
	loader.RegisterFunction(std::move(check_set));

	loader.RegisterFunction(
	    TableFunction("fuzzing_properties", {}, FuzzingPropertiesFunction, FuzzingPropertiesBind,
	                  FuzzingPropertiesInit));
}

void FuzzingExtension::Load(ExtensionLoader &loader) {
	LoadInternal(loader);
}
std::string FuzzingExtension::Name() {
	return "fuzzing";
}

std::string FuzzingExtension::Version() const {
	return FuzzingVersionString();
}

} // namespace duckdb

extern "C" {

DUCKDB_CPP_EXTENSION_ENTRY(fuzzing, loader) {
	duckdb::LoadInternal(loader);
}
}
