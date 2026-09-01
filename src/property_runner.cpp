#include "property_runner.hpp"

#include <chrono>
#include <exception>
#include <random>
#include <sstream>

#include <rapidcheck/detail/Configuration.h>
#include <rapidcheck/detail/Property.h>
#include <rapidcheck/detail/Results.h>
#include <rapidcheck/detail/TestMetadata.h>
#include <rapidcheck/detail/TestParams.h>

namespace duckdb_fuzzing {

//===--------------------------------------------------------------------===//
// Registry
//===--------------------------------------------------------------------===//
// A function-local static keeps registration order well defined regardless of
// the order the translation units are initialized in.
static vector<PropertyCase> &MutableRegistry() {
	static vector<PropertyCase> registry;
	return registry;
}

const vector<PropertyCase> &PropertyRegistry::All() {
	return MutableRegistry();
}

bool PropertyRegistry::Register(PropertyCase property) {
	MutableRegistry().push_back(std::move(property));
	return true;
}

vector<string> PropertyRegistry::Suites() {
	vector<string> suites;
	for (auto &property : MutableRegistry()) {
		bool seen = false;
		for (auto &suite : suites) {
			if (suite == property.suite) {
				seen = true;
				break;
			}
		}
		if (!seen) {
			suites.push_back(property.suite);
		}
	}
	return suites;
}

//===--------------------------------------------------------------------===//
// Runner
//===--------------------------------------------------------------------===//
const char *PropertyStatusName(PropertyStatus status) {
	switch (status) {
	case PropertyStatus::PASS:
		return "pass";
	case PropertyStatus::FAIL:
		return "fail";
	case PropertyStatus::KNOWN_FAIL:
		return "known_fail";
	case PropertyStatus::FIXED:
		return "fixed";
	case PropertyStatus::GAVE_UP:
		return "gave_up";
	case PropertyStatus::SKIPPED:
		return "skipped";
	default:
		return "unknown";
	}
}

static string FormatCounterExample(const rc::detail::Example &example) {
	std::ostringstream out;
	for (idx_t i = 0; i < example.size(); i++) {
		if (i > 0) {
			out << "\n";
		}
		out << example[i].first << " = " << example[i].second;
	}
	return out.str();
}

static string FormatReproduce(const rc::detail::TestParams &params) {
	std::ostringstream out;
	out << "seed=" << params.seed << " max_success=" << params.maxSuccess << " max_size=" << params.maxSize;
	if (params.disableShrinking) {
		out << " noshrink=true";
	}
	return out.str();
}

//! Returns true when the extension is usable in a fresh database.
static bool ExtensionAvailable(PropDB &db, const string &extension) {
	auto result = db.Query("SELECT 1 FROM duckdb_extensions() WHERE extension_name = '" + extension +
	                       "' AND loaded");
	if (result->HasError()) {
		return false;
	}
	return result->RowCount() > 0;
}

PropertyRunResult RunProperty(const PropertyCase &property, const PropertyRunOptions &options) {
	PropertyRunResult result;
	result.suite = property.suite;
	result.name = property.name;
	result.issue = property.issue;

	rc::detail::TestParams params;
	params.seed = options.seed;
	if (params.seed == 0) {
		// Always report a concrete seed so any failure can be replayed.
		std::random_device device;
		params.seed = (uint64_t(device()) << 32) | uint64_t(device());
	}
	// A deterministic probe replays the same case every time; one is enough.
	params.maxSuccess = property.deterministic ? 1 : NumericCast<int>(options.max_success);
	params.maxSize = NumericCast<int>(options.max_size);
	params.maxDiscardRatio = NumericCast<int>(options.max_discard_ratio);
	params.disableShrinking = options.no_shrink;
	result.reproduce = FormatReproduce(params);

	rc::detail::TestMetadata metadata;
	metadata.id = property.suite + "/" + property.name;
	metadata.description = property.name;

	const auto expects_failure = property.expectation == PropertyExpectation::KNOWN_FAIL;
	const auto start = std::chrono::steady_clock::now();

	try {
		// The database outlives every generated case of this property, matching
		// the lifetime the standalone Catch2 harness gave it.
		PropDB db;
		if (!property.requires_extension.empty() && !ExtensionAvailable(db, property.requires_extension)) {
			result.status = PropertyStatus::SKIPPED;
			result.description = "extension '" + property.requires_extension + "' is not loaded";
			return result;
		}

		auto &body = property.body;
		const auto test_result = rc::detail::checkTestable([&body, &db] { body(db); }, metadata, params);

		if (test_result.is<rc::detail::SuccessResult>()) {
			auto &success = test_result.get<rc::detail::SuccessResult>();
			result.cases = NumericCast<uint32_t>(success.numSuccess);
			result.status = expects_failure ? PropertyStatus::FIXED : PropertyStatus::PASS;
			if (expects_failure) {
				result.description = "property expected to reproduce " + property.issue +
				                     " but held for every case; the upstream fix can be adopted";
			}
		} else if (test_result.is<rc::detail::FailureResult>()) {
			auto &failure = test_result.get<rc::detail::FailureResult>();
			result.cases = NumericCast<uint32_t>(failure.numSuccess);
			result.shrinks = NumericCast<uint32_t>(failure.reproduce.shrinkPath.size());
			result.description = failure.description;
			result.counterexample = FormatCounterExample(failure.counterExample);
			result.status = expects_failure ? PropertyStatus::KNOWN_FAIL : PropertyStatus::FAIL;
		} else if (test_result.is<rc::detail::GaveUpResult>()) {
			auto &gave_up = test_result.get<rc::detail::GaveUpResult>();
			result.cases = NumericCast<uint32_t>(gave_up.numSuccess);
			result.description = gave_up.description;
			result.status = PropertyStatus::GAVE_UP;
		} else {
			result.description = test_result.get<rc::detail::Error>().description;
			result.status = PropertyStatus::FAIL;
		}
	} catch (const std::exception &error) {
		// A property that escapes with an exception (rather than failing an
		// assertion) is still a finding, not a crash of the whole run.
		result.status = expects_failure ? PropertyStatus::KNOWN_FAIL : PropertyStatus::FAIL;
		result.description = string("uncaught exception: ") + error.what();
	} catch (...) {
		result.status = expects_failure ? PropertyStatus::KNOWN_FAIL : PropertyStatus::FAIL;
		result.description = "uncaught non-standard exception";
	}

	const auto end = std::chrono::steady_clock::now();
	result.seconds = std::chrono::duration<double>(end - start).count();
	return result;
}

} // namespace duckdb_fuzzing
