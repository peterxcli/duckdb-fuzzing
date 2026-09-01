//===----------------------------------------------------------------------===//
//                         DuckDB fuzzing extension
//
// src/include/property_runner.hpp
//
// Runs a registered property through RapidCheck and reports the outcome as
// data (rather than printing it), so fuzzing_check() can return it as rows.
//===----------------------------------------------------------------------===//

#pragma once

#include "fuzzing_property.hpp"

namespace duckdb_fuzzing {

enum class PropertyStatus : uint8_t {
	//! Property held for every generated case
	PASS,
	//! Property was falsified; this is a bug unless it is a known failure
	FAIL,
	//! Property was falsified, and that is what the known-issue guard expects
	KNOWN_FAIL,
	//! Property was expected to fail but passed: the upstream bug looks fixed
	FIXED,
	//! Too many generated cases were discarded to conclude anything
	GAVE_UP,
	//! A required extension was unavailable
	SKIPPED
};

const char *PropertyStatusName(PropertyStatus status);

struct PropertyRunOptions {
	//! Number of successful cases required to consider a property passing
	uint32_t max_success = 100;
	//! Upper bound on generated value size
	uint32_t max_size = 100;
	//! Allowed discards per successful case
	uint32_t max_discard_ratio = 10;
	//! Skip shrinking: faster surveys, larger counterexamples
	bool no_shrink = false;
	//! RapidCheck seed; 0 picks a fresh random seed per run
	uint64_t seed = 0;
};

struct PropertyRunResult {
	string suite;
	string name;
	string issue;
	PropertyStatus status = PropertyStatus::PASS;
	//! Cases that passed before the property finished
	uint32_t cases = 0;
	//! Shrink steps applied to the counterexample
	uint32_t shrinks = 0;
	//! Failure message (empty when passing)
	string description;
	//! Shrunk counterexample, one "name: value" entry per generated input
	string counterexample;
	//! Named arguments that reproduce this exact run, as "key=value" pairs
	//! (e.g. "seed=123 max_success=200 max_size=100")
	string reproduce;
	//! Wall clock time of the property run
	double seconds = 0;
};

//! Run a single property. Never throws: any escaping exception becomes a FAIL.
PropertyRunResult RunProperty(const PropertyCase &property, const PropertyRunOptions &options);

} // namespace duckdb_fuzzing
