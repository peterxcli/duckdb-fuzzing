# This file is included by DuckDB's build system. It specifies which extension to load

# Extension from this repo
duckdb_extension_load(fuzzing
    SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}
)

# Extensions the property tests exercise (JSON round trips in test_roundtrip.cpp)
duckdb_extension_load(json)
