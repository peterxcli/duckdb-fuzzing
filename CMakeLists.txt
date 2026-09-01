cmake_minimum_required(VERSION 3.15)

# Set extension name here
set(TARGET_NAME fuzzing)

set(EXTENSION_NAME ${TARGET_NAME}_extension)
set(LOADABLE_EXTENSION_NAME ${TARGET_NAME}_loadable_extension)

project(${TARGET_NAME})

set(CMAKE_CXX_STANDARD "17" CACHE STRING "C++ standard to enforce")
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# RapidCheck (https://github.com/emil-e/rapidcheck) drives the property suite.
# Pass -DRAPIDCHECK_SOURCE_DIR=/path/to/rapidcheck to build against a local
# checkout instead of fetching it.
set(RAPIDCHECK_SOURCE_DIR
    ""
    CACHE PATH "Local RapidCheck checkout (optional)")

if(RAPIDCHECK_SOURCE_DIR)
  add_subdirectory("${RAPIDCHECK_SOURCE_DIR}" "${CMAKE_CURRENT_BINARY_DIR}/rapidcheck" EXCLUDE_FROM_ALL)
else()
  include(FetchContent)
  FetchContent_Declare(
    rapidcheck
    GIT_REPOSITORY https://github.com/emil-e/rapidcheck.git
    GIT_TAG 6e8dadfdafa3a74eabb52ead87f8787f72eccd0b)
  FetchContent_MakeAvailable(rapidcheck)
endif()

# The extension links RapidCheck statically, so it has to be position
# independent to end up in the loadable extension.
set_property(TARGET rapidcheck PROPERTY POSITION_INDEPENDENT_CODE ON)

include_directories(src/include)

set(EXTENSION_SOURCES
    src/fuzzing_extension.cpp
    src/property_runner.cpp
    src/properties/generators.cpp
    src/properties/prop_arithmetic.cpp
    src/properties/prop_datetime.cpp
    src/properties/prop_known_issues.cpp
    src/properties/prop_lists.cpp
    src/properties/prop_roundtrip.cpp
    src/properties/prop_storage.cpp
    src/properties/prop_strings.cpp)

build_static_extension(${TARGET_NAME} ${EXTENSION_SOURCES})
build_loadable_extension(${TARGET_NAME} " " ${EXTENSION_SOURCES})

target_link_libraries(${EXTENSION_NAME} rapidcheck)
target_link_libraries(${LOADABLE_EXTENSION_NAME} rapidcheck)

install(
  TARGETS ${EXTENSION_NAME}
  EXPORT "${DUCKDB_EXPORT_SET}"
  LIBRARY DESTINATION "${INSTALL_LIB_DIR}"
  ARCHIVE DESTINATION "${INSTALL_LIB_DIR}")
