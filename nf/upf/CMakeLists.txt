# SPDX-License-Identifier: LicenseRef-Proprietary
add_library(g5c_upf STATIC src/sdf.c src/ptrmap.c src/rules.c src/urr.c src/dp.c src/n4.c src/core.c)
target_include_directories(g5c_upf PUBLIC include PRIVATE src)
target_link_libraries(g5c_upf PUBLIC g5c_pfcp g5c_gtpu g5c_base)

add_library(g5c_upf_rt STATIC src/rt.c src/config.c)
target_include_directories(g5c_upf_rt PUBLIC include PRIVATE src)
target_link_libraries(g5c_upf_rt PUBLIC g5c_upf)

add_executable(upf src/main.c)
target_link_libraries(upf g5c_upf_rt g5c_nfcore)
install(TARGETS upf RUNTIME DESTINATION bin)

add_executable(test_upf_core tests/test_upf_core.c)
target_include_directories(test_upf_core PRIVATE ${CMAKE_SOURCE_DIR}/libs/pfcp/tests)
target_link_libraries(test_upf_core g5c_upf g5c_testkit)
add_test(NAME upf_engine COMMAND test_upf_core)

# layers of the validation strategy (ctest -L <label>)
set_property(TEST upf_engine APPEND PROPERTY LABELS component conformance)

add_executable(test_upf_io tests/test_upf_io.c)
target_link_libraries(test_upf_io g5c_upf_rt g5c_testkit)
add_test(NAME upf_runtime_sockets COMMAND test_upf_io)
set_property(TEST upf_runtime_sockets APPEND PROPERTY LABELS component integration)

# Throughput of the engine without I/O (Stage A: the ceiling the runtime can approach). Optimised, uninstrumented builds only.
add_executable(bench_upf tests/bench_upf.c)
target_include_directories(bench_upf PRIVATE ${CMAKE_SOURCE_DIR}/libs/pfcp/tests)
target_link_libraries(bench_upf g5c_upf g5c_testkit)
add_test(NAME upf_bench_noop COMMAND bench_upf)
set_property(TEST upf_bench_noop APPEND PROPERTY LABELS perf)
if(NOT (G5C_SANITIZE OR G5C_TSAN OR G5C_COVERAGE))
  add_test(NAME upf_bench_gate COMMAND bench_upf)
  set_tests_properties(upf_bench_gate PROPERTIES ENVIRONMENT "G5C_PERF=1" TIMEOUT 300 LABELS perf)
endif()

add_executable(bench_upf_io tests/bench_upf_io.c)
target_link_libraries(bench_upf_io g5c_upf_rt g5c_testkit)
add_test(NAME upf_io_bench_noop COMMAND bench_upf_io)
set_property(TEST upf_io_bench_noop APPEND PROPERTY LABELS perf)
if(NOT (G5C_SANITIZE OR G5C_TSAN OR G5C_COVERAGE))
  add_test(NAME upf_io_bench_gate COMMAND bench_upf_io)
  set_tests_properties(upf_io_bench_gate PROPERTIES ENVIRONMENT "G5C_PERF=1" TIMEOUT 120 LABELS perf)
endif()

add_executable(test_upf_units tests/test_upf_units.c)
target_include_directories(test_upf_units PRIVATE src)
target_link_libraries(test_upf_units g5c_upf g5c_testkit)
add_test(NAME upf_units COMMAND test_upf_units)
set_property(TEST upf_units APPEND PROPERTY LABELS unit)
