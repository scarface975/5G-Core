# SPDX-License-Identifier: LicenseRef-Proprietary
add_library(g5c_udm STATIC src/core.c src/udr.c src/udm.c src/ueau.c src/sdm.c src/uecm.c src/ee.c src/admin.c src/config.c)
target_include_directories(g5c_udm PUBLIC include)
target_link_libraries(g5c_udm PUBLIC g5c_nfcore g5c_sbi g5c_crypto g5c_base)

add_executable(udm src/main.c)
target_link_libraries(udm g5c_udm)

add_executable(test_udm tests/test_udm.c)
target_link_libraries(test_udm g5c_udm g5c_udr g5c_testkit)
add_test(NAME udm_unit_and_services COMMAND test_udm)

install(TARGETS udm RUNTIME DESTINATION bin)

add_executable(perf_udm tests/perf_udm.c)
target_link_libraries(perf_udm g5c_udm g5c_udr g5c_testkit)
add_test(NAME udm_perf_noop COMMAND perf_udm)

# Phase 1 exit criterion: >= 1,000 auth vectors/s on one instance with K/OPc encrypted at rest. Only meaningful in an
# optimised, uninstrumented build.
if(NOT (G5C_SANITIZE OR G5C_TSAN OR G5C_COVERAGE))
  add_test(NAME udm_perf_gate COMMAND perf_udm)
  set_tests_properties(udm_perf_gate PROPERTIES ENVIRONMENT "G5C_PERF=1" TIMEOUT 180 LABELS perf)
endif()

# layers of the validation strategy (ctest -L <label>)
set_property(TEST udm_unit_and_services APPEND PROPERTY LABELS component)
set_property(TEST udm_perf_noop APPEND PROPERTY LABELS perf)
