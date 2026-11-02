# SPDX-License-Identifier: LicenseRef-Proprietary
add_library(g5c_ngap STATIC src/aper.c src/schema.c)
target_include_directories(g5c_ngap PUBLIC include)
target_link_libraries(g5c_ngap PUBLIC g5c_base)
# the generated schema is large and regular; keep the strict flags but do not let -Woverlength-strings etc. matter

add_executable(test_ngap tests/test_ngap.c)
target_link_libraries(test_ngap g5c_ngap g5c_testkit)
target_compile_definitions(test_ngap PRIVATE G5C_FIXTURES="${CMAKE_SOURCE_DIR}/tests/fixtures/golden")
add_test(NAME ngap_aper_golden COMMAND test_ngap)

# layers of the validation strategy (ctest -L <label>)
set_property(TEST ngap_aper_golden APPEND PROPERTY LABELS conformance)
