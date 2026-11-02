# SPDX-License-Identifier: LicenseRef-Proprietary
add_library(g5c_nef STATIC src/nef.c src/config.c src/util.c src/ti.c src/me.c src/as.c src/api_schemas.gen.c)
target_include_directories(g5c_nef PUBLIC include PRIVATE src)
target_link_libraries(g5c_nef PUBLIC g5c_nfcore g5c_sbi g5c_base g5c_oaschema pthread)

add_executable(nef src/main.c)
target_link_libraries(nef g5c_nef)
install(TARGETS nef RUNTIME DESTINATION bin)

add_executable(test_nef tests/test_nef.c)
target_include_directories(test_nef PRIVATE src)
target_link_libraries(test_nef g5c_nef g5c_udm g5c_udr g5c_pcf g5c_bsf g5c_testkit)
add_test(NAME nef_e2e COMMAND test_nef)
set_tests_properties(nef_e2e PROPERTIES TIMEOUT 120 LABELS "component;integration")

add_executable(nef_af_sink tests/af_sink.c)
target_link_libraries(nef_af_sink g5c_sbi g5c_base pthread)
