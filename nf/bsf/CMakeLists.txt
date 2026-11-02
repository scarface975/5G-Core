# SPDX-License-Identifier: LicenseRef-Proprietary
add_library(g5c_bsf STATIC src/bsf.c src/config.c src/util.c src/bindings.c src/state.c src/api_schemas.gen.c)
target_include_directories(g5c_bsf PUBLIC include PRIVATE src)
target_link_libraries(g5c_bsf PUBLIC g5c_nfcore g5c_sbi g5c_base g5c_oaschema pthread)

add_executable(bsf src/main.c)
target_link_libraries(bsf g5c_bsf)
install(TARGETS bsf RUNTIME DESTINATION bin)

add_executable(test_bsf tests/test_bsf.c)
target_include_directories(test_bsf PRIVATE src)
target_link_libraries(test_bsf g5c_bsf g5c_testkit)
add_test(NAME bsf_e2e COMMAND test_bsf)
set_tests_properties(bsf_e2e PROPERTIES TIMEOUT 120 LABELS "component;integration")
