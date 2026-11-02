# SPDX-License-Identifier: LicenseRef-Proprietary
add_library(g5c_nssf STATIC src/nssf.c src/config.c src/util.c src/nsselect.c src/avail.c src/api_schemas.gen.c)
target_include_directories(g5c_nssf PUBLIC include PRIVATE src)
target_link_libraries(g5c_nssf PUBLIC g5c_nfcore g5c_sbi g5c_base g5c_oaschema pthread)

add_executable(nssf src/main.c)
target_link_libraries(nssf g5c_nssf)
install(TARGETS nssf RUNTIME DESTINATION bin)

add_executable(test_nssf tests/test_nssf.c)
target_include_directories(test_nssf PRIVATE src)
target_link_libraries(test_nssf g5c_nssf g5c_testkit)
add_test(NAME nssf_e2e COMMAND test_nssf)
set_tests_properties(nssf_e2e PROPERTIES TIMEOUT 120 LABELS "component;integration")
