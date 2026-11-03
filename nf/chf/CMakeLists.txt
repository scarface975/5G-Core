# SPDX-License-Identifier: LicenseRef-Proprietary
add_library(g5c_chf STATIC src/chf.c)
target_include_directories(g5c_chf PUBLIC include)
target_link_libraries(g5c_chf PUBLIC g5c_nfcore g5c_sbi g5c_base pthread)

add_executable(chf src/main.c)
target_link_libraries(chf g5c_chf)
install(TARGETS chf RUNTIME DESTINATION bin)

add_executable(test_chf tests/test_chf.c)
target_link_libraries(test_chf g5c_chf g5c_testkit)
add_test(NAME chf_e2e COMMAND test_chf)
set_tests_properties(chf_e2e PROPERTIES TIMEOUT 120 LABELS "component;integration")
