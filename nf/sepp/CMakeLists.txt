# SPDX-License-Identifier: LicenseRef-Proprietary
add_library(g5c_sepp STATIC src/sepp.c)
target_include_directories(g5c_sepp PUBLIC include)
target_link_libraries(g5c_sepp PUBLIC g5c_nfcore g5c_sbi g5c_base pthread)

add_executable(sepp src/main.c)
target_link_libraries(sepp g5c_sepp)
install(TARGETS sepp RUNTIME DESTINATION bin)

add_executable(test_sepp tests/test_sepp.c)
target_link_libraries(test_sepp g5c_sepp g5c_testkit)
add_test(NAME sepp_e2e COMMAND test_sepp)
set_tests_properties(sepp_e2e PROPERTIES TIMEOUT 120 LABELS "component;integration")
