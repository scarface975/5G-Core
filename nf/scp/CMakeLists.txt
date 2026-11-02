# SPDX-License-Identifier: LicenseRef-Proprietary
add_library(g5c_scp STATIC src/scp.c src/config.c src/select.c src/proxy.c)
target_include_directories(g5c_scp PUBLIC include PRIVATE src)
target_link_libraries(g5c_scp PUBLIC g5c_nfcore g5c_sbi g5c_base pthread)

add_executable(scp src/main.c)
target_link_libraries(scp g5c_scp)
install(TARGETS scp RUNTIME DESTINATION bin)

add_executable(test_scp tests/test_scp.c)
target_include_directories(test_scp PRIVATE src)
target_link_libraries(test_scp g5c_scp g5c_testkit)
add_test(NAME scp_e2e COMMAND test_scp)
set_tests_properties(scp_e2e PROPERTIES TIMEOUT 120 LABELS "component;integration")
