# SPDX-License-Identifier: LicenseRef-Proprietary
add_library(g5c_nrf STATIC src/store.c src/mgmt.c src/disc.c src/oauth.c src/config.c)
target_include_directories(g5c_nrf PUBLIC include PRIVATE src)
target_compile_definitions(g5c_nrf PRIVATE _GNU_SOURCE)
target_link_libraries(g5c_nrf PUBLIC g5c_nfcore g5c_sbi g5c_base pthread)

add_executable(nrf src/main.c)
target_compile_definitions(nrf PRIVATE _GNU_SOURCE)
target_link_libraries(nrf g5c_nrf)
install(TARGETS nrf RUNTIME DESTINATION bin)

add_executable(test_nrf tests/test_nrf.c)
target_include_directories(test_nrf PRIVATE src)
target_link_libraries(test_nrf g5c_nrf g5c_testkit)
add_test(NAME nrf_e2e COMMAND test_nrf)
set_tests_properties(nrf_e2e PROPERTIES TIMEOUT 180 LABELS "component;integration")

add_executable(test_oauth2 tests/test_oauth2.c)
target_link_libraries(test_oauth2 g5c_nrf g5c_testkit)
add_test(NAME nrf_oauth2 COMMAND test_oauth2)
set_tests_properties(nrf_oauth2 PROPERTIES TIMEOUT 120 LABELS "component;integration")
