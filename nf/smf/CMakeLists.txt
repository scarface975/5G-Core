# SPDX-License-Identifier: LicenseRef-Proprietary
add_library(g5c_smf STATIC src/ipam.c src/policy.c src/gsm.c src/n2sm.c src/n4c.c src/n4rules.c src/cdr.c src/peers.c src/persist.c src/ra.c src/sm.c src/smf.c)
target_include_directories(g5c_smf PUBLIC include PRIVATE src)
target_link_libraries(g5c_smf PUBLIC g5c_nfcore g5c_sbi g5c_pfcp g5c_gtpu g5c_nas g5c_ngap g5c_base)

add_executable(smf src/main.c)
target_link_libraries(smf g5c_smf)
install(TARGETS smf RUNTIME DESTINATION bin)

add_executable(test_smf_units tests/test_smf_units.c)
target_include_directories(test_smf_units PRIVATE ${CMAKE_SOURCE_DIR}/nf/upf/tests ${CMAKE_SOURCE_DIR}/libs/pfcp/tests)
target_link_libraries(test_smf_units g5c_smf g5c_upf g5c_gtpu g5c_testkit)
add_test(NAME smf_units COMMAND test_smf_units)
set_property(TEST smf_units APPEND PROPERTY LABELS unit conformance)

add_executable(test_smf_e2e tests/test_smf_e2e.c)
target_link_libraries(test_smf_e2e g5c_smf g5c_udm g5c_pcf g5c_udr g5c_upf_rt g5c_gtpu g5c_testkit)
add_test(NAME smf_e2e COMMAND test_smf_e2e)
set_tests_properties(smf_e2e PROPERTIES TIMEOUT 120 LABELS "component;integration")
