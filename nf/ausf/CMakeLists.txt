# SPDX-License-Identifier: LicenseRef-Proprietary
add_library(g5c_ausf STATIC src/ausf.c src/store.c src/udm.c src/ueau.c src/eap.c src/prot.c src/state.c src/config.c)
target_include_directories(g5c_ausf PUBLIC include PRIVATE src)
target_compile_definitions(g5c_ausf PRIVATE _GNU_SOURCE)
target_link_libraries(g5c_ausf PUBLIC g5c_nfcore g5c_sbi g5c_crypto g5c_base pthread)

add_executable(ausf src/main.c)
target_link_libraries(ausf g5c_ausf)
install(TARGETS ausf RUNTIME DESTINATION bin)

add_executable(test_ausf tests/test_ausf.c)
target_link_libraries(test_ausf g5c_ausf g5c_udm g5c_udr g5c_testkit)
add_test(NAME ausf_e2e COMMAND test_ausf)
set_tests_properties(ausf_e2e PROPERTIES TIMEOUT 180 LABELS "component;integration")
