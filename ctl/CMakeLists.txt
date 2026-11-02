# SPDX-License-Identifier: LicenseRef-Proprietary
add_library(g5c_ctl STATIC src/ctl.c)
target_include_directories(g5c_ctl PUBLIC include)
target_link_libraries(g5c_ctl PUBLIC g5c_nfcore g5c_sbi g5c_base)

add_executable(g5c-ctl src/main.c)
target_link_libraries(g5c-ctl g5c_ctl)

add_executable(test_ctl tests/test_ctl.c)
target_link_libraries(test_ctl g5c_ctl g5c_udm g5c_pcf g5c_udr g5c_testkit)
add_test(NAME ctl_cli COMMAND test_ctl WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

install(TARGETS g5c-ctl RUNTIME DESTINATION bin)

# layers of the validation strategy (ctest -L <label>)
set_property(TEST ctl_cli APPEND PROPERTY LABELS component)
