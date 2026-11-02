# SPDX-License-Identifier: LicenseRef-Proprietary
add_library(g5c_pfcp STATIC src/pfcp.c src/pfcp_ie.c)
target_include_directories(g5c_pfcp PUBLIC include)

add_executable(test_pfcp tests/test_pfcp.c)
target_link_libraries(test_pfcp g5c_pfcp g5c_testkit)
add_test(NAME pfcp_codec COMMAND test_pfcp)

add_executable(test_pfcp_ie tests/test_pfcp_ie.c)
target_link_libraries(test_pfcp_ie g5c_pfcp g5c_testkit)
add_test(NAME pfcp_typed_ies COMMAND test_pfcp_ie)

# layers of the validation strategy (ctest -L <label>)
set_property(TEST pfcp_codec APPEND PROPERTY LABELS unit)
set_property(TEST pfcp_typed_ies APPEND PROPERTY LABELS unit conformance)
