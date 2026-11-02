# SPDX-License-Identifier: LicenseRef-Proprietary
add_library(g5c_nas STATIC src/nas.c src/nasie.c src/security.c src/defs.c)
target_include_directories(g5c_nas PUBLIC include)
target_link_libraries(g5c_nas PUBLIC g5c_crypto g5c_base)

add_executable(test_nas tests/test_nas.c)
target_link_libraries(test_nas g5c_nas g5c_testkit)
add_test(NAME nas_codec COMMAND test_nas)

# layers of the validation strategy (ctest -L <label>)
set_property(TEST nas_codec APPEND PROPERTY LABELS unit)
