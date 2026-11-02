# SPDX-License-Identifier: LicenseRef-Proprietary
add_library(g5c_gtpu STATIC src/gtpu.c)
target_include_directories(g5c_gtpu PUBLIC include)

add_executable(test_gtpu tests/test_gtpu.c)
target_link_libraries(test_gtpu g5c_gtpu g5c_testkit)
add_test(NAME gtpu_codec COMMAND test_gtpu)

# layers of the validation strategy (ctest -L <label>)
set_property(TEST gtpu_codec APPEND PROPERTY LABELS unit)
