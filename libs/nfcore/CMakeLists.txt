# SPDX-License-Identifier: LicenseRef-Proprietary
add_library(g5c_nfcore STATIC src/nfcore.c src/disc.c src/oauth.c)
target_include_directories(g5c_nfcore PUBLIC include)
target_link_libraries(g5c_nfcore PUBLIC g5c_sbi g5c_base pthread)

add_executable(test_nfcore tests/test_nfcore.c)
target_link_libraries(test_nfcore g5c_nfcore g5c_testkit)
add_test(NAME nfcore_runtime_nrf COMMAND test_nfcore)

# layers of the validation strategy (ctest -L <label>)
set_property(TEST nfcore_runtime_nrf APPEND PROPERTY LABELS component)
