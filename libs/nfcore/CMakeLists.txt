# SPDX-License-Identifier: LicenseRef-Proprietary
add_library(g5c_nfcore STATIC src/nfcore.c src/disc.c src/oauth.c src/events.c src/overload.c src/reload.c src/authz.c src/hook.c)
target_include_directories(g5c_nfcore PUBLIC include)
target_link_libraries(g5c_nfcore PUBLIC g5c_sbi g5c_base pthread)

add_executable(test_nfcore tests/test_nfcore.c)
target_link_libraries(test_nfcore g5c_nfcore g5c_testkit)
add_test(NAME nfcore_runtime_nrf COMMAND test_nfcore)

# layers of the validation strategy (ctest -L <label>)
set_property(TEST nfcore_runtime_nrf APPEND PROPERTY LABELS component)

add_executable(test_events tests/test_events.c)
target_link_libraries(test_events g5c_nfcore g5c_testkit)
add_test(NAME nfcore_events COMMAND test_events)
set_property(TEST nfcore_events APPEND PROPERTY LABELS component)

add_executable(test_overload tests/test_overload.c)
target_link_libraries(test_overload g5c_nfcore g5c_testkit)
add_test(NAME nfcore_overload COMMAND test_overload)
set_property(TEST nfcore_overload APPEND PROPERTY LABELS component)

add_executable(test_reload tests/test_reload.c)
target_link_libraries(test_reload g5c_nfcore g5c_testkit)
add_test(NAME nfcore_reload COMMAND test_reload)
set_property(TEST nfcore_reload APPEND PROPERTY LABELS component)

add_executable(test_authz tests/test_authz.c)
target_link_libraries(test_authz g5c_nfcore g5c_testkit)
add_test(NAME nfcore_authz COMMAND test_authz)
set_property(TEST nfcore_authz APPEND PROPERTY LABELS component)

add_executable(test_hook tests/test_hook.c)
target_link_libraries(test_hook g5c_nfcore g5c_testkit)
add_test(NAME nfcore_hook COMMAND test_hook)
set_property(TEST nfcore_hook APPEND PROPERTY LABELS component)
