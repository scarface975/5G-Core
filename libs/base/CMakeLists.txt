# SPDX-License-Identifier: LicenseRef-Proprietary
find_package(Threads REQUIRED)

add_library(g5c_base STATIC src/base.c src/base64.c src/json.c src/jsonpatch.c src/yaml.c src/metrics.c ../config/src/config.c)
target_include_directories(g5c_base PUBLIC include ../config/include)
target_link_libraries(g5c_base PUBLIC OpenSSL::Crypto Threads::Threads m)

add_executable(test_base tests/test_base.c)
target_link_libraries(test_base g5c_base g5c_testkit)
add_test(NAME base_json_yaml_config_metrics COMMAND test_base)

# layers of the validation strategy (ctest -L <label>)
set_property(TEST base_json_yaml_config_metrics APPEND PROPERTY LABELS unit)
