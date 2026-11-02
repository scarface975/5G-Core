# SPDX-License-Identifier: LicenseRef-Proprietary
find_package(PkgConfig REQUIRED)
pkg_check_modules(NGHTTP2 REQUIRED IMPORTED_TARGET libnghttp2)
pkg_check_modules(LIBUV REQUIRED IMPORTED_TARGET libuv)

add_library(g5c_sbi STATIC src/types.c src/tls.c src/server.c src/client.c src/multipart.c src/jwt.c)
target_include_directories(g5c_sbi PUBLIC include)
target_link_libraries(g5c_sbi PUBLIC g5c_base PkgConfig::NGHTTP2 PkgConfig::LIBUV OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_sbi tests/test_sbi.c)
target_link_libraries(test_sbi g5c_sbi g5c_testkit)
target_compile_options(test_sbi PRIVATE -Wno-unused-function)
add_test(NAME sbi_router_h2_tls COMMAND test_sbi)

add_executable(test_sbi_oracle_interop tests/test_oracle_interop.c)
target_link_libraries(test_sbi_oracle_interop g5c_sbi g5c_testkit)
add_test(NAME sbi_oracle_interop COMMAND test_sbi_oracle_interop)

# layers of the validation strategy (ctest -L <label>)
set_property(TEST sbi_router_h2_tls APPEND PROPERTY LABELS component)
set_property(TEST sbi_oracle_interop APPEND PROPERTY LABELS integration conformance)

add_executable(test_multipart tests/test_multipart.c)
target_link_libraries(test_multipart g5c_sbi g5c_testkit)
add_test(NAME sbi_multipart COMMAND test_multipart)
set_property(TEST sbi_multipart APPEND PROPERTY LABELS unit)
