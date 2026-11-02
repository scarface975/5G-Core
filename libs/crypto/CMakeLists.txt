# SPDX-License-Identifier: LicenseRef-Proprietary
add_library(g5c_crypto STATIC src/milenage.c src/kdf.c src/aka5g.c src/nas_sec.c src/suci.c src/eapaka.c)
target_include_directories(g5c_crypto PUBLIC include)
target_link_libraries(g5c_crypto PUBLIC OpenSSL::Crypto)

foreach(t milenage kdf aka5g nas_sec suci eapaka)
  add_executable(test_${t} tests/test_${t}.c)
  target_link_libraries(test_${t} g5c_crypto g5c_testkit)
  target_include_directories(test_${t} PRIVATE tests)
  target_compile_options(test_${t} PRIVATE -Wno-overlength-strings) # long spec test vectors, tests only
  add_test(NAME crypto_${t} COMMAND test_${t})
  set_property(TEST crypto_${t} APPEND PROPERTY LABELS unit)
endforeach()
