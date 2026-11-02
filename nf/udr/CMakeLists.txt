# SPDX-License-Identifier: LicenseRef-Proprietary
# PostgreSQL backend (ADR-0020): libpq from the system, or from an unpacked package tree (G5C_PG_ROOT) when there is no
# root to install it. Without libpq the UDR builds with the in-memory / file backends only.
option(G5C_WITH_POSTGRES "Build the PostgreSQL storage backend when libpq is available" ON)
set(G5C_PG_ROOT "$ENV{HOME}/pg-local/root" CACHE PATH "unpacked PostgreSQL package tree searched for libpq (optional)")
set(G5C_HAVE_PQ OFF)
if(G5C_WITH_POSTGRES)
  find_path(G5C_PQ_INCLUDE libpq-fe.h HINTS ${G5C_PG_ROOT}/usr/include/postgresql PATH_SUFFIXES postgresql)
  find_library(G5C_PQ_LIB NAMES pq HINTS ${G5C_PG_ROOT}/usr/lib/x86_64-linux-gnu)
  if(G5C_PQ_INCLUDE AND G5C_PQ_LIB)
    set(G5C_HAVE_PQ ON)
  endif()
endif()

add_library(g5c_udr STATIC src/udr.c src/store.c src/db.c src/db_mem.c src/db_pg.c src/schema.c src/notify.c src/timeutil.c src/groupid.c src/config.c
            src/api_routes.gen.c src/api_schemas.gen.c)
target_include_directories(g5c_udr PUBLIC include PRIVATE src)
target_link_libraries(g5c_udr PUBLIC g5c_sbi g5c_base g5c_nfcore g5c_oaschema)
if(G5C_HAVE_PQ)
  target_compile_definitions(g5c_udr PRIVATE G5C_HAVE_LIBPQ)
  target_include_directories(g5c_udr SYSTEM PRIVATE ${G5C_PQ_INCLUDE})
  target_link_libraries(g5c_udr PUBLIC ${G5C_PQ_LIB})
  message(STATUS "UDR: PostgreSQL backend enabled (${G5C_PQ_LIB})")
else()
  message(STATUS "UDR: PostgreSQL backend disabled (libpq not found)")
endif()

add_executable(udr src/main.c)
target_link_libraries(udr g5c_udr g5c_nfcore)

add_executable(test_udr tests/test_udr.c)
target_link_libraries(test_udr g5c_udr g5c_testkit)
add_test(NAME udr_patch_store_routes COMMAND test_udr)

if(G5C_HAVE_PQ)
  # an unpacked package tree is not on the loader path: the installed binary finds its libpq there
  get_filename_component(G5C_PQ_DIR ${G5C_PQ_LIB} DIRECTORY)
  if(NOT G5C_PQ_DIR MATCHES "^/(usr/)?lib")
    set_target_properties(udr PROPERTIES INSTALL_RPATH "${G5C_PQ_DIR}")
  endif()
endif()

install(TARGETS udr RUNTIME DESTINATION bin)

# layers of the validation strategy (ctest -L <label>)
set_property(TEST udr_patch_store_routes APPEND PROPERTY LABELS component)

add_executable(test_udr_api tests/test_udr_api.c)
target_link_libraries(test_udr_api g5c_udr g5c_testkit)
add_test(NAME udr_api COMMAND test_udr_api)
set_property(TEST udr_api APPEND PROPERTY LABELS component)

add_executable(test_udr_notify tests/test_udr_notify.c)
target_link_libraries(test_udr_notify g5c_udr g5c_testkit)
add_test(NAME udr_notify COMMAND test_udr_notify)
set_property(TEST udr_notify APPEND PROPERTY LABELS component integration)

add_executable(test_udr_db tests/test_udr_db.c)
target_link_libraries(test_udr_db g5c_udr g5c_testkit)
target_include_directories(test_udr_db PRIVATE src)
add_test(NAME udr_db COMMAND test_udr_db)
set_property(TEST udr_db APPEND PROPERTY LABELS component)

# the same suites on PostgreSQL (a throw-away server per test; skipped when no server binaries are around)
if(G5C_HAVE_PQ)
  foreach(t db api notify)
    add_test(NAME udr_${t}_postgres COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/with_pg.sh $<TARGET_FILE:test_udr_${t}>)
    set_tests_properties(udr_${t}_postgres PROPERTIES SKIP_RETURN_CODE 77 LABELS "component;integration" TIMEOUT 180)
  endforeach()
endif()

add_executable(test_udr_config tests/test_udr_config.c)
target_link_libraries(test_udr_config g5c_udr g5c_testkit)
add_test(NAME udr_config COMMAND test_udr_config)
set_property(TEST udr_config APPEND PROPERTY LABELS component)
