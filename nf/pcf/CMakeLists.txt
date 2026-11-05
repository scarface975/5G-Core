# SPDX-License-Identifier: LicenseRef-Proprietary
add_library(g5c_pcf STATIC src/expr.c src/policy.c src/pcf.c src/smpolicy.c src/ampolicy.c src/admin.c src/policyauth.c src/bsfreg.c)
target_include_directories(g5c_pcf PUBLIC include)
target_link_libraries(g5c_pcf PUBLIC g5c_nfcore g5c_sbi g5c_base pthread)

add_executable(pcf src/main.c)
target_link_libraries(pcf g5c_pcf)

add_executable(test_pcf tests/test_pcf.c)
target_link_libraries(test_pcf g5c_pcf g5c_udr g5c_bsf g5c_testkit)
target_include_directories(test_pcf PRIVATE src)
add_test(NAME pcf_policy_and_services COMMAND test_pcf)

install(TARGETS pcf RUNTIME DESTINATION bin)

# layers of the validation strategy (ctest -L <label>)
set_property(TEST pcf_policy_and_services APPEND PROPERTY LABELS component)

# what the policy would decide for a session, without a running function (backlog G-02)
add_executable(g5c-policy-eval tools/policy_eval.c)
target_link_libraries(g5c-policy-eval g5c_pcf)
install(TARGETS g5c-policy-eval RUNTIME DESTINATION bin)
add_test(NAME pcf_policy_eval_tool COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/policy_eval.sh $<TARGET_FILE:g5c-policy-eval>)
set_property(TEST pcf_policy_eval_tool APPEND PROPERTY LABELS unit)
