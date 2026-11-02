# SPDX-License-Identifier: LicenseRef-Proprietary
add_executable(test_golden test_golden.c)
target_link_libraries(test_golden g5c_nas g5c_ngap g5c_udm g5c_testkit)
target_compile_definitions(test_golden PRIVATE G5C_FIXTURES="${CMAKE_SOURCE_DIR}/tests/fixtures/golden")
add_test(NAME conformance_golden_traces COMMAND test_golden)

add_executable(dump_payloads dump_payloads.c)
target_link_libraries(dump_payloads g5c_ausf g5c_udm g5c_pcf g5c_udr g5c_nssf g5c_nef g5c_scp g5c_bsf g5c_nrf g5c_nfcore g5c_testkit)
add_test(NAME conformance_dump_payloads_noop COMMAND dump_payloads)

add_test(NAME sample_configs_load
         COMMAND ${CMAKE_SOURCE_DIR}/tests/conformance/check_configs.sh ${CMAKE_SOURCE_DIR}/configs
                 $<TARGET_FILE:udm> $<TARGET_FILE:pcf> $<TARGET_FILE:udr> $<TARGET_FILE:ausf> $<TARGET_FILE:upf> $<TARGET_FILE:smf> $<TARGET_FILE:amf> $<TARGET_FILE:nrf> $<TARGET_FILE:nssf> $<TARGET_FILE:nef> $<TARGET_FILE:scp> $<TARGET_FILE:bsf>)

add_test(NAME compose_configs_load
         COMMAND ${CMAKE_SOURCE_DIR}/tests/conformance/check_configs.sh ${CMAKE_SOURCE_DIR}/deploy/compose/config
                 $<TARGET_FILE:udm> $<TARGET_FILE:pcf> $<TARGET_FILE:udr> $<TARGET_FILE:ausf> $<TARGET_FILE:upf> $<TARGET_FILE:smf> $<TARGET_FILE:amf> $<TARGET_FILE:nrf> $<TARGET_FILE:nssf> $<TARGET_FILE:nef> $<TARGET_FILE:scp> $<TARGET_FILE:bsf>)

add_test(NAME bad_configs_rejected
         COMMAND ${CMAKE_SOURCE_DIR}/tests/conformance/check_bad_configs.sh
                 $<TARGET_FILE:udm> $<TARGET_FILE:pcf> $<TARGET_FILE:udr> $<TARGET_FILE:ausf> $<TARGET_FILE:upf> $<TARGET_FILE:smf> $<TARGET_FILE:amf> $<TARGET_FILE:nrf> $<TARGET_FILE:nssf> $<TARGET_FILE:nef> $<TARGET_FILE:scp> $<TARGET_FILE:bsf>)

# layers of the validation strategy (ctest -L <label>)
set_property(TEST conformance_golden_traces APPEND PROPERTY LABELS conformance)
set_property(TEST conformance_dump_payloads_noop APPEND PROPERTY LABELS conformance)
set_property(TEST sample_configs_load APPEND PROPERTY LABELS component)
set_property(TEST compose_configs_load APPEND PROPERTY LABELS component)
set_property(TEST bad_configs_rejected APPEND PROPERTY LABELS component)

# Differential PFCP analysis against Open5GS's own UPF, same SMF and scenario (needs the pinned TS 29.244 text for element names).
find_program(G5C_PYTHON3 python3)
if(G5C_PYTHON3 AND EXISTS ${CMAKE_SOURCE_DIR}/docs/specs/src/txt/29244-gd0.txt)
  add_test(NAME pfcp_differential COMMAND ${G5C_PYTHON3} ${CMAKE_SOURCE_DIR}/tools/pfcp_diff.py)
  set_property(TEST pfcp_differential APPEND PROPERTY LABELS conformance)
endif()

# The same analysis for the SMF: same UPF and scenario, Open5GS's SMF versus ours (captures stored in tests/fixtures/golden).
if(G5C_PYTHON3 AND EXISTS ${CMAKE_SOURCE_DIR}/docs/specs/src/txt/29244-gd0.txt)
  add_test(NAME pfcp_differential_smf COMMAND ${G5C_PYTHON3} ${CMAKE_SOURCE_DIR}/tools/pfcp_diff.py --smf)
  set_property(TEST pfcp_differential_smf APPEND PROPERTY LABELS conformance)
endif()

# The same analysis for the AMF at N2 / N1: same UE, gNB and scenario, Open5GS's AMF versus ours (decoded by g5c-inspect with our own NGAP / NAS codecs).
find_program(G5C_TSHARK tshark)
if(G5C_PYTHON3 AND G5C_TSHARK AND TARGET g5c-inspect)
  add_test(NAME ngap_differential_amf COMMAND ${G5C_PYTHON3} ${CMAKE_SOURCE_DIR}/tools/amf_diff.py --inspect $<TARGET_FILE:g5c-inspect>)
  set_property(TEST ngap_differential_amf APPEND PROPERTY LABELS conformance)
endif()

# The NRF against Open5GS's NRF (the unmodified system binary), the same requests to both in a private namespace (deploy/oracle/nrf_diff.sh).
if(G5C_PYTHON3 AND EXISTS /usr/bin/open5gs-nrfd AND EXISTS $ENV{HOME}/o5gs-run/conf/nrf.yaml AND TARGET nrf)
  add_test(NAME nrf_differential COMMAND bash ${CMAKE_SOURCE_DIR}/deploy/oracle/nrf_diff.sh)
  set_tests_properties(nrf_differential PROPERTIES ENVIRONMENT "NRF_BIN=$<TARGET_FILE:nrf>" SKIP_RETURN_CODE 77 LABELS "conformance;integration" TIMEOUT 120)
endif()

# The UDR against Open5GS's UDR (the unmodified system binary over a private MongoDB), the same requests to both in a private namespace (deploy/oracle/udr_diff.sh).
if(G5C_PYTHON3 AND EXISTS /usr/bin/open5gs-udrd AND EXISTS /usr/bin/open5gs-nrfd AND EXISTS /usr/bin/mongod AND TARGET udr)
  add_test(NAME udr_differential COMMAND bash ${CMAKE_SOURCE_DIR}/deploy/oracle/udr_diff.sh)
  set_tests_properties(udr_differential PROPERTIES ENVIRONMENT "UDR_BIN=$<TARGET_FILE:udr>" SKIP_RETURN_CODE 77 LABELS "conformance;integration" TIMEOUT 120)
endif()

# The NSSF against Open5GS's NSSF (the unmodified system binary behind Open5GS's NRF), the same Nnssf_NSSelection requests to both in a private namespace (deploy/oracle/nssf_diff.sh).
if(G5C_PYTHON3 AND EXISTS /usr/bin/open5gs-nssfd AND EXISTS /usr/bin/open5gs-nrfd AND TARGET nssf)
  add_test(NAME nssf_differential COMMAND bash ${CMAKE_SOURCE_DIR}/deploy/oracle/nssf_diff.sh)
  set_tests_properties(nssf_differential PROPERTIES ENVIRONMENT "NSSF_BIN=$<TARGET_FILE:nssf>" SKIP_RETURN_CODE 77 LABELS "conformance;integration" TIMEOUT 120)
endif()

# The SCP against Open5GS's SCP (the unmodified system binary) in front of the same NRF and the same producer (our NSSF), the same indirect-communication requests to both
# in a private namespace (deploy/oracle/scp_diff.sh).
if(G5C_PYTHON3 AND EXISTS /usr/bin/open5gs-scpd AND EXISTS /usr/bin/open5gs-nrfd AND TARGET scp AND TARGET nssf)
  add_test(NAME scp_differential COMMAND bash ${CMAKE_SOURCE_DIR}/deploy/oracle/scp_diff.sh)
  set_tests_properties(scp_differential PROPERTIES ENVIRONMENT "SCP_BIN=$<TARGET_FILE:scp>;NSSF_BIN=$<TARGET_FILE:nssf>" SKIP_RETURN_CODE 77 LABELS "conformance;integration" TIMEOUT 120)
endif()

# The BSF against Open5GS's BSF (the unmodified system binary, registered at Open5GS's NRF), the same Nbsf_Management requests to both in a private namespace
# (deploy/oracle/bsf_diff.sh).
if(G5C_PYTHON3 AND EXISTS /usr/bin/open5gs-bsfd AND EXISTS /usr/bin/open5gs-nrfd AND TARGET bsf)
  add_test(NAME bsf_differential COMMAND bash ${CMAKE_SOURCE_DIR}/deploy/oracle/bsf_diff.sh)
  set_tests_properties(bsf_differential PROPERTIES ENVIRONMENT "BSF_BIN=$<TARGET_FILE:bsf>" SKIP_RETURN_CODE 77 LABELS "conformance;integration" TIMEOUT 120)
endif()

# The AUSF against Open5GS's AUSF (the unmodified system binary) behind the same UDM, the same requests to both in a private namespace (deploy/oracle/ausf_diff.sh).
if(G5C_PYTHON3 AND EXISTS /usr/bin/open5gs-ausfd AND EXISTS /usr/bin/open5gs-nrfd AND EXISTS $ENV{HOME}/o5gs-run/conf/nrf.yaml AND TARGET ausf)
  add_test(NAME ausf_differential COMMAND bash ${CMAKE_SOURCE_DIR}/deploy/oracle/ausf_diff.sh)
  set_tests_properties(ausf_differential PROPERTIES ENVIRONMENT "AUSF_BIN=$<TARGET_FILE:ausf>" SKIP_RETURN_CODE 77 LABELS "conformance;integration" TIMEOUT 120)
endif()
