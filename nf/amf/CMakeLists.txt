# SPDX-License-Identifier: LicenseRef-Proprietary
add_library(g5c_amf STATIC src/util.c src/amf.c src/sctp.c src/ngap.c src/sec.c src/sbi_out.c src/nasmsg.c src/gmm.c src/session.c src/ho.c src/events.c
            src/callbacks.c src/persist.c)
target_include_directories(g5c_amf PUBLIC include PRIVATE src)
target_link_libraries(g5c_amf PUBLIC g5c_nfcore g5c_sbi g5c_nas g5c_ngap g5c_crypto g5c_base pthread)

add_executable(amf src/main.c)
target_link_libraries(amf g5c_amf)
install(TARGETS amf RUNTIME DESTINATION bin)

add_executable(test_amf_e2e tests/test_amf_e2e.c)
target_include_directories(test_amf_e2e PRIVATE tests)
target_link_libraries(test_amf_e2e g5c_amf g5c_smf g5c_udm g5c_pcf g5c_udr g5c_ausf g5c_upf_rt g5c_gtpu g5c_testkit)
add_test(NAME amf_e2e COMMAND test_amf_e2e)
set_tests_properties(amf_e2e PROPERTIES TIMEOUT 180 LABELS "component;integration")

add_executable(load_core tests/load_core.c)
target_include_directories(load_core PRIVATE tests)
target_link_libraries(load_core g5c_amf g5c_smf g5c_udm g5c_pcf g5c_udr g5c_ausf g5c_upf_rt g5c_gtpu g5c_testkit)
# a small run in the regression (the scale runs are scripts/g5c_load.sh); not part of the default label sets that sanitizer builds repeat
add_test(NAME load_core_small COMMAND load_core)

# the same load against the daemons as separate processes (deploy/run/g5c-cluster.sh in a private user + network namespace; skipped where those are not
# available), and the chaos run that kills and restarts them
find_program(G5C_BASH bash)
if(G5C_BASH AND UNIX)
  set(_cl_env "G5C_BUILD_DIR=${CMAKE_BINARY_DIR};G5C_LOAD_BIN=$<TARGET_FILE:load_core>")
  if(G5C_TSAN)
    set(_cl_env "${_cl_env};TSAN_OPTIONS=suppressions=${CMAKE_SOURCE_DIR}/tests/tsan.supp:halt_on_error=1")
  endif()
  add_test(NAME cluster_load COMMAND ${G5C_BASH} ${CMAKE_SOURCE_DIR}/deploy/run/g5c-cluster.sh ns load 300 8 2)
  set_tests_properties(cluster_load PROPERTIES ENVIRONMENT "${_cl_env};G5C_RUN=${CMAKE_BINARY_DIR}/cluster-run-load" TIMEOUT 300
                       LABELS "integration;cluster" SKIP_RETURN_CODE 77 RUN_SERIAL TRUE)
  add_test(NAME cluster_chaos COMMAND ${G5C_BASH} ${CMAKE_SOURCE_DIR}/deploy/run/g5c-cluster.sh ns chaos 100 25)
  set_tests_properties(cluster_chaos PROPERTIES ENVIRONMENT "${_cl_env};G5C_RUN=${CMAKE_BINARY_DIR}/cluster-run-chaos" TIMEOUT 300
                       LABELS "integration;cluster" SKIP_RETURN_CODE 77 RUN_SERIAL TRUE)
  add_test(NAME cluster_soak COMMAND ${G5C_BASH} ${CMAKE_SOURCE_DIR}/deploy/run/g5c-cluster.sh ns soak 200 30)
  if(G5C_SANITIZE OR G5C_TSAN)
    set(_cl_env "${_cl_env};G5C_SOAK_CHECK_RSS=0")
  endif()
  set_tests_properties(cluster_soak PROPERTIES ENVIRONMENT "${_cl_env};G5C_RUN=${CMAKE_BINARY_DIR}/cluster-run-soak" TIMEOUT 300
                       LABELS "soak;cluster" SKIP_RETURN_CODE 77 RUN_SERIAL TRUE)
  # Phase 8: mutual TLS between all functions (load, then refusals and certificate rotation), and the secrets hygiene check
  set(_tls_env "${_cl_env};G5C_TLS=1")
  add_test(NAME cluster_load_tls COMMAND ${G5C_BASH} ${CMAKE_SOURCE_DIR}/deploy/run/g5c-cluster.sh ns load 300 8 1)
  set_tests_properties(cluster_load_tls PROPERTIES ENVIRONMENT "${_tls_env};G5C_RUN=${CMAKE_BINARY_DIR}/cluster-run-load-tls" TIMEOUT 300
                       LABELS "integration;cluster" SKIP_RETURN_CODE 77 RUN_SERIAL TRUE)
  # every function pinned to its callers (backlog D-02): a full wave works, and the load generator's direct calls use the operator certificate
  add_test(NAME cluster_load_pinned COMMAND ${G5C_BASH} ${CMAKE_SOURCE_DIR}/deploy/run/g5c-cluster.sh ns load 100 8 1)
  set_tests_properties(cluster_load_pinned PROPERTIES ENVIRONMENT "${_tls_env};G5C_PIN_PEERS=1;G5C_RUN=${CMAKE_BINARY_DIR}/cluster-run-load-pinned" TIMEOUT 300
                       LABELS "integration;cluster" SKIP_RETURN_CODE 77 RUN_SERIAL TRUE)
  add_test(NAME cluster_chaos_tls COMMAND ${G5C_BASH} ${CMAKE_SOURCE_DIR}/deploy/run/g5c-cluster.sh ns chaos 100 25)
  set_tests_properties(cluster_chaos_tls PROPERTIES ENVIRONMENT "${_tls_env};G5C_RUN=${CMAKE_BINARY_DIR}/cluster-run-chaos-tls" TIMEOUT 300
                       LABELS "integration;cluster" SKIP_RETURN_CODE 77 RUN_SERIAL TRUE)
  add_test(NAME cluster_tls COMMAND ${G5C_BASH} ${CMAKE_SOURCE_DIR}/deploy/run/g5c-cluster.sh ns tls)
  set_tests_properties(cluster_tls PROPERTIES ENVIRONMENT "${_tls_env};G5C_RUN=${CMAKE_BINARY_DIR}/cluster-run-tls" TIMEOUT 300
                       LABELS "integration;cluster" SKIP_RETURN_CODE 77 RUN_SERIAL TRUE)
  # the TLS key log (backlog C-02): a capture of the SBI is opaque without it and decrypts with it
  add_test(NAME cluster_keylog COMMAND ${G5C_BASH} ${CMAKE_SOURCE_DIR}/deploy/run/g5c-cluster.sh ns keylog)
  set_tests_properties(cluster_keylog PROPERTIES ENVIRONMENT "${_tls_env};G5C_TLS_KEYLOG=${CMAKE_BINARY_DIR}/cluster-keylog.txt;G5C_RUN=${CMAKE_BINARY_DIR}/cluster-run-keylog" TIMEOUT 300
                       LABELS "integration;cluster" SKIP_RETURN_CODE 77 RUN_SERIAL TRUE)
  add_test(NAME cluster_secrets COMMAND ${G5C_BASH} ${CMAKE_SOURCE_DIR}/deploy/run/g5c-cluster.sh ns secrets)
  set_tests_properties(cluster_secrets PROPERTIES ENVIRONMENT "${_tls_env};G5C_RUN=${CMAKE_BINARY_DIR}/cluster-run-secrets" TIMEOUT 300
                       LABELS "integration;cluster" SKIP_RETURN_CODE 77 RUN_SERIAL TRUE)
  # one UE per gNB, de-registered with the association closing right behind the request: the case in which the AMF once kept a de-registered context for ever (about one run in eight)
  add_test(NAME cluster_load_small COMMAND ${G5C_BASH} ${CMAKE_SOURCE_DIR}/deploy/run/g5c-cluster.sh ns load 10 10 6)
  set_tests_properties(cluster_load_small PROPERTIES ENVIRONMENT "${_cl_env};G5C_RUN=${CMAKE_BINARY_DIR}/cluster-run-load-small" TIMEOUT 300
                       LABELS "integration;cluster" SKIP_RETURN_CODE 77 RUN_SERIAL TRUE)
  # operations (log level at run time, master key rotation, exec: key source, charging records) and the slice decisions of the NSSF: the tests call the functions directly, so no access tokens
  set(_direct_env "${_tls_env};G5C_OAUTH2=0")
  add_test(NAME cluster_ops COMMAND ${G5C_BASH} ${CMAKE_SOURCE_DIR}/deploy/run/g5c-cluster.sh ns ops)
  set_tests_properties(cluster_ops PROPERTIES ENVIRONMENT "${_direct_env};G5C_RUN=${CMAKE_BINARY_DIR}/cluster-run-ops" TIMEOUT 300
                       LABELS "integration;cluster" SKIP_RETURN_CODE 77 RUN_SERIAL TRUE)
  add_test(NAME cluster_scenarios COMMAND ${G5C_BASH} ${CMAKE_SOURCE_DIR}/deploy/run/g5c-cluster.sh ns scenario
           ${CMAKE_SOURCE_DIR}/scenarios/basic-wave.yaml ${CMAKE_SOURCE_DIR}/scenarios/n4-delay.yaml ${CMAKE_SOURCE_DIR}/scenarios/smf-restart.yaml ${CMAKE_SOURCE_DIR}/scenarios/traffic-unlimited.yaml ${CMAKE_SOURCE_DIR}/scenarios/link-chaos.yaml)
  set_tests_properties(cluster_scenarios PROPERTIES ENVIRONMENT "${_direct_env};G5C_RUN=${CMAKE_BINARY_DIR}/cluster-run-scenarios" TIMEOUT 400
                       LABELS "integration;cluster" SKIP_RETURN_CODE 77 RUN_SERIAL TRUE)
  # failure injection (backlog B-04): the AMF refuses every registration with cause #11 / the SMF loses a tenth of the N4 responses; the core counts what it injected
  add_test(NAME cluster_inject_amf COMMAND /usr/bin/env "G5C_AMF_EXTRA=  inject: { registration_reject: [{ supi: imsi-00101, cause: 11 }] }"
           ${G5C_BASH} ${CMAKE_SOURCE_DIR}/deploy/run/g5c-cluster.sh ns scenario ${CMAKE_SOURCE_DIR}/scenarios/inject-amf-reject.yaml)
  set_tests_properties(cluster_inject_amf PROPERTIES ENVIRONMENT "${_direct_env};G5C_RUN=${CMAKE_BINARY_DIR}/cluster-run-inject-amf" TIMEOUT 300
                       LABELS "integration;cluster" SKIP_RETURN_CODE 77 RUN_SERIAL TRUE)
  # signalling-storm protection (backlog D-04): the AMF holds the registration rate and refuses the rest with cause #22; it stays up and serves a normal wave afterwards
  add_test(NAME cluster_overload_amf COMMAND /usr/bin/env "G5C_AMF_EXTRA=  overload: { registrations_per_s: 20, burst_s: 1, t3346_s: 10 }"
           ${G5C_BASH} ${CMAKE_SOURCE_DIR}/deploy/run/g5c-cluster.sh ns scenario ${CMAKE_SOURCE_DIR}/scenarios/registration-storm.yaml)
  set_tests_properties(cluster_overload_amf PROPERTIES ENVIRONMENT "${_direct_env};G5C_RUN=${CMAKE_BINARY_DIR}/cluster-run-overload-amf" TIMEOUT 300
                       LABELS "integration;cluster" SKIP_RETURN_CODE 77 RUN_SERIAL TRUE)
  # configuration hot reload (backlog F-06): SIGHUP changes the registration limit of a running AMF; an invalid change is refused and taken back
  add_test(NAME cluster_reload_amf COMMAND /usr/bin/env "G5C_AMF_EXTRA=  overload: { registrations_per_s: 100000, burst_s: 1, t3346_s: 10 }"
           ${G5C_BASH} ${CMAKE_SOURCE_DIR}/deploy/run/g5c-cluster.sh ns scenario ${CMAKE_SOURCE_DIR}/scenarios/reload-amf-overload.yaml)
  set_tests_properties(cluster_reload_amf PROPERTIES ENVIRONMENT "${_direct_env};G5C_RUN=${CMAKE_BINARY_DIR}/cluster-run-reload-amf" TIMEOUT 300
                       LABELS "integration;cluster" SKIP_RETURN_CODE 77 RUN_SERIAL TRUE)
  # replay of a capture (backlog B-11): our core differs from the recorded one for an unknown subscriber and matches it once the subscriber exists
  add_test(NAME cluster_replay COMMAND ${G5C_BASH} ${CMAKE_SOURCE_DIR}/deploy/run/g5c-cluster.sh ns scenario ${CMAKE_SOURCE_DIR}/scenarios/replay-registration.yaml)
  set_tests_properties(cluster_replay PROPERTIES ENVIRONMENT "${_direct_env};G5C_RUN=${CMAKE_BINARY_DIR}/cluster-run-replay" TIMEOUT 300
                       LABELS "integration;cluster" SKIP_RETURN_CODE 77 RUN_SERIAL TRUE)
  # negative testing (backlog B-05): hostile requests to the routes and corrupted N2 messages; no 5xx, no silence, every function ready afterwards
  add_test(NAME cluster_mutation COMMAND /usr/bin/env "G5C_OAUTH2=0" ${G5C_BASH} ${CMAKE_SOURCE_DIR}/deploy/run/g5c-cluster.sh ns scenario ${CMAKE_SOURCE_DIR}/scenarios/mutation-sweep.yaml)
  set_tests_properties(cluster_mutation PROPERTIES ENVIRONMENT "${_direct_env};G5C_RUN=${CMAKE_BINARY_DIR}/cluster-run-mutation" TIMEOUT 600
                       LABELS "integration;cluster" SKIP_RETURN_CODE 77 RUN_SERIAL TRUE)
  # the training lab (backlog G-04): exercise 3 is the one with a scenario of its own; `g5c-lab check all` runs every exercise
  add_test(NAME cluster_lab_03 COMMAND ${G5C_PYTHON} ${CMAKE_SOURCE_DIR}/tools/cli/g5c-lab check 03)
  set_tests_properties(cluster_lab_03 PROPERTIES ENVIRONMENT "G5C_BUILD_DIR=${CMAKE_BINARY_DIR};G5C_LOAD_BIN=$<TARGET_FILE:load_core>" TIMEOUT 300 LABELS "integration;cluster" SKIP_RETURN_CODE 77 RUN_SERIAL TRUE)
  add_test(NAME cluster_inject_smf COMMAND /usr/bin/env "G5C_SMF_EXTRA=  inject: { n4_drop_responses_percent: 10 }"
           ${G5C_BASH} ${CMAKE_SOURCE_DIR}/deploy/run/g5c-cluster.sh ns scenario ${CMAKE_SOURCE_DIR}/scenarios/inject-n4-drop.yaml)
  set_tests_properties(cluster_inject_smf PROPERTIES ENVIRONMENT "${_direct_env};G5C_RUN=${CMAKE_BINARY_DIR}/cluster-run-inject-smf" TIMEOUT 300
                       LABELS "integration;cluster" SKIP_RETURN_CODE 77 RUN_SERIAL TRUE)
  # mobility library (backlog B-09): Xn path switches between two gNBs against the real daemons
  add_test(NAME cluster_mobility_xn COMMAND ${G5C_BASH} ${CMAKE_SOURCE_DIR}/deploy/run/g5c-cluster.sh ns scenario ${CMAKE_SOURCE_DIR}/scenarios/mobility-xn.yaml)
  set_tests_properties(cluster_mobility_xn PROPERTIES ENVIRONMENT "${_direct_env};G5C_RUN=${CMAKE_BINARY_DIR}/cluster-run-mobility" TIMEOUT 300
                       LABELS "integration;cluster" SKIP_RETURN_CODE 77 RUN_SERIAL TRUE)
  add_test(NAME cluster_mobility_n2 COMMAND ${G5C_BASH} ${CMAKE_SOURCE_DIR}/deploy/run/g5c-cluster.sh ns scenario ${CMAKE_SOURCE_DIR}/scenarios/mobility-n2.yaml)
  set_tests_properties(cluster_mobility_n2 PROPERTIES ENVIRONMENT "${_direct_env};G5C_RUN=${CMAKE_BINARY_DIR}/cluster-run-mobility-n2" TIMEOUT 300
                       LABELS "integration;cluster" SKIP_RETURN_CODE 77 RUN_SERIAL TRUE)
  # the tester edition against a core that is not ours (backlog I-01): scripted UEs against the Open5GS 2.8.0 oracle; skipped where Open5GS is not installed
  add_test(NAME tester_vs_open5gs COMMAND ${G5C_BASH} ${CMAKE_SOURCE_DIR}/deploy/oracle/tester.sh 5 1)
  set_tests_properties(tester_vs_open5gs PROPERTIES ENVIRONMENT "G5C_LOAD_BIN=$<TARGET_FILE:load_core>" TIMEOUT 300 LABELS "integration;cluster" SKIP_RETURN_CODE 77 RUN_SERIAL TRUE)
  # extension hooks (backlog G-03): every charging record also goes to a program
  add_test(NAME cluster_cdr_sink COMMAND /usr/bin/env "G5C_CDR_SINK=1"
           ${G5C_BASH} ${CMAKE_SOURCE_DIR}/deploy/run/g5c-cluster.sh ns scenario ${CMAKE_SOURCE_DIR}/scenarios/cdr-sink.yaml)
  set_tests_properties(cluster_cdr_sink PROPERTIES ENVIRONMENT "${_direct_env};G5C_RUN=${CMAKE_BINARY_DIR}/cluster-run-cdr-sink" TIMEOUT 300
                       LABELS "integration;cluster" SKIP_RETURN_CODE 77 RUN_SERIAL TRUE)
  # SCTP multi-homing (backlog E-04): the AMF's N2 endpoint has two local addresses
  add_test(NAME cluster_n2_multihomed COMMAND /usr/bin/env "G5C_AMF_N2_ALT=127.2.0.6"
           ${G5C_BASH} ${CMAKE_SOURCE_DIR}/deploy/run/g5c-cluster.sh ns scenario ${CMAKE_SOURCE_DIR}/scenarios/n2-multihomed.yaml)
  set_tests_properties(cluster_n2_multihomed PROPERTIES ENVIRONMENT "${_direct_env};G5C_RUN=${CMAKE_BINARY_DIR}/cluster-run-n2-multihomed" TIMEOUT 300
                       LABELS "integration;cluster" SKIP_RETURN_CODE 77 RUN_SERIAL TRUE)
  # policy as code (backlog G-02): a script of the PCF, not the default, decides the session rate
  add_test(NAME cluster_policy_script COMMAND /usr/bin/env "G5C_PCF_POLICY_EXTRA=  scripts: [ { when: \"supi startswith 'imsi-00101'\", session_ambr: { uplink: 1 Mbps, downlink: 1 Mbps } } ]"
           ${G5C_BASH} ${CMAKE_SOURCE_DIR}/deploy/run/g5c-cluster.sh ns scenario ${CMAKE_SOURCE_DIR}/scenarios/policy-script.yaml)
  set_tests_properties(cluster_policy_script PROPERTIES ENVIRONMENT "${_direct_env};G5C_RUN=${CMAKE_BINARY_DIR}/cluster-run-policy-script" TIMEOUT 300
                       LABELS "integration;cluster" SKIP_RETURN_CODE 77 RUN_SERIAL TRUE)
  # the ORAN emulator's N2/NAS/N3 stack against the whole core (skipped where the emulator or its built drivers are not at ORAN_EMULATOR)
  add_test(NAME oran_emulator_proof COMMAND ${G5C_BASH} ${CMAKE_SOURCE_DIR}/deploy/oran/prove.sh 8)
  set_tests_properties(oran_emulator_proof PROPERTIES ENVIRONMENT "G5C_BUILD_DIR=${CMAKE_BINARY_DIR};G5C_RUN=${CMAKE_BINARY_DIR}/cluster-run-oran" TIMEOUT 400 LABELS "integration;cluster" SKIP_RETURN_CODE 77 RUN_SERIAL TRUE)
  # radio lab kit (backlog B-10): OCUDU gNB + srsUE over ZeroMQ against our core; skipped where the gNB or the UE is not installed
  add_test(NAME radio_kit COMMAND ${G5C_BASH} ${CMAKE_SOURCE_DIR}/deploy/radio-kit/g5c-radio-kit run)
  set_tests_properties(radio_kit PROPERTIES TIMEOUT 300 LABELS "integration;cluster" SKIP_RETURN_CODE 77 RUN_SERIAL TRUE)
  # scale emulation (backlog B-03): four load processes with disjoint IMSI ranges against one core
  add_test(NAME cluster_fanout COMMAND ${G5C_BASH} ${CMAKE_SOURCE_DIR}/deploy/run/g5c-cluster.sh ns scenario ${CMAKE_SOURCE_DIR}/scenarios/fanout.yaml)
  set_tests_properties(cluster_fanout PROPERTIES ENVIRONMENT "${_direct_env};G5C_RUN=${CMAKE_BINARY_DIR}/cluster-run-fanout;G5C_LOAD_BIN=$<TARGET_FILE:load_core>" TIMEOUT 300
                       LABELS "integration;cluster" SKIP_RETURN_CODE 77 RUN_SERIAL TRUE)
  # online charging (backlog A-02): the SMF opens a charging session at the CHF for every PDU session; with no credit the sessions are refused
  add_test(NAME cluster_charging COMMAND /usr/bin/env "G5C_CHF=1"
           ${G5C_BASH} ${CMAKE_SOURCE_DIR}/deploy/run/g5c-cluster.sh ns scenario ${CMAKE_SOURCE_DIR}/scenarios/charging.yaml)
  set_tests_properties(cluster_charging PROPERTIES ENVIRONMENT "${_direct_env};G5C_RUN=${CMAKE_BINARY_DIR}/cluster-run-charging" TIMEOUT 300
                       LABELS "integration;cluster" SKIP_RETURN_CODE 77 RUN_SERIAL TRUE)
  add_test(NAME cluster_charging_denied COMMAND /usr/bin/env "G5C_CHF=1" "G5C_CHF_EXTRA=  default_balance_bytes: 0"
           ${G5C_BASH} ${CMAKE_SOURCE_DIR}/deploy/run/g5c-cluster.sh ns scenario ${CMAKE_SOURCE_DIR}/scenarios/charging-denied.yaml)
  set_tests_properties(cluster_charging_denied PROPERTIES ENVIRONMENT "${_direct_env};G5C_RUN=${CMAKE_BINARY_DIR}/cluster-run-charging-denied" TIMEOUT 300
                       LABELS "integration;cluster" SKIP_RETURN_CODE 77 RUN_SERIAL TRUE)
  add_test(NAME cluster_charging_quota COMMAND /usr/bin/env "G5C_CHF=1" "G5C_CHF_QUOTA=50000" "G5C_CHF_GRANT=50000"
           ${G5C_BASH} ${CMAKE_SOURCE_DIR}/deploy/run/g5c-cluster.sh ns scenario ${CMAKE_SOURCE_DIR}/scenarios/charging-quota.yaml)
  set_tests_properties(cluster_charging_quota PROPERTIES ENVIRONMENT "${_direct_env};G5C_RUN=${CMAKE_BINARY_DIR}/cluster-run-charging-quota" TIMEOUT 300
                       LABELS "integration;cluster" SKIP_RETURN_CODE 77 RUN_SERIAL TRUE)
  add_test(NAME cluster_charging_exhausted COMMAND /usr/bin/env "G5C_CHF=1" "G5C_CHF_QUOTA=50000" "G5C_CHF_EXTRA=  default_balance_bytes: 120000\n  max_grant_bytes: 50000"
           ${G5C_BASH} ${CMAKE_SOURCE_DIR}/deploy/run/g5c-cluster.sh ns scenario ${CMAKE_SOURCE_DIR}/scenarios/charging-exhausted.yaml)
  set_tests_properties(cluster_charging_exhausted PROPERTIES ENVIRONMENT "${_direct_env};G5C_RUN=${CMAKE_BINARY_DIR}/cluster-run-charging-exhausted" TIMEOUT 300
                       LABELS "integration;cluster" SKIP_RETURN_CODE 77 RUN_SERIAL TRUE)
  # user plane (backlog B-02): the PCF gives every session 1 Mbit/s, each UE offers 4, the UPF must hold them to about 1 and count what it drops
  add_test(NAME cluster_traffic_ambr COMMAND /usr/bin/env "G5C_AMBR_UL=1 Mbps" "G5C_AMBR_DL=1 Mbps"
           ${G5C_BASH} ${CMAKE_SOURCE_DIR}/deploy/run/g5c-cluster.sh ns scenario ${CMAKE_SOURCE_DIR}/scenarios/traffic-ambr.yaml)
  set_tests_properties(cluster_traffic_ambr PROPERTIES ENVIRONMENT "${_direct_env};G5C_RUN=${CMAKE_BINARY_DIR}/cluster-run-traffic" TIMEOUT 300
                       LABELS "integration;cluster" SKIP_RETURN_CODE 77 RUN_SERIAL TRUE)
  add_test(NAME cluster_slices COMMAND ${G5C_BASH} ${CMAKE_SOURCE_DIR}/deploy/run/g5c-cluster.sh ns slices)
  set_tests_properties(cluster_slices PROPERTIES ENVIRONMENT "${_direct_env};G5C_RUN=${CMAKE_BINARY_DIR}/cluster-run-slices" TIMEOUT 300
                       LABELS "integration;cluster" SKIP_RETURN_CODE 77 RUN_SERIAL TRUE)
  add_test(NAME cluster_upgrade COMMAND ${G5C_BASH} ${CMAKE_SOURCE_DIR}/deploy/run/g5c-cluster.sh ns upgrade 100 70)
  set_tests_properties(cluster_upgrade PROPERTIES ENVIRONMENT "${_tls_env};G5C_RUN=${CMAKE_BINARY_DIR}/cluster-run-upgrade" TIMEOUT 400
                       LABELS "integration;cluster" SKIP_RETURN_CODE 77 RUN_SERIAL TRUE)
  add_test(NAME cluster_support COMMAND ${G5C_BASH} ${CMAKE_SOURCE_DIR}/deploy/run/g5c-cluster.sh ns support)
  set_tests_properties(cluster_support PROPERTIES ENVIRONMENT "${_tls_env};G5C_RUN=${CMAKE_BINARY_DIR}/cluster-run-support" TIMEOUT 300
                       LABELS "integration;cluster" SKIP_RETURN_CODE 77 RUN_SERIAL TRUE)
  find_program(G5C_PYTHON python3)
  if(G5C_PYTHON)
    # Phase 9 tools: the log / configuration redactor, the API reference that must match the sources, the automated licence audit
    add_test(NAME redact_tool COMMAND ${G5C_PYTHON} ${CMAKE_SOURCE_DIR}/tests/support/test_redact.py)
    set_tests_properties(redact_tool PROPERTIES LABELS "unit")
    add_test(NAME subscribers_tool COMMAND ${G5C_PYTHON} ${CMAKE_SOURCE_DIR}/tests/support/test_subscribers.py)
    set_tests_properties(subscribers_tool PROPERTIES LABELS "unit")
    add_test(NAME perf_history_tool COMMAND ${G5C_PYTHON} ${CMAKE_SOURCE_DIR}/tests/support/test_perf_history.py)
    set_tests_properties(perf_history_tool PROPERTIES LABELS "unit")
    add_test(NAME dossier_tool COMMAND ${G5C_PYTHON} ${CMAKE_SOURCE_DIR}/tests/support/test_dossier.py)
    set_tests_properties(dossier_tool PROPERTIES LABELS "unit")
    add_test(NAME sdk_tool COMMAND ${G5C_PYTHON} ${CMAKE_SOURCE_DIR}/tests/support/test_sdk.py)
    set_tests_properties(sdk_tool PROPERTIES LABELS "unit")
    add_test(NAME init_tool COMMAND ${G5C_PYTHON} ${CMAKE_SOURCE_DIR}/tests/support/test_init.py)
    set_tests_properties(init_tool PROPERTIES LABELS "unit")
    add_test(NAME dn_tool COMMAND ${G5C_PYTHON} ${CMAKE_SOURCE_DIR}/tests/support/test_dn.py)
    set_tests_properties(dn_tool PROPERTIES LABELS "unit")
    add_test(NAME scenario_tool COMMAND ${G5C_PYTHON} ${CMAKE_SOURCE_DIR}/tests/support/test_scenario.py)
    set_tests_properties(scenario_tool PROPERTIES LABELS "unit")
    add_test(NAME api_tool COMMAND ${G5C_PYTHON} ${CMAKE_SOURCE_DIR}/tests/support/test_api.py)
    set_tests_properties(api_tool PROPERTIES LABELS "unit")
    add_test(NAME ladder_tool COMMAND ${G5C_PYTHON} ${CMAKE_SOURCE_DIR}/tests/support/test_ladder.py)
    set_tests_properties(ladder_tool PROPERTIES LABELS "unit")
    add_test(NAME trace_tool COMMAND ${G5C_PYTHON} ${CMAKE_SOURCE_DIR}/tests/support/test_trace.py)
    set_tests_properties(trace_tool PROPERTIES LABELS "unit")
    add_test(NAME console_tool COMMAND ${G5C_PYTHON} ${CMAKE_SOURCE_DIR}/tests/support/test_console.py)
    set_tests_properties(console_tool PROPERTIES LABELS "unit")
    add_test(NAME kpi_tool COMMAND ${G5C_PYTHON} ${CMAKE_SOURCE_DIR}/tests/support/test_kpi.py)
    set_tests_properties(kpi_tool PROPERTIES LABELS "unit")
    add_test(NAME privacy_tool COMMAND ${G5C_PYTHON} ${CMAKE_SOURCE_DIR}/tests/support/test_privacy.py)
    set_tests_properties(privacy_tool PROPERTIES LABELS "unit;conformance")
    add_test(NAME k8s_manifests COMMAND ${G5C_PYTHON} ${CMAKE_SOURCE_DIR}/tests/support/test_k8s.py)
    set_tests_properties(k8s_manifests PROPERTIES LABELS "unit" SKIP_RETURN_CODE 77)
    add_test(NAME compat_tool COMMAND ${G5C_PYTHON} ${CMAKE_SOURCE_DIR}/tests/support/test_compat.py)
    set_tests_properties(compat_tool PROPERTIES LABELS "unit")
    add_test(NAME atlas_live_tool COMMAND ${G5C_PYTHON} ${CMAKE_SOURCE_DIR}/tests/support/test_atlas_live.py)
    set_tests_properties(atlas_live_tool PROPERTIES LABELS "unit")
    add_test(NAME lab_tool COMMAND ${G5C_PYTHON} ${CMAKE_SOURCE_DIR}/tests/support/test_lab.py)
    set_tests_properties(lab_tool PROPERTIES LABELS "unit")
    add_test(NAME mutate_tool COMMAND ${G5C_PYTHON} ${CMAKE_SOURCE_DIR}/tests/support/test_mutate.py)
    set_tests_properties(mutate_tool PROPERTIES LABELS "unit")
    add_test(NAME replay_tool COMMAND ${G5C_PYTHON} ${CMAKE_SOURCE_DIR}/tests/support/test_replay.py)
    set_tests_properties(replay_tool PROPERTIES LABELS "unit" SKIP_RETURN_CODE 77)
    add_test(NAME cdr_tool COMMAND ${G5C_PYTHON} ${CMAKE_SOURCE_DIR}/tests/support/test_cdr.py)
    set_tests_properties(cdr_tool PROPERTIES LABELS "unit")
    add_test(NAME fanout_tool COMMAND ${G5C_PYTHON} ${CMAKE_SOURCE_DIR}/tests/support/test_fanout.py)
    add_test(NAME triage_tool COMMAND ${G5C_PYTHON} ${CMAKE_SOURCE_DIR}/tests/support/test_triage.py)
    set_tests_properties(triage_tool PROPERTIES LABELS "unit")
    add_test(NAME conform_tool COMMAND ${G5C_PYTHON} ${CMAKE_SOURCE_DIR}/tests/support/test_conform.py)
    set_tests_properties(conform_tool PROPERTIES LABELS "unit")
    add_test(NAME nwdaf_tool COMMAND ${G5C_PYTHON} ${CMAKE_SOURCE_DIR}/tests/support/test_nwdaf.py)
    set_tests_properties(nwdaf_tool PROPERTIES LABELS "unit")
    add_test(NAME fleet_tool COMMAND ${G5C_PYTHON} ${CMAKE_SOURCE_DIR}/tests/support/test_fleet.py)
    set_tests_properties(fleet_tool PROPERTIES LABELS "unit")
    add_test(NAME tester_tool COMMAND ${G5C_PYTHON} ${CMAKE_SOURCE_DIR}/tests/support/test_tester.py)
    set_tests_properties(tester_tool PROPERTIES LABELS "unit")
    add_test(NAME interop_register COMMAND ${G5C_PYTHON} ${CMAKE_SOURCE_DIR}/tests/support/test_interop.py)
    set_tests_properties(interop_register PROPERTIES LABELS "unit")
    add_test(NAME why_tool COMMAND ${G5C_PYTHON} ${CMAKE_SOURCE_DIR}/tests/support/test_why.py)
    set_tests_properties(why_tool PROPERTIES LABELS "unit")
    set_tests_properties(fanout_tool PROPERTIES LABELS "unit")
    add_test(NAME tokens_tool COMMAND ${G5C_PYTHON} ${CMAKE_SOURCE_DIR}/tests/support/test_tokens.py)
    set_tests_properties(tokens_tool PROPERTIES LABELS "unit")
    add_test(NAME alarms_tool COMMAND ${G5C_PYTHON} ${CMAKE_SOURCE_DIR}/tests/support/test_alarms.py)
    set_tests_properties(alarms_tool PROPERTIES LABELS "unit" SKIP_RETURN_CODE 77)
    add_test(NAME api_docs_fresh COMMAND ${G5C_PYTHON} ${CMAKE_SOURCE_DIR}/tools/docs/gen_api_docs.py --check)
    set_tests_properties(api_docs_fresh PROPERTIES LABELS "unit")
    add_test(NAME licence_audit COMMAND ${G5C_PYTHON} ${CMAKE_SOURCE_DIR}/tools/release/licence_audit.py)
    set_tests_properties(licence_audit PROPERTIES LABELS "unit;conformance")
    add_test(NAME ops_files_check COMMAND ${G5C_PYTHON} ${CMAKE_SOURCE_DIR}/tools/check/check_ops.py)
    set_tests_properties(ops_files_check PROPERTIES LABELS "unit" SKIP_RETURN_CODE 77)
  endif()
endif()
set_tests_properties(load_core_small PROPERTIES ENVIRONMENT "G5C_LOAD_UES=150;G5C_LOAD_GNBS=6" TIMEOUT 240 LABELS "component;integration")

add_executable(test_amf_units tests/test_amf_units.c)
target_include_directories(test_amf_units PRIVATE src)
target_link_libraries(test_amf_units g5c_amf g5c_testkit)
add_test(NAME amf_units COMMAND test_amf_units)
set_property(TEST amf_units APPEND PROPERTY LABELS unit conformance)
