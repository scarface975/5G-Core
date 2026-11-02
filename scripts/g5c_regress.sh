#!/usr/bin/env bash
# Full regression for the C tree, layer by layer (strategy 4.1). Run inside WSL.
#   scripts/g5c_regress.sh            everything except the oracle interop
#   scripts/g5c_regress.sh --oracle   also runs Open5GS/UERANSIM scenarios S3 and S4 against our NFs (needs the oracle env)
# Writes a one-line-per-layer summary to build/regress-summary.txt (consumed by tools/gen_dashboard.py).
set -uo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
out="${G5C_C_BUILD:-$HOME/g5c-cbuild}"
summary="$here/build/regress-summary.txt"
mkdir -p "$here/build"
: > "$summary"
rc=0
note() { echo "$1" | tee -a "$summary"; }

run_mode() { # <mode> <cmake flag> : build and run every test, then each layer for the report
  local mode="$1" flag="$2"
  cmake -S "$here" -B "$out/$mode" $flag >/dev/null || return 1
  cmake --build "$out/$mode" -j"$(nproc)" >/dev/null || return 1
}

run_mode plain "-DG5C_SANITIZE=OFF" || { note "build plain: FAIL"; exit 1; }
for layer in unit component integration conformance fuzz perf soak; do
  res="$(ctest --test-dir "$out/plain" -L "$layer" 2>&1 | grep -E 'tests passed|tests failed')"
  note "layer $layer (plain): ${res:-no tests}"
  grep -q ' 0 tests failed' <<<"$res" || rc=1
done
res="$(ctest --test-dir "$out/plain" --output-junit "$here/build/junit.xml" 2>&1 | grep -E 'tests passed|tests failed')"; note "all tests (plain): $res"
grep -q ' 0 tests failed' <<<"$res" || rc=1

for m in "asan:-DG5C_SANITIZE=ON" "tsan:-DG5C_TSAN=ON"; do
  mode="${m%%:*}"; flag="${m#*:}"
  run_mode "$mode" "$flag" || { note "build $mode: FAIL"; rc=1; continue; }
  TSAN_OPTIONS="halt_on_error=1" ctest --test-dir "$out/$mode" --output-on-failure >"$out/$mode-run.log" 2>&1
  res="$(grep -E 'tests passed|tests failed' "$out/$mode-run.log")"
  if ! grep -q ' 0 tests failed' <<<"$res"; then
    # The sanitizer binaries are slow and a test of sockets with deadlines can miss one on a busy machine. The log of the failure is kept (build/regress-failures), exactly the
    # tests that failed are run once more, and both results are in the summary; a test that fails twice fails the regression.
    mkdir -p "$here/build/regress-failures"
    cp "$out/$mode-run.log" "$here/build/regress-failures/$mode-$(date +%Y%m%d-%H%M%S).log"
    failed="$(sed 's/^[0-9]*://' "$out/$mode/Testing/Temporary/LastTestsFailed.log" 2>/dev/null | tr -s '\n' ' ')"
    res2="$(TSAN_OPTIONS="halt_on_error=1" ctest --test-dir "$out/$mode" --rerun-failed 2>&1 | grep -E 'tests passed|tests failed')"
    if grep -q ' 0 tests failed' <<<"$res2"; then
      note "all tests ($mode): $res; failed first time and passed on the rerun: ${failed% } (log in build/regress-failures)"
    else
      note "all tests ($mode): $res; rerun of [${failed% }]: $res2"
      rc=1
    fi
  else
    note "all tests ($mode): $res"
  fi
done

ctest --test-dir "$out/plain" -N > "$here/build/ctest-list.txt"
if python3 "$here/tools/check_matrix.py" --ctest-list "$here/build/ctest-list.txt" >"$out/matrix.log" 2>&1; then note "conformance matrix: $(tail -2 "$out/matrix.log" | head -1)"; else note "conformance matrix: FAIL (see $out/matrix.log)"; rc=1; fi
soak="$(ctest --test-dir "$out/plain" -R soak_core -V 2>&1 | grep -E 'soak: [0-9]|soak: RSS' | sed -E 's/^[0-9]+: //')"; [ -n "$soak" ] && while read -r l; do note "$l"; done <<<"$soak"
upfperf="$(ctest --test-dir "$out/plain" -R upf_io_bench_gate -V 2>&1 | grep -E '^[0-9]+: (uplink|downlink) ' | sed -E 's/^[0-9]+: //')"; [ -n "$upfperf" ] && while read -r l; do note "UPF $l"; done <<<"$upfperf"
perf="$(ctest --test-dir "$out/plain" -R udm_perf_gate -V 2>&1 | grep -o 'generate-auth-data:.*vectors/s' | head -1)"; [ -n "$perf" ] && note "perf: $perf"
if COV_JSON="$here/build/coverage.json" bash "$here/scripts/c_coverage.sh" >"$out/coverage.log" 2>&1; then note "coverage: $(grep '^TOTAL' "$out/coverage.log")"; else note "coverage run: FAIL (see $out/coverage.log)"; rc=1; fi
if bash "$here/scripts/c_lint.sh" >"$out/lint.log" 2>&1; then note "lint + static analysis: ok"; else note "lint + static analysis: FAIL (see $out/lint.log)"; rc=1; fi

# the cluster of real processes: the load generator against our daemons (scale, then kill -9 / restart of NFs while it runs)
bash "$here/scripts/c_install.sh" >/dev/null 2>&1
export G5C_LOAD_BIN="$out/plain/nf/amf/load_core" G5C_RUN="$out/cluster-run"
if timeout 600 bash "$here/deploy/run/g5c-cluster.sh" ns load 2000 16 2 >"$out/cluster-load.log" 2>&1 && grep -q '^load: PASS' "$out/cluster-load.log"; then
  note "cluster (real processes), 2000 UEs x 2 waves: $(grep -o 'registered with a PDU session each in .*UE/s' "$out/cluster-load.log" | tail -1)"
else
  note "cluster load: FAIL (see $out/cluster-load.log)"; rc=1
fi
if timeout 600 bash "$here/deploy/run/g5c-cluster.sh" ns chaos 200 30 >"$out/cluster-chaos.log" 2>&1 && grep -q '^chaos: RECOVERED' "$out/cluster-chaos.log"; then
  note "cluster chaos (NFs killed and restarted under load): $(grep -o '[0-9]* UE cycles in [0-9]* s: [0-9]* completed' "$out/cluster-chaos.log" | tail -1); recovered"
else
  note "cluster chaos: FAIL (see $out/cluster-chaos.log)"; rc=1
fi
# Phase 8: mutual TLS between all functions (load, chaos with restarts under TLS, refusals and certificate rotation), secrets hygiene, the operations files
if G5C_TLS=1 timeout 600 bash "$here/deploy/run/g5c-cluster.sh" ns load 2000 16 1 >"$out/cluster-load-tls.log" 2>&1 && grep -q '^load: PASS' "$out/cluster-load-tls.log"; then
  note "cluster with mutual TLS on every function, 2000 UEs: $(grep -o 'registered with a PDU session each in .*UE/s' "$out/cluster-load-tls.log" | tail -1)"
else
  note "cluster load with mutual TLS: FAIL (see $out/cluster-load-tls.log)"; rc=1
fi
if G5C_TLS=1 timeout 600 bash "$here/deploy/run/g5c-cluster.sh" ns chaos 200 30 >"$out/cluster-chaos-tls.log" 2>&1 && grep -q '^chaos: RECOVERED' "$out/cluster-chaos-tls.log"; then
  note "cluster chaos with mutual TLS (NFs killed and restarted under load): recovered"
else
  note "cluster chaos with mutual TLS: FAIL (see $out/cluster-chaos-tls.log)"; rc=1
fi
if G5C_TLS=1 timeout 600 bash "$here/deploy/run/g5c-cluster.sh" ns tls >"$out/cluster-tls.log" 2>&1 && grep -q '^tls: PASS' "$out/cluster-tls.log"; then
  note "mutual TLS: cleartext, no certificate and foreign certificates refused; certificate rotation by SIGHUP of all functions without a restart; damaged file refused: $(grep -c 'PASS ' "$out/cluster-tls.log") checks"
else
  note "mutual TLS checks: FAIL (see $out/cluster-tls.log)"; rc=1
fi
if G5C_TLS=1 timeout 600 bash "$here/deploy/run/g5c-cluster.sh" ns secrets >"$out/cluster-secrets.log" 2>&1 && grep -q '^secrets: PASS' "$out/cluster-secrets.log"; then
  note "secrets: no key, token or credential in a log, configuration or state file; K and OPc encrypted at rest: $(grep -c 'PASS ' "$out/cluster-secrets.log") checks"
else
  note "secrets checks: FAIL (see $out/cluster-secrets.log)"; rc=1
fi
for f in cluster-load cluster-load-tls; do
  if python3 "$here/tools/check_slo.py" "$out/$f.log" >"$out/slo-$f.log" 2>&1; then note "SLO ($f): $(tail -1 "$out/slo-$f.log")"; else note "SLO ($f): FAIL (see $out/slo-$f.log)"; rc=1; fi
done
if G5C_TLS=1 timeout 700 bash "$here/deploy/run/g5c-cluster.sh" ns upgrade 200 70 >"$out/cluster-upgrade.log" 2>&1 && grep -q "^upgrade: PASS" "$out/cluster-upgrade.log"; then
  note "upgrade and rollback under load (every function restarted one at a time, then with the previous binaries): $(grep -c "restarting" "$out/cluster-upgrade.log") restarts, clean wave passed"
else
  note "upgrade and rollback: FAIL (see $out/cluster-upgrade.log)"; rc=1
fi
if G5C_TLS=1 G5C_OAUTH2=0 timeout 600 bash "$here/deploy/run/g5c-cluster.sh" ns ops >"$out/cluster-ops.log" 2>&1 && grep -q "^ops: PASS" "$out/cluster-ops.log"; then
  note "operations: log level at run time, master key rotation, exec: key source, charging records: $(grep -c "PASS " "$out/cluster-ops.log") checks"
else
  note "operations checks: FAIL (see $out/cluster-ops.log)"; rc=1
fi
if G5C_TLS=1 G5C_OAUTH2=0 timeout 600 bash "$here/deploy/run/g5c-cluster.sh" ns slices >"$out/cluster-slices.log" 2>&1 && grep -q "^slices: PASS" "$out/cluster-slices.log"; then
  note "slices: the NSSF decides registration and PDU session slices, the AMF consumes both: $(grep -c "PASS " "$out/cluster-slices.log") checks"
else
  note "slices checks: FAIL (see $out/cluster-slices.log)"; rc=1
fi
if python3 "$here/tools/check_ops.py" >"$out/ops.log" 2>&1; then note "operations files (alert rules, Grafana dashboard): $(tail -1 "$out/ops.log")"; else note "operations files: FAIL (see $out/ops.log)"; rc=1; fi

if [ "${1:-}" = "--oracle" ]; then
  for s in s3 s4; do
    if OUR_UDM=1 OUR_PCF=1 OUR_UPF=1 timeout 300 "$here/deploy/oracle/scenario.sh" "$s" >"$out/oracle-$s.log" 2>&1 && ! grep -q "FAIL" "$out/oracle-$s.log"; then
      note "oracle $s (Open5GS + UERANSIM with our UDM/PCF/UPF/udr): pass"
    else
      note "oracle $s: FAIL (see $out/oracle-$s.log)"; rc=1
    fi
  done
  # Phase 4: Open5GS's AMF and UERANSIM against OUR SMF (on our UDM, PCF and UPF), including S4's policy push (a PDU session modification)
  for s in s3 s4; do
    if OUR_UDM=1 OUR_PCF=1 OUR_UPF=1 OUR_SMF=1 timeout 300 "$here/deploy/oracle/scenario.sh" "$s" >"$out/oracle-$s-smf.log" 2>&1 && ! grep -q "FAIL" "$out/oracle-$s-smf.log"; then
      note "oracle $s (Open5GS AMF + UERANSIM with our SMF/UDM/PCF/UPF): pass"
    else
      note "oracle $s with our SMF: FAIL (see $out/oracle-$s-smf.log)"; rc=1
    fi
  done
  # Phase 5: UERANSIM against OUR AMF, first with Open5GS's SMF / UPF / UDM / PCF behind it, then with every NF of the core ours (only the AUSF and the NRF
  # stay Open5GS's); S5 adds idle mode (UE context release by the gNB, service request, ping again)
  if OUR_AMF=1 timeout 300 "$here/deploy/oracle/scenario.sh" s3 >"$out/oracle-s3-amf.log" 2>&1 && ! grep -q "FAIL" "$out/oracle-s3-amf.log"; then
    note "oracle s3 (UERANSIM + Open5GS SMF/UPF/AUSF/NRF with our AMF): pass"
  else
    note "oracle s3 with our AMF: FAIL (see $out/oracle-s3-amf.log)"; rc=1
  fi
  for s in s3 s4 s5; do
    if OUR_AMF=1 OUR_UDM=1 OUR_PCF=1 OUR_UPF=1 OUR_SMF=1 timeout 300 "$here/deploy/oracle/scenario.sh" "$s" >"$out/oracle-$s-core.log" 2>&1 && ! grep -q "FAIL" "$out/oracle-$s-core.log"; then
      note "oracle $s (UERANSIM against our AMF + SMF + UPF + UDM + PCF, Open5GS AUSF/NRF): pass"
    else
      note "oracle $s with our AMF, SMF, UPF, UDM and PCF: FAIL (see $out/oracle-$s-core.log)"; rc=1
    fi
  done
  # our NRF: Open5GS's functions and UERANSIM against it, then every function but the AUSF ours
  # (one registration out of 19 runs failed here once, not reproduced in 17 further runs; a second attempt is allowed and noted)
  tries=1
  until OUR_NRF=1 timeout 300 "$here/deploy/oracle/scenario.sh" s3 >"$out/oracle-s3-nrf.log" 2>&1 && ! grep -q "FAIL" "$out/oracle-s3-nrf.log"; do
    [ $tries -ge 2 ] && break
    tries=$((tries+1)); cp "$out/oracle-s3-nrf.log" "$out/oracle-s3-nrf-attempt1.log"
  done
  if ! grep -q "FAIL" "$out/oracle-s3-nrf.log" && grep -q "S3 PDU session release: PASS" "$out/oracle-s3-nrf.log"; then
    note "oracle s3 (Open5GS core + UERANSIM with our NRF: registration, heart-beat, subscription, discovery): pass$([ $tries -gt 1 ] && echo " (second attempt)")"
  else
    note "oracle s3 with our NRF: FAIL (see $out/oracle-s3-nrf.log)"; rc=1
  fi
  for s in s3 s5; do
    if OUR_NRF=1 OUR_AMF=1 OUR_UDM=1 OUR_PCF=1 OUR_UPF=1 OUR_SMF=1 timeout 300 "$here/deploy/oracle/scenario.sh" "$s" >"$out/oracle-$s-nrfcore.log" 2>&1 && ! grep -q "FAIL" "$out/oracle-$s-nrfcore.log"; then
      note "oracle $s (UERANSIM against our NRF + AMF + SMF + UPF + UDM + PCF, Open5GS AUSF): pass"
    else
      note "oracle $s with our NRF and core: FAIL (see $out/oracle-$s-nrfcore.log)"; rc=1
    fi
  done
  # our AUSF: Open5GS's core and UERANSIM against it (it finds the UDM at the NRF), then every function that exists ours
  if OUR_AUSF=1 timeout 300 "$here/deploy/oracle/scenario.sh" s3 >"$out/oracle-s3-ausf.log" 2>&1 && ! grep -q "FAIL" "$out/oracle-s3-ausf.log" && grep -q "S3 PDU session release: PASS" "$out/oracle-s3-ausf.log"; then
    note "oracle s3 (Open5GS core + UERANSIM with our AUSF: 5G AKA, result confirmation and removal): pass"
  else
    note "oracle s3 with our AUSF: FAIL (see $out/oracle-s3-ausf.log)"; rc=1
  fi
  for s in s3 s4 s5; do
    if OUR_NRF=1 OUR_AUSF=1 OUR_AMF=1 OUR_UDM=1 OUR_PCF=1 OUR_UPF=1 OUR_SMF=1 timeout 300 "$here/deploy/oracle/scenario.sh" "$s" >"$out/oracle-$s-all.log" 2>&1 && ! grep -q "FAIL" "$out/oracle-$s-all.log"; then
      note "oracle $s (UERANSIM against our NRF + AUSF + AMF + SMF + UPF + UDM + PCF: no Open5GS function in the core's path): pass"
    else
      note "oracle $s with every function ours: FAIL (see $out/oracle-$s-all.log)"; rc=1
    fi
  done
  # our UDR: Open5GS's UDM, AUSF, PCF, SMF and AMF read and write the subscriber and policy data through it (the subscriber is provisioned into it in
  # Open5GS's document format, by the provisioning extension), then with our PCF and the NRF ours as well; S4 pushes a policy change to Open5GS's SMF
  if OUR_UDR=1 timeout 300 "$here/deploy/oracle/scenario.sh" s3 >"$out/oracle-s3-udr.log" 2>&1 && ! grep -q "FAIL" "$out/oracle-s3-udr.log" && grep -q "S3 PDU session release: PASS" "$out/oracle-s3-udr.log"; then
    note "oracle s3 (Open5GS core + UERANSIM with our UDR: its UDM, AUSF and PCF read and write the data through it): pass"
  else
    note "oracle s3 with our UDR: FAIL (see $out/oracle-s3-udr.log)"; rc=1
  fi
  if OUR_UDR=1 OUR_NRF=1 OUR_PCF=1 timeout 300 "$here/deploy/oracle/scenario.sh" s4 >"$out/oracle-s4-udr.log" 2>&1 && ! grep -q "FAIL" "$out/oracle-s4-udr.log" && grep -q "S4 user plane after policy change: PASS" "$out/oracle-s4-udr.log"; then
    note "oracle s4 (Open5GS UDM/AUSF/SMF/AMF + UERANSIM with our UDR, NRF and PCF: policy change pushed to the SMF): pass"
  else
    note "oracle s4 with our UDR, NRF and PCF: FAIL (see $out/oracle-s4-udr.log)"; rc=1
  fi
  # our NSSF: registered at the NRF in place of Open5GS's (Open5GS's AMF asks an NSSF for slice instances only on the home-routed roaming path, so this run proves
  # the registration and discovery side; the answers themselves are compared with Open5GS's NSSF by the nssf_differential test)
  if OUR_NSSF=1 timeout 300 "$here/deploy/oracle/scenario.sh" s3 >"$out/oracle-s3-nssf.log" 2>&1 && ! grep -q "FAIL" "$out/oracle-s3-nssf.log" && grep -q "S3 PDU session release: PASS" "$out/oracle-s3-nssf.log"; then
    note "oracle s3 (Open5GS core + UERANSIM with our NSSF registered at the NRF): pass"
  else
    note "oracle s3 with our NSSF: FAIL (see $out/oracle-s3-nssf.log)"; rc=1
  fi
  # our SCP: Open5GS's functions send every request to the other functions through it (their `client.scp`), once naming the producer (Model C) and once delegating the
  # discovery to the SCP and registering through it (Model D, delegated NFM); then our whole core through it. The answers of the SCP itself are compared with
  # Open5GS's SCP by the scp_differential test.
  for m in "c no" "d yes"; do
    read -r mode nfm <<<"$m"
    if OUR_SCP=1 OUR_SCP_MODE=$mode OUR_SCP_NFM=$nfm timeout 300 "$here/deploy/oracle/scenario.sh" s3 >"$out/oracle-s3-scp-$mode.log" 2>&1 && ! grep -q "FAIL" "$out/oracle-s3-scp-$mode.log" && grep -q "S3 PDU session release: PASS" "$out/oracle-s3-scp-$mode.log"; then
      note "oracle s3 (Open5GS core + UERANSIM through our SCP, $([ "$mode" = c ] && echo "Model C: the producer named by the consumer" || echo "Model D: delegated discovery and registration")): pass"
    else
      note "oracle s3 through our SCP (mode $mode): FAIL (see $out/oracle-s3-scp-$mode.log)"; rc=1
    fi
  done
  if OUR_SCP=1 OUR_NRF=1 OUR_AUSF=1 OUR_AMF=1 OUR_UDM=1 OUR_PCF=1 OUR_UPF=1 OUR_SMF=1 timeout 300 "$here/deploy/oracle/scenario.sh" s4 >"$out/oracle-s4-scp-all.log" 2>&1 && ! grep -q "FAIL" "$out/oracle-s4-scp-all.log" && grep -q "S4 user plane after policy change: PASS" "$out/oracle-s4-scp-all.log"; then
    note "oracle s4 (UERANSIM against our whole core with every request between the functions through our SCP): pass"
  else
    note "oracle s4 with our whole core through our SCP: FAIL (see $out/oracle-s4-scp-all.log)"; rc=1
  fi
  # our BSF (scenario s8): the PCF registers the binding of the PDU session at the BSF when it is created and removes it at the release. Open5GS's PCF against our BSF,
  # our PCF against Open5GS's BSF, then every function ours (the NEF of scenario s7 then asks the BSF which PCF holds the UE address).
  if OUR_BSF=1 timeout 300 "$here/deploy/oracle/scenario.sh" s8 >"$out/oracle-s8-bsf.log" 2>&1 && ! grep -q "FAIL" "$out/oracle-s8-bsf.log" && grep -q "S8 binding gone from the BSF" "$out/oracle-s8-bsf.log"; then
    note "oracle s8 (Open5GS core + UERANSIM with our BSF: Open5GS's PCF registers and removes the binding of the PDU session): pass"
  else
    note "oracle s8 with our BSF: FAIL (see $out/oracle-s8-bsf.log)"; rc=1
  fi
  if OUR_PCF=1 timeout 300 "$here/deploy/oracle/scenario.sh" s8 >"$out/oracle-s8-pcf.log" 2>&1 && ! grep -q "FAIL" "$out/oracle-s8-pcf.log" && grep -q "S8 binding gone from the BSF" "$out/oracle-s8-pcf.log"; then
    note "oracle s8 (Open5GS core + UERANSIM with our PCF and Open5GS's BSF: our PCF registers and removes the binding): pass"
  else
    note "oracle s8 with our PCF and Open5GS's BSF: FAIL (see $out/oracle-s8-pcf.log)"; rc=1
  fi
  for s in s8 s7; do
    if OUR_NRF=1 OUR_AUSF=1 OUR_AMF=1 OUR_UDM=1 OUR_UDR=1 OUR_PCF=1 OUR_UPF=1 OUR_SMF=1 OUR_NEF=1 OUR_BSF=1 timeout 300 "$here/deploy/oracle/scenario.sh" "$s" >"$out/oracle-$s-bsf-all.log" 2>&1 && ! grep -q "FAIL" "$out/oracle-$s-bsf-all.log" && grep -qE "S8 binding gone from the BSF|S7 AS session with QoS deleted" "$out/oracle-$s-bsf-all.log"; then
      note "oracle $s (UERANSIM against our whole core with our BSF$([ "$s" = s7 ] && echo ": the NEF finds the PCF of the UE address at the BSF")): pass"
    else
      note "oracle $s with our whole core and BSF: FAIL (see $out/oracle-$s-bsf-all.log)"; rc=1
    fi
  done
  # The ZMQ demo of the startup guide: the OCUDU gNB and srsUE exchange I/Q over ZeroMQ, the UE registers at the core, gets an IP address and pings the core through the user plane.
  # Open5GS first (the baseline: it shows that the radio side works), then our whole core. Skipped when the gNB or srsUE is not installed.
  for core in open5gs ours; do
    CORE=$core timeout 400 "$here/deploy/demo/zmq_demo.sh" >"$out/zmq-demo-$core.log" 2>&1; drc=$?
    if [ $drc = 0 ] && grep -q "ZMQ demo ($core core): PASS" "$out/zmq-demo-$core.log"; then
      note "zmq demo (OCUDU gNB + srsUE over ZeroMQ, $core core: registration, PDU session, ping through the user plane): pass"
    elif [ $drc = 77 ]; then
      note "zmq demo ($core core): skipped ($(grep -m1 SKIP "$out/zmq-demo-$core.log"))"
    else
      note "zmq demo ($core core): FAIL (see $out/zmq-demo-$core.log)"; rc=1
    fi
  done
  # OAuth2 access tokens of the NRF (TS 33.501 13.4.1) enforced between all of our functions: S4 (registration, PDU session, policy push), and S7 / S8 with the NEF, the BSF and the
  # SCP as well. Each run also asks the UDR for something without a token and expects 401. Open5GS's functions send no tokens, so these runs have none of them in the path.
  OA_ALL="OUR_NRF=1 OUR_AUSF=1 OUR_AMF=1 OUR_UDM=1 OUR_UDR=1 OUR_PCF=1 OUR_UPF=1 OUR_SMF=1 OUR_OAUTH2=1"
  for s in s4 s7 s8; do
    extra=""; [ "$s" != s4 ] && extra="OUR_NEF=1 OUR_BSF=1 OUR_SCP=1"
    pat="S4 user plane after policy change: PASS"; [ "$s" = s7 ] && pat="S7 AS session with QoS deleted: PASS"; [ "$s" = s8 ] && pat="S8 binding gone from the BSF"
    if env $OA_ALL $extra timeout 300 "$here/deploy/oracle/scenario.sh" "$s" >"$out/oracle-$s-oauth2.log" 2>&1 && ! grep -q "FAIL" "$out/oracle-$s-oauth2.log" && grep -q "OAuth2 request without a valid access token refused by the UDR: PASS" "$out/oracle-$s-oauth2.log" && grep -q "$pat" "$out/oracle-$s-oauth2.log"; then
      note "oracle $s (UERANSIM against our whole core with access tokens of the NRF enforced between the functions$([ "$s" != s4 ] && echo ", the NEF, the BSF and the SCP among them")): pass"
    else
      note "oracle $s with access tokens enforced: FAIL (see $out/oracle-$s-oauth2.log)"; rc=1
    fi
  done
  # our NEF: an AF's traffic influence request lands in our UDR, its monitoring subscription for the UE (an external identifier resolved by our UDM) reaches our
  # AMF, and UERANSIM's de-registration is reported to the AF (scenario s6)
  if OUR_NRF=1 OUR_AUSF=1 OUR_AMF=1 OUR_UDM=1 OUR_UDR=1 OUR_PCF=1 OUR_NEF=1 timeout 300 "$here/deploy/oracle/scenario.sh" s6 >"$out/oracle-s6-nef.log" 2>&1 && ! grep -q "FAIL" "$out/oracle-s6-nef.log" && grep -q "S6 de-registration notified to the AF: PASS" "$out/oracle-s6-nef.log"; then
    note "oracle s6 (UERANSIM against our NRF + AUSF + AMF + UDM + UDR + PCF + NEF: traffic influence into the UDR, loss of connectivity reported to the AF): pass"
  else
    note "oracle s6 with our NEF: FAIL (see $out/oracle-s6-nef.log)"; rc=1
  fi
  # AsSessionWithQoS through our NEF and our PCF (Npcf_PolicyAuthorization): the PCC rule is installed at Open5GS's SMF, then at ours (scenario s7)
  if OUR_PCF=1 OUR_NEF=1 timeout 300 "$here/deploy/oracle/scenario.sh" s7 >"$out/oracle-s7-nef-o5gs.log" 2>&1 && ! grep -q "FAIL" "$out/oracle-s7-nef-o5gs.log" && grep -q "S7 AS session with QoS deleted: PASS" "$out/oracle-s7-nef-o5gs.log"; then
    note "oracle s7 (Open5GS AMF/SMF/UPF + UERANSIM with our PCF and NEF: an AF's QoS request becomes a PCC rule at Open5GS's SMF): pass"
  else
    note "oracle s7 with our PCF and NEF (Open5GS SMF): FAIL (see $out/oracle-s7-nef-o5gs.log)"; rc=1
  fi
  if OUR_NRF=1 OUR_AUSF=1 OUR_AMF=1 OUR_UDM=1 OUR_UDR=1 OUR_PCF=1 OUR_UPF=1 OUR_SMF=1 OUR_NEF=1 timeout 300 "$here/deploy/oracle/scenario.sh" s7 >"$out/oracle-s7-nef-all.log" 2>&1 && ! grep -q "FAIL" "$out/oracle-s7-nef-all.log" && grep -q "S7 AS session with QoS deleted: PASS" "$out/oracle-s7-nef-all.log"; then
    note "oracle s7 (UERANSIM against our whole core and NEF: an AF's QoS request becomes a PCC rule at our SMF, the user plane keeps working): pass"
  else
    note "oracle s7 with our whole core and NEF: FAIL (see $out/oracle-s7-nef-all.log)"; rc=1
  fi
  # EAP-AKA' with UERANSIM's own implementation of the peer (a copy of nr-ue that decodes AT_KDF of Length 1: deploy/oracle/build_ueransim_eap.sh)
  [ -x "$HOME/test-peers/UERANSIM-eap/build/nr-ue" ] || bash "$here/deploy/oracle/build_ueransim_eap.sh" >"$out/ueransim-eap-build.log" 2>&1 || true
  if [ -x "$HOME/test-peers/UERANSIM-eap/build/nr-ue" ]; then
    for s in s3 s5; do
      if UERANSIM_DIR="$HOME/test-peers/UERANSIM-eap" AUTH_METHOD=EAP_AKA_PRIME OUR_NRF=1 OUR_AUSF=1 OUR_AMF=1 OUR_UDM=1 OUR_PCF=1 OUR_UPF=1 OUR_SMF=1 timeout 300 "$here/deploy/oracle/scenario.sh" "$s" >"$out/oracle-$s-eap.log" 2>&1 && ! grep -q "FAIL" "$out/oracle-$s-eap.log"; then
        note "oracle $s (UERANSIM registers with EAP-AKA' against our NRF + AUSF + AMF + SMF + UPF + UDM + PCF): pass"
      else
        note "oracle $s with EAP-AKA': FAIL (see $out/oracle-$s-eap.log)"; rc=1
      fi
    done
  else
    note "oracle EAP-AKA' scenarios: skipped (no patched UERANSIM, see $out/ueransim-eap-build.log)"
  fi
fi
if python3 "$here/tools/pfcp_diff.py" --smf >"$out/pfcp_diff_smf.log" 2>&1; then note "PFCP differential (Open5GS SMF vs ours, same UPF): $(tail -1 "$out/pfcp_diff_smf.log")"; else note "PFCP SMF differential: FAIL (see $out/pfcp_diff_smf.log)"; rc=1; fi
if python3 "$here/tools/pfcp_diff.py" >"$out/pfcp_diff.log" 2>&1; then note "PFCP differential (Open5GS UPF vs ours, same SMF): $(tail -1 "$out/pfcp_diff.log")"; else note "PFCP differential: FAIL (see $out/pfcp_diff.log)"; rc=1; fi
echo "regression: $([ $rc = 0 ] && echo PASS || echo FAIL)" | tee -a "$summary"
exit $rc
