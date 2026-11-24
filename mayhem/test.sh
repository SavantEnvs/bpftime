#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# Runs bpftime's Catch2 runtime unit tests (built by build.sh with normal flags), restricted to the
# tags that exercise the code the fuzz targets reach and that need no kernel BPF, ptrace, seccomp
# or a large /dev/shm: the userspace map backends (hash, LRU, LPM trie, queue, stack, bloom
# filter) and map-in-map. The other tags (attach, syscall-server, rootless seccomp, kernel maps,
# and the 64 MiB map-ops fuzzer replay) need privileges or /dev/shm a container build lacks.
RUNNER="$SRC/build-mayhem-test/runtime/unit-test/bpftime_runtime_tests"
if [ ! -x "$RUNNER" ]; then
  echo "test runner $RUNNER missing: mayhem/build.sh must build it" >&2
  emit_ctrf "catch2" 0 1 0; exit 1
fi
TAGS="[maps],[lpm_trie],[map_in_map],[queue_map],[stack_map],[lru_hash],[update_flags],[value_lifetime],[map_flags],[bloom_filter]"
OUT="$(mktemp "${TMPDIR:-/tmp}/bpftime-tests.XXXXXX")"
( cd "$(dirname "$RUNNER")" && "$RUNNER" "$TAGS" --reporter compact ) >"$OUT" 2>&1
rc=$?
# Catch2 compact summary: "All tests passed (A assertions in N test cases)" or
# "test cases: N | P passed | F failed [| S skipped]".
line=$(grep -E '^(All tests passed|test cases:)' "$OUT" | tail -1)
grep -E 'failed:' "$OUT" | head -20 >&2
rm -f "$OUT"
passed=0; failed=0; skipped=0
if [[ "$line" =~ ^All\ tests\ passed.*\ in\ ([0-9]+)\ test\ case ]]; then
  passed=${BASH_REMATCH[1]}
elif [[ "$line" =~ test\ cases:\ +([0-9]+) ]]; then
  total=${BASH_REMATCH[1]}
  [[ "$line" =~ \|\ +([0-9]+)\ failed ]] && failed=${BASH_REMATCH[1]}
  [[ "$line" =~ \|\ +([0-9]+)\ skipped ]] && skipped=${BASH_REMATCH[1]}
  passed=$(( total - failed - skipped ))
fi
if [ $(( passed + failed + skipped )) -eq 0 ]; then
  echo "no Catch2 summary (runner exit $rc)" >&2
  emit_ctrf "catch2" 0 1 0; exit 1
fi
# A runner that exits non-zero without reporting a failure (crash, abort) still fails the suite.
if [ "$rc" -ne 0 ] && [ "$failed" -eq 0 ]; then failed=1; fi
emit_ctrf "catch2" "$passed" "$failed" "$skipped"
