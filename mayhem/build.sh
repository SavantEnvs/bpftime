#!/usr/bin/env bash
# mayhem/build.sh — build bpftime's fuzz targets (sanitized) and its runtime unit tests (normal flags).
#
# Configuration used for both trees: the uBPF VM only (no LLVM JIT), no frida uprobe backend
# (it is downloaded at configure time) and no daemon (needs kernel BPF skeletons). libbpf, ubpf,
# spdlog and Catch2 come from the git submodules in the checkout, so nothing is fetched.
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
COMMON_OPTS=(-DBPFTIME_LLVM_JIT=OFF -DBPFTIME_ENABLE_FRIDA=OFF -DBUILD_BPFTIME_DAEMON=OFF
             -DCMAKE_BUILD_TYPE=RelWithDebInfo -Wno-dev)

# 1) Fuzz tree: the runtime (maps, handlers, JSON import, prog loader, uBPF VM) and the ELF object
#    loader, built with the sanitizers plus -fsanitize=fuzzer-no-link for coverage. We do not use
#    upstream's -DBPFTIME_ENABLE_FUZZING, which hard-codes -fsanitize=address,undefined after our
#    flags, so neither the sanitizer off-switch nor the one relaxed check below could take effect.
#    UBSan's `alignment` check is relaxed: the userspace hash maps read their u32 bucket state from
#    byte-packed buffers (runtime/src/bpf_map/bpftime_hash_map.hpp get_bucket_state), which trips it
#    on the first map op of every input. ASan and every other UBSan check stay on and halting.
FUZZ_FLAGS="$SANITIZER_FLAGS -fno-sanitize=alignment -fsanitize=fuzzer-no-link"
cmake -S . -B build-mayhem-fuzz "${COMMON_OPTS[@]}" -DBPFTIME_ENABLE_FUZZING=OFF \
    -DCMAKE_C_FLAGS="$FUZZ_FLAGS" -DCMAKE_CXX_FLAGS="$FUZZ_FLAGS" \
    -DCMAKE_C_FLAGS_RELWITHDEBINFO="-O1 $DEBUG_FLAGS" -DCMAKE_CXX_FLAGS_RELWITHDEBINFO="-O1 $DEBUG_FLAGS"
cmake --build build-mayhem-fuzz -j"$MAYHEM_JOBS" --target runtime bpftime-object

# 2) Harnesses (mayhem/harnesses; map_ops_fuzzer.cpp builds upstream runtime/fuzz/map_ops_fuzzer.cpp), compiled
#    with the runtime's own generated defines and include paths and linked like upstream's
#    runtime/fuzz target (libruntime + VM + ubpf + spdlog + libbpf).
B="$SRC/build-mayhem-fuzz"
flags_of() { sed -n "s/^$1 = //p" "$B/runtime/CMakeFiles/runtime.dir/flags.make"; }
# flags.make shell-escapes string defines (-DDEFAULT_VM_NAME=\"ubpf\"), so split it with eval.
eval "CXX_DEFINES=($(flags_of CXX_DEFINES))"; eval "CXX_INCLUDES=($(flags_of CXX_INCLUDES))"
LINK_LIBS=("$B/runtime/libruntime.a" "$B/vm/vm-core/libbpftime_vm.a" "$B/vm/compat/ubpf-vm/libbpftime_ubpf_vm.a"
           "$B/vm/compat/ubpf-vm/ubpf/lib/libubpf.a" "$B/third_party/spdlog/libspdlog.a" "$B/libbpf/libbpf.a"
           -ldl -lrt -lpthread -lm -lelf -lz)
OBJ_O="$SRC/build-mayhem-fuzz/runtime/object/CMakeFiles/bpftime-object.dir/bpf_object.cpp.o"
OUT=build-mayhem-fuzz/mayhem
mkdir -p "$OUT"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o "$OUT/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OUT/standalone_main.o"

link_both() { # <name> <objects...>
  local name=$1; shift
  # shellcheck disable=SC2086
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$@" "$OUT/lsan_off.o" "${LINK_LIBS[@]}" -o "/mayhem/$name"
  # shellcheck disable=SC2086
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$@" "$OUT/lsan_off.o" "$OUT/standalone_main.o" "${LINK_LIBS[@]}" -o "/mayhem/$name-standalone"
}

for h in map_ops_fuzzer json_import_fuzzer maps_api_fuzzer prog_exec_fuzzer object_open_fuzzer; do
  src="mayhem/harnesses/$h.cpp"
  # shellcheck disable=SC2086
  $CXX "${CXX_DEFINES[@]}" "${CXX_INCLUDES[@]}" -I"$SRC/runtime/object" -I"$SRC/mayhem/harnesses" \
      -std=gnu++20 -fPIE $FUZZ_FLAGS -O1 $DEBUG_FLAGS -c "$src" -o "$OUT/$h.o"
  extra=()
  [ "$h" = object_open_fuzzer ] && extra=("$OBJ_O")
  link_both "bpftime_$h" "$OUT/$h.o" "${extra[@]}"
done

# 3) Unit-test tree with the project's normal flags (the functional oracle for mayhem/test.sh).
cmake -S . -B build-mayhem-test "${COMMON_OPTS[@]}" -DBPFTIME_ENABLE_UNIT_TESTING=ON \
    -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" -DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS"
cmake --build build-mayhem-test -j"$MAYHEM_JOBS" --target bpftime_runtime_tests
