#!/usr/bin/env bash
#
# mayhem/build.sh — build this repo's fuzz harness(es). EDIT per repo.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

GR_LIBS="-lgnuradio-blocks -lgnuradio-filter -lgnuradio-digital -lgnuradio-analog -lgnuradio-fft \
  -lgnuradio-runtime -lgnuradio-pmt -lvolk -lboost_log -lboost_log_setup -lboost_thread \
  -lboost_filesystem -lboost_program_options -lboost_chrono -lboost_regex -lboost_date_time \
  -lboost_atomic -lspdlog -lfmt -lssl -lcrypto -lcurl -lsndfile -lgmp -lgmpxx -ldl -lpthread -lm"
INCS="-I$SRC/trunk-recorder -I$SRC/lib -I$SRC/lib/op25_repeater/include -I$SRC/lib/op25_repeater/lib"
TARGETS="fuzz_p25_parser fuzz_smartnet_parser fuzz_dmr_parser fuzz_signal_decoders fuzz_ota_alias fuzz_op25_framers fuzz_csv_files"

# 1) The project itself (trunk-recorder core library + vendored OP25), sanitized + SanCov, DWARF 3.
#    Build dirs live under build/ (gitignored upstream).
# -fno-sanitize=shift-base: the vendored ETSI-style fixed-point IMBE/AMBE vocoder math
# (lib/op25_repeater/lib/imbe_vocoder/basicop2.cc L_shl/shl) left-shifts negative values on every
# voice frame by design; without this, every voice-carrying symbol stream stops at that UBSan report.
# ASan and the rest of UBSan stay on and halting.
FUZZ_FLAGS="$SANITIZER_FLAGS -fno-sanitize=shift-base $DEBUG_FLAGS -fsanitize=fuzzer-no-link"
[ -n "$SANITIZER_FLAGS" ] || FUZZ_FLAGS="$DEBUG_FLAGS"
cmake -S "$SRC" -B build/fuzz -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS="$FUZZ_FLAGS" -DCMAKE_CXX_FLAGS="$FUZZ_FLAGS" \
  -DCMAKE_C_FLAGS_DEBUG="" -DCMAKE_CXX_FLAGS_DEBUG="-Wno-deprecated-declarations"
cmake --build build/fuzz -j"$MAYHEM_JOBS" --target trunk_recorder_library gnuradio-op25_repeater git

# Same defines CMake gives the library (GNURADIO_VERSION etc.).
DEFS="$(sed -n 's/^CXX_DEFINES = //p' build/fuzz/CMakeFiles/trunk_recorder_library.dir/flags.make | sed 's/-DMANUAL_GITINFO=[^ ]*//')"

# 2) Harnesses: libFuzzer binary + standalone reproducer each.
$CXX $FUZZ_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o build/fuzz/lsan_off.o
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o build/fuzz/standalone_main.o
LINK="build/fuzz/libtrunk-recorder.a build/fuzz/libgit.a -Lbuild/fuzz \
  -lgnuradio-op25_repeater -Wl,-rpath,$SRC/build/fuzz $GR_LIBS"
for t in $TARGETS; do
  $CXX -std=c++17 $FUZZ_FLAGS $DEFS $INCS -I$SRC/build/fuzz -c "$SRC/mayhem/harnesses/$t.cc" -o "build/fuzz/$t.o"
  $CXX $FUZZ_FLAGS $LIB_FUZZING_ENGINE "build/fuzz/$t.o" build/fuzz/lsan_off.o $LINK -o "$SRC/$t"
  $CXX $FUZZ_FLAGS "build/fuzz/$t.o" build/fuzz/standalone_main.o build/fuzz/lsan_off.o $LINK -o "$SRC/$t-standalone"
done

# 3) Functional oracle: the core library again with upstream's normal (Release) flags, plus the
#    known-answer selftest in mayhem/tr_selftest.cc.
cmake -S "$SRC" -B build/test -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" -DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS"
cmake --build build/test -j"$MAYHEM_JOBS" --target trunk_recorder_library gnuradio-op25_repeater git
$CXX -std=c++17 -O2 $COVERAGE_FLAGS $DEFS $INCS -I$SRC/build/test "$SRC/mayhem/selftest/tr_selftest.cc" \
  build/test/libtrunk-recorder.a build/test/libgit.a -Lbuild/test \
  -lgnuradio-op25_repeater -Wl,-rpath,$SRC/build/test $GR_LIBS \
  -o build/test/tr_selftest
