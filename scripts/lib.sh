#!/bin/bash
# Shared helpers for the ImageMagick ARVO dataset image.
#
# /src/imagemagick-vuln    upstream 13ffeab + ResetImagePixels prerequisite
# /src/imagemagick-fixed   vuln + the 62 fix patches in /payload/patches
# /payload                 cases.tsv, pocs/, patches/, vulnerabilities.*
# /out/repro-<tree>-<san>  the instrumented reproducer, one per (tree, sanitizer)
# /work/build-<tree>-<san> out-of-tree build; install prefix is <dir>/inst
#
# A tree argument is a name (vuln|fixed) or an absolute directory, so the same
# helpers drive a tree a repair tool has edited (verify-one.sh, /work/partial).
set -uo pipefail

SRC=${SRC:-/src}; PAYLOAD=${PAYLOAD:-/payload}; OUT=${OUT:-/out}; WORK=${WORK:-/work}
die() { echo "error: $*" >&2; exit 1; }
ulimit -c 0 2>/dev/null || true   # a sanitizer crash must not leave core files

# One build per sanitizer — never merged (ASan+UBSan cross-talk makes the fixed
# tree report unrelated UB).
san_profile() { case "$1" in
  address|asan) echo address ;; undefined|ubsan) echo undefined ;;
  memory|msan) echo memory ;; *) die "unknown sanitizer '$1' (address|undefined|memory)" ;;
esac; }

# The environment the OSS-Fuzz runner uses for each profile.
san_env() { case "$1" in
  address|asan) echo "ASAN_OPTIONS=allocator_may_return_null=1:detect_leaks=0:detect_container_overflow=1:detect_odr_violation=0:detect_stack_use_after_return=1:fast_unwind_on_fatal=0:handle_abort=1:handle_segv=1:handle_sigill=1:print_scariness=1:quarantine_size_mb=10:strict_memcmp=1:symbolize=1:use_sigaltstack=1:dedup_token_length=3" ;;
  undefined|ubsan) echo "UBSAN_OPTIONS=print_stacktrace=1:print_summary=1:symbolize=1:dedup_token_length=3" ;;
  memory|msan) echo "MSAN_OPTIONS=print_stats=1:symbolize=1:dedup_token_length=3" ;;
  *) die "unknown sanitizer '$1'" ;;
esac; }

san_flags() { case "$1" in
  address|asan) echo "-fsanitize=address -fsanitize-address-use-after-scope" ;;
  undefined|ubsan) echo "-fsanitize=undefined -fno-sanitize-recover=undefined" ;;
  memory|msan) echo "-fsanitize=memory -fsanitize-memory-track-origins" ;;
  *) die "unknown sanitizer '$1'" ;;
esac; }

# MSan needs the image's instrumented libc++ in /usr/msan/lib (the copy in
# /usr/local/lib is not instrumented).
san_link_extra() { [ "$(san_profile "$1")" = memory ] && echo "-L/usr/msan/lib"; return 0; }

tree_dir() { case "$1" in
  vuln|fixed) echo "$SRC/imagemagick-$1" ;; /*) echo "$1" ;;
  *) die "tree '$1' is neither vuln|fixed nor an absolute directory" ;;
esac; }
tree_name() { case "$1" in
  vuln|fixed) echo "$1" ;; /*) basename "$1" ;;
  *) die "tree '$1' is neither vuln|fixed nor an absolute directory" ;;
esac; }

# The fixed tree's Magick++/fuzz/utils.cc gained ResourceLimits::width(2048) /
# height(2048) in e8be814f.  The reproducer mirrors what the tree itself says, so
# it keeps running under the harness that tree's own fuzz target would use.
fixed_limits() { grep -qs 'width(2048)' "$1/Magick++/fuzz/utils.cc" && echo "-DHARNESS_FIXED_LIMITS"; return 0; }

# run_poc <san> <binary> <coder> <poc> -> "<verdict><TAB><summary>"
#
#   CRASH  the sanitizer reported (`SUMMARY:` line) — the case still reproduces
#   CLEAN  exit status 0 and no report — the case is fixed
#   ERROR  neither: no report but the process did not exit 0
#
# MSan's runtime intermittently dies at startup with a bare SIGSEGV and no
# output (~15% of runs on this host, with or without setarch -R), which would
# look exactly like CLEAN.  Such a run is retried; a real crash always reports.
run_poc() {
  local san=$1 bin=$2 coder=$3 poc=$4 out sum rc try
  [ -x "$bin" ] || die "missing reproducer $bin (run: build-san.sh)"
  [ -f "$poc" ] || die "missing PoC $poc"
  local envs; envs=$(san_env "$san")
  for try in 1 2 3 4 5 6 7 8 9 10; do
    if [ "$(san_profile "$san")" = memory ]; then
      out=$(setarch x86_64 -R env $envs "$bin" "$coder" "$poc" 2>&1) 2>/dev/null
    else
      out=$(env $envs "$bin" "$coder" "$poc" 2>&1) 2>/dev/null
    fi
    rc=$?
    sum=$(printf '%s\n' "$out" | grep -m1 '^SUMMARY: ' || true)
    if [ -n "$sum" ]; then printf 'CRASH\t%s\n' "$sum"; return 0; fi
    if [ "$rc" -eq 0 ]; then printf 'CLEAN\t-\n'; return 0; fi
  done
  printf 'ERROR\texit=%s\n' "$rc"
}
