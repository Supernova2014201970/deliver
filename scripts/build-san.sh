#!/bin/bash
# Instrumented build of one or both trees — the same single script before and
# after a fix, and for a tree a repair tool has edited.
#
#   build-san.sh [vuln|fixed|all|DIR] [address|undefined|memory|all]
#   build-san.sh                                   # all trees, all sanitizers
#   build-san.sh vuln address
#   build-san.sh /work/partial address              # an edited copy of a tree
#
# Each build gets a private in-tree copy: /work/build-<name>-<san>/src with its
# install prefix in ../inst, so a build never writes into a source tree and the
# /src trees may carry a plain build (build.sh) themselves.  (A VPATH build works
# on a pristine tree, but ImageMagick's configure refuses one once the source
# directory has been configured in-tree, which is exactly what build.sh leaves
# behind.)  One artifact per (tree, sanitizer):
#   /out/repro-<name>-<san>   hand_repro.cc linked against that build's installed
#                             headers and static libs, instrumented identically.
#
# Re-running is cheap: a source fingerprint under /work skips an unchanged tree.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
. "$here/lib.sh"

tree=${1:-all}; san=${2:-all}
trees=$tree; if [ "$tree" = all ]; then trees="vuln fixed"; fi
sans=$san; if [ "$san" = all ]; then sans="address undefined memory"; fi

build_one() {
  local dir=$1 name=$2 s bld inst bin base sanflags cflags plain fp lim
  s=$(san_profile "$3"); bld="$WORK/build-$name-$s"; inst="$bld/inst"; bin="$OUT/repro-$name-$s"
  base="-O1 -gline-tables-only -fno-omit-frame-pointer -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"
  sanflags=$(san_flags "$s"); cflags="$base $sanflags"
  # Plain flags at configure time: an MSan-instrumented test program cannot run
  # during feature detection, so instrumentation is injected at make time only.
  plain="-O1 -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"
  fp=$( cd "$dir" && find . -path ./.git -prune -o -type f -printf '%P %s %T@\n' |
        LC_ALL=C sort | md5sum )
  if [ -x "$bin" ] && [ -f "$bld/src/Makefile" ] && [ "$(cat "$bld/.src-fp" 2>/dev/null)" = "$fp" ]; then
    echo "up to date: $bin"
    return 0
  fi
  rm -rf "$bld"; mkdir -p "$bld/src" "$OUT"
  ( cd "$dir" && tar -cf - --exclude=./.git . ) | ( cd "$bld/src" && tar -xf - ) ||
    die "cannot copy $dir"
  echo "$fp" > "$bld/.src-fp"

  cd "$bld/src"
  # A tree that build.sh built in-tree brings its own Makefile, config.status and
  # object files: configure refuses to run next to config.status, and stale
  # objects would be reused with the wrong (non-instrumented) flags.
  if [ -f Makefile ]; then make distclean > /dev/null 2>&1 || true; fi
  rm -f config.status config.log
  find . -name '*.o' -delete -o -name '*.lo' -delete

  echo "== configure $name/$s -> $bld"
  CC=clang CXX=clang++ CFLAGS="$plain" CXXFLAGS="$plain -stdlib=libc++" LDFLAGS="" \
    ./configure --prefix="$inst" --disable-shared --disable-docs \
    --disable-openmp --without-perl > "$bld/configure.log" 2>&1 ||
    { tail -n 6 "$bld/configure.log"; die "configure failed ($name/$s)"; }
  echo "== make $name/$s"
  make -j"$(nproc)" CFLAGS="$cflags" CXXFLAGS="$cflags -stdlib=libc++" LDFLAGS="$sanflags" \
    > "$bld/make.log" 2>&1 || { tail -n 20 "$bld/make.log"; die "make failed ($name/$s)"; }
  make install CFLAGS="$cflags" CXXFLAGS="$cflags -stdlib=libc++" LDFLAGS="$sanflags" \
    > "$bld/install.log" 2>&1 || { tail -n 20 "$bld/install.log"; die "make install failed ($name/$s)"; }

  echo "== reproduce $name/$s -> $bin"
  clang++ $cflags -stdlib=libc++ $(san_link_extra "$s") -std=c++11 $(fixed_limits "$dir") \
    -I"$inst/include/ImageMagick-7" "$here/hand_repro.cc" -o "$bin.new" \
    -DMAGICKCORE_HDRI_ENABLE=1 -DMAGICKCORE_QUANTUM_DEPTH=16 \
    "$inst/lib/libMagick++-7.Q16HDRI.a" "$inst/lib/libMagickWand-7.Q16HDRI.a" \
    "$inst/lib/libMagickCore-7.Q16HDRI.a" -lpthread -lm ||
    die "hand reproducer build failed ($name/$s)"
  mv -f "$bin.new" "$bin"
  # The instrumentation must really be in the binary.  Grep a file, not nm's
  # output: `nm | grep -q` dies from SIGPIPE under pipefail.
  nm "$bin" > "$bld/nm.txt" 2>/dev/null || die "nm failed on $bin"
  case "$s" in
    address) grep -q '__asan_' "$bld/nm.txt" || die "$bin is not ASan-instrumented" ;;
    memory) grep -q '__msan_' "$bld/nm.txt" || die "$bin is not MSan-instrumented" ;;
    undefined) grep -q '__ubsan_' "$bld/nm.txt" || die "$bin is not UBSan-instrumented" ;;
  esac
  lim=$(fixed_limits "$dir")
  echo "built $bin ($(stat -c %s "$bin") bytes, $s, harness limits: ${lim:-none})"
}

for t in $trees; do
  dir=$(tree_dir "$t")
  [ -d "$dir" ] || die "no such source tree: $dir"
  [ -f "$dir/configure" ] || die "$dir/configure missing (it is tracked; never regenerate)"
  for s in $sans; do build_one "$dir" "$(tree_name "$t")" "$s"; done
done
