#!/bin/bash
# Plain (non-instrumented) build of the source trees — no sanitizer, no
# reproducer, just the project's own configure and make.  This is the build a
# static-analysis tool can drive.
#
#   build.sh [vuln|fixed|all]        default: all
#
# In-tree, so /src/imagemagick-<tree>/utilities/magick appears.  Re-running is
# cheap: configure is skipped once a Makefile exists, and make is incremental.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
. "$here/lib.sh"

trees=${1:-all}
if [ "$trees" = all ]; then trees="vuln fixed"; fi

for t in $trees; do
  dir=$(tree_dir "$t")
  [ -f "$dir/configure" ] || die "$dir/configure missing (it is tracked; never regenerate)"
  start=$(date +%s)
  cd "$dir"
  if [ ! -f Makefile ]; then
    echo "== configure $dir"
    CC=clang CXX=clang++ ./configure --disable-shared --disable-docs \
      --disable-openmp --without-perl > "/tmp/plain-$(tree_name "$t").configure.log" 2>&1 ||
      { tail -n 6 "/tmp/plain-$(tree_name "$t").configure.log"; die "configure failed in $dir"; }
  fi
  echo "== make $dir"
  make -j"$(nproc)" > "/tmp/plain-$(tree_name "$t").make.log" 2>&1 ||
    { tail -n 20 "/tmp/plain-$(tree_name "$t").make.log"; die "make failed in $dir"; }
  [ -x utilities/magick ] || die "no utilities/magick after make in $dir"
  echo "built $(tree_name "$t"): $dir/utilities/magick ($(( $(date +%s) - start ))s) — $(utilities/magick -version | head -1)"
done
