#!/bin/bash
# Attribution: exactly one fix patch applied to the vulnerable tree, then every
# case of the suite.  This is what shows that a single fix flips only its own
# case(s), and it exercises the same path a repair tool takes.
#
#   verify-one.sh <localId> [--report DIR] [--keep]
#   verify-one.sh --patch <sha> [--report DIR] [--keep]
#
# 1. copy /src/imagemagick-vuln to /work/one-<sha>
# 2. apply exactly that one patch (git apply, else patch -p1)
# 3. build-san.sh /work/one-<sha> all      — instrumented, all three sanitizers,
#    through the same script the dataset uses before and after a fix
# 4. verify.sh /work/one-<sha> --expect any — all cases of cases.tsv
# 5. assert the only cases that turned CLEAN are the ones that patch fixes:
#    1 case normally, 2 for 60cb93d0 / 78eaf41a, 5 for e8be814f.
#
# Writes DIR/verify-one-<name>.md and keeps the console log next to it.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
. "$here/lib.sh"

ID=""; PATCH=""; report="reports/one"; keep=0
while [ $# -gt 0 ]; do case "$1" in
  --patch)  PATCH=${2:?}; shift 2 ;;
  --report) report=${2:?}; shift 2 ;;
  --keep)   keep=1; shift ;;
  -h|--help) sed -n '2,17p' "$0"; exit 0 ;;
  -*) die "unknown argument: $1" ;;
  *) [ -z "$ID" ] || die "only one localId at a time"; ID=$1; shift ;;
esac; done

if [ -n "$ID" ]; then
  row=$(awk -F'\t' -v id="$ID" '!/^#/ && $1 == id { print; exit }' "$PAYLOAD/cases.tsv")
  [ -n "$row" ] || die "case '$ID' not found in $PAYLOAD/cases.tsv"
  PATCH=$(printf '%s\n' "$row" | cut -f8)
fi
[ -n "$PATCH" ] || die "usage: verify-one.sh <localId> | --patch <sha> [--report DIR] [--keep]"

# --patch may be a bare commit sha (full or a unique prefix), or a path relative
# to /payload.
patch_file=""
if [ -f "$PAYLOAD/$PATCH" ]; then
  patch_file="$PAYLOAD/$PATCH"
else
  base=${PATCH##*/}; base=${base%.patch}
  for cand in "$PAYLOAD/patches/$base.patch" "$PAYLOAD/patches/resolved/$base.patch" \
              "$PAYLOAD"/patches/"$base"*.patch "$PAYLOAD"/patches/resolved/"$base"*.patch; do
    [ -f "$cand" ] && { patch_file=$cand; break; }
  done
fi
[ -f "${patch_file:-/nonexistent}" ] || die "patch not found for '$PATCH' under $PAYLOAD/patches"
patch_rel=${patch_file#"$PAYLOAD/"}
sha=$(basename "$patch_file" .patch)
name="one-${sha:0:8}"
work="$WORK/$name"

# The cases this one patch is supposed to fix (1, 2 or 5 of them).
want=$(awk -F'\t' -v p="$patch_rel" '!/^#/ && $8 == p { print $1 }' "$PAYLOAD/cases.tsv" | sort)
[ -n "$want" ] || die "no case in cases.tsv uses patch '$patch_rel'"

rm -rf "$work"; mkdir -p "$work"
cp -a "$(tree_dir vuln)/." "$work/"
echo "tree      $work (copy of $(tree_dir vuln))"
if ( cd "$work" && git apply --check "$patch_file" ) 2>/dev/null; then
  ( cd "$work" && git apply "$patch_file" ) || die "git apply failed: $patch_rel"
else
  ( cd "$work" && patch -p1 --forward --batch < "$patch_file" > /dev/null ) ||
    die "cannot apply $patch_rel"
fi
echo "patch     $patch_rel"

"$here/build-san.sh" "$work" all || die "instrumented build failed for $work"

mkdir -p "$report"; log="$report/verify-one-${sha:0:8}.log"
"$here/verify.sh" "$work" --expect any --report "$report" | tee "$log"
cleans=$(awk '$1 == "CLEAN" { print $2 }' "$log" | sort)
verdict=PASS
[ "$cleans" = "$want" ] || verdict=FAIL

{ printf '# verify-one — `%s`\n\n| field | value |\n| --- | --- |\n' "${sha:0:8}"
  printf '| tree | `%s` = vuln + exactly one patch |\n| patch | `%s` |\n' "$work" "$patch_rel"
  printf '| cases this patch fixes | %s |\n' "$(printf '%s ' $want)"
  printf '| cases clean after the build | %s |\n' "$(printf '%s ' ${cleans:-none})"
  printf '| all other cases | CRASH |\n| generated | %s |\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '\n**verdict: %s** — clean set %s expected set\n' "$verdict" \
    "$([ "$verdict" = PASS ] && echo == || echo !=)"
} > "$report/verify-one-${sha:0:8}.md"

printf 'clean     %s\n' "$(printf '%s ' ${cleans:-none})"
printf 'expected  %s\n' "$(printf '%s ' $want)"
printf 'verdict   %s\n' "$verdict"
printf 'report    %s\n' "$report/verify-one-${sha:0:8}.md"
if [ "$keep" -eq 0 ]; then rm -rf "$work" "$OUT"/repro-"$name"-*; fi
[ "$verdict" = PASS ]
