#!/bin/bash
# Run every case of /payload/cases.tsv against one tree — the same single script
# before, after, and in between (a tree a repair tool has edited).
#
#   verify.sh [vuln|fixed|all|DIR] [--san all|address|undefined|memory]
#             [--expect crash|clean|any] [--report DIR]
#
# One line per case: `CRASH|CLEAN localId coder sanitizer SUMMARY`, then
# `crash=N clean=M`.  With --expect crash|clean the exit status is non-zero
# unless the expectation holds; --expect any only reports.  Defaults:
# vuln -> crash, fixed -> clean, any other directory -> any.
#
# Writes DIR/verify-<name>.md and DIR/verify-<name>.json: one record per case
# plus totals and verdict — the machine-readable evidence.  Nothing is built
# here; run build-san.sh (or imdt build-san) first.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
. "$here/lib.sh"

tree=""; sans="address undefined memory"; expect=""; report="reports"
while [ $# -gt 0 ]; do case "$1" in
  --san) s=${2:?}; shift 2
         if [ "$s" = all ]; then sans="address undefined memory"; else sans=$(san_profile "$s"); fi ;;
  --expect) expect=${2:?}; shift 2 ;;
  --report) report=${2:?}; shift 2 ;;
  -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
  -*) die "unknown argument: $1" ;;
  *) [ -z "$tree" ] || die "only one tree at a time"; tree=$1; shift ;;
esac; done
[ -n "$tree" ] || tree=all
case "$expect" in ""|crash|clean|any) ;; *) die "--expect must be crash, clean or any" ;; esac

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
awk -F'\t' '!/^#/ && NF >= 11' "$PAYLOAD/cases.tsv" > "$tmp/cases"

jesc() { local s=$1; s=${s//\\/\\\\}; s=${s//\"/\\\"}; s=${s//$'\t'/ }; s=${s//$'\n'/ }; printf '%s' "$s"; }

rc=0
verify_tree() {
  local arg=$1 name exp verdict s md json sep sum res err
  local crash=0 clean=0 errors=0 n=0 id coder _t san _f _k poc _r
  name=$(tree_name "$arg")
  if [ -z "$expect" ]; then
    case "$name" in vuln) exp=crash ;; fixed) exp=clean ;; *) exp=any ;; esac
  else exp=$expect; fi
  mkdir -p "$report"; md="$report/verify-$name.md"; json="$report/verify-$name.json"
  echo "=== tree $name san=[$sans] expect=$exp"
  for s in $sans; do
    [ -x "$OUT/repro-$name-$s" ] ||
      die "missing $OUT/repro-$name-$s (run: build-san.sh $arg $s)"
  done
  : > "$tmp/rows"
  while IFS=$'\t' read -r id coder _t san _f _k poc _r; do
    case " $sans " in *" $san "*) ;; *) continue ;; esac
    res=$(run_poc "$san" "$OUT/repro-$name-$san" "$coder" "$PAYLOAD/$poc")
    sum=${res#*$'\t'}; res=${res%%$'\t'*}
    case "$res" in
      CRASH) crash=$((crash+1)) ;;
      CLEAN) clean=$((clean+1)) ;;
      *)     errors=$((errors+1)); res=ERROR ;;
    esac
    printf '%-5s %-9s %-6s %-9s %s\n' "$res" "$id" "$coder" "$san" "${sum:--}"
    printf '%s\t%s\t%s\t%s\t%s\n' "$id" "$coder" "$san" "$res" "$sum" >> "$tmp/rows"
  done < "$tmp/cases"
  n=$((crash+clean+errors))
  verdict=PASS
  case "$exp" in
    crash) [ "$crash" -eq "$n" ] || verdict=FAIL ;;
    clean) [ "$clean" -eq "$n" ] || verdict=FAIL ;;
  esac
  # An ERROR is an inconclusive run, never a pass: it would make a vulnerable
  # case look fixed.
  [ "$errors" -eq 0 ] || verdict=FAIL
  [ "$verdict" = PASS ] || rc=1
  local totals="crash=$crash clean=$clean"
  [ "$errors" -eq 0 ] || totals="$totals error=$errors"

  { printf '# verify — tree `%s`\n\n| field | value |\n| --- | --- |\n' "$name"
    printf '| tree dir | `%s` |\n| sanitizers | %s |\n| cases | %s |\n' "$(tree_dir "$arg")" "$sans" "$n"
    printf '| generated | %s |\n\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf '| localId | coder | sanitizer | result | SUMMARY |\n| --- | --- | --- | --- | --- |\n'
    while IFS=$'\t' read -r id coder san res sum; do
      printf '| %s | %s | %s | %s | %s |\n' "$id" "$coder" "$san" "$res" "${sum:--}"
    done < "$tmp/rows"
    printf '\n%s\n\n**verdict: %s** — `%s` expects `%s`\n' \
      "$totals" "$verdict" "$name" "$exp"
  } > "$md"

  { printf '{ "tree": "%s", "dir": "%s", "sanitizers": [%s], "cases": %s,\n' "$name" "$(tree_dir "$arg")" \
      "$(printf '"%s",' $sans | sed 's/,$//')" "$n"
    printf '  "totals": {"crash": %s, "clean": %s, "error": %s}, "expect": "%s", "verdict": "%s",\n' \
      "$crash" "$clean" "$errors" "$exp" "$verdict"
    printf '  "generated": "%s", "results": [\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    sep=""
    while IFS=$'\t' read -r id coder san res sum; do
      printf '%s    {"localId": "%s", "coder": "%s", "sanitizer": "%s", "result": "%s", "summary": "%s"}' \
        "$sep" "$id" "$(jesc "$coder")" "$san" "$res" "$(jesc "$sum")"
      sep=$',\n'
    done < "$tmp/rows"
    printf '\n  ]\n}\n'
  } > "$json"
  printf '%s verdict=%s (expect %s)\n' "$totals" "$verdict" "$exp"
  printf 'report: %s\nreport: %s\n' "$md" "$json"
}

if [ "$tree" = all ]; then verify_tree vuln; verify_tree fixed; else verify_tree "$tree"; fi
exit "$rc"
