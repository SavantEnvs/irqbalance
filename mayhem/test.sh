#!/usr/bin/env bash
#
# mayhem/test.sh — irqbalance's functional oracle (binaries built by mayhem/build.sh, normal flags).
# exit 0 = pass. PATCH-grade oracle: after an agent patches the source, the grader rebuilds
# (build.sh) then runs this.
#
# Upstream's only test (tests/runoneshot.sh) runs `irqbalance --oneshot` against the host's real
# /proc and /sys and checks nothing but the exit code, so it is neither deterministic nor an oracle.
# Instead this runs known-answer probes built from upstream's own daemon and UI sources:
#   mayhem/out/selftest     the daemon on a fixed fake topology (mayhem/harness/fuzz_env.c):
#                           cpumask/cpulist parsing, /proc/interrupts tokenising + IRQ classes,
#                           sysfs topology + PCI classification, control-socket commands and replies
#   mayhem/out/ui_selftest  irqbalance-ui parsing a fixed daemon setup/stats reply into its cpu tree
#   mayhem/out/irqbalance   the real daemon executable's --version
# Every expected line below must appear exactly in the probe's output; a missing line is a failure.
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


OUT="$SRC/mayhem/out"
passed=0; failed=0

# check <name> <actual-output> <expected-line>
check() {
  if grep -qxF -- "$3" <<<"$2"; then
    passed=$((passed + 1))
  else
    failed=$((failed + 1))
    echo "FAIL [$1]: expected line: $3" >&2
  fi
}

run_probe() {
  local bin="$OUT/$1"
  if [ ! -x "$bin" ]; then
    echo "FAIL: $bin missing (mayhem/build.sh should have built it)" >&2
    return 1
  fi
  "$bin" 2>&1
}

daemon=$(run_probe selftest) || true
while IFS= read -r want; do
  [ -n "$want" ] && check selftest "$daemon" "$want"
done <<'EXPECTED'
cpulist 0-2,5: 00000027 weight=4
cpulist 1,3,64-65: 00000003,00000000,0000000a weight=4
cpumask f0: 000000f0 weight=4
cpumask 1,00000002: 00000001,00000002 weight=2
collect count: 8
collect irq0: type=0 class=0 name=timer\n
collect irq8: type=0 class=0 name=rtc0\n
collect irq9: type=0 class=0 name=acpi\n
collect irq16: type=0 class=0 name=ahci[0000:00:1f.2]\n
collect irq24: type=0 class=0 name=eth0-rx-0\n
collect irq25: type=0 class=0 name=eth0-tx-0\n
collect irq26: type=0 class=0 name=eth0\n
collect irq30: type=3 class=7 name=xen-pirq-event\n
topology: nodes=2 packages=1 caches=2 cpus=4 online=4
start irq0: type=0 class=0 level=1 count=22 node=-1
start irq8: type=0 class=0 level=1 count=1 node=-1
start irq9: type=0 class=0 level=1 count=4 node=-1
start irq16: type=0 class=2 level=3 count=300 node=0
start irq24: type=2 class=4 level=3 count=6000 node=0
start irq25: type=2 class=4 level=3 count=3700 node=0
start irq26: type=2 class=4 level=3 count=5 node=0
start irq30: type=3 class=7 level=3 count=40 node=-1
scan cycle=1 rescan=0
sock setup: SLEEP 10 BANNED 00000000
sock stats: objects=0/0,0/1,0/2,0/3,1/0,1/1,2/0,3/-1,3/0 irqs=8
sock sleep: 7
sock sleep 0 ignored: 7
sock ban rescan: 1 banned=2
banned irq16: type=0 class=2 level=3 count=300 node=0
banned irq24: type=0 class=0 level=0 count=6000 node=-99
banned irq25: type=0 class=0 level=0 count=3700 node=-99
banned irq26: type=2 class=4 level=3 count=5 node=0
sock setup banned: objects= irqs=2
sock setup banned prefix: SLEEP 7 
sock unban: banned=0
sock cpus 3 banned: 00000008 weight=1
sock cpus 3 cpus=3
sock cpus 3 setup tail: 00000008
sock cpus 3 stats: objects=0/0,0/1,0/2,1/0,1/1,2/0,3/-1,3/0 irqs=0
sock cpus NULL cpus=4
done
EXPECTED

ui=$(run_probe ui_selftest) || true
while IFS= read -r want; do
  [ -n "$want" ] && check ui_selftest "$ui" "$want"
done <<'EXPECTED'
setup sleep: 7
setup banned irqs: 24/10/3/4 25/0/0/4
setup banned cpus: 2 3
tree roots: 1
tree  type=3 number=0 load=900 powersave=0 mask=0xf cpus=0,1,2,3 irqs=
tree    type=2 number=0 load=900 powersave=0 mask=0xf cpus=0,1,2,3 irqs=16/5/300/2/on4
tree      type=1 number=0 load=400 powersave=0 mask=0x3 cpus=0,1 irqs=
tree        type=0 number=0 load=200 powersave=0 mask=0x1 cpus=0 irqs=24/7/6000/4/on1
tree        type=0 number=1 load=200 powersave=1 mask=0x2 cpus=1 irqs=
tree      type=1 number=1 load=500 powersave=0 mask=0xc cpus=2,3 irqs=
tree        type=0 number=2 load=250 powersave=0 mask=0x4 cpus=2 irqs=25/1/3700/4/on1,26/1/5/4/on1
tree        type=0 number=3 load=250 powersave=0 mask=0x8 cpus=3 irqs=
done
EXPECTED

version=$(sed -n "s/^ *version: *'\([^']*\)'.*/\1/p" "$SRC/meson.build" | head -n1)
ver=$("$OUT/irqbalance" --version 2>&1) || true
check irqbalance-version "$ver" "irqbalance version $version"

emit_ctrf "irqbalance-kat" "$passed" "$failed" 0
