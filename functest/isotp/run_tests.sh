#!/bin/sh
# SPDX-License-Identifier: (GPL-2.0-only OR BSD-3-Clause)
#
# run_tests.sh - run the CAN_ISOTP functional test suite (no root needed)
#
# usage: run_tests.sh [options]
#
#   -q            quick mode: skip tests that run into 1 s protocol timeouts
#   -v            verbose: trace of all test cases (-v -v: all CAN frames)
#   -T <ms>       timing tolerance for upper bounds (default 20 ms)
#   -s <suites>   comma separated suites (api,tx,rx,xl,e2e,timing)
#   -t <patterns> run only test cases matching the shell patterns
#   -x <patterns> exclude test cases matching the shell patterns
#   -o <dir>      log directory (default logs/<date>-<time>)
#
# Run setup_vcan.sh as root before. The results are written to the log
# directory (one TAP log per suite, environment info, summary) and packed
# into <logdir>.tar.gz to be sent back for analysis.

cd "$(dirname "$0")" || exit 2

SUITES="api,tx,rx,xl,e2e,timing"
OPTS=""
LOGDIR=""

while getopts "qvT:s:t:x:o:h" opt; do
	case $opt in
	q) OPTS="$OPTS -q" ;;
	v) OPTS="$OPTS -v" ;;
	T) OPTS="$OPTS -T $OPTARG" ;;
	s) SUITES="$OPTARG" ;;
	t) OPTS="$OPTS -t $OPTARG" ;;
	x) OPTS="$OPTS -x $OPTARG" ;;
	o) LOGDIR="$OPTARG" ;;
	*) sed -n '4,21p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
	esac
done

[ -z "$LOGDIR" ] && LOGDIR="logs/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$LOGDIR" || exit 2

# interfaces
missing=""
for i in vcaniso0 vcaniso1 vcaniso2 vcaniso3 vcaniso4 vcaniso5; do
	[ -e /sys/class/net/$i ] || missing="$missing $i"
done
if [ -n "$missing" ]; then
	echo "missing interfaces:$missing"
	echo "run 'sudo ./setup_vcan.sh up' first"
	exit 2
fi

# build
if ! make -s >/dev/null; then
	echo "build failed"
	exit 2
fi

# environment information
{
	echo "date:          $(date -R)"
	echo "kernel:        $(uname -a)"
	echo "can-tests:     $(git describe --always --dirty 2>/dev/null)"
	echo "options:       $OPTS"
	echo "max_pdu_size:  $(cat /sys/module/can_isotp/parameters/max_pdu_size 2>/dev/null || echo n/a)"
	echo "rmem_max:      $(cat /proc/sys/net/core/rmem_max)"
	echo "cpus:          $(nproc)"
	echo "FT_IF_HW:      ${FT_IF_HW:-not set}"
	[ -n "$FT_IF_HW" ] && ip -details -statistics link show "$FT_IF_HW"
	echo
	for i in vcaniso0 vcaniso1 vcaniso2 vcaniso3 vcaniso4 vcaniso5; do
		echo "$i mtu $(cat /sys/class/net/$i/mtu) $(cat /sys/class/net/$i/operstate)"
	done
	echo
	ip -details link show 2>/dev/null | grep -A3 vcaniso
} > "$LOGDIR/environment.txt" 2>&1

# test case patterns must not be expanded by the shell
set -f

total_fail=0
SUMMARY="$LOGDIR/summary.txt"
: > "$SUMMARY"

for s in $(echo "$SUITES" | tr ',' ' '); do
	prg=./tst-isotp-$s
	if [ ! -x $prg ]; then
		echo "unknown suite $s"
		continue
	fi
	echo "=== suite $s"
	# shellcheck disable=SC2086
	$prg $OPTS > "$LOGDIR/$s.log" 2>&1
	rc=$?
	grep -E "^not ok|^Bail out" "$LOGDIR/$s.log"
	tail -n 1 "$LOGDIR/$s.log" | tee -a "$SUMMARY"
	[ $rc -ne 0 ] && total_fail=1
done

set +f

{
	echo
	echo "failed test cases:"
	grep -h "^not ok" "$LOGDIR"/*.log || echo "  none"
	echo
	echo "test cases with DEVIATION from ISO 15765-2:"
	grep -h "# DEVIATION" "$LOGDIR"/*.log | sed 's/^ok [0-9]* - /  /'
	echo
	echo "test cases with REVIEW note:"
	grep -h "# REVIEW" "$LOGDIR"/*.log | sed 's/^ok [0-9]* - /  /'
} >> "$SUMMARY"

tar czf "$LOGDIR.tar.gz" -C "$(dirname "$LOGDIR")" "$(basename "$LOGDIR")"

echo
echo "logs: $LOGDIR (archive $LOGDIR.tar.gz)"
exit $total_fail
