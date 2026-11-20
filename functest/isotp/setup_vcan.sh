#!/bin/sh
# SPDX-License-Identifier: (GPL-2.0-only OR BSD-3-Clause)
#
# setup_vcan.sh - create the virtual CAN interfaces for the CAN_ISOTP
#                 functional test suite (run as root)
#
# usage: setup_vcan.sh [-r] [-e [-f]] [up|down|status]
#
#   up      (default) load the CAN modules and create the interfaces
#   down    remove the interfaces
#   status  show the interfaces
#   -r      also raise net.core.rmem_max to 8 MByte (recommended: the
#           CAN_RAW peer of the test suite records long frame bursts)
#   -e      echo mode: (re)load the vcan module with echo=1 and create
#           the additional interfaces vcaniso6..9 with netem/tbf qdiscs for
#           the echo timeout tests. The vcan module parameter applies to
#           all vcan interfaces: the module is only reloaded when no other
#           vcan interfaces than vcaniso* exist (-f forces the reload and
#           removes all vcan interfaces). Needs sch_netem, sch_tbf, tc.
#
# Interfaces (names do not collide with existing vcanX interfaces):
#
#   vcaniso0  MTU 16    CAN CC
#   vcaniso1  MTU 72    CAN FD
#   vcaniso2  MTU 2060  CAN XL (2048 byte data)
#   vcaniso3  MTU 524   CAN XL (512 byte data)
#   vcaniso4  MTU 268   CAN XL (256 byte data)
#   vcaniso5  MTU 16    CAN CC, interface stays DOWN (ENETDOWN tests)
#
# with -e (vcan echo=1, the local echo passes the qdisc):
#
#   vcaniso6  MTU 16    netem loss 100%   => echo never arrives
#   vcaniso7  MTU 16    netem delay 3000ms => echo after the 2 s timeout
#   vcaniso8  MTU 16    netem delay 100ms  => slow tx confirmation
#   vcaniso9  MTU 16    tbf rate 2kbit     => slow bus (64 ms per CC frame)
#
# netem orphans the skbs when a delay is configured (see TIM-ECHO-006/007),
# tbf keeps the socket reference of the skbs.
#
# The test suite itself runs without root privileges.

IFACES="vcaniso0:16:up vcaniso1:72:up vcaniso2:2060:up vcaniso3:524:up vcaniso4:268:up vcaniso5:16:down"

ECHO_IFACES="vcaniso6:16:up:netem_loss_100% vcaniso7:16:up:netem_delay_3000ms vcaniso8:16:up:netem_delay_100ms vcaniso9:16:up:tbf_rate_2kbit_burst_20b_limit_1000"

RMEM=0
ECHO=0
FORCE=0
while [ $# -gt 0 ]; do
	case "$1" in
	-r) RMEM=1 ;;
	-e) ECHO=1 ;;
	-f) FORCE=1 ;;
	*) break ;;
	esac
	shift
done

CMD=${1:-up}

die() {
	echo "setup_vcan.sh: $*" >&2
	exit 1
}

if [ "$CMD" != "status" ] && [ "$(id -u)" != "0" ]; then
	die "must be run as root"
fi

vcan_echo() {
	cat /sys/module/vcan/parameters/echo 2>/dev/null || echo N
}

# list all interfaces of link type vcan
vcan_list() {
	for d in /sys/class/net/*; do
		n=$(basename "$d")
		ip -d -o link show dev "$n" 2>/dev/null | grep -qw vcan && \
			echo "$n"
	done
}

# (re)load vcan with echo=1
load_vcan_echo() {
	[ "$(vcan_echo)" = "Y" ] && return 0

	if [ -d /sys/module/vcan ]; then
		others=""
		for n in $(vcan_list); do
			case $n in vcaniso*) ;; *) others="$others $n" ;; esac
		done
		if [ -n "$others" ] && [ $FORCE = 0 ]; then
			die "other vcan interfaces exist:$others - reloading vcan with echo=1 removes them (use -f to force)"
		fi
		for n in $(vcan_list); do
			ip link del dev "$n" 2>/dev/null
		done
		modprobe -r vcan || die "can not unload vcan"
	fi
	modprobe vcan echo=1 || die "can not load vcan echo=1"
	[ "$(vcan_echo)" = "Y" ] || die "vcan echo=1 not active (vcan built-in?)"
}

case "$CMD" in
up)
	[ $ECHO = 1 ] && load_vcan_echo

	for m in can can_raw can_bcm can_isotp vcan sch_netem sch_tbf; do
		modprobe $m 2>/dev/null || \
			echo "note: modprobe $m failed (built-in?)"
	done

	for e in $IFACES; do
		name=${e%%:*}
		rest=${e#*:}
		mtu=${rest%%:*}
		state=${rest#*:}

		if [ -e /sys/class/net/$name ]; then
			ip link set dev $name down
		else
			ip link add dev $name type vcan || \
				die "can not create $name"
		fi
		ip link set dev $name mtu $mtu || \
			die "can not set MTU $mtu on $name (CAN XL MTU support missing?)"
		if [ "$state" = "up" ]; then
			ip link set dev $name up || die "can not set $name up"
		fi
	done

	if [ $ECHO = 1 ]; then
		for e in $ECHO_IFACES; do
			name=${e%%:*}
			rest=${e#*:}
			mtu=${rest%%:*}
			qdisc=$(echo "${rest##*:}" | tr '_' ' ')

			if [ ! -e /sys/class/net/$name ]; then
				ip link add dev $name type vcan || \
					die "can not create $name"
			fi
			ip link set dev $name down
			ip link set dev $name mtu $mtu
			ip link set dev $name up || die "can not set $name up"
			# shellcheck disable=SC2086
			tc qdisc replace dev $name root $qdisc || \
				die "can not set qdisc $qdisc on $name"
		done
	fi

	if [ $RMEM = 1 ]; then
		sysctl -w net.core.rmem_max=8388608
	fi
	;;
down)
	for e in $IFACES $ECHO_IFACES; do
		name=${e%%:*}
		if [ -e /sys/class/net/$name ]; then
			ip link del dev $name
		fi
	done
	;;
status)
	;;
*)
	die "usage: setup_vcan.sh [-r] [up|down|status]"
	;;
esac

for e in $IFACES $ECHO_IFACES; do
	name=${e%%:*}
	if [ -e /sys/class/net/$name ]; then
		qd=$(tc qdisc show dev $name 2>/dev/null | head -n 1 | \
		     sed 's/ *refcnt.*//')
		printf "%-9s mtu %-5s %-8s %s\n" $name \
			"$(cat /sys/class/net/$name/mtu)" \
			"$(cat /sys/class/net/$name/operstate)" "$qd"
	else
		printf "%-9s missing\n" $name
	fi
done
printf "vcan echo=%s\n" "$(vcan_echo)"
printf "net.core.rmem_max %s\n" "$(cat /proc/sys/net/core/rmem_max)"

exit 0
