#!/bin/sh
# SPDX-License-Identifier: (GPL-2.0-only OR BSD-3-Clause)
#
# setup_vcan.sh - create the virtual CAN interfaces for the CAN_ISOTP
#                 functional test suite (run as root)
#
# usage: setup_vcan.sh [-r] [up|down|status]
#
#   up      (default) load the CAN modules and create the interfaces
#   down    remove the interfaces
#   status  show the interfaces
#   -r      also raise net.core.rmem_max to 8 MByte (recommended: the
#           CAN_RAW peer of the test suite records long frame bursts)
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
# The test suite itself runs without root privileges.

IFACES="vcaniso0:16:up vcaniso1:72:up vcaniso2:2060:up vcaniso3:524:up vcaniso4:268:up vcaniso5:16:down"

RMEM=0
if [ "$1" = "-r" ]; then
	RMEM=1
	shift
fi

CMD=${1:-up}

die() {
	echo "setup_vcan.sh: $*" >&2
	exit 1
}

if [ "$CMD" != "status" ] && [ "$(id -u)" != "0" ]; then
	die "must be run as root"
fi

case "$CMD" in
up)
	for m in can can_raw can_bcm can_isotp vcan; do
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

	if [ $RMEM = 1 ]; then
		sysctl -w net.core.rmem_max=8388608
	fi
	;;
down)
	for e in $IFACES; do
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

for e in $IFACES; do
	name=${e%%:*}
	if [ -e /sys/class/net/$name ]; then
		printf "%-9s mtu %-5s %s\n" $name \
			"$(cat /sys/class/net/$name/mtu)" \
			"$(cat /sys/class/net/$name/operstate)"
	else
		printf "%-9s missing\n" $name
	fi
done
printf "net.core.rmem_max %s\n" "$(cat /proc/sys/net/core/rmem_max)"

exit 0
