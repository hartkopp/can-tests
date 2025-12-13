/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-3-Clause) */
/*
 * tst-bcm-recvmsg.c
 *
 * Copyright (c) 2024 Oliver Hartkopp
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of Volkswagen nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * Alternatively, provided that this notice is retained in full, this
 * software may be distributed under the terms of the GNU General
 * Public License ("GPL") version 2, in which case the provisions of the
 * GPL apply INSTEAD OF those given above.
 *
 * The provided data structures and external interfaces from this code
 * are not restricted to be used by modules with a GPL compatible license.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
 * Send feedback to <linux-can@vger.kernel.org>
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <net/if.h>

#include <linux/can.h>
#include <linux/can/bcm.h>
#include <linux/sockios.h>

#define U64_DATA(p) (*(unsigned long long*)(p)->data)
#define MHSIZ sizeof(struct bcm_msg_head)
#define CFSIZ sizeof(struct can_frame)
#define CANDEV "can0"

int main(int argc, char **argv)
{
	int s,nbytes;
	struct sockaddr_can addr;
	struct ifreq ifr;
	struct timeval tv;
	char ctrlmsg[2000];

	static struct {
		struct bcm_msg_head msg_head;
		struct can_frame frame;
	} txmsg, rxmsg;

	struct iovec iov = {
		.iov_base = &rxmsg,
	};

	struct msghdr msg = {
		.msg_control = &ctrlmsg,
		.msg_name = &addr,
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};

	s = socket(PF_CAN, SOCK_DGRAM, CAN_BCM);
	if (s < 0) {
		perror("socket");
		return 1;
	}

	addr.can_family = PF_CAN;
	strcpy(ifr.ifr_name, CANDEV);
	ioctl(s, SIOCGIFINDEX, &ifr);
	addr.can_ifindex = ifr.ifr_ifindex;

	if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("connect");
		return 1;
	}

	txmsg.msg_head.opcode  = RX_SETUP;
	txmsg.msg_head.can_id  = 0x42;
	txmsg.msg_head.flags   = RX_FILTER_ID;
	txmsg.msg_head.nframes = 0;

	printf("RX_SETUP with RX_FILTER_ID for CAN ID 0x%03X\n",
	       txmsg.msg_head.can_id);

	if (write(s, &txmsg, sizeof(txmsg)) < 0)
		perror("write");

	txmsg.msg_head.opcode  = TX_SEND;
	txmsg.msg_head.nframes = 1;
	txmsg.frame.can_id    = 0x42;
	txmsg.frame.can_dlc   = 8;
	U64_DATA(&txmsg.frame) = (__u64) 0xdeadbeefdeadbeefULL;

	printf("TX_SEND of CAN ID 0x%03X\n",
	       txmsg.frame.can_id);

	if (write(s, &txmsg, MHSIZ + CFSIZ) < 0)
		perror("write");
loop:
	/* these settings may be modified by recvmsg() */
	iov.iov_len = sizeof(rxmsg);
	msg.msg_namelen = sizeof(addr);
	msg.msg_controllen = sizeof(ctrlmsg);
	msg.msg_flags = 0;

	nbytes = recvmsg(s, &msg, 0);
	if (nbytes < 0)
		perror("recvmsg");

	if (nbytes != (MHSIZ + CFSIZ))
		perror("bcm msg size");

	/* don't parse ctrlmsg and get the timestamp the old fashioned way */
	ioctl(s, SIOCGSTAMP, &tv);
	printf("(%ld.%06ld) %s ", tv.tv_sec, tv.tv_usec, CANDEV);

	if (rxmsg.msg_head.opcode == RX_CHANGED &&
	    nbytes == sizeof(struct bcm_msg_head) + sizeof(struct can_frame) &&
	    rxmsg.msg_head.can_id == 0x42 && rxmsg.frame.can_id == 0x42) {
		int i;

		printf("%03X ", rxmsg.frame.can_id);
		for (i = 0; i < rxmsg.frame.len; i++)
			printf("%02X ", rxmsg.frame.data[i]);

		if (msg.msg_flags & MSG_DONTROUTE)
			printf("local ");

		if (msg.msg_flags & MSG_CONFIRM)
			printf("orig_socket ");

		printf("\n");
		fflush(stdout);
	}

	goto loop;

	close(s);

	return 0;
}
