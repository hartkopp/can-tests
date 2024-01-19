/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-3-Clause) */
/*
 * tst-bcm-tx_locktest.c
 *
 * Author: Oliver Hartkopp <socketcan@hartkopp.net>
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

#define U64_DATA(p) (*(unsigned long long*)(p)->data)
#define SEQLEN 256

int main(int argc, char **argv)
{
	int s;
	struct sockaddr_can addr;
	struct ifreq ifr;
	int i;

	struct {
		struct bcm_msg_head msg_head;
		struct can_frame frame[SEQLEN];
	} msg;


	if ((s = socket(PF_CAN, SOCK_DGRAM, CAN_BCM)) < 0) {
		perror("socket");
		return 1;
	}

	addr.can_family = PF_CAN;
	strcpy(ifr.ifr_name, "vcan2");
	ioctl(s, SIOCGIFINDEX, &ifr);
	addr.can_ifindex = ifr.ifr_ifindex;

	if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("connect");
		return 1;
	}

	msg.msg_head.opcode  = TX_SETUP;
	msg.msg_head.can_id  = 0x42;
	msg.msg_head.flags   = SETTIMER|STARTTIMER|TX_CP_CAN_ID;
	msg.msg_head.nframes = SEQLEN;
	msg.msg_head.count = 0;
	msg.msg_head.ival1.tv_sec = 0;
	msg.msg_head.ival1.tv_usec = 0;
	msg.msg_head.ival2.tv_sec = 0;
	msg.msg_head.ival2.tv_usec = 10000;
	for (i = 0; i < SEQLEN; i++) {
		msg.frame[i].can_dlc   = 8;
		U64_DATA(&msg.frame[i]) = (__u64) 0xdeadbeefdeadbeefULL;
		memset(msg.frame[i].data, i , 4);
	}

	if (write(s, &msg, sizeof(msg)) < 0)
		perror("write");

	printf("Press any key to run test 1 ...\n");

	getchar();

	for (i = 0; i < 20*256*256*256; i++) {
		msg.msg_head.opcode  = TX_SETUP;
		msg.msg_head.can_id  = 0x42;
		msg.msg_head.flags   = SETTIMER|TX_CP_CAN_ID|TX_RESET_MULTI_IDX;
		if (i == 1) {
			msg.msg_head.flags |= STARTTIMER;
			printf("starttimer\n");
		}
		msg.msg_head.nframes = SEQLEN;
		msg.msg_head.count = 6;
		msg.msg_head.ival1.tv_sec = 0;
		msg.msg_head.ival1.tv_usec = 40;
		msg.msg_head.ival2.tv_sec = 0;
		//msg.msg_head.ival2.tv_usec = (i & 0xFF) * 10;
		msg.msg_head.ival2.tv_usec = 60;

		usleep(160 + ((i & 0x3F) * 4));

		if (write(s, &msg, sizeof(msg)) < 0)
			perror("write");

	}

	printf("Press any key to run test 2 ...\n");

	getchar();

	for (i = 0; i < 256*256*256; i++) {
		msg.msg_head.opcode  = TX_SETUP;
		msg.msg_head.can_id  = 0x42;
		msg.msg_head.flags   = TX_CP_CAN_ID|TX_RESET_MULTI_IDX|(i==1?SETTIMER:0);
		msg.msg_head.nframes = 1;
		msg.msg_head.count = 0;
		msg.msg_head.ival1.tv_sec = 0;
		msg.msg_head.ival1.tv_usec = 0;
		msg.msg_head.ival2.tv_sec = 0;
		//msg.msg_head.ival2.tv_usec = (i & 0x3F) + 10;
		msg.msg_head.ival2.tv_usec = 40;
		memset(msg.frame[0].data, i & 0xFF, 8);

		usleep(160 + (i & 0x3F * 4));

		if (write(s, &msg, sizeof(msg)) < 0)
			perror("write");

	}

	printf("Press any key to stop the test ...\n");

	getchar();

	msg.msg_head.opcode  = TX_DELETE;
	msg.msg_head.can_id  = 0x42;
	msg.msg_head.flags   = 0;
	msg.msg_head.nframes = 0;
	msg.msg_head.count = 0;
	msg.msg_head.ival1.tv_sec = 0;
	msg.msg_head.ival1.tv_usec = 0;
	msg.msg_head.ival2.tv_sec = 0;
	msg.msg_head.ival2.tv_usec = 0;

	if (write(s, &msg, sizeof(struct bcm_msg_head)) < 0)
		perror("write");

	printf("Press any key to close the socket ...\n");

	getchar();

	close(s);

	printf("done\n");

	return 0;
}
