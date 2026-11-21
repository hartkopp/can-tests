// SPDX-License-Identifier: (GPL-2.0-only OR BSD-3-Clause)
/*
 * tst-isotp-rx.c - CAN_ISOTP reception path
 *
 * A CAN_RAW peer sends (malformed) SF/FF/CF frames to the DUT socket and
 * checks the DUT flow control frames, the received PDUs and the reported
 * socket errors.
 *
 * Send feedback to <linux-can@vger.kernel.org>
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>

#include "ft.h"

struct seg_param {
	const char *mode;
	int var;
};

/* ------------------------------------------------------------------------
 * test environment
 * ------------------------------------------------------------------------
 */

struct rxenv {
	struct ft_isotp_cfg c;
	int s;
	struct ft_peer p;
	struct ft_enc de, pe;	/* DUT tx encoder, peer encoder */
	struct ft_frame htx, hrx;
};

static struct rxenv env;

static bool rxenv_open(struct ft_ctx *ctx, const struct ft_isotp_cfg *c)
{
	memset(&env, 0, sizeof(env));
	env.s = -1;
	env.p.s = -1;
	env.c = *c;

	ft_enc_dut(c, &env.de);
	ft_enc_peer(c, &env.pe);
	ft_hdr_dut_tx(c, &env.htx);
	ft_hdr_dut_rx(c, &env.hrx);

	env.s = ft_isotp_open(ctx, c);
	if (env.s < 0)
		return false;

	if (ft_peer_open(ctx, &env.p, c->iface)) {
		close(env.s);
		env.s = -1;
		return false;
	}

	return true;
}

static void rxenv_close(void)
{
	ft_peer_close(&env.p);
	if (env.s >= 0)
		close(env.s);
	env.s = -1;
}

static bool rxenv_mode(struct ft_ctx *ctx, const char *mode, uint32_t flags)
{
	struct ft_isotp_cfg c;

	ft_cfg_init(&c);
	if (mode)
		ft_cfg_mode(&c, ft_mode_by_name(mode));
	c.opts.flags |= flags;

	return rxenv_open(ctx, &c);
}

/* send a frame with CAN_DL len; nb data bytes given (others zero) */
static bool rx_tx(struct ft_ctx *ctx, unsigned int len, int nb, ...)
{
	struct ft_frame f;
	va_list ap;
	int i;

	ft_frame_set(&f, &env.hrx, NULL, len);
	va_start(ap, nb);
	for (i = 0; i < nb; i++)
		f.data[i] = (uint8_t)va_arg(ap, int);
	va_end(ap);

	return ft_peer_tx(ctx, &env.p, &f);
}

/* send a frame with CAN_DL len filled with fill after the given bytes */
static bool rx_txf(struct ft_ctx *ctx, unsigned int len, uint8_t fill, int nb,
		   ...)
{
	struct ft_frame f;
	va_list ap;
	int i;

	ft_frame_set(&f, &env.hrx, NULL, len);
	memset(f.data, fill, len);
	va_start(ap, nb);
	for (i = 0; i < nb; i++)
		f.data[i] = (uint8_t)va_arg(ap, int);
	va_end(ap);

	return ft_peer_tx(ctx, &env.p, &f);
}

/* expect a FC frame of the DUT */
static bool rx_expect_fc(struct ft_ctx *ctx, uint8_t fs)
{
	struct ft_frame fc;

	ft_enc_fc(&env.de, &env.htx, fs, env.c.fc.bs, env.c.fc.stmin, &fc);

	return ft_peer_expect(ctx, &env.p, &fc, 500);
}

/* send the frames of a PDU from index from to to (exclusive) */
static void rx_send_frames(struct ft_ctx *ctx, struct ft_frame *f, int from,
			   int to)
{
	int i;

	for (i = from; i < to; i++)
		ft_peer_tx(ctx, &env.p, &f[i]);
}

/* ------------------------------------------------------------------------
 * reassembly
 * ------------------------------------------------------------------------
 */

static void rx_seg(struct ft_ctx *ctx, const void *param)
{
	const struct seg_param *sp = param;
	static const uint8_t bs[FT_V_MAX] = { 0, 3, 1, 15 };
	static uint8_t data[FT_MAX_PDU];
	struct ft_isotp_cfg c;
	unsigned int lens[32];
	int i, n;

	ft_cfg_init(&c);
	ft_cfg_mode(&c, ft_mode_by_name(sp->mode));
	ft_cfg_variant(&c, sp->var);
	c.fc.bs = bs[sp->var];
	if (!rxenv_open(ctx, &c))
		return;

	n = ft_seg_lengths(&env.pe, FT_MAX_PDU, lens, 32);
	for (i = 0; i < n; i++) {
		ft_pattern(data, lens[i], 0x80 + i);
		if (!ft_rx_pdu(ctx, env.s, &c, &env.p, &env.pe, data, lens[i]))
			break;
	}

	rxenv_close();
}

struct lldl_param {
	const char *mode;
	unsigned int dl[12];
};

static void rx_lldl(struct ft_ctx *ctx, const void *param)
{
	const struct lldl_param *lp = param;
	static uint8_t data[FT_MAX_PDU];
	unsigned int lens[] = { 1, 7, 8, 63, 64, 100, 2046, 2047, 3000, 4096 };
	struct ft_enc e;
	int i;
	unsigned int k;

	if (!rxenv_mode(ctx, lp->mode, 0))
		return;

	/* the receiver accepts all LL_DL values of the sender */
	for (i = 0; lp->dl[i]; i++) {
		e = env.pe;
		e.ll_dl = lp->dl[i];
		ft_log(ctx, "sender LL_DL %u", e.ll_dl);
		for (k = 0; k < sizeof(lens) / sizeof(lens[0]); k++) {
			ft_pattern(data, lens[k], k + i);
			if (!ft_rx_pdu(ctx, env.s, &env.c, &env.p, &e, data,
				       lens[k]))
				goto out;
		}
	}
out:
	rxenv_close();
}

/* ------------------------------------------------------------------------
 * single frames
 * ------------------------------------------------------------------------
 */

static void rx_sf_cc_valid(struct ft_ctx *ctx, const void *param)
{
	uint8_t pdu[8] = { 1, 2, 3, 4, 5, 6, 7 };
	unsigned int sfdl, len;

	if (!rxenv_mode(ctx, NULL, 0))
		return;

	for (sfdl = 1; sfdl <= 7; sfdl++) {
		for (len = sfdl + 1; len <= 8; len++) {
			ft_log(ctx, "SF_DL %u CAN_DL %u", sfdl, len);
			rx_txf(ctx, len, 0xEE, 8, sfdl, 1, 2, 3, 4, 5, 6, 7);
			ft_dut_expect_pdu(ctx, env.s, pdu, sfdl, 200);
			FT_BAIL(ctx);
		}
	}
	ft_peer_expect_none(ctx, &env.p, 20);
	ft_dut_expect_noerr(ctx, env.s);
	rxenv_close();
}

static void rx_sf_cc_invalid(struct ft_ctx *ctx, const void *param)
{
	unsigned int len, sfdl;

	if (!rxenv_mode(ctx, NULL, 0))
		return;

	/* SF_DL 0 */
	for (len = 1; len <= 8; len++)
		rx_txf(ctx, len, 0x11, 1, 0x00);

	/* SF_DL > CAN_DL - 1 */
	for (sfdl = 1; sfdl <= 15; sfdl++)
		for (len = 1; len <= 8; len++)
			if (sfdl > len - 1)
				rx_txf(ctx, len, 0x11, 1, sfdl);

	ft_dut_expect_nopdu(ctx, env.s, 50);
	ft_peer_expect_none(ctx, &env.p, 10);
	ft_dut_expect_noerr(ctx, env.s);
	rxenv_close();
}

static void rx_sf_dl0(struct ft_ctx *ctx, const void *param)
{
	uint8_t pdu[3] = { 0x31, 0x32, 0x33 };
	uint8_t buf[32];
	ssize_t n;
	int which = param ? *(const int *)param : 0;

	if (which == 2) {
		struct ft_isotp_cfg c;

		ft_cfg_init(&c);
		ft_cfg_variant(&c, FT_V_AE);
		if (!rxenv_open(ctx, &c))
			return;
	} else if (!rxenv_mode(ctx, NULL, 0)) {
		return;
	}

	switch (which) {
	case 0:
		/* CAN_DL 0 with a stale SF N_PCI in data[0] */
		rx_tx(ctx, 0, 4, 0x03, 0x31, 0x32, 0x33);
		n = ft_dut_recv(ctx, env.s, buf, sizeof(buf), 100);
		if (n == -ETIME) {
			ft_log(ctx, "frame without N_PCI ignored (ISO behaviour)");
		} else {
			FT_CHECK(ctx, n == 3 && !memcmp(buf, pdu, 3),
				 "unexpected result %zd", n);
			ft_note_dev(ctx, "CAN_DL 0 frame processed as SF with SF_DL 3 from data beyond CAN_DL");
		}
		break;
	case 1:
		/* CAN_DL 0 with SF_DL 15 => 15 bytes from a CAN CC frame */
		rx_tx(ctx, 0, 8, 0x0F, 1, 2, 3, 4, 5, 6, 7);
		n = ft_dut_recv(ctx, env.s, buf, sizeof(buf), 100);
		if (n == -ETIME) {
			ft_log(ctx, "frame without N_PCI ignored (ISO behaviour)");
		} else {
			FT_CHECK(ctx, n == 15, "unexpected result %zd", n);
			ft_note_dev(ctx, "CAN_DL 0 frame processed as SF with SF_DL 15: %zd bytes delivered, 8 of them from beyond the CAN CC frame data", n);
		}
		break;
	case 2:
		/* extended addressing: CAN_DL 1 (only the address byte) */
		rx_tx(ctx, 1, 4, 0xA5, 0x03, 0x31, 0x32, 0x33);
		n = ft_dut_recv(ctx, env.s, buf, sizeof(buf), 100);
		if (n == -ETIME) {
			ft_log(ctx, "frame without N_PCI ignored (ISO behaviour)");
		} else {
			FT_CHECK(ctx, n == 3, "unexpected result %zd", n);
			ft_note_dev(ctx, "CAN_DL 1 frame (only AE) processed as SF with SF_DL 3 from data beyond CAN_DL");
		}
		break;
	}

	rxenv_close();
}

static void rx_sf_ae(struct ft_ctx *ctx, const void *param)
{
	uint8_t pdu[3] = { 0x31, 0x32, 0x33 };
	struct ft_isotp_cfg c;

	ft_cfg_init(&c);
	ft_cfg_variant(&c, param ? FT_V_AEPAD : FT_V_AE);
	c.opts.flags &= ~(CAN_ISOTP_TX_PADDING | CAN_ISOTP_RX_PADDING |
			  CAN_ISOTP_CHK_PAD_LEN | CAN_ISOTP_CHK_PAD_DATA);
	if (!rxenv_open(ctx, &c))
		return;

	if (param) {
		/* RX_EXT_ADDR: rx 0x5A, tx 0xA5 */
		rx_tx(ctx, 5, 5, 0xA5, 0x03, 0x31, 0x32, 0x33);
		ft_dut_expect_nopdu(ctx, env.s, 50);
		rx_tx(ctx, 5, 5, 0x5A, 0x03, 0x31, 0x32, 0x33);
		ft_dut_expect_pdu(ctx, env.s, pdu, 3, 200);
	} else {
		rx_tx(ctx, 5, 5, 0xA6, 0x03, 0x31, 0x32, 0x33);
		rx_tx(ctx, 4, 4, 0x03, 0x31, 0x32, 0x33);
		ft_dut_expect_nopdu(ctx, env.s, 50);
		rx_tx(ctx, 5, 5, 0xA5, 0x03, 0x31, 0x32, 0x33);
		ft_dut_expect_pdu(ctx, env.s, pdu, 3, 200);
		/* SF_DL max is 6 with extended addressing */
		rx_tx(ctx, 8, 8, 0xA5, 0x07, 1, 2, 3, 4, 5, 6);
		ft_dut_expect_nopdu(ctx, env.s, 50);
	}

	ft_dut_expect_noerr(ctx, env.s);
	rxenv_close();
}

static void rx_sf_fd(struct ft_ctx *ctx, const void *param)
{
	static const unsigned int dls[] = { 12, 16, 20, 24, 32, 48, 64 };
	uint8_t pdu[64];
	struct ft_frame f;
	unsigned int i, len, sfdl;

	if (!rxenv_mode(ctx, "FD64", 0))
		return;

	ft_pattern(pdu, sizeof(pdu), 0x20);

	/* CAN_DL <= 8: 4 bit SF_DL */
	for (len = 2; len <= 8; len++) {
		ft_frame_set(&f, &env.hrx, NULL, len);
		f.data[0] = len - 1;
		memcpy(&f.data[1], pdu, len - 1);
		ft_peer_tx(ctx, &env.p, &f);
		ft_dut_expect_pdu(ctx, env.s, pdu, len - 1, 200);
	}

	/* CAN_DL > 8: SF_DL escape with all SF_DL values 1 .. CAN_DL-2 */
	for (i = 0; i < sizeof(dls) / sizeof(dls[0]); i++) {
		for (sfdl = 1; sfdl <= dls[i] - 2; sfdl++) {
			ft_frame_set(&f, &env.hrx, NULL, dls[i]);
			memset(f.data, 0xCC, dls[i]);
			f.data[0] = 0x00;
			f.data[1] = sfdl;
			memcpy(&f.data[2], pdu, sfdl);
			ft_peer_tx(ctx, &env.p, &f);
			ft_dut_expect_pdu(ctx, env.s, pdu, sfdl, 200);
			FT_BAIL(ctx);
		}
	}

	ft_dut_expect_noerr(ctx, env.s);
	rxenv_close();
}

static void rx_sf_fd_invalid(struct ft_ctx *ctx, const void *param)
{
	struct ft_frame f;
	unsigned int len;

	if (!rxenv_mode(ctx, "FD64", 0))
		return;

	for (len = 12; len <= 64; len += 4) {
		/* 4 bit SF_DL in CAN_DL > 8 */
		ft_frame_set(&f, &env.hrx, NULL, len);
		f.data[0] = 0x05;
		ft_peer_tx(ctx, &env.p, &f);
		/* escape with SF_DL 0 */
		f.data[0] = 0x00;
		f.data[1] = 0x00;
		ft_peer_tx(ctx, &env.p, &f);
		/* escape with SF_DL > CAN_DL - 2 */
		f.data[1] = len - 1;
		ft_peer_tx(ctx, &env.p, &f);
		/* escape with high bits in N_PCI (XL SF style) */
		f.data[0] = 0x08;
		f.data[1] = 0x05;
		ft_peer_tx(ctx, &env.p, &f);
	}

	/* escape in CAN_DL <= 8 => SF_DL 0 */
	ft_frame_set(&f, &env.hrx, NULL, 8);
	f.data[0] = 0x00;
	f.data[1] = 0x05;
	ft_peer_tx(ctx, &env.p, &f);

	ft_dut_expect_nopdu(ctx, env.s, 50);
	ft_peer_expect_none(ctx, &env.p, 10);
	ft_dut_expect_noerr(ctx, env.s);
	rxenv_close();
}

static void rx_sf_fd_nodlc(struct ft_ctx *ctx, const void *param)
{
	uint8_t pdu[64];
	struct ft_frame f;
	unsigned int len;

	if (!rxenv_mode(ctx, "FD64", 0))
		return;

	ft_pattern(pdu, sizeof(pdu), 0x20);

	/* CAN FD frames with lengths that are no DLC values (vcan only) */
	for (len = 9; len <= 63; len++) {
		if (ft_padlen(len) == len)
			continue;
		ft_frame_set(&f, &env.hrx, NULL, len);
		f.data[0] = 0x00;
		f.data[1] = len - 2;
		memcpy(&f.data[2], pdu, len - 2);
		ft_peer_tx(ctx, &env.p, &f);
		ft_dut_expect_pdu(ctx, env.s, pdu, len - 2, 200);
		FT_BAIL(ctx);
	}

	rxenv_close();
}

struct pad_case {
	const char *mode;
	uint32_t flags;
	uint8_t rxpad;
	unsigned int len;	/* CAN_DL */
	uint8_t pci[2];		/* SF PCI */
	int pcilen;
	unsigned int sfdl;
	uint8_t fill;		/* padding content */
	bool ok;		/* else EBADMSG */
};

#define RXP CAN_ISOTP_RX_PADDING
#define CPL CAN_ISOTP_CHK_PAD_LEN
#define CPD CAN_ISOTP_CHK_PAD_DATA

static const struct pad_case sf_pad_cases[] = {
	/* CHK_PAD_LEN without RX_PADDING: optimized length */
	{ "CC8", CPL, 0xCC, 4, { 0x03 }, 1, 3, 0xCC, true },
	{ "CC8", CPL, 0xCC, 5, { 0x03 }, 1, 3, 0xCC, false },
	{ "CC8", CPL, 0xCC, 8, { 0x03 }, 1, 3, 0xCC, false },
	{ "CC8", CPL, 0xCC, 8, { 0x07 }, 1, 7, 0xCC, true },
	/* RX_PADDING + CHK_PAD_LEN: CAN_DL 8 */
	{ "CC8", RXP | CPL, 0xCC, 8, { 0x03 }, 1, 3, 0x00, true },
	{ "CC8", RXP | CPL, 0xCC, 4, { 0x03 }, 1, 3, 0xCC, false },
	{ "CC8", RXP | CPL, 0xCC, 7, { 0x03 }, 1, 3, 0xCC, false },
	/* RX_PADDING + CHK_PAD_DATA: content */
	{ "CC8", RXP | CPD, 0xAA, 8, { 0x03 }, 1, 3, 0xAA, true },
	{ "CC8", RXP | CPD, 0xAA, 6, { 0x03 }, 1, 3, 0xAA, true },
	{ "CC8", RXP | CPD, 0xAA, 4, { 0x03 }, 1, 3, 0xAA, true },
	{ "CC8", RXP | CPD, 0xAA, 8, { 0x03 }, 1, 3, 0xCC, false },
	/* RX_PADDING + both checks */
	{ "CC8", RXP | CPL | CPD, 0x55, 8, { 0x03 }, 1, 3, 0x55, true },
	{ "CC8", RXP | CPL | CPD, 0x55, 8, { 0x03 }, 1, 3, 0x56, false },
	/* CHK_PAD_DATA without RX_PADDING: all SFs fail */
	{ "CC8", CPD, 0xCC, 4, { 0x03 }, 1, 3, 0xCC, false },
	{ "CC8", CPD, 0xCC, 8, { 0x03 }, 1, 3, 0xCC, false },
	/* RX_PADDING only: no checks */
	{ "CC8", RXP, 0x55, 4, { 0x03 }, 1, 3, 0xCC, true },
	{ "CC8", RXP, 0x55, 8, { 0x03 }, 1, 3, 0xCC, true },
	/* CAN FD: CHK_PAD_LEN without RX_PADDING => next valid DLC length */
	{ "FD64", CPL, 0xCC, 12, { 0x00, 10 }, 2, 10, 0xCC, true },
	{ "FD64", CPL, 0xCC, 12, { 0x00, 9 }, 2, 9, 0xCC, true },
	{ "FD64", CPL, 0xCC, 16, { 0x00, 10 }, 2, 10, 0xCC, false },
	{ "FD64", CPL, 0xCC, 64, { 0x00, 62 }, 2, 62, 0xCC, true },
	{ "FD64", CPL, 0xCC, 64, { 0x00, 40 }, 2, 40, 0xCC, false },
	{ "FD64", CPL, 0xCC, 8, { 0x03 }, 1, 3, 0xCC, false },
	{ "FD64", CPL, 0xCC, 4, { 0x03 }, 1, 3, 0xCC, true },
	/* CAN FD: RX_PADDING + CHK_PAD_LEN => valid DLC length >= 8 */
	{ "FD64", RXP | CPL, 0xCC, 12, { 0x00, 7 }, 2, 7, 0xCC, true },
	{ "FD64", RXP | CPL, 0xCC, 64, { 0x00, 7 }, 2, 7, 0xCC, true },
	{ "FD64", RXP | CPL, 0xCC, 9, { 0x00, 7 }, 2, 7, 0xCC, false },
	{ "FD64", RXP | CPL, 0xCC, 4, { 0x03 }, 1, 3, 0xCC, false },
	/* CAN FD: RX_PADDING + CHK_PAD_DATA */
	{ "FD64", RXP | CPD, 0xAA, 64, { 0x00, 7 }, 2, 7, 0xAA, true },
	{ "FD64", RXP | CPD, 0xAA, 64, { 0x00, 7 }, 2, 7, 0xAB, false },
};

static void rx_pad_cases(struct ft_ctx *ctx, const struct pad_case *cases,
			 int n)
{
	int i;

	for (i = 0; i < n; i++) {
		const struct pad_case *pc = &cases[i];
		uint8_t pdu[64];
		struct ft_frame f;

		ft_log(ctx, "case %d: %s flags %03X rxpad %02X CAN_DL %u SF_DL %u fill %02X => %s",
		       i, pc->mode, pc->flags, pc->rxpad, pc->len, pc->sfdl,
		       pc->fill, pc->ok ? "PDU" : "EBADMSG");

		{
			struct ft_isotp_cfg c;

			ft_cfg_init(&c);
			ft_cfg_mode(&c, ft_mode_by_name(pc->mode));
			c.opts.flags |= pc->flags;
			c.opts.rxpad_content = pc->rxpad;
			if (!rxenv_open(ctx, &c))
				return;
		}

		ft_pattern(pdu, sizeof(pdu), i);
		ft_frame_set(&f, &env.hrx, NULL, pc->len);
		memset(f.data, pc->fill, pc->len);
		memcpy(f.data, pc->pci, pc->pcilen);
		memcpy(f.data + pc->pcilen, pdu, pc->sfdl);
		ft_peer_tx(ctx, &env.p, &f);

		if (pc->ok) {
			ft_dut_expect_pdu(ctx, env.s, pdu, pc->sfdl, 200);
			ft_dut_expect_noerr(ctx, env.s);
		} else {
			ft_dut_expect_err(ctx, env.s, EBADMSG, 200, NULL);
			ft_dut_expect_nopdu(ctx, env.s, 10);
		}

		rxenv_close();
		FT_BAIL(ctx);
	}
}

static void rx_sf_pad(struct ft_ctx *ctx, const void *param)
{
	rx_pad_cases(ctx, sf_pad_cases,
		     sizeof(sf_pad_cases) / sizeof(sf_pad_cases[0]));
}

/* start a reception of len bytes: FF + FC, returns the encoded frames */
static int rx_start(struct ft_ctx *ctx, unsigned int len, uint8_t *pdu,
		    struct ft_frame **frames)
{
	int n;

	ft_pattern(pdu, len, len);
	n = ft_enc_pdu(&env.pe, &env.hrx, pdu, len, frames);
	if (n < 2) {
		ft_fail(ctx, "rx_start: no FF");
		return n;
	}

	ft_peer_tx(ctx, &env.p, &(*frames)[0]);
	if (!(env.c.opts.flags & CAN_ISOTP_LISTEN_MODE))
		rx_expect_fc(ctx, FT_FS_CTS);

	return n;
}

static void rx_sf_during_rx(struct ft_ctx *ctx, const void *param)
{
	uint8_t pdu[40], sfpdu[3] = { 0x61, 0x62, 0x63 };
	struct ft_frame *fr = NULL;
	bool invalid = param && !strcmp(param, "invalid");
	bool slow = param && !strcmp(param, "slow");
	int n;

	if (!rxenv_mode(ctx, NULL, 0))
		return;

	n = rx_start(ctx, sizeof(pdu), pdu, &fr);
	if (n < 2)
		goto out;
	ft_peer_tx(ctx, &env.p, &fr[1]);

	if (invalid) {
		/* invalid SF (SF_DL 0) */
		rx_tx(ctx, 4, 4, 0x00, 0x61, 0x62, 0x63);
		ft_dut_expect_nopdu(ctx, env.s, 20);
	} else {
		/* valid SF is received */
		rx_tx(ctx, 4, 4, 0x03, 0x61, 0x62, 0x63);
		ft_dut_expect_pdu(ctx, env.s, sfpdu, 3, 200);
	}

	/* the reception is terminated: the remaining CFs are ignored */
	rx_send_frames(ctx, fr, 2, n);
	ft_dut_expect_nopdu(ctx, env.s, 50);
	ft_peer_expect_none(ctx, &env.p, 10);
	ft_dut_expect_noerr(ctx, env.s);

	if (slow) {
		/* no N_Cr timeout for the terminated reception */
		ft_sleep_ms(FT_FC_TIMEOUT_MS + 200);
		ft_dut_expect_noerr(ctx, env.s);
	}
out:
	free(fr);
	rxenv_close();
}

/* ------------------------------------------------------------------------
 * first frames
 * ------------------------------------------------------------------------
 */

static void rx_ff_short(struct ft_ctx *ctx, const void *param)
{
	unsigned int len;

	if (!rxenv_mode(ctx, NULL, 0))
		return;

	/* FF with CAN_DL < 8 */
	for (len = 0; len < 8; len++)
		rx_txf(ctx, len, 0x11, 2, 0x10, 0x14);

	ft_peer_expect_none(ctx, &env.p, 50);
	ft_dut_expect_noerr(ctx, env.s);
	rxenv_close();
}

static void rx_ff_fd_len(struct ft_ctx *ctx, const void *param)
{
	static uint8_t pdu[200];
	struct ft_frame *fr;
	struct ft_enc e;
	unsigned int len;
	int n;

	if (!rxenv_mode(ctx, "FD64", 0))
		return;

	/* FF with CAN FD lengths that are no DLC values are ignored */
	for (len = 9; len < 64; len++) {
		if (ft_padlen(len) == len)
			continue;
		rx_txf(ctx, len, 0x11, 2, 0x10, 200);
	}
	ft_peer_expect_none(ctx, &env.p, 50);

	/* the FF length defines the sender LL_DL for the CFs */
	e = env.pe;
	e.ll_dl = 12;
	ft_pattern(pdu, sizeof(pdu), 5);
	n = ft_enc_pdu(&e, &env.hrx, pdu, sizeof(pdu), &fr);
	ft_peer_tx(ctx, &env.p, &fr[0]);
	rx_expect_fc(ctx, FT_FS_CTS);
	/* a CF with the DUT TX_DL (64) is longer than the FF => ignored */
	{
		struct ft_frame big = fr[1];

		big.len = 64;
		ft_peer_tx(ctx, &env.p, &big);
	}
	rx_send_frames(ctx, fr, 1, n);
	ft_dut_expect_pdu(ctx, env.s, pdu, sizeof(pdu), 500);
	ft_dut_expect_noerr(ctx, env.s);
	free(fr);
	rxenv_close();
}

static void rx_ff_escape(struct ft_ctx *ctx, const void *param)
{
	if (!rxenv_mode(ctx, NULL, 0))
		return;

	/* 32 bit FF_DL with a value <= 4095 */
	rx_tx(ctx, 8, 8, 0x10, 0x00, 0x00, 0x00, 0x0F, 0xFF, 1, 2);
	rx_tx(ctx, 8, 8, 0x10, 0x00, 0x00, 0x00, 0x00, 0x08, 1, 2);
	rx_tx(ctx, 8, 8, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 1, 2);
	ft_peer_expect_none(ctx, &env.p, 50);

	/* 32 bit FF_DL 4096 */
	rx_tx(ctx, 8, 8, 0x10, 0x00, 0x00, 0x00, 0x10, 0x00, 1, 2);
	rx_expect_fc(ctx, FT_FS_CTS);
	ft_dut_expect_noerr(ctx, env.s);
	rxenv_close();
}

struct ffmin_param {
	const char *mode;
	int var;
	unsigned int iso_min;	/* smallest FF_DL according to ISO */
};

static void rx_ff_min(struct ft_ctx *ctx, const void *param)
{
	const struct ffmin_param *fp = param;
	static uint8_t pdu[4096];
	struct ft_isotp_cfg c;
	struct ft_frame *fr;
	struct ft_frame ff, f;
	unsigned int ffdl;
	int n;

	ft_cfg_init(&c);
	ft_cfg_mode(&c, ft_mode_by_name(fp->mode));
	ft_cfg_variant(&c, fp->var);
	if (!rxenv_open(ctx, &c))
		return;

	ft_pattern(pdu, sizeof(pdu), 9);

	/* encode a PDU with iso_min + 1 bytes and patch the FF_DL */
	for (ffdl = fp->iso_min - 2; ffdl <= fp->iso_min + 1; ffdl++) {
		n = ft_enc_pdu(&env.pe, &env.hrx, pdu, fp->iso_min + 1, &fr);
		ff = fr[0];
		ff.data[env.pe.ae ? 1 : 0] = 0x10 | (ffdl >> 8);
		ff.data[env.pe.ae ? 2 : 1] = ffdl & 0xFF;
		ft_log(ctx, "FF_DL %u", ffdl);
		ft_peer_tx(ctx, &env.p, &ff);

		if (ft_peer_next(ctx, &env.p, &f, 50)) {
			/* FC received => complete the PDU */
			rx_send_frames(ctx, fr, 1, n);
			ft_dut_expect_pdu(ctx, env.s, pdu, ffdl, 500);
			if (ffdl < fp->iso_min)
				ft_note_dev(ctx, "FF_DL %u accepted (ISO 15765-2 FF_DLmin is %u)",
					    ffdl, fp->iso_min);
		} else {
			FT_CHECK(ctx, ffdl < fp->iso_min,
				 "FF_DL %u (>= FF_DLmin %u) ignored", ffdl,
				 fp->iso_min);
		}
		free(fr);
		FT_BAIL(ctx);
	}

	ft_dut_expect_noerr(ctx, env.s);
	rxenv_close();
}

static void rx_ff_ovflw(struct ft_ctx *ctx, const void *param)
{
	bool listen = param != NULL;
	unsigned int max = ft_max_pdu();
	struct ft_frame fc;

	if (!rxenv_mode(ctx, NULL, listen ? CAN_ISOTP_LISTEN_MODE : 0))
		return;

	/* FF_DL > max_pdu_size => FC.OVFLW */
	rx_tx(ctx, 8, 8, 0x10, 0x00, (max + 1) >> 24, (max + 1) >> 16,
	      (max + 1) >> 8, (max + 1), 1, 2);
	ft_enc_fc(&env.de, &env.htx, FT_FS_OVFLW, env.c.fc.bs, env.c.fc.stmin,
		  &fc);
	if (listen) {
		struct ft_frame f;

		if (ft_peer_next(ctx, &env.p, &f, 100)) {
			FT_CHECK(ctx, ft_frame_eq(&f, &fc), "unexpected frame");
			ft_note_dev(ctx, "FC.OVFLW sent in CAN_ISOTP_LISTEN_MODE");
		} else {
			ft_log(ctx, "no FC.OVFLW in listen mode");
		}
	} else {
		ft_peer_expect(ctx, &env.p, &fc, 200);
	}

	/* CF is ignored, no error */
	rx_tx(ctx, 8, 8, 0x21, 1, 2, 3, 4, 5, 6, 7);
	ft_dut_expect_nopdu(ctx, env.s, 50);
	ft_dut_expect_noerr(ctx, env.s);

	/* large FF_DL (2^31) */
	rx_tx(ctx, 8, 8, 0x10, 0x00, 0x80, 0x00, 0x00, 0x00, 1, 2);
	if (listen) {
		struct ft_frame f;

		/* same behaviour as for the first FF (see above) */
		if (ft_peer_next(ctx, &env.p, &f, 100))
			FT_CHECK(ctx, ft_frame_eq(&f, &fc), "unexpected frame");
	} else {
		ft_peer_expect(ctx, &env.p, &fc, 200);
	}

	/* FF_DL == max_pdu_size => FC.CTS (not in listen mode) */
	rx_tx(ctx, 8, 8, 0x10, 0x00, max >> 24, max >> 16, max >> 8, max, 1, 2);
	if (listen)
		ft_peer_expect_none(ctx, &env.p, 50);
	else
		rx_expect_fc(ctx, FT_FS_CTS);

	rxenv_close();
}

static void rx_ff_maxdl(struct ft_ctx *ctx, const void *param)
{
	static const uint32_t dls[] = { 0xFFFFFFF0, 0xFFFFFFF8, 0xFFFFFFF9,
					0xFFFFFFFA, 0xFFFFFFFE, 0xFFFFFFFF };
	struct ft_isotp_cfg c;
	struct ft_frame fc, f;
	unsigned int ae = param ? 1 : 0;
	unsigned int i;

	ft_cfg_init(&c);
	if (ae)
		ft_cfg_variant(&c, FT_V_AE);
	if (!rxenv_open(ctx, &c))
		return;

	ft_enc_fc(&env.de, &env.htx, FT_FS_OVFLW, 0, 0, &fc);

	/* Expected: every FF_DL > max_pdu_size => FC.OVFLW */
	for (i = 0; i < sizeof(dls) / sizeof(dls[0]); i++) {
		uint32_t dl = dls[i];

		if (ae)
			rx_tx(ctx, 8, 8, 0xA5, 0x10, 0x00, dl >> 24, dl >> 16,
			      dl >> 8, dl, 1);
		else
			rx_tx(ctx, 8, 8, 0x10, 0x00, dl >> 24, dl >> 16,
			      dl >> 8, dl, 1, 2);

		if (ft_peer_next(ctx, &env.p, &f, 100)) {
			FT_CHECK(ctx, ft_frame_eq(&f, &fc),
				 "FF_DL %08X: unexpected frame", dl);
		} else {
			ft_note_dev(ctx, "FF_DL %08X ignored without FC.OVFLW (FF_DL + PCI + AE wraps around in the 'single FF' check)",
				    dl);
		}
	}

	ft_dut_expect_noerr(ctx, env.s);
	rxenv_close();
}

static void rx_ff_restart(struct ft_ctx *ctx, const void *param)
{
	uint8_t pdu1[40], pdu2[60];
	struct ft_frame *f1 = NULL, *f2 = NULL;
	int n1, n2;

	if (!rxenv_mode(ctx, NULL, 0))
		return;

	n1 = rx_start(ctx, sizeof(pdu1), pdu1, &f1);
	if (n1 < 2)
		goto out;
	ft_peer_tx(ctx, &env.p, &f1[1]);

	/* a new FF restarts the reception */
	n2 = rx_start(ctx, sizeof(pdu2), pdu2, &f2);
	if (n2 < 2)
		goto out;
	rx_send_frames(ctx, f2, 1, n2);
	ft_dut_expect_pdu(ctx, env.s, pdu2, sizeof(pdu2), 500);
	ft_dut_expect_noerr(ctx, env.s);

	/* the remaining CFs of the 1st PDU are ignored */
	rx_send_frames(ctx, f1, 2, n1);
	ft_dut_expect_nopdu(ctx, env.s, 50);
	ft_dut_expect_noerr(ctx, env.s);
out:
	free(f1);
	free(f2);
	rxenv_close();
}

static void rx_ff_invalid_during_rx(struct ft_ctx *ctx, const void *param)
{
	uint8_t pdu[40];
	struct ft_frame *fr = NULL;
	int n;

	if (!rxenv_mode(ctx, NULL, 0))
		return;

	n = rx_start(ctx, sizeof(pdu), pdu, &fr);
	if (n < 2)
		goto out;
	ft_peer_tx(ctx, &env.p, &fr[1]);

	/* invalid FF (CAN_DL 7) */
	rx_tx(ctx, 7, 7, 0x10, 0x14, 1, 2, 3, 4, 5);
	ft_peer_expect_none(ctx, &env.p, 20);

	/* the reception is terminated */
	rx_send_frames(ctx, fr, 2, n);
	ft_dut_expect_nopdu(ctx, env.s, 50);
	ft_dut_expect_noerr(ctx, env.s);
out:
	free(fr);
	rxenv_close();
}

static void rx_ff_fc_content(struct ft_ctx *ctx, const void *param)
{
	static const struct can_isotp_fc_options fcs[] = {
		{ 0, 0, 0 }, { 5, 0x80, 3 }, { 0xFF, 0xFF, 0xFF },
		{ 1, 0xF1, 0 }, { 0, 0x7F, 0 },
	};
	struct ft_isotp_cfg c;
	unsigned int i;

	for (i = 0; i < sizeof(fcs) / sizeof(fcs[0]); i++) {
		ft_cfg_init(&c);
		c.fc = fcs[i];
		if (!rxenv_open(ctx, &c))
			return;

		/* the FC frame contains BS and STmin unchecked */
		rx_tx(ctx, 8, 8, 0x10, 0x40, 1, 2, 3, 4, 5, 6);
		rx_expect_fc(ctx, FT_FS_CTS);
		ft_peer_expect_none(ctx, &env.p, 20);
		rxenv_close();
		FT_BAIL(ctx);
	}
}

static void rx_ff_listen(struct ft_ctx *ctx, const void *param)
{
	static uint8_t data[FT_MAX_PDU];
	struct ft_isotp_cfg c;
	unsigned int lens[] = { 3, 7, 8, 100, 4095, 4096, FT_MAX_PDU };
	unsigned int i;

	/* listen mode: no FC frames are sent */
	ft_cfg_init(&c);
	ft_cfg_mode(&c, ft_mode_by_name(param));
	c.opts.flags |= CAN_ISOTP_LISTEN_MODE;
	c.fc.bs = 2;
	if (!rxenv_open(ctx, &c))
		return;

	for (i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
		ft_pattern(data, lens[i], i);
		if (!ft_rx_pdu(ctx, env.s, &c, &env.p, &env.pe, data, lens[i]))
			break;
	}

	rxenv_close();
}

/* ------------------------------------------------------------------------
 * consecutive frames
 * ------------------------------------------------------------------------
 */

static void rx_cf_sn(struct ft_ctx *ctx, const void *param)
{
	static const uint8_t wrong[] = { 0x23, 0x20, 0x2F, 0x21 };
	uint8_t pdu[40];
	struct ft_frame *fr = NULL;
	unsigned int i;
	int n;

	if (!rxenv_mode(ctx, NULL, 0))
		return;

	for (i = 0; i < sizeof(wrong); i++) {
		n = rx_start(ctx, sizeof(pdu), pdu, &fr);
		if (n < 3)
			break;
		/* CF1 ok, wrong SN in CF2 (0x21 = repeated CF1) */
		ft_peer_tx(ctx, &env.p, &fr[1]);
		fr[2].data[0] = wrong[i];
		ft_log(ctx, "CF2 with N_PCI %02X", fr[2].data[0]);
		ft_peer_tx(ctx, &env.p, &fr[2]);
		ft_dut_expect_err(ctx, env.s, EILSEQ, 200, NULL);

		/* reception aborted: remaining CFs ignored */
		rx_send_frames(ctx, fr, 3, n);
		ft_dut_expect_nopdu(ctx, env.s, 50);
		ft_dut_expect_noerr(ctx, env.s);
		free(fr);
		fr = NULL;
		FT_BAIL(ctx);
	}

	/* wrong SN in the first CF */
	n = rx_start(ctx, sizeof(pdu), pdu, &fr);
	if (n >= 2) {
		fr[1].data[0] = 0x20;
		ft_peer_tx(ctx, &env.p, &fr[1]);
		ft_dut_expect_err(ctx, env.s, EILSEQ, 200, NULL);
	}
	free(fr);
	rxenv_close();
}

static void rx_cf_idle(struct ft_ctx *ctx, const void *param)
{
	int sn;

	if (!rxenv_mode(ctx, NULL, 0))
		return;

	for (sn = 0; sn < 16; sn++)
		rx_tx(ctx, 8, 8, 0x20 | sn, 1, 2, 3, 4, 5, 6, 7);

	ft_dut_expect_nopdu(ctx, env.s, 50);
	ft_peer_expect_none(ctx, &env.p, 10);
	ft_dut_expect_noerr(ctx, env.s);
	rxenv_close();
}

static void rx_cf_len(struct ft_ctx *ctx, const void *param)
{
	static uint8_t pdu[200];
	struct ft_frame *fr = NULL;
	struct ft_frame f;
	bool fd = param != NULL;
	int n;

	if (!rxenv_mode(ctx, fd ? "FD64" : NULL, 0))
		return;

	n = rx_start(ctx, fd ? 200 : 40, pdu, &fr);
	if (n < 4)
		goto out;

	ft_peer_tx(ctx, &env.p, &fr[1]);

	/* CF2 shorter than LL_DL (not the last CF) => ignored */
	f = fr[2];
	f.len = fd ? 48 : 7;
	ft_peer_tx(ctx, &env.p, &f);

	/* the reception continues with the correct CF */
	rx_send_frames(ctx, fr, 2, n);
	ft_dut_expect_pdu(ctx, env.s, pdu, fd ? 200 : 40, 500);
	ft_dut_expect_noerr(ctx, env.s);
out:
	free(fr);
	rxenv_close();
}

static void rx_cf_last_long(struct ft_ctx *ctx, const void *param)
{
	uint8_t pdu[20];
	struct ft_frame *fr = NULL;
	int n;

	if (!rxenv_mode(ctx, NULL, 0))
		return;

	/* 14 byte: FF 6, CF 7, CF 1 => send the last CF with CAN_DL 8 */
	n = rx_start(ctx, 14, pdu, &fr);
	if (n != 3)
		goto out;
	ft_peer_tx(ctx, &env.p, &fr[1]);
	fr[2].len = 8;
	memset(&fr[2].data[2], 0xEE, 6);
	ft_peer_tx(ctx, &env.p, &fr[2]);
	ft_dut_expect_pdu(ctx, env.s, pdu, 14, 500);
	ft_dut_expect_noerr(ctx, env.s);
out:
	free(fr);
	rxenv_close();
}

static void rx_cf_dl0(struct ft_ctx *ctx, const void *param)
{
	uint8_t pdu[20];
	struct ft_frame *fr = NULL;
	ssize_t n;
	uint8_t buf[32];
	int nf;

	if (!rxenv_mode(ctx, NULL, 0))
		return;

	/* 20 byte: FF (6), CF1 (7), CF2 (7) */
	nf = rx_start(ctx, 20, pdu, &fr);
	if (nf != 3)
		goto out;
	ft_peer_tx(ctx, &env.p, &fr[1]);

	/* CAN_DL 0 with a stale CF N_PCI (SN 2) in data[0] */
	rx_tx(ctx, 0, 1, 0x22);
	ft_peer_tx(ctx, &env.p, &fr[2]);

	n = ft_dut_recv(ctx, env.s, buf, sizeof(buf), 200);
	if (n == 20 && !memcmp(buf, pdu, 20)) {
		ft_log(ctx, "CAN_DL 0 frame ignored (ISO behaviour)");
	} else {
		FT_CHECK(ctx, n == -EILSEQ, "unexpected result %zd %s", n,
			 n < 0 ? ft_errname(n) : "");
		ft_note_dev(ctx, "CAN_DL 0 frame processed as CF (SN 2 from data beyond CAN_DL) => following CF2 reported as EILSEQ");
	}
out:
	free(fr);
	rxenv_close();
}

static void rx_cf_short_last(struct ft_ctx *ctx, const void *param)
{
	int dl = *(const int *)param;
	uint8_t pdu[20];
	struct ft_frame *fr = NULL;
	ssize_t n;
	uint8_t buf[32];
	int nf;

	if (!rxenv_mode(ctx, NULL, 0))
		return;

	/* 20 byte: FF (6), CF1 (7), CF2 (7) */
	nf = rx_start(ctx, 20, pdu, &fr);
	if (nf != 3)
		goto out;
	ft_peer_tx(ctx, &env.p, &fr[1]);

	/* short CF2 with SN 2 which lacks bytes of the remaining 7 */
	rx_tx(ctx, dl, 8, 0x22, pdu[13], pdu[14], pdu[15], pdu[16], pdu[17],
	      pdu[18], pdu[19]);
	/* the correct last CF2 */
	ft_peer_tx(ctx, &env.p, &fr[2]);

	n = ft_dut_recv(ctx, env.s, buf, sizeof(buf), 200);
	if (n == 20 && !memcmp(buf, pdu, 20)) {
		ft_log(ctx, "short CF with CAN_DL %d ignored (ISO behaviour)", dl);
	} else {
		FT_CHECK(ctx, n == -EILSEQ, "unexpected result %zd %s", n,
			 n < 0 ? ft_errname(n) : "");
		ft_note_dev(ctx, "short CF with CAN_DL %d accepted although bytes of the PDU were missing => following CF2 reported as EILSEQ",
			    dl);
	}
	ft_dut_expect_noerr(ctx, env.s);
out:
	free(fr);
	rxenv_close();
}

static void rx_cf_bs(struct ft_ctx *ctx, const void *param)
{
	static const uint8_t bss[] = { 1, 2, 3, 7, 15, 16, 255 };
	static uint8_t data[1000];
	struct ft_isotp_cfg c;
	unsigned int i;

	for (i = 0; i < sizeof(bss); i++) {
		ft_cfg_init(&c);
		if (param)
			ft_cfg_mode(&c, ft_mode_by_name(param));
		c.fc.bs = bss[i];
		ft_log(ctx, "BS %u", bss[i]);
		if (!rxenv_open(ctx, &c))
			return;
		ft_pattern(data, sizeof(data), i);
		ft_rx_pdu(ctx, env.s, &c, &env.p, &env.pe, data, sizeof(data));
		rxenv_close();
		FT_BAIL(ctx);
	}
}

static const struct pad_case cf_pad_cases[] = {
	/* last CF with SF like layout: N_PCI 0x2N, 3 data bytes */
	{ "CC8", CPL, 0xCC, 4, { 0x22 }, 1, 3, 0xCC, true },
	{ "CC8", CPL, 0xCC, 8, { 0x22 }, 1, 3, 0xCC, false },
	{ "CC8", RXP | CPL, 0xCC, 8, { 0x22 }, 1, 3, 0x00, true },
	{ "CC8", RXP | CPL, 0xCC, 4, { 0x22 }, 1, 3, 0xCC, false },
	{ "CC8", RXP | CPD, 0xAA, 8, { 0x22 }, 1, 3, 0xAA, true },
	{ "CC8", RXP | CPD, 0xAA, 8, { 0x22 }, 1, 3, 0xAB, false },
	{ "CC8", RXP | CPD, 0xAA, 4, { 0x22 }, 1, 3, 0xAB, true },
	{ "CC8", CPD, 0xCC, 4, { 0x22 }, 1, 3, 0xCC, false },
	{ "FD64", CPL, 0xCC, 4, { 0x22 }, 1, 3, 0xCC, true },
	{ "FD64", CPL, 0xCC, 8, { 0x22 }, 1, 3, 0xCC, false },
	{ "FD64", RXP | CPL, 0xCC, 8, { 0x22 }, 1, 3, 0xCC, true },
	{ "FD64", RXP | CPL, 0xCC, 12, { 0x22 }, 1, 3, 0xCC, true },
	{ "FD64", RXP | CPL, 0xCC, 9, { 0x22 }, 1, 3, 0xCC, false },
	{ "FD64", RXP | CPD, 0xAA, 64, { 0x22 }, 1, 3, 0xAA, true },
	{ "FD64", RXP | CPD, 0xAA, 64, { 0x22 }, 1, 3, 0xCC, false },
};

static void rx_cf_pad(struct ft_ctx *ctx, const void *param)
{
	unsigned int i;

	for (i = 0; i < sizeof(cf_pad_cases) / sizeof(cf_pad_cases[0]); i++) {
		const struct pad_case *pc = &cf_pad_cases[i];
		struct ft_isotp_cfg c;
		static uint8_t pdu[200];
		struct ft_frame *fr = NULL;
		struct ft_frame f;
		unsigned int len;
		int n;

		ft_cfg_init(&c);
		ft_cfg_mode(&c, ft_mode_by_name(pc->mode));
		c.opts.flags |= pc->flags;
		c.opts.rxpad_content = pc->rxpad;
		ft_log(ctx, "case %u: %s flags %03X rxpad %02X last CF CAN_DL %u fill %02X => %s",
		       i, pc->mode, pc->flags, pc->rxpad, pc->len, pc->fill,
		       pc->ok ? "PDU" : "EBADMSG");
		if (!rxenv_open(ctx, &c))
			return;

		/* FF + CF1 + last CF (CF2) with 3 bytes */
		len = (env.pe.ll_dl - 2) + (env.pe.ll_dl - 1) + 3;
		n = rx_start(ctx, len, pdu, &fr);
		if (n == 3) {
			ft_peer_tx(ctx, &env.p, &fr[1]);
			ft_frame_set(&f, &env.hrx, NULL, pc->len);
			memset(f.data, pc->fill, pc->len);
			f.data[0] = 0x22;
			memcpy(&f.data[1], &pdu[len - 3], 3);
			ft_peer_tx(ctx, &env.p, &f);
			if (pc->ok) {
				ft_dut_expect_pdu(ctx, env.s, pdu, len, 200);
				ft_dut_expect_noerr(ctx, env.s);
			} else {
				ft_dut_expect_err(ctx, env.s, EBADMSG, 200, NULL);
				ft_dut_expect_nopdu(ctx, env.s, 10);
			}
		} else {
			ft_fail(ctx, "unexpected number of frames %d", n);
		}
		free(fr);
		rxenv_close();
		FT_BAIL(ctx);
	}
}

static void rx_cf_rxstmin(struct ft_ctx *ctx, const void *param)
{
	const char *mode = param;
	struct ft_isotp_cfg c;
	static uint8_t pdu[400];
	struct ft_frame *fr = NULL;
	int n, gap;

	for (gap = 0; gap < 2; gap++) {
		ft_cfg_init(&c);
		ft_cfg_mode(&c, ft_mode_by_name(mode));
		c.opts.flags |= CAN_ISOTP_FORCE_RXSTMIN;
		c.set_rx_stmin = true;
		c.rx_stmin = 10000000; /* 10 ms */
		if (!rxenv_open(ctx, &c))
			return;

		/* FF + 5 CFs */
		n = rx_start(ctx, (env.pe.ll_dl - 2) + 4 * (env.pe.ll_dl - 1) + 3,
			     pdu, &fr);
		if (n != 6) {
			ft_fail(ctx, "unexpected number of frames %d", n);
			goto out;
		}

		if (gap == 0) {
			/* 20 ms gap => all CFs accepted */
			ft_bcm_send_seq(ctx, c.iface, &fr[1], n - 1, 20000);
			ft_dut_expect_pdu(ctx, env.s, pdu,
					  (env.pe.ll_dl - 2) + 4 * (env.pe.ll_dl - 1) + 3,
					  500);
			ft_dut_expect_noerr(ctx, env.s);
		} else {
			/* 6 ms gap => CF2 dropped (6 ms after CF1),
			 * CF3 accepted (12 ms after CF1) => wrong SN
			 */
			ft_bcm_send_seq(ctx, c.iface, &fr[1], n - 1, 6000);
			ft_dut_expect_err(ctx, env.s, EILSEQ, 500, NULL);
			ft_dut_expect_nopdu(ctx, env.s, 20);
		}
out:
		free(fr);
		fr = NULL;
		rxenv_close();
		FT_BAIL(ctx);
	}
}

static void rx_cf_rxstmin_bs(struct ft_ctx *ctx, const void *param)
{
	struct ft_isotp_cfg c;
	static uint8_t pdu[100];
	struct ft_frame *fr = NULL;
	unsigned int len = 6 + 5 * 7 + 3; /* FF + 6 CFs */
	int n, i;

	ft_cfg_init(&c);
	c.opts.flags |= CAN_ISOTP_FORCE_RXSTMIN;
	c.set_rx_stmin = true;
	c.rx_stmin = 10000000; /* 10 ms */
	c.fc.bs = 2;
	if (!rxenv_open(ctx, &c))
		return;

	n = rx_start(ctx, len, pdu, &fr);
	if (n != 7)
		goto out;

	/* CF pairs with 15 ms gap; the first CF after each FC is sent
	 * immediately after the previous CF (RX STmin reset by the FC)
	 */
	for (i = 1; i < n; i++) {
		ft_peer_tx(ctx, &env.p, &fr[i]);
		if (i % 2 == 1) {
			ft_sleep_ms(15);
		} else if (i < n - 1) {
			rx_expect_fc(ctx, FT_FS_CTS);
		}
	}

	ft_dut_expect_pdu(ctx, env.s, pdu, len, 500);
	ft_dut_expect_noerr(ctx, env.s);
out:
	free(fr);
	rxenv_close();
}

static void rx_cf_timeout(struct ft_ctx *ctx, const void *param)
{
	const char *what = param;
	uint8_t pdu[40];
	struct ft_frame *fr = NULL;
	int n;

	if (!rxenv_mode(ctx, NULL,
			!strcmp(what, "listen") ? CAN_ISOTP_LISTEN_MODE : 0))
		return;

	n = rx_start(ctx, sizeof(pdu), pdu, &fr);
	if (n < 3)
		goto out;

	if (!strcmp(what, "cf"))
		ft_peer_tx(ctx, &env.p, &fr[1]);

	ft_dut_expect_err(ctx, env.s, ETIMEDOUT, FT_FC_TIMEOUT_MS + 500, NULL);

	/* the remaining CFs are ignored */
	rx_send_frames(ctx, fr, 2, n);
	ft_dut_expect_nopdu(ctx, env.s, 50);
	ft_dut_expect_noerr(ctx, env.s);
out:
	free(fr);
	rxenv_close();
}

/* ------------------------------------------------------------------------
 * frame filtering
 * ------------------------------------------------------------------------
 */

static void rx_id_filter(struct ft_ctx *ctx, const void *param)
{
	uint8_t pdu[3] = { 1, 2, 3 };
	struct ft_frame f;

	if (!rxenv_mode(ctx, NULL, 0))
		return;

	ft_frame_bytes(&f, &env.hrx, 4, 0x03, 1, 2, 3);
	f.id = FT_DUT_RX_ID + 1;
	ft_peer_tx(ctx, &env.p, &f);
	f.id = FT_DUT_RX_ID | CAN_EFF_FLAG;
	ft_peer_tx(ctx, &env.p, &f);
	f.id = FT_DUT_RX_ID | CAN_RTR_FLAG;
	ft_peer_tx(ctx, &env.p, &f);
	f.id = FT_DUT_TX_ID;
	ft_peer_tx(ctx, &env.p, &f);
	ft_dut_expect_nopdu(ctx, env.s, 50);

	f.id = FT_DUT_RX_ID;
	ft_peer_tx(ctx, &env.p, &f);
	ft_dut_expect_pdu(ctx, env.s, pdu, 3, 200);

	/* own transmitted PDUs are not received */
	FT_CHECK(ctx, ft_dut_send(ctx, env.s, pdu, 3, 0) == 3, "send");
	ft_dut_expect_nopdu(ctx, env.s, 50);
	rxenv_close();
}

static void rx_id_eff(struct ft_ctx *ctx, const void *param)
{
	uint8_t pdu[3] = { 1, 2, 3 };
	struct ft_isotp_cfg c;
	struct ft_frame f;

	ft_cfg_init(&c);
	c.rx_id = CAN_EFF_FLAG | 0x123;
	c.tx_id = CAN_EFF_FLAG | 0x321;
	if (!rxenv_open(ctx, &c))
		return;

	ft_frame_bytes(&f, &env.hrx, 4, 0x03, 1, 2, 3);
	f.id = 0x123;
	ft_peer_tx(ctx, &env.p, &f);
	f.id = CAN_EFF_FLAG | 0x124;
	ft_peer_tx(ctx, &env.p, &f);
	f.id = CAN_EFF_FLAG | CAN_RTR_FLAG | 0x123;
	ft_peer_tx(ctx, &env.p, &f);
	ft_dut_expect_nopdu(ctx, env.s, 50);

	f.id = CAN_EFF_FLAG | 0x123;
	ft_peer_tx(ctx, &env.p, &f);
	ft_dut_expect_pdu(ctx, env.s, pdu, 3, 200);
	rxenv_close();
}

static void rx_id_mtu(struct ft_ctx *ctx, const void *param)
{
	static const char *modes[] = { "CC8", "FD8", "FD64" };
	uint8_t pdu[3] = { 1, 2, 3 };
	struct ft_isotp_cfg c;
	struct ft_frame f;
	int i;

	for (i = 0; i < 3; i++) {
		ft_cfg_init(&c);
		ft_cfg_mode(&c, ft_mode_by_name(modes[i]));
		c.iface = FT_IF_FD;
		if (!rxenv_open(ctx, &c))
			return;

		/* SF in the other frame type is ignored */
		ft_frame_bytes(&f, &env.hrx, 4, 0x03, 1, 2, 3);
		f.type = (env.hrx.type == FT_CC) ? FT_FD : FT_CC;
		f.flags = (f.type == FT_FD) ? CANFD_FDF : 0;
		ft_peer_tx(ctx, &env.p, &f);
		ft_dut_expect_nopdu(ctx, env.s, 50);

		ft_frame_bytes(&f, &env.hrx, 4, 0x03, 1, 2, 3);
		ft_peer_tx(ctx, &env.p, &f);
		ft_dut_expect_pdu(ctx, env.s, pdu, 3, 200);
		rxenv_close();
		FT_BAIL(ctx);
	}
}

static void rx_id_fdflags(struct ft_ctx *ctx, const void *param)
{
	static const uint8_t flags[] = { 0, CANFD_BRS, CANFD_ESI, 0xFF };
	uint8_t pdu[3] = { 1, 2, 3 };
	struct ft_frame f;
	unsigned int i;

	if (!rxenv_mode(ctx, "FD64", 0))
		return;

	/* CAN FD flags of received frames are not checked */
	for (i = 0; i < sizeof(flags); i++) {
		ft_frame_bytes(&f, &env.hrx, 4, 0x03, 1, 2, 3);
		f.flags = flags[i];
		ft_peer_tx(ctx, &env.p, &f);
		ft_dut_expect_pdu(ctx, env.s, pdu, 3, 200);
	}
	rxenv_close();
}

/* ------------------------------------------------------------------------
 * multicast first frame (MF)
 * ------------------------------------------------------------------------
 */

static void rx_mf(struct ft_ctx *ctx, const void *param)
{
	bool listen = param != NULL;
	static uint8_t pdu[5000];
	unsigned int lens[] = { 20, 4095, 4096, 5000 };
	struct ft_enc e;
	struct ft_frame *fr;
	unsigned int i;
	int n;

	if (!rxenv_mode(ctx, NULL, listen ? CAN_ISOTP_LISTEN_MODE : 0))
		return;

	e = env.pe;
	e.mf = true;

	for (i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
		ft_pattern(pdu, lens[i], i);
		n = ft_enc_pdu(&e, &env.hrx, pdu, lens[i], &fr);
		rx_send_frames(ctx, fr, 0, n);
		free(fr);
		if (listen)
			ft_dut_expect_pdu(ctx, env.s, pdu, lens[i], 500);
		else
			ft_dut_expect_nopdu(ctx, env.s, 50);
		ft_peer_expect_none(ctx, &env.p, 10);
		ft_dut_expect_noerr(ctx, env.s);
		FT_BAIL(ctx);
	}

	rxenv_close();
}

static void rx_pci_reserved(struct ft_ctx *ctx, const void *param)
{
	int t;

	if (!rxenv_mode(ctx, NULL, param ? CAN_ISOTP_LISTEN_MODE : 0))
		return;

	/* N_PCI types 0x5 .. 0xF are ignored */
	for (t = 5; t <= 15; t++)
		rx_tx(ctx, 8, 8, t << 4, 0x14, 1, 2, 3, 4, 5, 6);

	ft_dut_expect_nopdu(ctx, env.s, 50);
	ft_peer_expect_none(ctx, &env.p, 10);
	ft_dut_expect_noerr(ctx, env.s);
	rxenv_close();
}

/* ------------------------------------------------------------------------
 * test table
 * ------------------------------------------------------------------------
 */

#define T(i, t, fl, f, p, rq, rf, is)					\
	{ .id = i, .title = t, .req = rq, .ref = rf, .iso = is,		\
	  .flags = fl, .fn = f, .param = p }

static const char seg_req[] =
	"The DUT reassembles PDUs of all relevant lengths sent with the DUT TX_DL as LL_DL and the DUT rx addressing/padding settings. "
	"After a FF the DUT sends FC.CTS with BS/STmin from CAN_ISOTP_RECV_FC (ext_address and TX_PADDING as for all tx frames) and after every BS CFs another FC. "
	"The PDU is delivered with recv() after the last CF without socket error. Variants: plain (BS 0), ae (BS 3), pad (BS 1, RX_PADDING|CHK_PAD_LEN|CHK_PAD_DATA), aepad (BS 15).";

static const char seg_ref[] =
	"protocolrx.c:isotp_rcv(), isotp_rcv_sf(), isotp_rcv_ff(), isotp_rcv_cf(), protocoltx.c:isotp_send_fc()";

#define SEG(m, v)							\
	T("RX-SEG-" m "-" #v, "reassembly " m " " #v, 0, rx_seg,	\
	  &((const struct seg_param){ m, FT_V_##v }), seg_req, seg_ref, NULL)

#define SEG4(m) SEG(m, PLAIN), SEG(m, AE), SEG(m, PAD), SEG(m, AEPAD)
#define SEG2(m) SEG(m, PLAIN), SEG(m, AE)

static const char lldl_req[] =
	"The receiver accepts PDUs with any sender LL_DL (taken from the FF CAN_DL), independent of its own TX_DL: all CAN FD DLC lengths for CAN FD, any length >= 8 for CAN XL.";

static const int dl0_0 = 0, dl0_1 = 1, dl0_2 = 2, dl0_4 = 4;

static const struct ft_test tests[] = {
	SEG4("CC8"),
	SEG4("FD8"),
	SEG4("FD12"),
	SEG4("FD16"),
	SEG4("FD20"),
	SEG4("FD24"),
	SEG4("FD32"),
	SEG4("FD48"),
	SEG4("FD64"),
	SEG4("XL9-8"),
	SEG2("XL9-9"),
	SEG2("XL9-12"),
	SEG2("XL9-64"),
	SEG2("XL9-65"),
	SEG2("XL9-255"),
	SEG2("XL9-1000"),
	SEG2("XL9-2048"),
	SEG2("XL9-2048-SEC-VCID"),
	SEG2("XL9-100-RRS"),
	SEG2("XL9-512-IF512"),
	SEG2("XL9-256-IF256"),
	SEG4("XL9FD-12"),
	SEG4("XL9FD-64"),
	SEG4("XL6-8"),
	SEG4("XL7-8"),
	SEG4("XL7-12"),
	SEG4("XL7-64"),
	SEG4("XL7-64BRS"),

	T("RX-LL-001", "any sender LL_DL (CAN FD)", 0, rx_lldl,
	  &((const struct lldl_param){ "FD8", { 8, 12, 16, 20, 24, 32, 48, 64 } }),
	  lldl_req, "protocolrx.c:isotp_rcv_ff() so->rx.ll_dl", NULL),
	T("RX-LL-002", "any sender LL_DL (CAN FD TX_DL 64)", 0, rx_lldl,
	  &((const struct lldl_param){ "FD64", { 8, 12, 32, 64 } }),
	  lldl_req, "protocolrx.c:isotp_rcv_ff() so->rx.ll_dl", NULL),
	T("RX-LL-003", "any sender LL_DL (CAN XL)", 0, rx_lldl,
	  &((const struct lldl_param){ "XL9-8", { 8, 9, 12, 63, 64, 65, 255, 256, 1000, 2047, 2048 } }),
	  lldl_req, "protocolrx.c:isotp_rcv_ff() so->rx.ll_dl", NULL),
	T("RX-LL-004", "any sender LL_DL (CAN XL 256 interface)", 0, rx_lldl,
	  &((const struct lldl_param){ "XL9-256-IF256", { 8, 100, 256 } }),
	  lldl_req, "protocolrx.c:isotp_rcv_ff() so->rx.ll_dl", NULL),

	T("RX-SF-001", "CAN CC SF valid", 0, rx_sf_cc_valid, NULL,
	  "A CAN CC SF with SF_DL 1..7 is accepted with any CAN_DL >= SF_DL+1 (no padding checks configured); the bytes behind SF_DL are ignored.",
	  "protocolrx.c:isotp_rcv() N_PCI_SF, isotp_rcv_sf()", NULL),
	T("RX-SF-002", "CAN CC SF invalid SF_DL", 0, rx_sf_cc_invalid, NULL,
	  "A SF with SF_DL 0 or SF_DL > CAN_DL-1 (incl. 8..15) is ignored silently (no PDU, no error).",
	  "protocolrx.c:isotp_rcv_sf()", NULL),
	T("RX-SF-003", "CAN_DL 0 frame with stale N_PCI", 0, rx_sf_dl0,
	  &dl0_0,
	  "Expected (ISO): a frame without N_PCI byte (CAN_DL 0) is ignored. Observed behaviour is reported.",
	  "protocolrx.c:isotp_rcv() reads data[ae] without CAN_DL check, isotp_rcv_sf() 'sf_dl > datalen - pcilen' unsigned underflow",
	  "DEVIATION (if observed): frames shorter than the N_PCI are processed with data beyond CAN_DL (see test output)."),
	T("RX-SF-004", "CAN_DL 0 frame with SF_DL 15", 0, rx_sf_dl0, &dl0_1,
	  "Expected (ISO): a frame without N_PCI byte (CAN_DL 0) is ignored. Observed behaviour is reported.",
	  "protocolrx.c:isotp_rcv_sf() unsigned underflow of datalen - pcilen",
	  "DEVIATION (if observed): up to 15 bytes are copied from a CAN CC frame with CAN_DL 0 (8 bytes beyond struct can_frame)."),
	T("RX-SF-005", "ext. addressing: CAN_DL 1 frame", 0, rx_sf_dl0,
	  &dl0_2,
	  "Expected (ISO): a frame with only the address extension (CAN_DL 1) is ignored. Observed behaviour is reported.",
	  "protocolrx.c:isotp_rcv_sf() unsigned underflow of datalen - pcilen",
	  "DEVIATION (if observed): frames shorter than AE + N_PCI are processed with data beyond CAN_DL."),
	T("RX-SF-006", "SF with extended addressing", 0, rx_sf_ae, NULL,
	  "With extended addressing only frames with data[0] == rx_ext_address are processed, the SF_DL maximum is 6 for CAN_DL 8.",
	  "protocolrx.c:isotp_rcv()", NULL),
	T("RX-SF-007", "SF with separate rx address", 0, rx_sf_ae, "rxext",
	  "With CAN_ISOTP_RX_EXT_ADDR the rx_ext_address (not ext_address) is expected in received frames.",
	  "protocolrx.c:isotp_rcv(), isotp.c:isotp_setsockopt_locked()", NULL),
	T("RX-SF-008", "CAN FD SF valid", 0, rx_sf_fd, NULL,
	  "CAN FD SF with CAN_DL <= 8 use the 4 bit SF_DL; with CAN_DL > 8 the escape sequence (N_PCI 0x00 + SF_DL byte) with SF_DL 1..CAN_DL-2 is accepted.",
	  "protocolrx.c:isotp_rcv() N_PCI_SF can_is_canfd_skb()",
	  "REVIEW: SF_DL values which would fit into a shorter CAN FD frame (e.g. SF_DL 1 in CAN_DL 64) and SF_DL <= 7 with escape are accepted (ISO 15765-2 requires the optimal CAN_DL for SF_DL > 7 / uses the escape only for CAN_DL > 8)."),
	T("RX-SF-009", "CAN FD SF invalid", 0, rx_sf_fd_invalid, NULL,
	  "CAN FD SF with CAN_DL > 8 and a non-zero low nibble (no escape), escape with SF_DL 0 or SF_DL > CAN_DL-2, and the escape in CAN_DL <= 8 are ignored silently.",
	  "protocolrx.c:isotp_rcv(), isotp_rcv_sf()", NULL),
	T("RX-SF-010", "CAN FD frames with non-DLC length", 0, rx_sf_fd_nodlc,
	  NULL,
	  "Without padding checks CAN FD SFs with a CAN_DL that is no CAN FD DLC length (e.g. 9..11, only possible on virtual CAN) are accepted.",
	  "protocolrx.c:isotp_rcv()", NULL),
	T("RX-SF-011", "SF padding checks", 0, rx_sf_pad, NULL,
	  "CHK_PAD_LEN without RX_PADDING requires the optimized length (CC: exact, FD: next DLC length after the data); RX_PADDING|CHK_PAD_LEN requires a valid CAN FD DLC length >= 8; RX_PADDING|CHK_PAD_DATA requires rxpad_content in all bytes after the data; CHK_PAD_DATA without RX_PADDING fails always. Failures are reported as EBADMSG and the PDU is dropped.",
	  "protocolrx.c:isotp_rcv_sf(), chk_pad_fail(), chk_optimized_fail()", NULL),
	T("RX-SF-012", "valid SF during reception", 0, rx_sf_during_rx, NULL,
	  "A valid SF received during a segmented reception is delivered and terminates the reception silently (remaining CFs are ignored, no error).",
	  "protocolrx.c:isotp_rcv_sf()",
	  "REVIEW: ISO 15765-2 reports N_UNEXP_PDU for the terminated reception, the implementation reports nothing."),
	T("RX-SF-013", "invalid SF during reception", 0, rx_sf_during_rx,
	  "invalid",
	  "An invalid SF (SF_DL 0) received during a segmented reception terminates the reception silently.",
	  "protocolrx.c:isotp_rcv_sf() sets ISOTP_IDLE before the SF_DL check",
	  "REVIEW: an invalid (to be ignored) SF terminates an ongoing reception."),
	T("RX-SF-014", "no N_Cr timeout after terminated reception", FT_SLOW,
	  rx_sf_during_rx, "slow",
	  "After the reception was terminated by a SF no N_Cr timeout error is reported.",
	  "protocolrx.c:isotp_rcv_sf() hrtimer_cancel(&so->rxtimer)", NULL),

	T("RX-FF-001", "FF with CAN_DL < 8", 0, rx_ff_short, NULL,
	  "A FF with CAN_DL < 8 is ignored (no FC).",
	  "protocolrx.c:isotp_rcv_ff()", NULL),
	T("RX-FF-002", "CAN FD FF length / CF length", 0, rx_ff_fd_len, NULL,
	  "A CAN FD FF must have a CAN FD DLC length (else ignored). The FF CAN_DL defines the sender LL_DL; longer CFs are ignored and the reception continues.",
	  "protocolrx.c:isotp_rcv_ff(), isotp_rcv_cf()", NULL),
	T("RX-FF-003", "32 bit FF_DL escape", 0, rx_ff_escape, NULL,
	  "A FF with FF_DL escape (12 bit FF_DL 0) and a 32 bit FF_DL <= 4095 is ignored, FF_DL 4096 is accepted.",
	  "protocolrx.c:isotp_rcv_ff()", NULL),
	T("RX-FF-004-CC8", "FF_DL minimum CC8", 0, rx_ff_min,
	  &((const struct ffmin_param){ "CC8", FT_V_PLAIN, 8 }),
	  "A FF with FF_DL < FF_DLmin (the PDU fits into a SF of the sender LL_DL: 7-ae for LL_DL 8, LL_DL-2-ae else) is ignored, FF_DL >= FF_DLmin is answered with a FC.",
	  "protocolrx.c:isotp_rcv_ff() FF_DLmin check",
	  "DEVIATION (if observed): CAN CC FF_DL 7 (normal) / 6 (extended addressing) is accepted although it fits into a SF (ISO 15765-2 FF_DLmin 8 / 7), fixed by xl-isotp split_v2 patch 16."),
	T("RX-FF-004-CC8-ae", "FF_DL minimum CC8 ext. addr.", 0, rx_ff_min,
	  &((const struct ffmin_param){ "CC8", FT_V_AE, 7 }),
	  "A FF with FF_DL < FF_DLmin (the PDU fits into a SF of the sender LL_DL: 7-ae for LL_DL 8, LL_DL-2-ae else) is ignored, FF_DL >= FF_DLmin is answered with a FC.",
	  "protocolrx.c:isotp_rcv_ff() FF_DLmin check",
	  "DEVIATION (if observed): CAN CC FF_DL 7 (normal) / 6 (extended addressing) is accepted although it fits into a SF (ISO 15765-2 FF_DLmin 8 / 7), fixed by xl-isotp split_v2 patch 16."),
	T("RX-FF-004-FD64", "FF_DL minimum FD64", 0, rx_ff_min,
	  &((const struct ffmin_param){ "FD64", FT_V_PLAIN, 63 }),
	  "A FF with FF_DL < FF_DLmin (the PDU fits into a SF of the sender LL_DL: 7-ae for LL_DL 8, LL_DL-2-ae else) is ignored, FF_DL >= FF_DLmin is answered with a FC.",
	  "protocolrx.c:isotp_rcv_ff() FF_DLmin check", NULL),
	T("RX-FF-004-XL9-2048", "FF_DL minimum XL9-2048", 0, rx_ff_min,
	  &((const struct ffmin_param){ "XL9-2048", FT_V_PLAIN, 2047 }),
	  "A FF with FF_DL < FF_DLmin (the PDU fits into a SF of the sender LL_DL: 7-ae for LL_DL 8, LL_DL-2-ae else) is ignored, FF_DL >= FF_DLmin is answered with a FC.",
	  "protocolrx.c:isotp_rcv_ff() FF_DLmin check", NULL),
	T("RX-FF-005", "FF_DL > max_pdu_size", 0, rx_ff_ovflw, NULL,
	  "A FF with FF_DL > max_pdu_size is answered with FC.OVFLW, the following CFs are ignored and no error is reported. FF_DL == max_pdu_size is answered with FC.CTS.",
	  "protocolrx.c:isotp_rcv_ff()", NULL),
	T("RX-FF-006", "FF_DL > max_pdu_size in listen mode", 0, rx_ff_ovflw,
	  "listen",
	  "Expected: in CAN_ISOTP_LISTEN_MODE no frames are sent. Observed behaviour for a FF with FF_DL > max_pdu_size is reported.",
	  "protocolrx.c:isotp_rcv_ff() isotp_send_fc(OVFLW) before the LISTEN_MODE check",
	  "DEVIATION (if observed): a FC.OVFLW is sent in listen mode, which can abort transfers between other nodes (fixed by xl-isotp split_v2 patch 18)."),
	T("RX-FF-011", "FF_DL close to 2^32", 0, rx_ff_maxdl, NULL,
	  "Expected: all FF_DL values > max_pdu_size (up to 0xFFFFFFFF) are answered with FC.OVFLW. Observed behaviour is reported.",
	  "protocolrx.c:isotp_rcv_ff() 'so->rx.len + ae + ff_pci_sz <= so->rx.ll_dl' (u32 arithmetic)",
	  "DEVIATION (if observed): FF_DL >= 0xFFFFFFFA (0xFFFFFFF9 with ext. addressing) wraps around in the single FF check and the FF is ignored without FC.OVFLW."),
	T("RX-FF-011-ae", "FF_DL close to 2^32 (ext. addr.)", 0, rx_ff_maxdl,
	  "ae",
	  "Expected: all FF_DL values > max_pdu_size (up to 0xFFFFFFFF) are answered with FC.OVFLW. Observed behaviour is reported.",
	  "protocolrx.c:isotp_rcv_ff() 'so->rx.len + ae + ff_pci_sz <= so->rx.ll_dl' (u32 arithmetic)",
	  "DEVIATION (if observed): FF_DL >= 0xFFFFFFFA (0xFFFFFFF9 with ext. addressing) wraps around in the single FF check and the FF is ignored without FC.OVFLW."),
	T("RX-FF-007", "FF during reception", 0, rx_ff_restart, NULL,
	  "A valid FF during a reception restarts the reception with the new PDU (new FC), the old PDU is discarded silently.",
	  "protocolrx.c:isotp_rcv_ff()",
	  "REVIEW: ISO 15765-2 reports N_UNEXP_PDU for the terminated reception."),
	T("RX-FF-008", "invalid FF during reception", 0,
	  rx_ff_invalid_during_rx, NULL,
	  "An invalid FF (CAN_DL < 8) during a reception terminates the reception silently.",
	  "protocolrx.c:isotp_rcv_ff() sets ISOTP_IDLE before the checks",
	  "REVIEW: an invalid (to be ignored) FF terminates an ongoing reception."),
	T("RX-FF-009", "FC content from RECV_FC", 0, rx_ff_fc_content, NULL,
	  "The FC.CTS contains BS and STmin from CAN_ISOTP_RECV_FC without checks (also reserved STmin values). wftmax has no effect, FC.WT is never sent.",
	  "protocoltx.c:isotp_send_fc()",
	  "REVIEW: reserved STmin values are sent; N_WFTmax / FC.WT are not implemented (no flow control wait on the receiver side)."),
	T("RX-FF-010-CC8", "listen mode reception CC8", 0, rx_ff_listen,
	  "CC8",
	  "In CAN_ISOTP_LISTEN_MODE PDUs are received without sending FC frames (BS is ignored).",
	  "protocolrx.c:isotp_rcv_ff(), isotp_rcv_cf()", NULL),
	T("RX-FF-010-FD64", "listen mode reception FD64", 0, rx_ff_listen,
	  "FD64",
	  "In CAN_ISOTP_LISTEN_MODE PDUs are received without sending FC frames (BS is ignored).",
	  "protocolrx.c:isotp_rcv_ff(), isotp_rcv_cf()", NULL),
	T("RX-FF-010-XL9-2048", "listen mode reception XL9-2048", 0,
	  rx_ff_listen, "XL9-2048",
	  "In CAN_ISOTP_LISTEN_MODE PDUs are received without sending FC frames (BS is ignored).",
	  "protocolrx.c:isotp_rcv_ff(), isotp_rcv_cf()", NULL),

	T("RX-CF-001", "wrong sequence number", 0, rx_cf_sn, NULL,
	  "A CF with a wrong SN aborts the reception with EILSEQ; the remaining CFs are ignored.",
	  "protocolrx.c:isotp_rcv_cf()", NULL),
	T("RX-CF-002", "CF without reception", 0, rx_cf_idle, NULL,
	  "CFs without an active reception are ignored silently.",
	  "protocolrx.c:isotp_rcv_cf()", NULL),
	T("RX-CF-003", "CF shorter than LL_DL (CC)", 0, rx_cf_len, NULL,
	  "A CF shorter than LL_DL which is not the last CF is ignored, the reception continues.",
	  "protocolrx.c:isotp_rcv_cf()", NULL),
	T("RX-CF-004", "CF shorter than LL_DL (FD)", 0, rx_cf_len, "fd",
	  "A CF shorter than LL_DL which is not the last CF is ignored, the reception continues.",
	  "protocolrx.c:isotp_rcv_cf()", NULL),
	T("RX-CF-005", "last CF longer than needed", 0, rx_cf_last_long, NULL,
	  "The last CF may contain more bytes than needed (without padding checks); only FF_DL bytes are delivered.",
	  "protocolrx.c:isotp_rcv_cf()", NULL),
	T("RX-CF-006", "CAN_DL 0 frame with stale CF N_PCI", 0, rx_cf_dl0,
	  NULL,
	  "Expected (ISO): a frame without N_PCI (CAN_DL 0) is ignored and the PDU completes. Observed behaviour is reported.",
	  "protocolrx.c:isotp_rcv() / isotp_rcv_cf() no minimum CAN_DL check",
	  "DEVIATION (if observed): a CAN_DL 0 frame is processed as (empty) CF and advances the SN (see test output)."),
	T("RX-CF-014", "short last CF lacking bytes", 0, rx_cf_short_last,
	  &dl0_4,
	  "Only the last CF may be shorter than LL_DL and it has to contain all remaining bytes of the PDU. A short CF lacking bytes (here 3 of 7) is ignored and the reception continues with the correct CF.",
	  "protocolrx.c:isotp_rcv_cf() last CF length check",
	  "DEVIATION (if observed): the short CF is accepted, consumes a SN and the reception waits for further CFs (fixed by xl-isotp split_v2 patch 17)."),
	T("RX-CF-015", "CF with N_PCI only", 0, rx_cf_short_last, &dl0_1,
	  "A CF with only the N_PCI (no data) is a short CF lacking bytes and is ignored; the reception continues with the correct CF.",
	  "protocolrx.c:isotp_rcv_cf() last CF length check",
	  "DEVIATION (if observed): the empty CF is accepted and consumes a SN (fixed by xl-isotp split_v2 patch 17)."),
	T("RX-CF-007-CC8", "block size handling CC8", 0, rx_cf_bs, NULL,
	  "The receiver sends a FC after every BS CFs (BS 1..255).",
	  "protocolrx.c:isotp_rcv_cf() so->rxfc.bs", NULL),
	T("RX-CF-007-FD64", "block size handling FD64", 0, rx_cf_bs, "FD64",
	  "The receiver sends a FC after every BS CFs (BS 1..255).",
	  "protocolrx.c:isotp_rcv_cf() so->rxfc.bs", NULL),
	T("RX-CF-008", "last CF padding checks", 0, rx_cf_pad, NULL,
	  "The padding checks are applied to the last CF (rules as for SF); failures are reported with EBADMSG and the PDU is dropped.",
	  "protocolrx.c:isotp_rcv_cf() chk_pad_fail()", NULL),
	T("RX-CF-009-CC8", "RX STmin enforcement CC8", 0, rx_cf_rxstmin,
	  "CC8",
	  "With CAN_ISOTP_FORCE_RXSTMIN CFs received with a timestamp gap < CAN_ISOTP_RX_STMIN are dropped silently, which leads to EILSEQ for the next CF. CFs with larger gaps are accepted. The gap is measured to the last accepted CF. (CF sequences sent with CAN_BCM)",
	  "protocolrx.c:isotp_rcv_cf() CAN_ISOTP_FORCE_RXSTMIN", NULL),
	T("RX-CF-009-FD64", "RX STmin enforcement FD64", 0, rx_cf_rxstmin,
	  "FD64",
	  "With CAN_ISOTP_FORCE_RXSTMIN CFs received with a timestamp gap < CAN_ISOTP_RX_STMIN are dropped silently, which leads to EILSEQ for the next CF. CFs with larger gaps are accepted. The gap is measured to the last accepted CF. (CF sequences sent with CAN_BCM)",
	  "protocolrx.c:isotp_rcv_cf() CAN_ISOTP_FORCE_RXSTMIN", NULL),
	T("RX-CF-010", "RX STmin reset by FC", 0, rx_cf_rxstmin_bs, NULL,
	  "The RX STmin reference timestamp is reset by each sent FC: the first CF after a FC is always accepted.",
	  "protocoltx.c:isotp_send_fc() lastrxcf_tstamp", NULL),
	T("RX-CF-011", "N_Cr timeout after FF", FT_SLOW, rx_cf_timeout, "ff",
	  "Without CF after the FC the reception is aborted after N_Cr (1 s + frame_txtime) with ETIMEDOUT; later CFs are ignored.",
	  "protocoltx.c:isotp_send_fc(), hrtimer.c:isotp_rx_timer_handler()", NULL),
	T("RX-CF-012", "N_Cr timeout after CF", FT_SLOW, rx_cf_timeout, "cf",
	  "Without further CF the reception is aborted after N_Cr (1 s) with ETIMEDOUT.",
	  "protocolrx.c:isotp_rcv_cf(), hrtimer.c:isotp_rx_timer_handler()", NULL),
	T("RX-CF-013", "N_Cr timeout in listen mode", FT_SLOW, rx_cf_timeout,
	  "listen",
	  "In listen mode a FF without CFs leads to ETIMEDOUT after 1 s.",
	  "protocolrx.c:isotp_rcv_ff() hrtimer_start(rxtimer)", NULL),

	T("RX-ID-001", "CAN ID filter", 0, rx_id_filter, NULL,
	  "Only frames with exactly the rx_id are processed (no other ID, no EFF with the same value, no RTR, not the own tx_id); own sent PDUs are not received.",
	  "isotp.c:isotp_bind() can_rx_register(SINGLE_MASK), protocolrx.c:isotp_check_frame_head()", NULL),
	T("RX-ID-002", "29 bit CAN ID filter", 0, rx_id_eff, NULL,
	  "A 29 bit rx_id only matches 29 bit frames with the same ID (no RTR).",
	  "isotp.c:isotp_bind() SINGLE_MASK", NULL),
	T("RX-ID-003", "frame type (MTU) filter", 0, rx_id_mtu, NULL,
	  "A CAN CC socket only processes CAN CC frames and a CAN FD socket (also with TX_DL 8) only CAN FD frames.",
	  "protocolrx.c:isotp_check_frame_head() skb->len != so->ll.mtu", NULL),
	T("RX-ID-004", "CAN FD flags not checked", 0, rx_id_fdflags, NULL,
	  "The CAN FD flags (BRS, ESI, ..) of received frames are not checked.",
	  "protocolrx.c:isotp_check_frame_head()", NULL),
	T("RX-MF-001", "MF ignored without listen mode", 0, rx_mf, NULL,
	  "Multicast first frames (N_PCI 0x4) are ignored by sockets without CAN_ISOTP_LISTEN_MODE (no FC, no PDU).",
	  "protocolrx.c:isotp_rcv() N_PCI_MF", NULL),
	T("RX-MF-002", "MF reception in listen mode", 0, rx_mf, "listen",
	  "Sockets with CAN_ISOTP_LISTEN_MODE receive PDUs started with a multicast first frame (12 and 32 bit FF_DL) without sending FC frames.",
	  "protocolrx.c:isotp_rcv() N_PCI_MF => isotp_rcv_ff()", NULL),
	T("RX-PCI-001", "reserved N_PCI types", 0, rx_pci_reserved, NULL,
	  "Frames with N_PCI types 0x5..0xF are ignored silently.",
	  "protocolrx.c:isotp_rcv()", NULL),
	T("RX-PCI-002", "reserved N_PCI types (listen mode)", 0,
	  rx_pci_reserved, "listen",
	  "Frames with N_PCI types 0x5..0xF are ignored silently in listen mode.",
	  "protocolrx.c:isotp_rcv()", NULL),
};

int main(int argc, char **argv)
{
	return ft_main(argc, argv, "rx", tests,
		       sizeof(tests) / sizeof(tests[0]));
}
