// SPDX-License-Identifier: (GPL-2.0-only OR BSD-3-Clause)
/*
 * tst-isotp-tx.c - CAN_ISOTP transmission path
 *
 * The DUT socket sends PDUs, a CAN_RAW peer checks the created CAN frames
 * against the reference encoder and answers with (malformed) flow control
 * frames.
 *
 * Send feedback to <linux-can@vger.kernel.org>
 */

#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
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
 * test environment: DUT socket + peer + one PDU transfer
 * ------------------------------------------------------------------------
 */

struct txenv {
	struct ft_isotp_cfg c;
	int s;
	struct ft_peer p;
	struct ft_enc e, pe;
	struct ft_frame htx, hrx;
	uint8_t data[FT_MAX_PDU];
	unsigned int len;
	struct ft_frame *frames;
	int n;
	struct ft_async a;
};

static struct txenv env;

static bool txenv_open(struct ft_ctx *ctx, const struct ft_isotp_cfg *c)
{
	memset(&env, 0, sizeof(env));
	env.s = -1;
	env.p.s = -1;
	env.c = *c;

	ft_enc_dut(c, &env.e);
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

static void txenv_join(struct ft_ctx *ctx)
{
	if (env.a.started)
		ft_async_join(ctx, &env.a, 4000);
}

static void txenv_close(struct ft_ctx *ctx)
{
	txenv_join(ctx);
	free(env.frames);
	env.frames = NULL;
	ft_peer_close(&env.p);
	if (env.s >= 0)
		close(env.s);
	env.s = -1;
}

/* start a transfer of len bytes and check the first frame */
static bool txenv_start(struct ft_ctx *ctx, unsigned int len)
{
	txenv_join(ctx);
	free(env.frames);

	env.len = len;
	ft_pattern(env.data, len, len);
	env.n = ft_enc_pdu(&env.e, &env.htx, env.data, len, &env.frames);
	if (env.n < 0) {
		ft_fail(ctx, "out of memory");
		return false;
	}

	ft_log(ctx, "start transfer len %u (%d frames)", len, env.n);
	ft_async_send(&env.a, env.s, env.data, len, 0);

	return ft_peer_expect(ctx, &env.p, &env.frames[0], 500);
}

static bool txenv_fc(struct ft_ctx *ctx, uint8_t fs, uint8_t bs, uint8_t stmin)
{
	struct ft_frame f;

	ft_enc_fc(&env.pe, &env.hrx, fs, bs, stmin, &f);
	return ft_peer_tx(ctx, &env.p, &f);
}

/* expect consecutive frames [from, to) */
static bool txenv_cfs(struct ft_ctx *ctx, int from, int to, int64_t *ts)
{
	struct ft_frame f;
	int i;

	for (i = from; i < to && i < env.n; i++) {
		if (!ft_peer_next(ctx, &env.p, &f, 1500)) {
			ft_fail(ctx, "CF %d of %d not received", i, env.n - 1);
			return false;
		}
		if (!ft_frame_eq(&f, &env.frames[i])) {
			char b1[512], b2[512];

			ft_frame_str(&env.frames[i], b1, sizeof(b1));
			ft_frame_str(&f, b2, sizeof(b2));
			ft_fail(ctx, "CF %d mismatch:\n#   exp %s\n#   got %s", i,
				b1, b2);
			return false;
		}
		if (ts)
			ts[i] = f.ts;
	}

	return true;
}

/* wait for the send() result */
static bool txenv_result(struct ft_ctx *ctx, ssize_t exp)
{
	if (!ft_async_join(ctx, &env.a, 3000))
		return false;

	return FT_CHECK(ctx, env.a.ret == exp, "send() returned %zd %s, expected %zd %s",
			env.a.ret, env.a.ret < 0 ? ft_errname(env.a.ret) : "",
			exp, exp < 0 ? ft_errname(exp) : "");
}

/* length with a FF and n CFs (last CF with 3 bytes) */
static unsigned int len_cfs(const struct ft_enc *e, int n)
{
	unsigned int ae = e->ae ? 1 : 0;

	return (e->ll_dl - 2 - ae) + (n - 1) * (e->ll_dl - 1 - ae) + 3;
}

static void cfg_wtd(struct ft_isotp_cfg *c, const char *mode)
{
	ft_cfg_init(c);
	if (mode)
		ft_cfg_mode(c, ft_mode_by_name(mode));
	c->opts.flags |= CAN_ISOTP_WAIT_TX_DONE;
}

/* ------------------------------------------------------------------------
 * segmentation
 * ------------------------------------------------------------------------
 */

static void tx_seg(struct ft_ctx *ctx, const void *param)
{
	const struct seg_param *sp = param;
	const struct ft_mode *m = ft_mode_by_name(sp->mode);
	static uint8_t data[FT_MAX_PDU];
	struct ft_isotp_cfg c;
	unsigned int lens[32];
	int i, n;

	ft_cfg_init(&c);
	ft_cfg_mode(&c, m);
	ft_cfg_variant(&c, sp->var);
	c.opts.flags |= CAN_ISOTP_WAIT_TX_DONE;

	if (!txenv_open(ctx, &c))
		return;

	n = ft_seg_lengths(&env.e, FT_MAX_PDU, lens, 32);
	for (i = 0; i < n; i++) {
		uint8_t bs = (i % 3 == 2) ? 3 : 0;

		ft_pattern(data, lens[i], i);
		if (!ft_tx_pdu(ctx, env.s, &c, &env.p, data, lens[i], bs, 0))
			break;
	}

	txenv_close(ctx);
}

static void tx_pad_fd_default(struct ft_ctx *ctx, const void *param)
{
	static uint8_t data[200];
	struct ft_isotp_cfg c;
	unsigned int lens[] = { 3, 7, 8, 9, 10, 20, 61, 62, 63, 100, 130 };
	unsigned int i;

	/* txpad_content is only used with CAN_ISOTP_TX_PADDING */
	cfg_wtd(&c, "FD64");
	c.opts.txpad_content = 0x55;
	if (!txenv_open(ctx, &c))
		return;

	for (i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
		ft_pattern(data, lens[i], i);
		if (!ft_tx_pdu(ctx, env.s, &c, &env.p, data, lens[i], 0, 0))
			break;
	}

	txenv_close(ctx);
}

/* ------------------------------------------------------------------------
 * flow control handling
 * ------------------------------------------------------------------------
 */

static void tx_fc_block(struct ft_ctx *ctx, const void *param)
{
	struct ft_isotp_cfg c;

	cfg_wtd(&c, param);
	if (!txenv_open(ctx, &c))
		return;

	if (!txenv_start(ctx, len_cfs(&env.e, 8)))
		goto out;

	txenv_fc(ctx, FT_FS_CTS, 3, 0);
	txenv_cfs(ctx, 1, 4, NULL);
	ft_peer_expect_none(ctx, &env.p, 50);
	FT_BAIL(ctx);
	txenv_fc(ctx, FT_FS_CTS, 3, 0);
	txenv_cfs(ctx, 4, 7, NULL);
	ft_peer_expect_none(ctx, &env.p, 50);
	FT_BAIL(ctx);
	txenv_fc(ctx, FT_FS_CTS, 3, 0);
	txenv_cfs(ctx, 7, 9, NULL);
	txenv_result(ctx, env.len);
	ft_peer_expect_none(ctx, &env.p, 20);
out:
	txenv_close(ctx);
}

static void tx_fc_static(struct ft_ctx *ctx, const void *param)
{
	struct ft_isotp_cfg c;
	int64_t ts[16];

	cfg_wtd(&c, NULL);
	if (!txenv_open(ctx, &c))
		return;

	if (!txenv_start(ctx, len_cfs(&env.e, 8)))
		goto out;

	txenv_fc(ctx, FT_FS_CTS, 2, 0);
	txenv_cfs(ctx, 1, 3, ts);
	ft_peer_expect_none(ctx, &env.p, 50);

	/* BS and STmin of the following FCs are ignored */
	txenv_fc(ctx, FT_FS_CTS, 5, 0x7F);
	txenv_cfs(ctx, 3, 5, ts);
	FT_CHECK(ctx, ts[4] - ts[3] < 50000000LL,
		 "STmin of 2nd FC used (gap %lld us)",
		 (long long)(ts[4] - ts[3]) / 1000);
	ft_peer_expect_none(ctx, &env.p, 50);
	txenv_fc(ctx, FT_FS_CTS, 0, 0);
	txenv_cfs(ctx, 5, 7, ts);
	ft_peer_expect_none(ctx, &env.p, 50);
	txenv_fc(ctx, FT_FS_CTS, 1, 0);
	txenv_cfs(ctx, 7, 9, ts);
	txenv_result(ctx, env.len);
out:
	txenv_close(ctx);
}

static void tx_fc_dyn(struct ft_ctx *ctx, const void *param)
{
	struct ft_isotp_cfg c;
	int64_t ts[16];

	cfg_wtd(&c, NULL);
	c.opts.flags |= CAN_ISOTP_DYN_FC_PARMS;
	if (!txenv_open(ctx, &c))
		return;

	if (!txenv_start(ctx, len_cfs(&env.e, 8)))
		goto out;

	txenv_fc(ctx, FT_FS_CTS, 2, 0);
	txenv_cfs(ctx, 1, 3, ts);
	ft_peer_expect_none(ctx, &env.p, 50);

	/* BS 3 and STmin 10 ms from the 2nd FC */
	txenv_fc(ctx, FT_FS_CTS, 3, 0x0A);
	txenv_cfs(ctx, 3, 6, ts);
	FT_CHECK(ctx, ts[4] - ts[3] >= 10000000LL && ts[5] - ts[4] >= 10000000LL,
		 "STmin 10 ms of 2nd FC not used (gaps %lld/%lld us)",
		 (long long)(ts[4] - ts[3]) / 1000,
		 (long long)(ts[5] - ts[4]) / 1000);
	ft_peer_expect_none(ctx, &env.p, 50);

	/* BS 0 and STmin 0 from the 3rd FC */
	txenv_fc(ctx, FT_FS_CTS, 0, 0);
	txenv_cfs(ctx, 6, 9, ts);
	FT_CHECK(ctx, ts[8] - ts[7] < 10000000LL,
		 "STmin 0 of 3rd FC not used (gap %lld us)",
		 (long long)(ts[8] - ts[7]) / 1000);
	txenv_result(ctx, env.len);
out:
	txenv_close(ctx);
}

static void tx_fc_wait(struct ft_ctx *ctx, const void *param)
{
	struct ft_isotp_cfg c;
	int i, n = param ? 25 : 3;
	int gap = param ? 60 : 100;

	cfg_wtd(&c, NULL);
	if (!txenv_open(ctx, &c))
		return;

	if (!txenv_start(ctx, 30))
		goto out;

	/* each FC.WT restarts N_Bs, no limit for the number of FC.WT */
	for (i = 0; i < n; i++) {
		txenv_fc(ctx, FT_FS_WT, 0, 0);
		ft_peer_expect_none(ctx, &env.p, gap);
		FT_BAIL(ctx);
	}

	txenv_fc(ctx, FT_FS_CTS, 0, 0);
	txenv_cfs(ctx, 1, env.n, NULL);
	txenv_result(ctx, env.len);
out:
	txenv_close(ctx);
}

static void tx_fc_wait_timeout(struct ft_ctx *ctx, const void *param)
{
	struct ft_isotp_cfg c;

	cfg_wtd(&c, NULL);
	if (!txenv_open(ctx, &c))
		return;

	if (!txenv_start(ctx, 30))
		goto out;

	txenv_fc(ctx, FT_FS_WT, 0, 0);
	txenv_result(ctx, -ECOMM);
	ft_peer_expect_none(ctx, &env.p, 20);
	ft_dut_expect_noerr(ctx, env.s);
out:
	txenv_close(ctx);
}

static void tx_fc_ovflw(struct ft_ctx *ctx, const void *param)
{
	struct ft_isotp_cfg c;
	bool block = param != NULL;

	cfg_wtd(&c, NULL);
	if (!txenv_open(ctx, &c))
		return;

	if (!txenv_start(ctx, len_cfs(&env.e, 6)))
		goto out;

	if (block) {
		txenv_fc(ctx, FT_FS_CTS, 2, 0);
		txenv_cfs(ctx, 1, 3, NULL);
	}

	txenv_fc(ctx, FT_FS_OVFLW, 0, 0);
	txenv_result(ctx, -EMSGSIZE);
	ft_peer_expect_none(ctx, &env.p, 50);
	ft_dut_expect_noerr(ctx, env.s);

	/* the socket is usable again */
	ft_tx_pdu(ctx, env.s, &c, &env.p, env.data, 20, 0, 0);
out:
	txenv_close(ctx);
}

static void tx_fc_reserved(struct ft_ctx *ctx, const void *param)
{
	struct ft_isotp_cfg c;
	int fs;

	cfg_wtd(&c, NULL);
	if (!txenv_open(ctx, &c))
		return;

	for (fs = 3; fs <= 15; fs++) {
		ft_log(ctx, "flow status %d", fs);
		if (!txenv_start(ctx, 20))
			break;
		txenv_fc(ctx, fs, 0, 0);
		txenv_result(ctx, -EBADMSG);
		ft_peer_expect_none(ctx, &env.p, 20);
		FT_BAIL(ctx);
	}

	txenv_close(ctx);
}

struct fc_short_param {
	int var;
};

static void tx_fc_short(struct ft_ctx *ctx, const void *param)
{
	const struct fc_short_param *fp = param;
	struct ft_isotp_cfg c;
	struct ft_frame f;
	unsigned int ae = (fp->var == FT_V_AE) ? 1 : 0;
	unsigned int len;
	uint8_t buf[8];

	cfg_wtd(&c, NULL);
	ft_cfg_variant(&c, fp->var);
	if (!txenv_open(ctx, &c))
		return;

	/* CAN_DL 0 .. ae+2 => malformed FC; data bytes beyond CAN_DL are
	 * set to show that only CAN_DL is used for the check
	 */
	for (len = 0; len <= ae + 3; len++) {
		ft_log(ctx, "FC with CAN_DL %u", len);
		if (!txenv_start(ctx, 20))
			break;

		memset(buf, 0, sizeof(buf));
		if (ae)
			buf[0] = 0xA5;
		buf[ae] = FT_PCI_FC | FT_FS_CTS;
		ft_frame_set(&f, &env.hrx, buf, sizeof(buf));
		f.len = len;
		ft_peer_tx(ctx, &env.p, &f);

		if (len < ae + 1) {
			/* no N_PCI => no N_PDU, expected to be ignored */
			ft_sleep_ms(50);
			if (ft_async_done(&env.a)) {
				txenv_result(ctx, -EBADMSG);
				ft_note_dev(ctx, "FC with CAN_DL %u (no N_PCI) processed with data beyond CAN_DL => EBADMSG",
					    len);
			} else {
				ft_log(ctx, "FC without N_PCI ignored");
				ft_peer_expect_none(ctx, &env.p, 10);
				txenv_fc(ctx, FT_FS_CTS, 0, 0);
				txenv_cfs(ctx, 1, env.n, NULL);
				txenv_result(ctx, env.len);
			}
		} else if (len < ae + 3) {
			txenv_result(ctx, -EBADMSG);
			ft_peer_expect_none(ctx, &env.p, 20);
		} else {
			txenv_cfs(ctx, 1, env.n, NULL);
			txenv_result(ctx, env.len);
		}
		FT_BAIL(ctx);
	}

	txenv_close(ctx);
}

struct fc_pad_case {
	const char *mode;
	uint32_t flags;
	uint8_t rxpad;
	unsigned int fclen;
	uint8_t padval;
	int last_byte;		/* >= 0: different value for the last byte */
	bool ok;
};

static const struct fc_pad_case fc_pad_cases[] = {
	/* CHK_PAD_LEN only: FC needs optimized length (3) */
	{ "CC8", CAN_ISOTP_CHK_PAD_LEN, 0xCC, 3, 0xCC, -1, true },
	{ "CC8", CAN_ISOTP_CHK_PAD_LEN, 0xCC, 4, 0xCC, -1, false },
	{ "CC8", CAN_ISOTP_CHK_PAD_LEN, 0xCC, 8, 0xCC, -1, false },
	/* RX_PADDING + CHK_PAD_LEN: FC needs 8 byte */
	{ "CC8", CAN_ISOTP_RX_PADDING | CAN_ISOTP_CHK_PAD_LEN, 0xCC, 8, 0x00, -1, true },
	{ "CC8", CAN_ISOTP_RX_PADDING | CAN_ISOTP_CHK_PAD_LEN, 0xCC, 3, 0xCC, -1, false },
	{ "CC8", CAN_ISOTP_RX_PADDING | CAN_ISOTP_CHK_PAD_LEN, 0xCC, 7, 0xCC, -1, false },
	/* RX_PADDING + CHK_PAD_DATA: padding content, any length */
	{ "CC8", CAN_ISOTP_RX_PADDING | CAN_ISOTP_CHK_PAD_DATA, 0xAA, 8, 0xAA, -1, true },
	{ "CC8", CAN_ISOTP_RX_PADDING | CAN_ISOTP_CHK_PAD_DATA, 0xAA, 5, 0xAA, -1, true },
	{ "CC8", CAN_ISOTP_RX_PADDING | CAN_ISOTP_CHK_PAD_DATA, 0xAA, 3, 0xAA, -1, true },
	{ "CC8", CAN_ISOTP_RX_PADDING | CAN_ISOTP_CHK_PAD_DATA, 0xAA, 8, 0xCC, -1, false },
	{ "CC8", CAN_ISOTP_RX_PADDING | CAN_ISOTP_CHK_PAD_DATA, 0xAA, 8, 0xAA, 0xAB, false },
	/* RX_PADDING + CHK_PAD_LEN + CHK_PAD_DATA */
	{ "CC8", CAN_ISOTP_RX_PADDING | CAN_ISOTP_CHK_PAD_LEN | CAN_ISOTP_CHK_PAD_DATA, 0x55, 8, 0x55, -1, true },
	{ "CC8", CAN_ISOTP_RX_PADDING | CAN_ISOTP_CHK_PAD_LEN | CAN_ISOTP_CHK_PAD_DATA, 0x55, 8, 0x55, 0x54, false },
	{ "CC8", CAN_ISOTP_RX_PADDING | CAN_ISOTP_CHK_PAD_LEN | CAN_ISOTP_CHK_PAD_DATA, 0x55, 6, 0x55, -1, false },
	/* RX_PADDING only: no checks */
	{ "CC8", CAN_ISOTP_RX_PADDING, 0x55, 3, 0x00, -1, true },
	{ "CC8", CAN_ISOTP_RX_PADDING, 0x55, 8, 0x13, -1, true },
	/* CHK_PAD_DATA without RX_PADDING: no valid check => all dropped */
	{ "CC8", CAN_ISOTP_CHK_PAD_DATA, 0xCC, 3, 0xCC, -1, false },
	{ "CC8", CAN_ISOTP_CHK_PAD_DATA, 0xCC, 8, 0xCC, -1, false },
	/* CAN FD */
	{ "FD64", CAN_ISOTP_CHK_PAD_LEN, 0xCC, 3, 0xCC, -1, true },
	{ "FD64", CAN_ISOTP_CHK_PAD_LEN, 0xCC, 8, 0xCC, -1, false },
	{ "FD64", CAN_ISOTP_CHK_PAD_LEN, 0xCC, 12, 0xCC, -1, false },
	{ "FD64", CAN_ISOTP_RX_PADDING | CAN_ISOTP_CHK_PAD_LEN, 0xCC, 8, 0xCC, -1, true },
	{ "FD64", CAN_ISOTP_RX_PADDING | CAN_ISOTP_CHK_PAD_LEN, 0xCC, 12, 0xCC, -1, true },
	{ "FD64", CAN_ISOTP_RX_PADDING | CAN_ISOTP_CHK_PAD_LEN, 0xCC, 64, 0xCC, -1, true },
	{ "FD64", CAN_ISOTP_RX_PADDING | CAN_ISOTP_CHK_PAD_LEN, 0xCC, 3, 0xCC, -1, false },
	{ "FD64", CAN_ISOTP_RX_PADDING | CAN_ISOTP_CHK_PAD_LEN, 0xCC, 9, 0xCC, -1, false },
	{ "FD64", CAN_ISOTP_RX_PADDING | CAN_ISOTP_CHK_PAD_LEN, 0xCC, 13, 0xCC, -1, false },
	{ "FD64", CAN_ISOTP_RX_PADDING | CAN_ISOTP_CHK_PAD_DATA, 0xAA, 64, 0xAA, 0x00, false },
	/* CAN XL */
	{ "XL9-2048", CAN_ISOTP_CHK_PAD_LEN, 0xCC, 3, 0xCC, -1, true },
	{ "XL9-2048", CAN_ISOTP_CHK_PAD_LEN, 0xCC, 4, 0xCC, -1, false },
	{ "XL9-2048", CAN_ISOTP_RX_PADDING | CAN_ISOTP_CHK_PAD_LEN, 0xCC, 8, 0xCC, -1, true },
	{ "XL9-2048", CAN_ISOTP_RX_PADDING | CAN_ISOTP_CHK_PAD_LEN, 0xCC, 3, 0xCC, -1, false },
	/* FC with CAN_DL > 8: CAN XL N_PDUs are not padded => no check */
	{ "XL9-2048", CAN_ISOTP_RX_PADDING | CAN_ISOTP_CHK_PAD_LEN, 0xCC, 100, 0xCC, -1, true },
};

static void tx_fc_pad(struct ft_ctx *ctx, const void *param)
{
	unsigned int i;

	for (i = 0; i < sizeof(fc_pad_cases) / sizeof(fc_pad_cases[0]); i++) {
		const struct fc_pad_case *pc = &fc_pad_cases[i];
		struct ft_isotp_cfg c;
		struct ft_frame f;
		uint8_t buf[128];

		ft_log(ctx, "case %u: %s flags %03X rxpad %02X FC len %u pad %02X%s",
		       i, pc->mode, pc->flags, pc->rxpad, pc->fclen, pc->padval,
		       pc->ok ? " => accepted" : " => EBADMSG");

		cfg_wtd(&c, pc->mode);
		c.opts.flags |= pc->flags;
		c.opts.rxpad_content = pc->rxpad;
		if (!ft_need_if(ctx, c.iface))
			return;
		if (!txenv_open(ctx, &c))
			return;

		if (txenv_start(ctx, len_cfs(&env.e, 2))) {
			memset(buf, pc->padval, sizeof(buf));
			buf[0] = FT_PCI_FC | FT_FS_CTS;
			buf[1] = 0;
			buf[2] = 0;
			if (pc->last_byte >= 0)
				buf[pc->fclen - 1] = pc->last_byte;
			ft_frame_set(&f, &env.hrx, buf, pc->fclen);
			ft_peer_tx(ctx, &env.p, &f);

			if (pc->ok) {
				txenv_cfs(ctx, 1, env.n, NULL);
				txenv_result(ctx, env.len);
			} else {
				txenv_result(ctx, -EBADMSG);
				ft_peer_expect_none(ctx, &env.p, 20);
			}
		}

		txenv_close(ctx);
		FT_BAIL(ctx);
	}
}

static void tx_fc_idle(struct ft_ctx *ctx, const void *param)
{
	struct ft_isotp_cfg c;
	int fs;

	cfg_wtd(&c, NULL);
	if (!txenv_open(ctx, &c))
		return;

	for (fs = 0; fs < 16; fs++)
		txenv_fc(ctx, fs, 0, 0);

	ft_peer_expect_none(ctx, &env.p, 50);
	ft_dut_expect_noerr(ctx, env.s);
	ft_tx_pdu(ctx, env.s, &c, &env.p, env.data, 20, 0, 0);

	txenv_close(ctx);
}

static void tx_fc_sending(struct ft_ctx *ctx, const void *param)
{
	struct ft_isotp_cfg c;

	cfg_wtd(&c, NULL);
	if (!txenv_open(ctx, &c))
		return;

	if (!txenv_start(ctx, len_cfs(&env.e, 3)))
		goto out;

	/* STmin 50 ms: FCs received while sending CFs are ignored */
	txenv_fc(ctx, FT_FS_CTS, 0, 50);
	txenv_cfs(ctx, 1, 2, NULL);
	txenv_fc(ctx, FT_FS_OVFLW, 0, 0);
	txenv_fc(ctx, 0x0F, 0, 0);
	txenv_fc(ctx, FT_FS_WT, 0, 0);
	txenv_cfs(ctx, 2, env.n, NULL);
	txenv_result(ctx, env.len);
	ft_dut_expect_noerr(ctx, env.s);
out:
	txenv_close(ctx);
}

static void tx_fc_filter(struct ft_ctx *ctx, const void *param)
{
	struct ft_isotp_cfg c;
	struct ft_frame fc, f;
	int var = param ? FT_V_AE : FT_V_PLAIN;

	cfg_wtd(&c, NULL);
	ft_cfg_variant(&c, var);
	if (!txenv_open(ctx, &c))
		return;

	if (!txenv_start(ctx, 30))
		goto out;

	ft_enc_fc(&env.pe, &env.hrx, FT_FS_OVFLW, 0, 0, &fc);

	/* other CAN ID */
	f = fc;
	f.id = FT_DUT_RX_ID + 1;
	ft_peer_tx(ctx, &env.p, &f);
	/* 29 bit CAN ID with the same numeric value */
	f.id = FT_DUT_RX_ID | CAN_EFF_FLAG;
	ft_peer_tx(ctx, &env.p, &f);
	/* RTR frame */
	f.id = FT_DUT_RX_ID | CAN_RTR_FLAG;
	ft_peer_tx(ctx, &env.p, &f);
	/* the DUT tx_id (own frames) */
	f.id = FT_DUT_TX_ID;
	ft_peer_tx(ctx, &env.p, &f);
	/* other address extension */
	if (var == FT_V_AE) {
		f = fc;
		f.data[0] = 0xA6;
		ft_peer_tx(ctx, &env.p, &f);
	}

	ft_peer_expect_none(ctx, &env.p, 50);
	FT_CHECK(ctx, !ft_async_done(&env.a), "transfer terminated");
	FT_BAIL(ctx);

	txenv_fc(ctx, FT_FS_CTS, 0, 0);
	txenv_cfs(ctx, 1, env.n, NULL);
	txenv_result(ctx, env.len);
out:
	txenv_close(ctx);
}

static void tx_fc_mtu(struct ft_ctx *ctx, const void *param)
{
	static const char *modes[] = { "CC8", "FD64" };
	struct ft_isotp_cfg c;
	struct ft_frame fc;
	int i;

	for (i = 0; i < 2; i++) {
		cfg_wtd(&c, modes[i]);
		c.iface = FT_IF_FD;
		if (!txenv_open(ctx, &c))
			return;

		if (txenv_start(ctx, len_cfs(&env.e, 2))) {
			/* FC in the other CAN frame type is ignored */
			ft_enc_fc(&env.pe, &env.hrx, FT_FS_OVFLW, 0, 0, &fc);
			fc.type = (env.hrx.type == FT_CC) ? FT_FD : FT_CC;
			fc.flags = (fc.type == FT_FD) ? CANFD_FDF : 0;
			ft_peer_tx(ctx, &env.p, &fc);
			ft_peer_expect_none(ctx, &env.p, 50);

			txenv_fc(ctx, FT_FS_CTS, 0, 0);
			txenv_cfs(ctx, 1, env.n, NULL);
			txenv_result(ctx, env.len);
		}

		txenv_close(ctx);
		FT_BAIL(ctx);
	}
}

static void tx_fc_timeout(struct ft_ctx *ctx, const void *param)
{
	struct ft_isotp_cfg c;
	bool block = param != NULL;

	cfg_wtd(&c, NULL);
	if (!txenv_open(ctx, &c))
		return;

	if (!txenv_start(ctx, len_cfs(&env.e, 4)))
		goto out;

	if (block) {
		txenv_fc(ctx, FT_FS_CTS, 2, 0);
		txenv_cfs(ctx, 1, 3, NULL);
	}

	txenv_result(ctx, -ECOMM);
	ft_peer_expect_none(ctx, &env.p, 20);
	ft_dut_expect_noerr(ctx, env.s);

	/* late FC is ignored */
	txenv_fc(ctx, FT_FS_CTS, 0, 0);
	ft_peer_expect_none(ctx, &env.p, 50);
out:
	txenv_close(ctx);
}

/* ------------------------------------------------------------------------
 * broadcast modes
 * ------------------------------------------------------------------------
 */

struct bc_param {
	const char *mode;
	uint32_t flag;
};

static void tx_bc_seg(struct ft_ctx *ctx, const void *param)
{
	const struct bc_param *bp = param;
	static uint8_t data[FT_MAX_PDU];
	struct ft_isotp_cfg c;
	unsigned int lens[32];
	int i, n;

	cfg_wtd(&c, bp->mode);
	c.opts.flags |= bp->flag;
	if (!txenv_open(ctx, &c))
		return;

	n = ft_seg_lengths(&env.e, FT_MAX_PDU, lens, 32);
	for (i = 0; i < n; i++) {
		ft_pattern(data, lens[i], i);
		if (!ft_tx_pdu(ctx, env.s, &c, &env.p, data, lens[i], 0, 0))
			break;
	}

	txenv_close(ctx);
}

static void tx_bc_sf(struct ft_ctx *ctx, const void *param)
{
	const struct bc_param *bp = param;
	static uint8_t data[FT_MAX_PDU];
	struct ft_isotp_cfg c;
	unsigned int sfmax, len;
	ssize_t n;

	cfg_wtd(&c, bp->mode);
	c.opts.flags |= bp->flag;
	if (!txenv_open(ctx, &c))
		return;

	sfmax = ft_enc_sf_max(&env.e);
	for (len = 1; len <= sfmax; len += (len < 10 ? 1 : 97)) {
		ft_pattern(data, len, len);
		if (!ft_tx_pdu(ctx, env.s, &c, &env.p, data, len, 0, 0))
			goto out;
	}
	ft_tx_pdu(ctx, env.s, &c, &env.p, data, sfmax, 0, 0);

	/* PDUs which do not fit into a SF are rejected */
	n = ft_dut_send(ctx, env.s, data, sfmax + 1, 0);
	FT_CHECK(ctx, n == -EINVAL, "send(%u) %s", sfmax + 1, ft_errname(n));
	n = ft_dut_send(ctx, env.s, data, FT_MAX_PDU, 0);
	FT_CHECK(ctx, n == -EINVAL, "send(%u) %s", FT_MAX_PDU, ft_errname(n));
	ft_peer_expect_none(ctx, &env.p, 20);

	/* the socket is usable again */
	ft_tx_pdu(ctx, env.s, &c, &env.p, data, 1, 0, 0);
out:
	txenv_close(ctx);
}

static void tx_bc_norx(struct ft_ctx *ctx, const void *param)
{
	static const uint32_t flags[] = { CAN_ISOTP_SF_BROADCAST,
					  CAN_ISOTP_CF_BROADCAST,
					  CAN_ISOTP_MF_BROADCAST };
	struct ft_isotp_cfg c;
	struct ft_frame f;
	unsigned int i;

	for (i = 0; i < 3; i++) {
		cfg_wtd(&c, NULL);
		c.opts.flags |= flags[i];
		if (!txenv_open(ctx, &c))
			return;

		/* SF, FF and MF to the rx_id are not processed */
		ft_frame_bytes(&f, &env.hrx, 3, 0x02, 0x11, 0x22);
		ft_peer_tx(ctx, &env.p, &f);
		ft_frame_bytes(&f, &env.hrx, 8, 0x10, 0x14, 1, 2, 3, 4, 5, 6);
		ft_peer_tx(ctx, &env.p, &f);
		ft_frame_bytes(&f, &env.hrx, 8, 0x40, 0x14, 1, 2, 3, 4, 5, 6);
		ft_peer_tx(ctx, &env.p, &f);
		ft_peer_expect_none(ctx, &env.p, 50);
		ft_dut_expect_nopdu(ctx, env.s, 10);
		ft_dut_expect_noerr(ctx, env.s);

		txenv_close(ctx);
		FT_BAIL(ctx);
	}
}

static void tx_bc_fcignored(struct ft_ctx *ctx, const void *param)
{
	struct ft_isotp_cfg c;
	struct ft_frame fc;

	cfg_wtd(&c, NULL);
	c.opts.flags |= CAN_ISOTP_CF_BROADCAST | CAN_ISOTP_FORCE_TXSTMIN;
	c.set_tx_stmin = true;
	c.tx_stmin = 20000000; /* 20 ms */
	if (!txenv_open(ctx, &c))
		return;

	if (!txenv_start(ctx, len_cfs(&env.e, 4)))
		goto out;

	ft_enc_fc(&env.pe, &env.hrx, FT_FS_OVFLW, 0, 0, &fc);
	ft_peer_tx(ctx, &env.p, &fc);
	ft_enc_fc(&env.pe, &env.hrx, FT_FS_CTS, 1, 0, &fc);
	ft_peer_tx(ctx, &env.p, &fc);
	txenv_cfs(ctx, 1, env.n, NULL);
	txenv_result(ctx, env.len);
	ft_dut_expect_noerr(ctx, env.s);
out:
	txenv_close(ctx);
}

/* ------------------------------------------------------------------------
 * half duplex
 * ------------------------------------------------------------------------
 */

static void tx_hd_rx_during_tx(struct ft_ctx *ctx, const void *param)
{
	bool hd = param != NULL;
	struct ft_isotp_cfg c;
	struct ft_frame sf;
	uint8_t pdu[3] = { 0x11, 0x22, 0x33 };

	cfg_wtd(&c, NULL);
	if (hd)
		c.opts.flags |= CAN_ISOTP_HALF_DUPLEX;
	if (!txenv_open(ctx, &c))
		return;

	ft_frame_bytes(&sf, &env.hrx, 4, 0x03, 0x11, 0x22, 0x33);

	if (!txenv_start(ctx, 20))
		goto out;

	/* SF received while waiting for the FC */
	ft_peer_tx(ctx, &env.p, &sf);
	if (hd)
		ft_dut_expect_nopdu(ctx, env.s, 50);
	else
		ft_dut_expect_pdu(ctx, env.s, pdu, 3, 200);

	txenv_fc(ctx, FT_FS_CTS, 0, 0);
	txenv_cfs(ctx, 1, env.n, NULL);
	txenv_result(ctx, env.len);

	/* idle again => SF is received */
	ft_peer_tx(ctx, &env.p, &sf);
	ft_dut_expect_pdu(ctx, env.s, pdu, 3, 200);
out:
	txenv_close(ctx);
}

static void tx_hd_fc_during_rx(struct ft_ctx *ctx, const void *param)
{
	bool hd = param != NULL;
	struct ft_isotp_cfg c;
	struct ft_frame *rf;
	struct ft_frame dfc;
	uint8_t pdu[20];
	int rn, i;

	cfg_wtd(&c, NULL);
	if (hd)
		c.opts.flags |= CAN_ISOTP_HALF_DUPLEX;
	if (!txenv_open(ctx, &c))
		return;

	/* peer starts a reception on the DUT */
	ft_pattern(pdu, sizeof(pdu), 0x77);
	rn = ft_enc_pdu(&env.pe, &env.hrx, pdu, sizeof(pdu), &rf);
	ft_enc_fc(&env.e, &env.htx, FT_FS_CTS, 0, 0, &dfc);
	ft_peer_tx(ctx, &env.p, &rf[0]);
	ft_peer_expect(ctx, &env.p, &dfc, 500);

	/* DUT starts a transmission */
	if (!txenv_start(ctx, 20))
		goto out;

	txenv_fc(ctx, FT_FS_CTS, 0, 0);
	if (hd) {
		/* FC is dropped while the reception is active ... */
		ft_peer_expect_none(ctx, &env.p, 50);
		/* ... and CFs are dropped while the transmission is active */
		for (i = 1; i < rn; i++)
			ft_peer_tx(ctx, &env.p, &rf[i]);
		ft_dut_expect_nopdu(ctx, env.s, 50);
		/* both transfers time out, the tx error is reported last */
		txenv_result(ctx, -ECOMM);
		ft_peer_expect_none(ctx, &env.p, 20);
		ft_dut_expect_nopdu(ctx, env.s, 20);
	} else {
		txenv_cfs(ctx, 1, env.n, NULL);
		for (i = 1; i < rn; i++)
			ft_peer_tx(ctx, &env.p, &rf[i]);
		ft_dut_expect_pdu(ctx, env.s, pdu, sizeof(pdu), 200);
		txenv_result(ctx, env.len);
	}
out:
	free(rf);
	txenv_close(ctx);
}

/* ------------------------------------------------------------------------
 * misc
 * ------------------------------------------------------------------------
 */

static void tx_eff(struct ft_ctx *ctx, const void *param)
{
	static uint8_t data[300];
	struct ft_isotp_cfg c;

	cfg_wtd(&c, param);
	c.tx_id = CAN_EFF_FLAG | 0x18DA00F1;
	c.rx_id = CAN_EFF_FLAG | 0x18DAF100;
	if (!txenv_open(ctx, &c))
		return;

	ft_pattern(data, sizeof(data), 3);
	ft_tx_pdu(ctx, env.s, &c, &env.p, data, 5, 0, 0);
	ft_tx_pdu(ctx, env.s, &c, &env.p, data, sizeof(data), 0, 0);

	txenv_close(ctx);
}

static void tx_fd_flags(struct ft_ctx *ctx, const void *param)
{
	static const uint8_t flags[] = { CANFD_BRS, CANFD_ESI,
					 CANFD_BRS | CANFD_ESI, CANFD_FDF,
					 0xFF };
	static uint8_t data[200];
	struct ft_isotp_cfg c;
	unsigned int i;

	for (i = 0; i < sizeof(flags); i++) {
		cfg_wtd(&c, "FD64");
		c.ll.tx_flags = flags[i];
		ft_log(ctx, "tx_flags %02X", flags[i]);
		if (!txenv_open(ctx, &c))
			return;
		ft_pattern(data, sizeof(data), i);
		ft_tx_pdu(ctx, env.s, &c, &env.p, data, 30, 0, 0);
		ft_tx_pdu(ctx, env.s, &c, &env.p, data, sizeof(data), 0, 0);
		txenv_close(ctx);
		FT_BAIL(ctx);
	}
}

static void tx_wtd_block(struct ft_ctx *ctx, const void *param)
{
	struct ft_isotp_cfg c;

	cfg_wtd(&c, NULL);
	if (!txenv_open(ctx, &c))
		return;

	if (!txenv_start(ctx, len_cfs(&env.e, 3)))
		goto out;

	ft_sleep_ms(200);
	FT_CHECK(ctx, !ft_async_done(&env.a),
		 "send() returned before the transfer was done");
	txenv_fc(ctx, FT_FS_CTS, 0, 0);
	txenv_cfs(ctx, 1, env.n, NULL);
	txenv_result(ctx, env.len);
out:
	txenv_close(ctx);
}

static void tx_nowtd(struct ft_ctx *ctx, const void *param)
{
	struct ft_isotp_cfg c;
	struct ft_frame f;
	ssize_t n;
	int64_t t0;

	ft_cfg_init(&c);
	if (!txenv_open(ctx, &c))
		return;

	ft_pattern(env.data, 20, 0);
	t0 = ft_now_ns();
	n = ft_dut_send(ctx, env.s, env.data, 20, 0);
	FT_CHECK(ctx, n == 20, "send() %zd", n);
	FT_CHECK(ctx, ft_now_ns() - t0 < 50000000LL,
		 "send() did not return immediately");

	if (ft_peer_next(ctx, &env.p, &f, 500))
		FT_CHECK(ctx, f.data[0] == 0x10 && f.data[1] == 20,
			 "no FF (%02X %02X)", f.data[0], f.data[1]);
	else
		ft_fail(ctx, "no FF received");

	/* the result is reported asynchronously as socket error */
	txenv_fc(ctx, FT_FS_OVFLW, 0, 0);
	ft_dut_expect_err(ctx, env.s, EMSGSIZE, 200, NULL);

	txenv_close(ctx);
}

static void tx_wtd_err(struct ft_ctx *ctx, const void *param)
{
	struct ft_isotp_cfg c;

	cfg_wtd(&c, NULL);
	if (!txenv_open(ctx, &c))
		return;

	/* errors are returned by send() and the socket error is cleared */
	if (txenv_start(ctx, 20)) {
		txenv_fc(ctx, FT_FS_OVFLW, 0, 0);
		txenv_result(ctx, -EMSGSIZE);
		ft_dut_expect_noerr(ctx, env.s);
	}

	if (txenv_start(ctx, 20)) {
		txenv_fc(ctx, 7, 0, 0);
		txenv_result(ctx, -EBADMSG);
		ft_dut_expect_noerr(ctx, env.s);
	}

	/* SF: send() returns after the local echo */
	ft_tx_pdu(ctx, env.s, &c, &env.p, env.data, 7, 0, 0);

	txenv_close(ctx);
}

/* ------------------------------------------------------------------------
 * signals
 * ------------------------------------------------------------------------
 */

static void sig_noop(int sig)
{
	(void)sig;
}

static void sig_setup(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_noop;	/* no SA_RESTART */
	sigaction(SIGUSR1, &sa, NULL);
}

static void tx_sig_wtd(struct ft_ctx *ctx, const void *param)
{
	struct ft_isotp_cfg c;

	sig_setup();
	cfg_wtd(&c, NULL);
	if (!txenv_open(ctx, &c))
		return;

	if (!txenv_start(ctx, 30))
		goto out;

	/* send() waits for the end of the transfer => interrupt it */
	ft_sleep_ms(50);
	pthread_kill(env.a.thread, SIGUSR1);
	txenv_result(ctx, -EINTR);

	/* the transfer has been aborted: a late FC is ignored */
	txenv_fc(ctx, FT_FS_CTS, 0, 0);
	ft_peer_expect_none(ctx, &env.p, 50);
	ft_dut_expect_noerr(ctx, env.s);

	/* the socket is idle */
	ft_tx_pdu(ctx, env.s, &c, &env.p, env.data, 5, 0, 0);
out:
	txenv_close(ctx);
}

static void tx_sig_claim(struct ft_ctx *ctx, const void *param)
{
	struct ft_isotp_cfg c;
	struct ft_async a2;
	uint8_t pdu2[5] = { 1, 2, 3, 4, 5 };

	sig_setup();
	ft_cfg_init(&c);
	if (!txenv_open(ctx, &c))
		return;

	/* 1st transfer waits for the FC */
	if (!txenv_start(ctx, 30))
		goto out;
	txenv_join(ctx);

	/* 2nd send() blocks until the 1st transfer is done => interrupt */
	ft_async_send(&a2, env.s, pdu2, sizeof(pdu2), 0);
	ft_sleep_ms(50);
	FT_CHECK(ctx, !ft_async_done(&a2), "2nd send() did not block");
	pthread_kill(a2.thread, SIGUSR1);
	if (ft_async_join(ctx, &a2, 1000))
		FT_CHECK(ctx, a2.ret == -EINTR, "2nd send() %zd %s", a2.ret,
			 ft_errname(a2.ret));

	/* the 1st transfer is not affected */
	txenv_fc(ctx, FT_FS_CTS, 0, 0);
	txenv_cfs(ctx, 1, env.n, NULL);
	ft_peer_expect_none(ctx, &env.p, 50);
	ft_dut_expect_noerr(ctx, env.s);
out:
	txenv_close(ctx);
}

/* ------------------------------------------------------------------------
 * test table
 * ------------------------------------------------------------------------
 */

#define T(i, t, fl, f, p, rq, rf, is)					\
	{ .id = i, .title = t, .req = rq, .ref = rf, .iso = is,		\
	  .flags = fl, .fn = f, .param = p }

static const char seg_req[] =
	"The DUT segments PDUs of all relevant lengths (1, 2, SF boundaries, FF with 1..n CFs, SN wrap around, 4095 (12 bit FF_DL), 4096 (32 bit FF_DL escape), 8300) into SF/FF/CF frames with the exact layout of the reference encoder: "
	"SF with 4 bit SF_DL for TX_DL 8 or SF_DL <= 7-ae, else SF with escape (0x00 + SF_DL byte for CAN FD PDUs, 0x08|SF_DL>>8 + low byte for CAN XL PDUs); FF uses the full TX_DL with 12 bit FF_DL (<= 4095) or 32 bit FF_DL; CFs carry SN 1..15,0,.. and use TX_DL except the last one; "
	"the last CF/SF is padded to the next CAN FD DLC length with CAN_ISOTP_TX_PADDING (content txpad_content) or for CAN FD PDUs > 8 byte (content 0xCC). Block size (FC.BS) is honoured. With CAN_ISOTP_WAIT_TX_DONE send() returns the PDU length after the last frame was sent. CAN FD frames carry FDF|ll.tx_flags, CAN XL frames the configured prio/VCID/flags/SDT/AF.";

static const char seg_ref[] =
	"protocoltx.c:isotp_sendmsg(), isotp_sf_ff_pci(), isotp_ff_pci(), isotp_send_cframe(), get_padlength(), isotp_fill_frame_head(), protocolrx.c:isotp_rcv_fc(), isotp_rcv_echo()";

#define SEG(m, v)							\
	T("TX-SEG-" m "-" #v, "segmentation " m " " #v, 0, tx_seg,	\
	  &((const struct seg_param){ m, FT_V_##v }), seg_req, seg_ref, NULL)

#define SEG4(m) SEG(m, PLAIN), SEG(m, AE), SEG(m, PAD), SEG(m, AEPAD)
#define SEG2(m) SEG(m, PLAIN), SEG(m, AE)

static const char bc_seg_req[] =
	"With CAN_ISOTP_CF_BROADCAST (FF N_PCI 0x1) or CAN_ISOTP_MF_BROADCAST (multicast FF N_PCI 0x4) all CFs are sent without waiting for FC frames (separation time = frame_txtime or CAN_ISOTP_TX_STMIN with FORCE_TXSTMIN). SFs are sent normally.";

#define BCSEG(m, f, fn)							\
	T("TX-BC-" #fn "-" m, #fn " broadcast segmentation " m, 0,	\
	  tx_bc_seg, &((const struct bc_param){ m, f }), bc_seg_req,	\
	  "protocoltx.c:isotp_sendmsg() CF/MF broadcast, isotp_ff_pci()", NULL)

static const char bc_sf_req[] =
	"With CAN_ISOTP_SF_BROADCAST only PDUs fitting into a single frame can be sent, larger PDUs are rejected with EINVAL without sending a frame.";

#define BCSF(m)								\
	T("TX-BC-SF-" m, "SF broadcast " m, 0, tx_bc_sf,		\
	  &((const struct bc_param){ m, CAN_ISOTP_SF_BROADCAST }),	\
	  bc_sf_req, "protocoltx.c:isotp_sendmsg()", NULL)

static const char fc_block_req[] =
	"After a FC with BS = n the DUT sends n CFs and waits for the next FC before sending the next block.";

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
	SEG4("FD64BRS"),
	SEG4("XL9-8"),
	SEG2("XL9-9"),
	SEG2("XL9-12"),
	SEG2("XL9-64"),
	SEG2("XL9-65"),
	SEG2("XL9-255"),
	SEG2("XL9-256"),
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

	T("TX-PAD-001", "mandatory CAN FD padding content", 0,
	  tx_pad_fd_default, NULL,
	  "Without CAN_ISOTP_TX_PADDING CAN FD frames > 8 byte are padded with 0xCC (not txpad_content), frames <= 8 byte are not padded.",
	  "protocoltx.c:get_padlength()", NULL),

	T("TX-FC-001-CC8", "FC block size CC8", 0, tx_fc_block, "CC8",
	  fc_block_req, "protocolrx.c:isotp_rcv_fc(), protocoltx.c:isotp_rcv_echo()", NULL),
	T("TX-FC-001-FD64", "FC block size FD64", 0, tx_fc_block, "FD64",
	  fc_block_req, "protocolrx.c:isotp_rcv_fc(), protocoltx.c:isotp_rcv_echo()", NULL),
	T("TX-FC-001-XL9-256", "FC block size XL9-256", 0, tx_fc_block,
	  "XL9-256", fc_block_req,
	  "protocolrx.c:isotp_rcv_fc(), protocoltx.c:isotp_rcv_echo()", NULL),
	T("TX-FC-002", "BS/STmin only from the first FC", 0, tx_fc_static,
	  NULL,
	  "Without CAN_ISOTP_DYN_FC_PARMS BS and STmin are taken from the first FC of a transfer only, the values in later FCs are ignored.",
	  "protocolrx.c:isotp_rcv_fc() ISOTP_WAIT_FIRST_FC", NULL),
	T("TX-FC-003", "dynamic BS/STmin (DYN_FC_PARMS)", 0, tx_fc_dyn, NULL,
	  "With CAN_ISOTP_DYN_FC_PARMS BS and STmin are taken from every FC.",
	  "protocolrx.c:isotp_rcv_fc() CAN_ISOTP_DYN_FC_PARMS", NULL),
	T("TX-FC-004", "FC wait (WT)", 0, tx_fc_wait, NULL,
	  "FC.WT stops the sender until a FC.CTS arrives; each FC.WT restarts the N_Bs timer.",
	  "protocolrx.c:isotp_rcv_fc() ISOTP_FC_WT", NULL),
	T("TX-FC-005", "unlimited number of FC.WT", FT_SLOW, tx_fc_wait,
	  "many",
	  "The sender accepts any number of FC.WT frames (here 25 within 1.5 s > N_Bs) as long as each arrives within N_Bs.",
	  "protocolrx.c:isotp_rcv_fc() ISOTP_FC_WT",
	  "REVIEW: there is no N_WFTmax limit on the sender side (ISO 15765-2 defines N_WFTmax for the receiver only); CAN_ISOTP_RECV_FC.wftmax is stored but unused and the receiver never sends FC.WT."),
	T("TX-FC-006", "N_Bs timeout after FC.WT", FT_SLOW, tx_fc_wait_timeout,
	  NULL,
	  "Without a further FC after FC.WT the transfer is aborted after N_Bs (1 s) with ECOMM.",
	  "protocolrx.c:isotp_rcv_fc(), hrtimer.c:isotp_tx_timeout()", NULL),
	T("TX-FC-007", "FC overflow on first FC", 0, tx_fc_ovflw, NULL,
	  "FC.OVFLW aborts the transfer with EMSGSIZE, no CF is sent. The socket can be used for the next PDU.",
	  "protocolrx.c:isotp_rcv_fc() ISOTP_FC_OVFLW", NULL),
	T("TX-FC-008", "FC overflow after a block", 0, tx_fc_ovflw, "block",
	  "FC.OVFLW after a block also aborts the transfer with EMSGSIZE.",
	  "protocolrx.c:isotp_rcv_fc() ISOTP_FC_OVFLW",
	  "REVIEW: ISO 15765-2 only allows FC.OVFLW as response to a FF."),
	T("TX-FC-009", "reserved flow status", 0, tx_fc_reserved, NULL,
	  "A FC with reserved flow status 3..15 aborts the transfer with EBADMSG.",
	  "protocolrx.c:isotp_rcv_fc() default case", NULL),
	T("TX-FC-010-plain", "FC too short", 0, tx_fc_short,
	  &((const struct fc_short_param){ FT_V_PLAIN }),
	  "A frame without N_PCI (CAN_DL < 1, +1 with extended addressing) is no N_PDU and is ignored. A FC with N_PCI and CAN_DL < 3 (+1 with extended addressing) aborts the transfer with EBADMSG. Data bytes beyond CAN_DL are not used.",
	  "protocolrx.c:isotp_rcv() N_PCI length check, isotp_rcv_fc()",
	  "DEVIATION (if observed): a FC without N_PCI is processed with data beyond CAN_DL (EBADMSG), fixed by xl-isotp split_v2 patch 14."),
	T("TX-FC-010-ae", "FC too short (ext. addressing)", 0, tx_fc_short,
	  &((const struct fc_short_param){ FT_V_AE }),
	  "A frame without N_PCI (CAN_DL < 1, +1 with extended addressing) is no N_PDU and is ignored. A FC with N_PCI and CAN_DL < 3 (+1 with extended addressing) aborts the transfer with EBADMSG. Data bytes beyond CAN_DL are not used.",
	  "protocolrx.c:isotp_rcv() N_PCI length check, isotp_rcv_fc()",
	  "DEVIATION (if observed): a FC without N_PCI is processed with data beyond CAN_DL (EBADMSG), fixed by xl-isotp split_v2 patch 14."),
	T("TX-FC-011", "FC padding checks", 0, tx_fc_pad, NULL,
	  "With CAN_ISOTP_CHK_PAD_LEN (without RX_PADDING) a FC must have the optimized length 3 (+ae). With RX_PADDING|CHK_PAD_LEN the FC length must be a valid CAN FD DLC length >= 8. With RX_PADDING|CHK_PAD_DATA all bytes behind the FC content must be rxpad_content. CHK_PAD_DATA without RX_PADDING rejects every FC. Failing FCs abort the transfer with EBADMSG.",
	  "protocolrx.c:isotp_rcv_fc(), chk_pad_fail(), chk_optimized_fail()",
	  "REVIEW: CAN_ISOTP_CHK_PAD_DATA without CAN_ISOTP_RX_PADDING makes every frame fail the check (configuration not rejected)."),
	T("TX-FC-012", "FC in idle state", 0, tx_fc_idle, NULL,
	  "FC frames received without an active transfer are ignored silently.",
	  "protocolrx.c:isotp_rcv_fc()", NULL),
	T("TX-FC-013", "FC while sending CFs", 0, tx_fc_sending, NULL,
	  "FC frames received while the sender is not waiting for a FC (sending CFs) are ignored silently.",
	  "protocolrx.c:isotp_rcv_fc()",
	  "REVIEW: ISO 15765-2 handles an unexpected FC as N_UNEXP_PDU (ignored) - matches."),
	T("TX-FC-014-plain", "FC CAN ID filter", 0, tx_fc_filter, NULL,
	  "Only FC frames with exactly the rx_id (no EFF/RTR variants) and the rx extended address are processed.",
	  "af_can.c:can_rcv_filter(), protocolrx.c:isotp_check_frame_head(), isotp_rcv()", NULL),
	T("TX-FC-014-ae", "FC CAN ID + address filter", 0, tx_fc_filter,
	  "ae",
	  "Only FC frames with exactly the rx_id (no EFF/RTR variants) and the rx extended address are processed.",
	  "af_can.c:can_rcv_filter(), protocolrx.c:isotp_check_frame_head(), isotp_rcv()", NULL),
	T("TX-FC-015", "FC frame type (MTU) filter", 0, tx_fc_mtu, NULL,
	  "A CAN CC socket ignores CAN FD FC frames and a CAN FD socket ignores CAN CC FC frames (strict separation by the LL mtu).",
	  "protocolrx.c:isotp_check_frame_head()", NULL),
	T("TX-FC-016", "N_Bs timeout after FF", FT_SLOW, tx_fc_timeout, NULL,
	  "Without FC after the FF the transfer is aborted with ECOMM after N_Bs (1 s + frame_txtime). A late FC is ignored.",
	  "protocoltx.c:isotp_sendmsg(), hrtimer.c:isotp_tx_timeout()", NULL),
	T("TX-FC-017", "N_Bs timeout after a block", FT_SLOW, tx_fc_timeout,
	  "block",
	  "Without FC after a block the transfer is aborted with ECOMM after N_Bs (1 s).",
	  "protocoltx.c:isotp_rcv_echo(), hrtimer.c:isotp_tx_timeout()", NULL),

	BCSEG("CC8", CAN_ISOTP_CF_BROADCAST, CF),
	BCSEG("FD64", CAN_ISOTP_CF_BROADCAST, CF),
	BCSEG("XL9-2048", CAN_ISOTP_CF_BROADCAST, CF),
	BCSEG("CC8", CAN_ISOTP_MF_BROADCAST, MF),
	BCSEG("FD64", CAN_ISOTP_MF_BROADCAST, MF),
	BCSEG("XL9-2048", CAN_ISOTP_MF_BROADCAST, MF),
	BCSF("CC8"),
	BCSF("FD64"),
	BCSF("XL9-2048"),
	T("TX-BC-001", "broadcast sockets do not receive", 0, tx_bc_norx,
	  NULL,
	  "Sockets with SF/CF/MF broadcast flags do not register the rx_id: no PDU reception and no FC frames.",
	  "protocolrx.c:isotp_register_rxid(), isotp.c:isotp_bind()", NULL),
	T("TX-BC-002", "CF broadcast ignores FC frames", 0, tx_bc_fcignored,
	  NULL,
	  "A CF broadcast transfer is not influenced by FC frames.",
	  "protocolrx.c:isotp_register_rxid()", NULL),

	T("TX-HD-001", "full duplex: SF reception during tx", 0,
	  tx_hd_rx_during_tx, NULL,
	  "Without CAN_ISOTP_HALF_DUPLEX a SF is received while a transmission waits for a FC.",
	  "protocolrx.c:isotp_rcv()", NULL),
	T("TX-HD-002", "half duplex: no reception during tx", 0,
	  tx_hd_rx_during_tx, "hd",
	  "With CAN_ISOTP_HALF_DUPLEX all non-FC frames are dropped while a transmission is active.",
	  "protocolrx.c:isotp_rcv() CAN_ISOTP_HALF_DUPLEX", NULL),
	T("TX-HD-003", "full duplex: FC during reception", 0,
	  tx_hd_fc_during_rx, NULL,
	  "Without CAN_ISOTP_HALF_DUPLEX a FC for the own transmission is processed while a reception is active.",
	  "protocolrx.c:isotp_rcv()", NULL),
	T("TX-HD-004", "half duplex: no FC during reception", FT_SLOW,
	  tx_hd_fc_during_rx, "hd",
	  "With CAN_ISOTP_HALF_DUPLEX FC frames are dropped while a reception is active and CFs are dropped while a transmission is active. Simultaneous transfers in both directions therefore block each other until both time out (tx: ECOMM, rx: ETIMEDOUT overwritten by the later ECOMM socket error).",
	  "protocolrx.c:isotp_rcv() CAN_ISOTP_HALF_DUPLEX", NULL),

	T("TX-ID-001-CC8", "29 bit CAN IDs CC8", 0, tx_eff, "CC8",
	  "29 bit CAN IDs (CAN_EFF_FLAG) are used for tx_id and rx_id.",
	  "protocoltx.c:isotp_fill_frame_head()", NULL),
	T("TX-ID-001-FD64", "29 bit CAN IDs FD64", 0, tx_eff, "FD64",
	  "29 bit CAN IDs (CAN_EFF_FLAG) are used for tx_id and rx_id.",
	  "protocoltx.c:isotp_fill_frame_head()", NULL),
	T("TX-FL-001", "CAN FD tx_flags", 0, tx_fd_flags, NULL,
	  "The LL tx_flags are copied into each CAN FD frame (CANFD_FDF is added by the CAN core), also undefined bits.",
	  "protocoltx.c:isotp_fill_frame_head(), af_can.c:can_send()",
	  "REVIEW: undefined CAN FD flags and CANFD_ESI are sent as configured."),
	T("TX-WTD-001", "WAIT_TX_DONE blocks until done", 0, tx_wtd_block,
	  NULL,
	  "With CAN_ISOTP_WAIT_TX_DONE send() blocks until the transfer is complete and returns the PDU length.",
	  "protocoltx.c:isotp_sendmsg() wait_tx_done", NULL),
	T("TX-WTD-002", "send() without WAIT_TX_DONE", 0, tx_nowtd, NULL,
	  "Without CAN_ISOTP_WAIT_TX_DONE send() returns the PDU length immediately after the first frame was sent.",
	  "protocoltx.c:isotp_sendmsg()", NULL),
	T("TX-WTD-003", "WAIT_TX_DONE error results", 0, tx_wtd_err, NULL,
	  "With CAN_ISOTP_WAIT_TX_DONE transfer errors (EMSGSIZE, EBADMSG) are returned by send() and the pending socket error is cleared. A SF send() returns after the local echo.",
	  "protocoltx.c:isotp_sendmsg() isotp_get_tx_result(), sock_error()", NULL),
	T("TX-SIG-001", "signal during WAIT_TX_DONE", 0, tx_sig_wtd, NULL,
	  "A signal interrupting send() while waiting for the end of the own transfer (CAN_ISOTP_WAIT_TX_DONE) aborts the transfer: send() returns EINTR, the timers are stopped, later FCs are ignored and the socket is idle.",
	  "protocoltx.c:isotp_sendmsg() err_event_drop", NULL),
	T("TX-SIG-002", "signal while waiting for a busy socket", 0,
	  tx_sig_claim, NULL,
	  "A signal interrupting a send() which waits for the end of another transfer returns EINTR without sending; the active transfer continues.",
	  "protocoltx.c:isotp_sendmsg() wait_event_interruptible() in the claim loop", NULL),
};

int main(int argc, char **argv)
{
	return ft_main(argc, argv, "tx", tests,
		       sizeof(tests) / sizeof(tests[0]));
}
