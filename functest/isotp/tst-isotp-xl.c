// SPDX-License-Identifier: (GPL-2.0-only OR BSD-3-Clause)
/*
 * tst-isotp-xl.c - CAN_ISOTP CAN XL specific functionality
 *
 * CAN XL frame header content (priority, VCID, flags, SDT, acceptance
 * field), reception filtering, SF/FF formats in CAN XL frames, CiA 611-1
 * SDT 6/7 tunneling modes and CAN XL interface MTUs.
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

struct xlenv {
	struct ft_isotp_cfg c;
	int s;
	struct ft_peer p;
	struct ft_enc de, pe;
	struct ft_frame htx, hrx;
};

static struct xlenv env;

static bool xlenv_open(struct ft_ctx *ctx, const struct ft_isotp_cfg *c)
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

static void xlenv_close(void)
{
	ft_peer_close(&env.p);
	if (env.s >= 0)
		close(env.s);
	env.s = -1;
}

static void cfg_xl(struct ft_isotp_cfg *c, const char *mode)
{
	ft_cfg_init(c);
	ft_cfg_mode(c, ft_mode_by_name(mode));
	c->opts.flags |= CAN_ISOTP_WAIT_TX_DONE;
}

/* ------------------------------------------------------------------------
 * CAN XL frame header (tx)
 * ------------------------------------------------------------------------
 */

static void xl_hdr_tx(struct ft_ctx *ctx, const void *param)
{
	static const uint8_t flags[] = {
		CANXL_XLF, CANXL_XLF | CANXL_SEC, CANXL_XLF | CANXL_RRS,
		CANXL_XLF | CANXL_SEC | CANXL_RRS,
	};
	static const uint8_t vcids[] = { 0x00, 0x01, 0xAB, 0xFF };
	static const canid_t addrs[] = {
		0x000, 0x123, 0x7FF, CAN_EFF_FLAG | 0x0, CAN_EFF_FLAG | 0x12345,
		CAN_EFF_FLAG | 0x1FFFFFFF,
	};
	static const struct {
		const char *mode;
		uint8_t ll_flags;
	} sdts[] = {
		{ "XL9-64", 0 }, { "XL7-64", 0 }, { "XL7-64", CANFD_BRS },
		{ "XL6-8", 0 },
	};
	static const canid_t prios[] = { 0x000, 0x7FF };
	static uint8_t data[200];
	struct ft_isotp_cfg c;
	unsigned int i;

	ft_pattern(data, sizeof(data), 0x33);

	for (i = 0; i < 4 * 4 * 6 * 4; i++) {
		unsigned int fi = i % 4, vi = (i / 4) % 4;
		unsigned int ai = (i / 16) % 6, si = (i / 96) % 4;

		/* reduce the number of combinations */
		if (fi != vi && (fi + ai) % 2)
			continue;

		cfg_xl(&c, sdts[si].mode);
		c.ll.tx_flags = sdts[si].ll_flags;
		c.xl.tx_flags = flags[fi];
		c.xl.rx_flags = flags[(fi + 1) % 4];
		c.xl.tx_vcid = vcids[vi];
		c.xl.rx_vcid = vcids[(vi + 2) % 4];
		c.xl.tx_addr = addrs[ai];
		c.xl.rx_addr = addrs[(ai + 3) % 6];
		c.tx_id = prios[i % 2];
		c.rx_id = 0x555;

		ft_log(ctx, "%s ll_flags %02X tx_flags %02X vcid %02X addr %08X prio %03X",
		       sdts[si].mode, sdts[si].ll_flags, flags[fi], vcids[vi],
		       addrs[ai], c.tx_id);

		if (!xlenv_open(ctx, &c))
			return;

		/* SF, FF + CF (FC with the rx header) */
		ft_tx_pdu(ctx, env.s, &c, &env.p, data, 5, 0, 0);
		ft_tx_pdu(ctx, env.s, &c, &env.p, data,
			  ft_cfg_tx_dl(&c) + 10, 0, 0);
		xlenv_close();
		FT_BAIL(ctx);
	}
}

/* ------------------------------------------------------------------------
 * CAN XL reception filter
 * ------------------------------------------------------------------------
 */

static bool xl_rx_sf(struct ft_ctx *ctx, const struct ft_frame *hdr,
		     bool accept, const char *what)
{
	uint8_t pdu[5] = { 1, 2, 3, 4, 5 };
	struct ft_frame f;

	ft_log(ctx, "%s => %s", what, accept ? "accepted" : "ignored");
	ft_frame_bytes(&f, hdr, 6, 0x05, 1, 2, 3, 4, 5);
	if (!ft_peer_tx(ctx, &env.p, &f))
		return false;

	if (accept)
		return ft_dut_expect_pdu(ctx, env.s, pdu, 5, 200);

	return ft_dut_expect_nopdu(ctx, env.s, 30);
}

static void xl_rx_filter(struct ft_ctx *ctx, const void *param)
{
	struct ft_isotp_cfg c;
	struct ft_frame h;

	cfg_xl(&c, "XL9-64");
	c.xl.rx_flags = CANXL_XLF | CANXL_SEC;
	c.xl.rx_vcid = 0x34;
	c.xl.rx_addr = CAN_EFF_FLAG | 0x54321;
	if (!xlenv_open(ctx, &c))
		return;

	xl_rx_sf(ctx, &env.hrx, true, "matching header");

	h = env.hrx;
	h.id = (h.id & ~CANXL_PRIO_MASK) | 0x322;
	xl_rx_sf(ctx, &h, false, "other priority");

	h = env.hrx;
	h.id = 0x321 | (0x35 << CANXL_VCID_OFFSET);
	xl_rx_sf(ctx, &h, false, "other VCID");
	h.id = 0x321;
	xl_rx_sf(ctx, &h, false, "no VCID");

	h = env.hrx;
	h.flags = CANXL_XLF;
	xl_rx_sf(ctx, &h, false, "flags XLF (SEC missing)");
	h.flags = CANXL_XLF | CANXL_SEC | CANXL_RRS;
	xl_rx_sf(ctx, &h, false, "flags XLF|SEC|RRS");
	h.flags = CANXL_XLF | CANXL_SEC | 0x04;
	xl_rx_sf(ctx, &h, false, "flags XLF|SEC|0x04");

	h = env.hrx;
	h.af = 0x54321;
	xl_rx_sf(ctx, &h, false, "AF without 29 bit flag");
	h.af = FT_AF_SDT_EFF | 0x54322;
	xl_rx_sf(ctx, &h, false, "other AF");
	h.af = CAN_EFF_FLAG | 0x54321;
	xl_rx_sf(ctx, &h, false, "AF with CAN_EFF_FLAG (bit 31)");

	h = env.hrx;
	h.sdt = CAN_CIA_FD_TUNNEL_SDT;
	xl_rx_sf(ctx, &h, false, "SDT 7");
	h.sdt = CAN_CIA_CC_TUNNEL_SDT;
	xl_rx_sf(ctx, &h, false, "SDT 6");
	h.sdt = 0x0A;
	xl_rx_sf(ctx, &h, false, "SDT 0x0A");

	/* CAN CC and CAN FD frames with the rx_id */
	h = env.hrx;
	h.type = FT_CC;
	h.id = 0x321;
	h.flags = 0;
	xl_rx_sf(ctx, &h, false, "CAN CC frame");
	h.type = FT_FD;
	h.flags = CANFD_FDF;
	xl_rx_sf(ctx, &h, false, "CAN FD frame");

	xl_rx_sf(ctx, &env.hrx, true, "matching header");
	ft_dut_expect_noerr(ctx, env.s);
	ft_peer_expect_none(ctx, &env.p, 10);
	xlenv_close();
}

struct af_bits_param {
	const char *mode;
	bool bit30_ok;		/* SDT 7 BRS / SDT 6 RTR */
	bool bit31_ok;		/* ZDLC (SDT 6/7) */
};

/* SF with the given header: accepted as expected, or a deviation when an
 * expected drop is accepted
 */
static void xl_rx_sf_obs(struct ft_ctx *ctx, const struct ft_frame *hdr,
			 bool accept, const char *what)
{
	uint8_t pdu[5] = { 1, 2, 3, 4, 5 };
	uint8_t buf[16];
	struct ft_frame f;
	ssize_t n;

	ft_frame_bytes(&f, hdr, 6, 0x05, 1, 2, 3, 4, 5);
	ft_peer_tx(ctx, &env.p, &f);
	n = ft_dut_recv(ctx, env.s, buf, sizeof(buf), 100);

	if (n >= 0) {
		FT_CHECK(ctx, n == 5 && !memcmp(buf, pdu, 5),
			 "%s: unexpected PDU (len %zd)", what, n);
		if (accept)
			ft_log(ctx, "%s => accepted", what);
		else
			ft_note_dev(ctx, "%s accepted", what);
	} else {
		FT_CHECK(ctx, !accept, "%s ignored: %s", what, ft_errname(n));
		ft_log(ctx, "%s => ignored", what);
	}
}

static void xl_rx_af_bits(struct ft_ctx *ctx, const void *param)
{
	const struct af_bits_param *ap = param;
	struct ft_isotp_cfg c;
	struct ft_frame h;

	cfg_xl(&c, ap->mode);
	c.xl.rx_addr = CAN_EFF_FLAG | 0x54321;
	if (!xlenv_open(ctx, &c))
		return;

	xl_rx_sf_obs(ctx, &env.hrx, true, "AF without bit 30/31");

	h = env.hrx;
	h.af |= 0x40000000;
	xl_rx_sf_obs(ctx, &h, ap->bit30_ok, "AF with bit 30 (SDT 7 BRS / SDT 6 RTR)");

	h = env.hrx;
	h.af |= 0x80000000;
	xl_rx_sf_obs(ctx, &h, ap->bit31_ok, "AF with bit 31 (ZDLC)");

	ft_dut_expect_noerr(ctx, env.s);
	xlenv_close();
}

static void xl_rx_sff_af(struct ft_ctx *ctx, const void *param)
{
	struct ft_isotp_cfg c;
	struct ft_frame h;

	cfg_xl(&c, "XL9-64");
	c.xl.rx_addr = 0x123;
	c.xl.tx_addr = 0x7FF;
	if (!xlenv_open(ctx, &c))
		return;

	FT_CHECK(ctx, env.hrx.af == 0x123, "rx AF %08X", env.hrx.af);
	xl_rx_sf(ctx, &env.hrx, true, "11 bit AF 0x123");
	h = env.hrx;
	h.af = FT_AF_SDT_EFF | 0x123;
	xl_rx_sf(ctx, &h, false, "29 bit AF 0x123");

	xlenv_close();
}

static void xl_rx_type(struct ft_ctx *ctx, const void *param)
{
	static const char *modes[] = { "CC8", "FD64" };
	uint8_t pdu[5] = { 1, 2, 3, 4, 5 };
	struct ft_isotp_cfg c;
	struct ft_frame f;
	int i;

	/* CAN CC/FD sockets on a CAN XL interface ignore CAN XL frames */
	for (i = 0; i < 2; i++) {
		ft_cfg_init(&c);
		ft_cfg_mode(&c, ft_mode_by_name(modes[i]));
		c.iface = FT_IF_XL;
		if (!xlenv_open(ctx, &c))
			return;

		memset(&f, 0, sizeof(f));
		f.type = FT_XL;
		f.id = FT_DUT_RX_ID;
		f.flags = CANXL_XLF;
		f.sdt = CAN_CIA_ISO15765_2_SDT;
		f.len = 6;
		f.data[0] = 0x05;
		memcpy(&f.data[1], pdu, 5);
		ft_peer_tx(ctx, &env.p, &f);
		ft_dut_expect_nopdu(ctx, env.s, 50);

		xl_rx_sf(ctx, &env.hrx, true, modes[i]);
		xlenv_close();
		FT_BAIL(ctx);
	}
}

/* ------------------------------------------------------------------------
 * CAN XL SF formats
 * ------------------------------------------------------------------------
 */

static bool xl_sf(struct ft_ctx *ctx, unsigned int len, uint8_t pci0,
		  uint8_t pci1, int pcilen, unsigned int sfdl, int expect)
{
	static uint8_t pdu[CANXL_MAX_DLEN];
	struct ft_frame f;

	ft_pattern(pdu, sizeof(pdu), len);
	ft_frame_set(&f, &env.hrx, NULL, len);
	memset(f.data, 0xCC, len);
	f.data[0] = pci0;
	if (pcilen > 1)
		f.data[1] = pci1;
	if (sfdl <= len - pcilen)
		memcpy(&f.data[pcilen], pdu, sfdl);

	ft_log(ctx, "CAN_DL %u N_PCI %02X %02X => %s", len, pci0, pci1,
	       expect > 0 ? "PDU" : (expect < 0 ? ft_errname(expect) : "ignored"));
	if (!ft_peer_tx(ctx, &env.p, &f))
		return false;

	if (expect > 0)
		return ft_dut_expect_pdu(ctx, env.s, pdu, sfdl, 200);
	if (expect < 0)
		return ft_dut_expect_err(ctx, env.s, -expect, 200, NULL) &&
		       ft_dut_expect_nopdu(ctx, env.s, 10);

	return ft_dut_expect_nopdu(ctx, env.s, 20);
}

static void xl_sf_native(struct ft_ctx *ctx, const void *param)
{
	struct ft_isotp_cfg c;
	unsigned int len;

	cfg_xl(&c, "XL9-2048");
	if (!xlenv_open(ctx, &c))
		return;

	/* CAN_DL <= 8: 4 bit SF_DL */
	for (len = 2; len <= 8; len++)
		xl_sf(ctx, len, len - 1, 0, 1, len - 1, 1);
	xl_sf(ctx, 8, 0x08, 0, 1, 8, 0);
	xl_sf(ctx, 8, 0x0F, 0, 1, 15, 0);
	xl_sf(ctx, 4, 0x04, 0, 1, 4, 0);

	/* CAN_DL > 8: N_PCI 0x08 | SF_DL bits 10..8, SF_DL bits 7..0 */
	xl_sf(ctx, 9, 0x08, 7, 2, 7, 1);
	xl_sf(ctx, 12, 0x08, 10, 2, 10, 1);
	xl_sf(ctx, 100, 0x08, 98, 2, 98, 1);
	xl_sf(ctx, 300, 0x09, 298 - 256, 2, 298, 1);
	xl_sf(ctx, 2048, 0x0F, 0xFE, 2, 2046, 1);
	/* only the presence of the SF data is checked (no exact length) */
	xl_sf(ctx, 100, 0x08, 1, 2, 1, 1);
	xl_sf(ctx, 2048, 0x08, 3, 2, 3, 1);
	xl_sf(ctx, 13, 0x08, 10, 2, 10, 1);

	/* invalid */
	xl_sf(ctx, 12, 0x00, 10, 2, 10, 0);	/* FD style escape */
	xl_sf(ctx, 12, 0x05, 0, 1, 5, 0);	/* 4 bit SF_DL */
	xl_sf(ctx, 12, 0x08, 0, 2, 0, 0);	/* SF_DL 0 */
	xl_sf(ctx, 12, 0x08, 11, 2, 11, 0);	/* SF_DL > CAN_DL - 2 */
	xl_sf(ctx, 2048, 0x0F, 0xFF, 2, 2047, 0);
	xl_sf(ctx, 300, 0x0A, 0x00, 2, 512, 0);

	ft_dut_expect_noerr(ctx, env.s);
	ft_peer_expect_none(ctx, &env.p, 10);
	xlenv_close();
}

static void xl_sf_pad(struct ft_ctx *ctx, const void *param)
{
	struct ft_isotp_cfg c;

	/* enabled rx padding checks follow the CAN CC/FD rules */
	cfg_xl(&c, "XL9-2048");
	c.opts.flags |= CAN_ISOTP_RX_PADDING | CAN_ISOTP_CHK_PAD_LEN |
			CAN_ISOTP_CHK_PAD_DATA;
	c.opts.rxpad_content = 0xCC;
	if (!xlenv_open(ctx, &c))
		return;

	xl_sf(ctx, 12, 0x08, 10, 2, 10, 1);	/* XL SF, CAN FD DLC length */
	xl_sf(ctx, 64, 0x08, 7, 2, 7, 1);	/* 0xCC behind the SF data */
	xl_sf(ctx, 11, 0x08, 9, 2, 9, -EBADMSG); /* no CAN FD DLC length */
	xl_sf(ctx, 100, 0x08, 98, 2, 98, -EBADMSG); /* > 64 */
	xl_sf(ctx, 12, 0x00, 10, 2, 10, 0);	/* FD style escape */
	xl_sf(ctx, 11, 0x00, 9, 2, 9, 0);
	xl_sf(ctx, 12, 0x05, 0, 1, 5, 0);	/* 4 bit SF_DL */

	/* CAN_DL <= 8: CAN CC padding rules */
	xl_sf(ctx, 8, 0x03, 0, 1, 3, 1);
	xl_sf(ctx, 4, 0x03, 0, 1, 3, -EBADMSG);

	ft_peer_expect_none(ctx, &env.p, 10);
	xlenv_close();
}

/* send a PDU with ll_dl where the last CF has the length lastlen (more bytes
 * than the missing PDU data) - only the presence of the data is checked
 */
static void xl_last_cf(struct ft_ctx *ctx, unsigned int len, unsigned int ll_dl,
		       unsigned int lastlen)
{
	static uint8_t pdu[300], buf[CANXL_MAX_DLEN];
	struct ft_frame *fr;
	struct ft_frame f;
	struct ft_enc e;
	int i, n;

	ft_pattern(pdu, sizeof(pdu), len);
	e = env.pe;
	e.ll_dl = ll_dl;
	n = ft_enc_pdu(&e, &env.hrx, pdu, len, &fr);

	ft_log(ctx, "PDU len %u LL_DL %u: last CF %u (exact %u) => PDU",
	       len, ll_dl, lastlen, fr[n - 1].len);
	ft_peer_tx(ctx, &env.p, &fr[0]);
	if (!FT_CHECK(ctx, ft_peer_next(ctx, &env.p, &f, 100), "no FC"))
		goto out;
	for (i = 1; i < n - 1; i++)
		ft_peer_tx(ctx, &env.p, &fr[i]);

	/* last CF with additional bytes behind the PDU data */
	memset(buf, 0xCC, sizeof(buf));
	memcpy(buf, fr[n - 1].data, fr[n - 1].len);
	ft_frame_set(&f, &env.hrx, buf, lastlen);
	ft_peer_tx(ctx, &env.p, &f);
	ft_dut_expect_pdu(ctx, env.s, pdu, len, 200);
out:
	free(fr);
}

static void xl_cf_len(struct ft_ctx *ctx, const void *param)
{
	struct ft_isotp_cfg c;

	cfg_xl(&c, "XL9-2048");
	if (!xlenv_open(ctx, &c))
		return;

	xl_last_cf(ctx, 150, 100, 60);	/* exact: 53 */
	xl_last_cf(ctx, 150, 100, 100);	/* full CF */
	xl_last_cf(ctx, 201, 100, 8);	/* exact: 5 */
	xl_last_cf(ctx, 201, 100, 100);

	ft_dut_expect_noerr(ctx, env.s);
	xlenv_close();
}

/* ------------------------------------------------------------------------
 * CiA 611-1 SDT 6 / 7 tunneling
 * ------------------------------------------------------------------------
 */

static void xl_sdt6_rx(struct ft_ctx *ctx, const void *param)
{
	static uint8_t pdu[200];
	struct ft_isotp_cfg c;
	struct ft_frame *fr;
	struct ft_frame f;
	struct ft_enc e;
	int n;

	cfg_xl(&c, "XL6-8");
	if (!xlenv_open(ctx, &c))
		return;

	/* XL SF with CAN_DL 12 */
	ft_pattern(pdu, sizeof(pdu), 6);
	ft_frame_set(&f, &env.hrx, NULL, 12);
	f.data[0] = 0x08;
	f.data[1] = 10;
	memcpy(&f.data[2], pdu, 10);
	ft_peer_tx(ctx, &env.p, &f);
	if (ft_dut_recv(ctx, env.s, f.data, sizeof(f.data), 100) == 10)
		ft_note_dev(ctx, "SDT 6 (CAN CC tunnel) accepts a SF with CAN_DL 12");
	else
		ft_log(ctx, "SDT 6: SF with CAN_DL 12 ignored");

	/* FF with CAN_DL 64 */
	e = env.pe;
	e.ll_dl = 64;
	n = ft_enc_pdu(&e, &env.hrx, pdu, sizeof(pdu), &fr);
	ft_peer_tx(ctx, &env.p, &fr[0]);
	if (ft_peer_next(ctx, &env.p, &f, 100)) {
		int i;

		for (i = 1; i < n; i++)
			ft_peer_tx(ctx, &env.p, &fr[i]);
		if (ft_dut_expect_pdu(ctx, env.s, pdu, sizeof(pdu), 500))
			ft_note_dev(ctx, "SDT 6 (CAN CC tunnel) accepts PDUs with LL_DL 64");
	} else {
		ft_log(ctx, "SDT 6: FF with CAN_DL 64 ignored");
	}
	free(fr);
	xlenv_close();
}

static void xl_sdt7_rx(struct ft_ctx *ctx, const void *param)
{
	static uint8_t pdu[300];
	struct ft_isotp_cfg c;
	struct ft_frame *fr;
	struct ft_enc e;
	int n;

	cfg_xl(&c, "XL7-64");
	if (!xlenv_open(ctx, &c))
		return;

	ft_pattern(pdu, sizeof(pdu), 7);

	/* FF with a CAN_DL that is no CAN FD length is ignored */
	e = env.pe;
	e.ll_dl = 100;
	e.fd = false;
	n = ft_enc_pdu(&e, &env.hrx, pdu, sizeof(pdu), &fr);
	ft_peer_tx(ctx, &env.p, &fr[0]);
	ft_peer_expect_none(ctx, &env.p, 50);
	free(fr);
	(void)n;

	e.ll_dl = 13;
	n = ft_enc_pdu(&e, &env.hrx, pdu, sizeof(pdu), &fr);
	ft_peer_tx(ctx, &env.p, &fr[0]);
	ft_peer_expect_none(ctx, &env.p, 50);
	free(fr);

	/* CAN FD SF format: escape 0x00 + SF_DL, XL SF flag not set */
	env.pe.ll_dl = 64;
	ft_rx_pdu(ctx, env.s, &c, &env.p, &env.pe, pdu, 30);
	ft_rx_pdu(ctx, env.s, &c, &env.p, &env.pe, pdu, 62);
	ft_rx_pdu(ctx, env.s, &c, &env.p, &env.pe, pdu, 300);

	/* sender LL_DL 12 */
	e = env.pe;
	e.ll_dl = 12;
	ft_rx_pdu(ctx, env.s, &c, &env.p, &e, pdu, 300);

	xlenv_close();
}

/* send a SF and report whether the DUT received it */
static bool xl_sf_received(struct ft_ctx *ctx, unsigned int len, uint8_t pci0,
			   uint8_t pci1, unsigned int sfdl)
{
	static uint8_t pdu[CANXL_MAX_DLEN];
	struct ft_frame f;
	ssize_t n;

	ft_pattern(pdu, sizeof(pdu), len);
	ft_frame_set(&f, &env.hrx, NULL, len);
	memset(f.data, 0xCC, len);
	f.data[0] = pci0;
	f.data[1] = pci1;
	memcpy(&f.data[2], pdu, sfdl);
	ft_peer_tx(ctx, &env.p, &f);

	n = ft_dut_recv(ctx, env.s, f.data, sizeof(f.data), 100);
	if (n < 0)
		return false;

	FT_CHECK(ctx, n == (ssize_t)sfdl && !memcmp(f.data, pdu, sfdl),
		 "unexpected PDU (len %zd)", n);
	return true;
}

static void xl_sdt7_sf_len(struct ft_ctx *ctx, const void *param)
{
	struct ft_isotp_cfg c;

	cfg_xl(&c, "XL7-64");
	if (!xlenv_open(ctx, &c))
		return;

	/* XL SF format with CAN_DL > 64 */
	if (xl_sf_received(ctx, 100, 0x08, 98, 98))
		ft_note_dev(ctx, "SDT 7 (CAN FD tunnel) accepts a SF with CAN_DL 100");
	else
		ft_log(ctx, "SDT 7: SF with CAN_DL 100 ignored");

	/* XL SF format with CAN_DL 13 (no CAN FD DLC length) */
	if (xl_sf_received(ctx, 13, 0x08, 11, 11))
		ft_note_dev(ctx, "SDT 7 (CAN FD tunnel) accepts a SF with CAN_DL 13");
	else
		ft_log(ctx, "SDT 7: SF with CAN_DL 13 ignored");

	/* valid CAN FD SF with escape still accepted */
	FT_CHECK(ctx, xl_sf_received(ctx, 12, 0x00, 10, 10),
		 "SDT 7: valid SF with CAN_DL 12 not received");

	ft_dut_expect_noerr(ctx, env.s);
	xlenv_close();
}

static void xl_sdt7_sf_pci(struct ft_ctx *ctx, const void *param)
{
	struct ft_isotp_cfg c;

	cfg_xl(&c, "XL7-64");
	if (!xlenv_open(ctx, &c))
		return;

	/* CAN FD only allows N_PCI 0x00 for the SF_DL escape */
	FT_CHECK(ctx, !xl_sf_received(ctx, 12, 0x08, 10, 10),
		 "SDT 7: SF with N_PCI 0x08 0x0A accepted");
	FT_CHECK(ctx, xl_sf_received(ctx, 12, 0x00, 10, 10),
		 "SDT 7: SF with N_PCI 0x00 0x0A not received");

	ft_dut_expect_noerr(ctx, env.s);
	xlenv_close();
}

/* CAN FD N_PDUs in CAN XL frames with SDT 9 (LL mtu 72) */
static void xl_sdt9_fd_rx(struct ft_ctx *ctx, const void *param)
{
	static uint8_t pdu[300];
	struct ft_isotp_cfg c;
	struct ft_frame *fr;
	struct ft_enc e;

	cfg_xl(&c, "XL9FD-64");
	if (!xlenv_open(ctx, &c))
		return;

	/* SF with CAN_DL > 8: only the CAN FD escape and CAN FD lengths */
	FT_CHECK(ctx, xl_sf_received(ctx, 12, 0x00, 10, 10),
		 "SF CAN_DL 12 N_PCI 0x00 not received");
	FT_CHECK(ctx, !xl_sf_received(ctx, 12, 0x08, 10, 10),
		 "SF CAN_DL 12 N_PCI 0x08 (XL SF) accepted");
	FT_CHECK(ctx, !xl_sf_received(ctx, 13, 0x00, 11, 11),
		 "SF CAN_DL 13 (no CAN FD length) accepted");
	FT_CHECK(ctx, !xl_sf_received(ctx, 100, 0x00, 98, 98),
		 "SF CAN_DL 100 (> 64) accepted");

	/* FF with a CAN_DL that is no CAN FD length is ignored */
	ft_pattern(pdu, sizeof(pdu), 9);
	e = env.pe;
	e.ll_dl = 100;
	e.fd = false;
	ft_enc_pdu(&e, &env.hrx, pdu, sizeof(pdu), &fr);
	ft_peer_tx(ctx, &env.p, &fr[0]);
	ft_peer_expect_none(ctx, &env.p, 50);
	free(fr);

	/* CAN FD N_PDUs with sender LL_DL 64 and 12 */
	ft_rx_pdu(ctx, env.s, &c, &env.p, &env.pe, pdu, 30);
	ft_rx_pdu(ctx, env.s, &c, &env.p, &env.pe, pdu, 300);
	e = env.pe;
	e.ll_dl = 12;
	ft_rx_pdu(ctx, env.s, &c, &env.p, &e, pdu, 300);

	ft_dut_expect_noerr(ctx, env.s);
	xlenv_close();
}

/* ------------------------------------------------------------------------
 * socket option handling
 * ------------------------------------------------------------------------
 */

static void xl_opt_order(struct ft_ctx *ctx, const void *param)
{
	struct can_isotp_ll_options ll = { CAN_MTU, 8, 0 };
	struct can_isotp_xl_options xl, get;
	struct sockaddr_can addr = { .can_family = AF_CAN };
	struct ft_isotp_cfg c;
	socklen_t len = sizeof(get);
	static uint8_t data[100];
	int s;

	if (!ft_need_if(ctx, FT_IF_XL))
		return;

	cfg_xl(&c, "XL9-64");
	xl = c.xl;

	/* XL_OPTS (tx_dl 64) followed by LL_OPTS (tx_dl 8): XL tx_dl wins */
	s = socket(PF_CAN, SOCK_DGRAM, CAN_ISOTP);
	FT_CHECK(ctx, s >= 0, "socket");
	FT_BAIL(ctx);
	setsockopt(s, SOL_CAN_ISOTP, CAN_ISOTP_OPTS, &c.opts, sizeof(c.opts));
	FT_CHECK(ctx, !setsockopt(s, SOL_CAN_ISOTP, CAN_ISOTP_XL_OPTS, &xl,
				  sizeof(xl)), "XL_OPTS");
	FT_CHECK(ctx, !setsockopt(s, SOL_CAN_ISOTP, CAN_ISOTP_LL_OPTS, &ll,
				  sizeof(ll)), "LL_OPTS");
	addr.can_ifindex = ft_ifindex(FT_IF_XL);
	addr.can_addr.tp.tx_id = c.tx_id;
	addr.can_addr.tp.rx_id = c.rx_id;
	FT_CHECK(ctx, !bind(s, (struct sockaddr *)&addr, sizeof(addr)),
		 "bind: %s", ft_errname(errno));
	FT_BAIL(ctx);

	getsockopt(s, SOL_CAN_ISOTP, CAN_ISOTP_XL_OPTS, &get, &len);
	FT_CHECK(ctx, get.tx_dl == 64, "XL tx_dl %u", get.tx_dl);

	if (ft_peer_open(ctx, &env.p, FT_IF_XL)) {
		close(s);
		return;
	}

	/* the effective TX_DL is 64 from XL_OPTS (set at bind() time) */
	ft_pattern(data, sizeof(data), 1);
	ft_tx_pdu(ctx, s, &c, &env.p, data, 7, 0, 0);
	ft_tx_pdu(ctx, s, &c, &env.p, data, 62, 0, 0);
	ft_tx_pdu(ctx, s, &c, &env.p, data, 100, 0, 0);

	ft_peer_close(&env.p);
	close(s);
}

static void xl_opt_disable(struct ft_ctx *ctx, const void *param)
{
	struct can_isotp_xl_options xl;
	struct ft_isotp_cfg c, cc;
	struct sockaddr_can addr = { .can_family = AF_CAN };
	static uint8_t data[100];
	int s;

	if (!ft_need_if(ctx, FT_IF_XL))
		return;

	/* LL (FD 16), XL enabled, XL disabled => CAN FD with TX_DL 16 */
	cfg_xl(&c, "XL9-64");
	c.ll.mtu = CANFD_MTU;
	c.ll.tx_dl = 16;
	c.xl.tx_dl = 64;

	s = socket(PF_CAN, SOCK_DGRAM, CAN_ISOTP);
	FT_CHECK(ctx, s >= 0, "socket");
	FT_BAIL(ctx);
	setsockopt(s, SOL_CAN_ISOTP, CAN_ISOTP_OPTS, &c.opts, sizeof(c.opts));
	FT_CHECK(ctx, !setsockopt(s, SOL_CAN_ISOTP, CAN_ISOTP_LL_OPTS, &c.ll,
				  sizeof(c.ll)), "LL_OPTS");
	FT_CHECK(ctx, !setsockopt(s, SOL_CAN_ISOTP, CAN_ISOTP_XL_OPTS, &c.xl,
				  sizeof(c.xl)), "XL_OPTS");
	memset(&xl, 0, sizeof(xl));
	FT_CHECK(ctx, !setsockopt(s, SOL_CAN_ISOTP, CAN_ISOTP_XL_OPTS, &xl,
				  sizeof(xl)), "XL_OPTS disable");
	addr.can_ifindex = ft_ifindex(FT_IF_XL);
	addr.can_addr.tp.tx_id = c.tx_id;
	addr.can_addr.tp.rx_id = c.rx_id;
	FT_CHECK(ctx, !bind(s, (struct sockaddr *)&addr, sizeof(addr)),
		 "bind: %s", ft_errname(errno));
	FT_BAIL(ctx);

	if (ft_peer_open(ctx, &env.p, FT_IF_XL)) {
		close(s);
		return;
	}

	cc = c;
	cc.set_xl = false;
	ft_pattern(data, sizeof(data), 1);
	ft_tx_pdu(ctx, s, &cc, &env.p, data, 14, 0, 0);
	ft_tx_pdu(ctx, s, &cc, &env.p, data, 15, 0, 0);
	ft_tx_pdu(ctx, s, &cc, &env.p, data, 100, 0, 0);

	ft_peer_close(&env.p);
	close(s);
}

/* ------------------------------------------------------------------------
 * CAN XL interface MTU
 * ------------------------------------------------------------------------
 */

static void xl_mtu(struct ft_ctx *ctx, const void *param)
{
	static const struct {
		const char *mode;
		enum ft_if iface;
		int ret;
	} tc[] = {
		{ "XL9-2048", FT_IF_XL, 0 },		/* MTU 2060 */
		{ "XL9-256-IF256", FT_IF_XL256, 0 },	/* MTU 268 = 12 + 256 */
		{ "XL9-2048", FT_IF_XL256, -EINVAL },
		{ "XL9-512-IF512", FT_IF_XL256, -EINVAL },
		{ "XL9-512-IF512", FT_IF_XL512, 0 },	/* MTU 524 = 12 + 512 */
		{ "XL9-2048", FT_IF_XL512, -EINVAL },
		{ "XL9-8", FT_IF_XL256, 0 },		/* >= CANXL_MIN_MTU */
		{ "XL9-64", FT_IF_FD, -EINVAL },	/* < CANXL_MIN_MTU */
		{ "XL9-8", FT_IF_FD, -EINVAL },
		{ "XL7-64", FT_IF_FD, -EINVAL },
		{ "XL9-8", FT_IF_CC, -EINVAL },
	};
	struct ft_isotp_cfg c;
	unsigned int i;
	int s;

	(void)param;

	for (i = 0; i < sizeof(tc) / sizeof(tc[0]); i++) {
		if (!ft_ifindex(tc[i].iface)) {
			ft_log(ctx, "case %u: interface %s not available", i,
			       ft_ifname(tc[i].iface));
			continue;
		}
		cfg_xl(&c, tc[i].mode);
		c.iface = tc[i].iface;
		s = ft_isotp_open_err(&c);
		FT_CHECK(ctx, (s >= 0 ? 0 : s) == tc[i].ret,
			 "case %u: %s on %s: %s (expected %s)", i, tc[i].mode,
			 ft_ifname(tc[i].iface), ft_errname(s >= 0 ? 0 : s),
			 ft_errname(tc[i].ret));
		if (s >= 0)
			close(s);
	}
}

/* ------------------------------------------------------------------------
 * test table
 * ------------------------------------------------------------------------
 */

#define T(i, t, fl, f, p, rq, rf, is)					\
	{ .id = i, .title = t, .req = rq, .ref = rf, .iso = is,		\
	  .flags = fl, .fn = f, .param = p }

static const struct ft_test tests[] = {
	T("XL-HDR-001", "CAN XL tx frame header", 0, xl_hdr_tx, NULL,
	  "CAN XL frames (SF, FF, CF, FC) carry prio = tx_id (11 bit) | tx_vcid << 16, flags = tx_flags (XLF + SEC/RRS), sdt = sdt_mode, len = exact frame length and af = tx_addr where a 29 bit tx_addr is marked with bit 29 (instead of CAN_EFF_FLAG); in SDT 7 mode with CANFD_BRS in the LL tx_flags bit 30 of the AF is set.",
	  "protocoltx.c:isotp_fill_frame_head(), isotp.c:isotp_bind_xl()", NULL),
	T("XL-HDR-002", "CAN XL rx header filter", 0, xl_rx_filter, NULL,
	  "A CAN XL frame is only processed if prio & 0x7FF == rx_id, VCID == rx_vcid, flags == rx_flags (exact match), (af & 0x3FFFFFFF) == rx_addr (29 bit address with bit 29) and sdt == sdt_mode. CAN CC/FD frames are ignored by CAN XL sockets.",
	  "protocolrx.c:isotp_check_frame_head()", NULL),
	T("XL-HDR-003", "AF bits 30/31 ignored (SDT 9)", 0, xl_rx_af_bits,
	  &((const struct af_bits_param){ "XL9-64", true, true }),
	  "In SDT 9 mode the AF bits 31/30 are reserved: they are sent as 0 (see XL-HDR-001) and ignored at reception time (forward compatibility).",
	  "protocolrx.c:isotp_check_frame_head() CAN_CIA_ADDR_MASK", NULL),
	T("XL-HDR-004", "AF bits 30/31 (SDT 7)", 0, xl_rx_af_bits,
	  &((const struct af_bits_param){ "XL7-64", true, false }),
	  "In SDT 7 (CAN FD tunnel) mode the AF bit 30 (BRS) is ignored at reception time, frames with AF bit 31 (CiA 611-1 ZDLC, zero data length) are dropped.",
	  "protocolrx.c:isotp_check_frame_head() CAN_CIA_SDT_ZDLC",
	  "DEVIATION (if observed): tunneled ZDLC frames are processed (fixed by xl-isotp split_v2 patch 35)."),
	T("XL-HDR-005", "11 bit AF", 0, xl_rx_sff_af, NULL,
	  "An 11 bit rx_addr is used as AF without bit 29; frames with the same address and bit 29 are ignored.",
	  "isotp.c:isotp_bind_xl(), protocolrx.c:isotp_check_frame_head()", NULL),
	T("XL-HDR-006", "CC/FD sockets ignore CAN XL frames", 0, xl_rx_type,
	  NULL,
	  "CAN CC and CAN FD sockets bound to a CAN XL interface ignore CAN XL frames.",
	  "protocolrx.c:isotp_check_frame_head()", NULL),
	T("XL-HDR-007", "AF bits 30/31 (SDT 6)", 0, xl_rx_af_bits,
	  &((const struct af_bits_param){ "XL6-8", false, false }),
	  "In SDT 6 (CAN CC tunnel) mode frames with AF bit 30 (CiA 611-1 RTR) or bit 31 (ZDLC, zero data length) are dropped.",
	  "protocolrx.c:isotp_check_frame_head() CAN_CIA_SDT6_RTR, CAN_CIA_SDT_ZDLC",
	  "DEVIATION (if observed): tunneled RTR/ZDLC frames are processed (fixed by xl-isotp split_v2 patch 35)."),
	T("XL-SF-001", "CAN XL SF format", 0, xl_sf_native, NULL,
	  "CAN XL N_PDUs (SDT 9, no CAN FD LL) use the 4 bit SF_DL for CAN_DL <= 8. For CAN_DL > 8 the N_PCI is 0x08 | SF_DL bits 10..8 followed by SF_DL bits 7..0 (SF_DL 1..CAN_DL-2). Like for CAN CC/FD only the presence of the SF data is checked, not the exact CAN_DL. The CAN FD escape (0x00) and 4 bit SF_DL are ignored for CAN_DL > 8.",
	  "protocolrx.c:isotp_rcv() N_PCI_XL_SF, isotp_rcv_sf()", NULL),
	T("XL-SF-002", "CAN XL N_PDUs with padding checks", 0, xl_sf_pad,
	  NULL,
	  "Enabled rx padding checks (RX_PADDING/CHK_PAD_*) keep their CAN CC/FD semantics also for CAN XL N_PDUs (LL mtu 16): with RX_PADDING|CHK_PAD_LEN a SF with CAN_DL > 8 must have a CAN FD DLC length (else EBADMSG) and CHK_PAD_DATA checks the bytes behind the data. A SF with CAN_DL > 8 always needs the XL SF PCI flag (the CAN FD escape 0x00 is ignored).",
	  "protocolrx.c:isotp_rcv() N_PCI_XL_SF, chk_pad_fail()", NULL),
	T("XL-CF-001", "CAN XL last CF length", 0, xl_cf_len, NULL,
	  "Like for CAN CC/FD only the presence of the PDU data is checked: a last CF of a CAN XL N_PDU (RX_DL > 8) with more bytes than the missing PDU data (also with CAN_DL <= 8) completes the PDU.",
	  "protocolrx.c:isotp_rcv_cf()", NULL),
	T("XL-SDT6-001", "SDT 6 reception of long frames", 0, xl_sdt6_rx, NULL,
	  "Expected: a CAN CC tunnel (SDT 6) socket only processes frames with CAN_DL <= 8. Observed behaviour is reported.",
	  "protocolrx.c:isotp_rcv(), isotp_rcv_ff() (no SDT 6 specific length check)",
	  "DEVIATION (if observed): SDT 6 sockets accept SF/FF/CF with CAN_DL > 8 (fixed by xl-isotp split_v2 patch 35)."),
	T("XL-SDT7-001", "SDT 7 reception", 0, xl_sdt7_rx, NULL,
	  "A CAN FD tunnel (SDT 7) socket uses CAN FD PDU rules: FF must have a CAN FD DLC length, SF > 8 byte use the CAN FD escape, any sender LL_DL <= 64.",
	  "protocolrx.c:isotp_rcv_ff() fd_pdu(), isotp_rcv()", NULL),
	T("XL-SDT7-002", "SDT 7 SF length", 0, xl_sdt7_sf_len, NULL,
	  "Expected: a CAN FD tunnel (SDT 7) socket only processes frames with a CAN FD data length (<= 8 or a DLC length up to 64). Observed behaviour for SF in the CAN XL SF format with CAN_DL 100 and 13 is reported; a valid CAN FD SF is received.",
	  "protocolrx.c:isotp_check_frame_head() tunnel length check, isotp_rcv() N_PCI_XL_SF",
	  "DEVIATION (if observed): SDT 7 sockets accept SF with CAN_DL > 64 or without CAN FD DLC length (fixed by xl-isotp split_v2 patch 35)."),
	T("XL-SDT7-003", "SDT 7 SF with N_PCI 0x08", 0, xl_sdt7_sf_pci, NULL,
	  "A CAN FD tunnel (SDT 7) SF with CAN_DL 12 and N_PCI 0x08 0x0A is ignored, CAN FD only defines N_PCI 0x00 for the SF_DL escape.",
	  "protocolrx.c:isotp_rcv() fd_pdu()", NULL),
	T("XL-SDT9-001", "CAN FD N_PDUs in SDT 9", 0, xl_sdt9_fd_rx, NULL,
	  "A SDT 9 socket with LL mtu 72 handles CAN FD N_PDUs: SF with CAN_DL > 8 need the CAN FD escape (0x00) and a CAN FD length <= 64, FF with other lengths are ignored, PDUs with any CAN FD sender LL_DL are received.",
	  "protocolrx.c:isotp_check_frame_head() fd_pdu(), isotp_rcv()", NULL),
	T("XL-OPT-001", "LL_OPTS after XL_OPTS", 0, xl_opt_order, NULL,
	  "The effective TX_DL is set at bind() time independent of the order of the socket options: in XL mode the tx_dl from CAN_ISOTP_XL_OPTS (as returned by getsockopt()), else the tx_dl from CAN_ISOTP_LL_OPTS.",
	  "isotp.c:isotp_bind() so->tx.ll_dl", NULL),
	T("XL-OPT-002", "disabling XL mode", 0, xl_opt_disable, NULL,
	  "Disabling the XL mode restores the LL tx_dl and CAN CC/FD frames are sent.",
	  "isotp.c:isotp_setsockopt_locked() CAN_ISOTP_XL_OPTS", NULL),
	T("XL-MTU-001", "TX_DL larger than interface MTU", 0, xl_mtu, NULL,
	  "In XL mode bind() requires an interface MTU >= CANXL_HDR_SIZE + TX_DL and >= CANXL_MIN_MTU (CAN XL capable interface), else EINVAL.",
	  "isotp.c:isotp_bind() isotp_req_mtu()", NULL),
};

int main(int argc, char **argv)
{
	return ft_main(argc, argv, "xl", tests,
		       sizeof(tests) / sizeof(tests[0]));
}
