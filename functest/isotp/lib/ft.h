/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-3-Clause) */
/*
 * ft.h - functional test framework for the CAN_ISOTP protocol
 *
 * The framework provides
 *
 * - a test runner with TAP style output (one process per test case)
 * - a CAN_RAW based peer that sends arbitrary CC/FD/XL frames and records
 *   all frames on the CAN interface with timestamps in a background thread
 * - helpers to configure and operate CAN_ISOTP sockets (the DUT)
 * - a reference model of the ISO 15765-2 frame layout as implemented by the
 *   Linux CAN_ISOTP protocol (SF/FF/CF/FC encoding incl. CAN FD/XL rules)
 * - a CAN_BCM helper to send frame sequences with precise frame gaps
 *
 * Send feedback to <linux-can@vger.kernel.org>
 */

#ifndef FT_H
#define FT_H

#include <stdarg.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <pthread.h>
#include <sys/types.h>

#include <linux/can.h>
#include <linux/can/isotp.h>

/* ------------------------------------------------------------------------
 * constants derived from the CAN_ISOTP implementation
 * ------------------------------------------------------------------------
 */

#define FT_MAX_PDU		8300	/* DEFAULT_MAX_PDU_SIZE (static buffer) */
#define FT_MAX_12BIT_PDU	4095	/* max. FF_DL with 12 bit notation */
#define FT_FC_TIMEOUT_MS	1000	/* ISOTP_FC_TIMEOUT (N_Bs / N_Cr) */
#define FT_ECHO_TIMEOUT_MS	2000	/* ISOTP_ECHO_TIMEOUT */
#define FT_DEF_FRAME_TXTIME	50000	/* CAN_ISOTP_DEFAULT_FRAME_TXTIME (ns) */
#define FT_MAX_FRAME_TXTIME	100000000 /* ISOTP_MAX_FRAME_TXTIME_NS */

/* CAN CiA 611-1 acceptance field flags (see isotp_defines.h) */
#define FT_AF_SDT_EFF		0x20000000U
#define FT_AF_SDT7_BRS		0x40000000U

/* N_PCI types */
#define FT_PCI_SF	0x00
#define FT_PCI_FF	0x10
#define FT_PCI_CF	0x20
#define FT_PCI_FC	0x30
#define FT_PCI_MF	0x40

/* flow status values */
#define FT_FS_CTS	0
#define FT_FS_WT	1
#define FT_FS_OVFLW	2

/* default CAN identifiers used by the tests */
#define FT_DUT_TX_ID	0x123
#define FT_DUT_RX_ID	0x321
#define FT_XL_TX_AF	0x80012345U	/* 29 bit address for XL AF */
#define FT_XL_RX_AF	0x80054321U	/* 29 bit address for XL AF */

/* ------------------------------------------------------------------------
 * test runner
 * ------------------------------------------------------------------------
 */

/* test case flags */
#define FT_SLOW		0x01	/* runs into protocol timeouts (>= 1 sec) */
#define FT_TIMING	0x02	/* checks timing values (with tolerance) */

struct ft_ctx;
struct ft_enc;

struct ft_test {
	const char *id;		/* unique test case identifier */
	const char *title;	/* short description */
	const char *req;	/* checked behaviour (specification statement) */
	const char *ref;	/* reference to the implementation */
	const char *iso;	/* "DEVIATION: .." or "REVIEW: .." or NULL */
	unsigned int flags;	/* FT_SLOW, FT_TIMING */
	void (*fn)(struct ft_ctx *ctx, const void *param);
	const void *param;	/* test case specific parameter */
};

/* interfaces (see setup_vcan.sh) */
enum ft_if {
	FT_IF_CC,	/* vcaniso0 MTU 16 */
	FT_IF_FD,	/* vcaniso1 MTU 72 */
	FT_IF_XL,	/* vcaniso2 MTU 2060 */
	FT_IF_XL512,	/* vcaniso3 MTU 524 */
	FT_IF_XL256,	/* vcaniso4 MTU 268 */
	FT_IF_DOWN,	/* vcaniso5 MTU 16, interface down */
	FT_IF_ELOSS,	/* vcaniso6 vcan echo=1 + netem loss 100% */
	FT_IF_EDELAY,	/* vcaniso7 vcan echo=1 + netem delay 3000ms */
	FT_IF_ESLOW,	/* vcaniso8 vcan echo=1 + netem delay 100ms */
	FT_IF_ERATE,	/* vcaniso9 vcan echo=1 + tbf rate 2kbit */
	FT_IF_MAX
};

struct ft_config {
	const char *ifname[FT_IF_MAX];
	int verbose;
	int quick;		/* skip FT_SLOW tests */
	int tol_ms;		/* timing tolerance (upper bound) */
	int watchdog_s;		/* per test case watchdog */
};

extern struct ft_config ft_cfg;

struct ft_ctx {
	const struct ft_test *t;
	int failed;
	int skipped;
	int ndev;		/* dynamic deviation notes */
	int nfind;		/* implementation findings */
	FILE *log;		/* trace (memstream) */
	char *logbuf;
	size_t loglen;
};

/* run all tests in the table (main() of each test program) */
int ft_main(int argc, char **argv, const char *suite,
	    const struct ft_test *tests, int ntests);

/* tracing and result handling inside a test case */
void ft_log(struct ft_ctx *ctx, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));
void ft_fail_at(struct ft_ctx *ctx, const char *file, int line,
		const char *fmt, ...)
	__attribute__((format(printf, 4, 5)));
void ft_skip(struct ft_ctx *ctx, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));
void ft_note_dev(struct ft_ctx *ctx, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));
/* implementation finding (no ISO deviation), test case passes */
void ft_note_finding(struct ft_ctx *ctx, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

#define ft_fail(ctx, ...) ft_fail_at(ctx, __FILE__, __LINE__, __VA_ARGS__)

/* check a condition, log and mark the test as failed if false */
#define FT_CHECK(ctx, cond, ...)					\
	({								\
		bool __c = (cond);					\
		if (!__c)						\
			ft_fail_at(ctx, __FILE__, __LINE__, __VA_ARGS__); \
		__c;							\
	})

/* return from the test function if the test already failed/skipped */
#define FT_BAIL(ctx)							\
	do {								\
		if ((ctx)->failed || (ctx)->skipped)			\
			return;						\
	} while (0)

/* interface helpers */
const char *ft_ifname(enum ft_if i);
int ft_ifindex(enum ft_if i);
/* skip the test case if the interface is not available */
bool ft_need_if(struct ft_ctx *ctx, enum ft_if i);
/* skip the test case if the interface is not up or has no IFF_ECHO */
bool ft_need_echo_if(struct ft_ctx *ctx, enum ft_if i);

/* time helpers (CLOCK_REALTIME to match SO_TIMESTAMPNS values) */
int64_t ft_now_ns(void);
int64_t ft_ts_ns(const struct timespec *ts);
void ft_sleep_ms(int ms);
void ft_sleep_us(int us);

/* max. PDU size (module parameter max_pdu_size, default 8300) */
unsigned int ft_max_pdu(void);

/* test data pattern */
void ft_pattern(uint8_t *buf, size_t len, unsigned int seed);

/* error number name for logs */
const char *ft_errname(int err);

/* ------------------------------------------------------------------------
 * CAN frames
 * ------------------------------------------------------------------------
 */

enum ft_ftype {
	FT_CC,
	FT_FD,
	FT_XL,
};

struct ft_frame {
	int type;		/* FT_CC, FT_FD, FT_XL */
	canid_t id;		/* can_id (CC/FD) or prio incl. VCID (XL) */
	uint8_t flags;		/* CAN FD flags / CAN XL flags */
	uint8_t sdt;		/* CAN XL SDT */
	uint32_t af;		/* CAN XL acceptance field */
	unsigned int len;	/* CAN_DL / CAN XL data length */
	uint8_t data[CANXL_MAX_DLEN];
	int64_t ts;		/* timestamp (ns) of received frames */
};

/* format frame in candump like style */
void ft_frame_str(const struct ft_frame *f, char *buf, size_t size);
/* compare frames, returns true when equal (ts is ignored) */
bool ft_frame_eq(const struct ft_frame *a, const struct ft_frame *b);
/* set payload of frame */
void ft_frame_set(struct ft_frame *f, const struct ft_frame *hdr,
		  const uint8_t *data, unsigned int len);
/* build frame from header and variable list of data bytes */
void ft_frame_bytes(struct ft_frame *f, const struct ft_frame *hdr,
		    unsigned int len, ...);

/* ------------------------------------------------------------------------
 * CAN_RAW peer with background receive thread
 * ------------------------------------------------------------------------
 */

struct ft_peer {
	int s;
	int ifindex;
	const char *ifname;
	pthread_t thread;
	pthread_mutex_t lock;
	pthread_cond_t cond;
	struct ft_frame *frames;	/* recorded frames */
	unsigned int nframes;		/* number of recorded frames */
	unsigned int size;		/* allocated entries */
	unsigned int rd;		/* read index for ft_peer_next() */
	uint32_t drops;			/* SO_RXQ_OVFL counter */
	int stop;
	struct ft_ctx *ctx;
};

int ft_peer_open(struct ft_ctx *ctx, struct ft_peer *p, enum ft_if i);
void ft_peer_close(struct ft_peer *p);
/* send frame, returns 0 or -errno */
int ft_peer_send(struct ft_ctx *ctx, struct ft_peer *p, const struct ft_frame *f);
/* send frame and fail the test on error */
bool ft_peer_tx(struct ft_ctx *ctx, struct ft_peer *p, const struct ft_frame *f);
/* get next recorded frame, wait up to timeout_ms; returns false on timeout */
bool ft_peer_next(struct ft_ctx *ctx, struct ft_peer *p, struct ft_frame *f,
		  int timeout_ms);
/* discard all recorded frames not read yet */
void ft_peer_flush(struct ft_peer *p);
/* wait for the next frame and compare with expected frame */
bool ft_peer_expect(struct ft_ctx *ctx, struct ft_peer *p,
		    const struct ft_frame *exp, int timeout_ms);
/* check that no frame is received within ms */
bool ft_peer_expect_none(struct ft_ctx *ctx, struct ft_peer *p, int ms);
/* check for receive queue overflows of the peer */
bool ft_peer_check_drops(struct ft_ctx *ctx, struct ft_peer *p);

/* ------------------------------------------------------------------------
 * CAN_BCM frame sequence sender (CC/FD only)
 * ------------------------------------------------------------------------
 */

/* send n frames with gap_us between them (first frame immediately) and
 * wait until the sequence has been sent completely
 */
bool ft_bcm_send_seq(struct ft_ctx *ctx, enum ft_if i,
		     const struct ft_frame *frames, int n, int gap_us);

/* ------------------------------------------------------------------------
 * CAN_ISOTP socket (DUT) configuration
 * ------------------------------------------------------------------------
 */

struct ft_isotp_cfg {
	enum ft_if iface;
	canid_t tx_id;
	canid_t rx_id;
	struct can_isotp_options opts;
	struct can_isotp_fc_options fc;
	struct can_isotp_ll_options ll;
	struct can_isotp_xl_options xl;
	uint32_t tx_stmin;
	uint32_t rx_stmin;
	bool set_opts, set_fc, set_ll, set_xl, set_tx_stmin, set_rx_stmin;
};

/* link layer modes for parameterized tests */
struct ft_mode {
	const char *name;
	enum ft_if iface;
	uint8_t mtu;		/* CAN_MTU or CANFD_MTU */
	uint8_t ll_tx_dl;
	uint8_t ll_tx_flags;
	bool xl;
	uint8_t sdt;
	uint32_t xl_tx_dl;
	uint8_t xl_flags;	/* CANXL_XLF (+ SEC/RRS) for tx and rx */
	uint8_t tx_vcid;
	uint8_t rx_vcid;
};

extern const struct ft_mode ft_modes[];
extern const int ft_nmodes;
const struct ft_mode *ft_mode_by_name(const char *name);

/* addressing / padding variants for parameterized tests */
enum ft_variant {
	FT_V_PLAIN,	/* normal addressing, no padding */
	FT_V_AE,	/* extended addressing (same address for rx/tx) */
	FT_V_PAD,	/* TX padding (0x55) + RX padding checks (0xAA) */
	FT_V_AEPAD,	/* RX_EXT_ADDR (tx 0xA5, rx 0x5A) + padding */
	FT_V_MAX
};

extern const char *ft_variant_name[FT_V_MAX];

/* apply variant settings (ext. addressing, padding) */
void ft_cfg_variant(struct ft_isotp_cfg *c, int var);
/* padding variants require a CAN FD DLC length as TX_DL */
bool ft_variant_valid(const struct ft_mode *m, int var);
/* create interesting PDU lengths for the given encoder (sorted, unique) */
int ft_seg_lengths(const struct ft_enc *e, unsigned int max,
		   unsigned int *out, int size);

/* initialize configuration with default values (CC, 0x123/0x321) */
void ft_cfg_init(struct ft_isotp_cfg *c);
/* apply link layer mode */
void ft_cfg_mode(struct ft_isotp_cfg *c, const struct ft_mode *m);
/* effective TX LL_DL of a configured socket (tx.ll_dl) */
unsigned int ft_cfg_tx_dl(const struct ft_isotp_cfg *c);
bool ft_cfg_is_xl(const struct ft_isotp_cfg *c);
bool ft_cfg_is_fdpdu(const struct ft_isotp_cfg *c);
/* swap tx/rx (ids, addresses, vcid, padding content) for the counterpart */
void ft_cfg_swap(struct ft_isotp_cfg *c);

/* create, configure and bind socket; returns fd or -errno (no failure) */
int ft_isotp_open_err(const struct ft_isotp_cfg *c);
/* same but fails the test case on errors */
int ft_isotp_open(struct ft_ctx *ctx, const struct ft_isotp_cfg *c);

/* frame headers of a configured DUT socket */
void ft_hdr_dut_tx(const struct ft_isotp_cfg *c, struct ft_frame *hdr);
void ft_hdr_dut_rx(const struct ft_isotp_cfg *c, struct ft_frame *hdr);

/* ------------------------------------------------------------------------
 * ISO-TP reference encoder (frame layout as created by CAN_ISOTP)
 * ------------------------------------------------------------------------
 */

struct ft_enc {
	unsigned int ll_dl;	/* LL_DL (TX_DL) */
	bool ae;		/* extended / mixed addressing */
	uint8_t ae_val;		/* address extension value */
	bool pad;		/* CAN_ISOTP_TX_PADDING */
	uint8_t pad_val;	/* padding content */
	bool fd;		/* CAN FD PDU (mandatory padding for > 8) */
	bool xlsf;		/* XL native SF PCI flag (bit 3) */
	bool mf;		/* multicast first frame N_PCI type */
};

/* padded CAN FD length for a given data length (padlen()) */
unsigned int ft_padlen(unsigned int len);
/* encoder of the DUT socket (tx path) */
void ft_enc_dut(const struct ft_isotp_cfg *c, struct ft_enc *e);
/* encoder of a peer sending to the DUT (matching the DUT rx settings) */
void ft_enc_peer(const struct ft_isotp_cfg *c, struct ft_enc *e);
/* max. SF payload length */
unsigned int ft_enc_sf_max(const struct ft_enc *e);
/* encode a PDU into frames, returns number of frames (array allocated) */
int ft_enc_pdu(const struct ft_enc *e, const struct ft_frame *hdr,
	       const uint8_t *data, unsigned int len, struct ft_frame **frames);
/* encode a flow control frame */
void ft_enc_fc(const struct ft_enc *e, const struct ft_frame *hdr,
	       uint8_t fs, uint8_t bs, uint8_t stmin, struct ft_frame *f);
/* frames between two FCs for a given block size (0 => all) */
int ft_enc_block_end(int cf_idx, int bs);

/* ------------------------------------------------------------------------
 * DUT socket operations
 * ------------------------------------------------------------------------
 */

/* returns sent bytes or -errno */
ssize_t ft_dut_send(struct ft_ctx *ctx, int s, const void *buf, size_t len,
		    int flags);
/* wait up to timeout_ms for a PDU; returns length, -errno or -ETIME */
ssize_t ft_dut_recv(struct ft_ctx *ctx, int s, void *buf, size_t size,
		    int timeout_ms);
bool ft_dut_expect_pdu(struct ft_ctx *ctx, int s, const uint8_t *data,
		       size_t len, int timeout_ms);
bool ft_dut_expect_nopdu(struct ft_ctx *ctx, int s, int ms);
/* read and clear SO_ERROR */
int ft_sock_error(int s);
/* wait up to timeout_ms for POLLERR and check SO_ERROR == err;
 * stores the time of the POLLERR wakeup in *t_ns (optional)
 */
bool ft_dut_expect_err(struct ft_ctx *ctx, int s, int err, int timeout_ms,
		       int64_t *t_ns);
/* check that no error is pending (SO_ERROR == 0) */
bool ft_dut_expect_noerr(struct ft_ctx *ctx, int s);

/* asynchronous (blocking) send in a separate thread */
struct ft_async {
	pthread_t thread;
	int s;
	const void *buf;
	size_t len;
	int flags;
	ssize_t ret;		/* result: length or -errno */
	int64_t t_start;
	int64_t t_done;
	int done;
	int started;
};

void ft_async_send(struct ft_async *a, int s, const void *buf, size_t len,
		   int flags);
/* wait for the send() to return; false on timeout */
bool ft_async_join(struct ft_ctx *ctx, struct ft_async *a, int timeout_ms);
/* check whether send() has returned already */
bool ft_async_done(struct ft_async *a);

/* ------------------------------------------------------------------------
 * high level protocol helpers
 * ------------------------------------------------------------------------
 */

/* DUT sends a PDU, peer checks all frames against the reference encoder
 * and answers FFs with FC(CTS, bs, stmin). Uses CAN_ISOTP_WAIT_TX_DONE
 * semantics if the socket has the flag set (checks the send() result).
 */
bool ft_tx_pdu(struct ft_ctx *ctx, int s, const struct ft_isotp_cfg *c,
	       struct ft_peer *p, const uint8_t *data, unsigned int len,
	       uint8_t bs, uint8_t stmin);

/* peer sends a PDU (encoded with enc) to the DUT, checks the DUT FC frames
 * and the received PDU
 */
bool ft_rx_pdu(struct ft_ctx *ctx, int s, const struct ft_isotp_cfg *c,
	       struct ft_peer *p, const struct ft_enc *enc,
	       const uint8_t *data, unsigned int len);

#endif /* FT_H */
