# CAN_ISOTP functional test cases

Generated with `make doc` from the test case tables of the test programs.
Do not edit manually.

Each test case lists

- **Behaviour**: the checked behaviour of the CAN_ISOTP implementation
  (input for the specification derived from the code),
- **Code**: the implementation parts (patched net/can/isotp/*.c),
- **ISO 15765-2**: `DEVIATION` notes (behaviour differs from ISO 15765-2,
  shown as `# DEVIATION` in the test output), `DEVIATION (if observed)`
  notes (the test case checks the ISO behaviour and reports the deviation
  only when it is observed), `NOTE` notes (documented implementation
  specific behaviour) and `REVIEW` notes (needs a check against the
  ISO 15765-2 text),
- **Flags**: `slow` (runs into 1 s protocol timeouts, skipped with -q),
  `timing` (checks timing with a tolerance).

Parameterized test cases with the same behaviour are grouped.

## api

### API-SOCK-001

**socket creation**

- **Behaviour:** CAN_ISOTP sockets are created with socket(PF_CAN, SOCK_DGRAM, CAN_ISOTP). Other socket types fail with EPROTOTYPE.
- **Code:** af_can.c:can_create(), isotp.c:isotp_can_proto

### API-SOCK-002

**unsupported socket operations**

- **Behaviour:** connect(), listen(), accept(), shutdown(), getpeername() and socketpair() are not supported and return EOPNOTSUPP.
- **Code:** isotp.c:isotp_ops, isotp_getname()

### API-SOCK-003

**ioctl() handling**

- **Behaviour:** CAN_ISOTP has no protocol specific ioctls. Socket/netdev ioctls (e.g. SIOCGIFINDEX) are handled by the generic layers, others (e.g. FIONREAD) fail with ENOTTY.
- **Code:** isotp.c:isotp_sock_no_ioctlcmd()

### API-SOCK-004

**getsockname()**

- **Behaviour:** getsockname() returns 16 bytes (sockaddr_can up to can_addr.tp) with AF_CAN, the bound ifindex, rx_id and tx_id (all zero before bind()).
- **Code:** isotp.c:isotp_getname()

### API-OPT-001

**default socket option values**

- **Behaviour:** A new socket has: flags 0, frame_txtime 50000 ns, ext_address 0, rx_ext_address 0, txpad/rxpad content 0xCC, RECV_FC bs 0 stmin 0 wftmax 0, TX_STMIN 0, RX_STMIN 0, LL mtu 16 tx_dl 8 tx_flags 0 and all XL options 0 (XL mode disabled).
- **Code:** isotp.c:isotp_init(), uapi isotp.h CAN_ISOTP_DEFAULT_*

### API-OPT-002

**getsockopt() error handling**

- **Behaviour:** getsockopt() requires level SOL_CAN_ISOTP (else EINVAL), known option names 1..6 (else ENOPROTOOPT) and optlen >= 0 (else EINVAL). Shorter buffers get the first optlen bytes, longer buffers get the option size in optlen. NULL optval leads to EFAULT.
- **Code:** isotp.c:isotp_getsockopt()

### API-OPT-003

**setsockopt() error handling**

- **Behaviour:** setsockopt() requires level SOL_CAN_ISOTP (EINVAL, checked first), a known option name (ENOPROTOOPT) and optlen equal to the option size (EINVAL). NULL optval leads to EFAULT.
- **Code:** isotp.c:isotp_setsockopt()

### API-OPT-004

**CAN_ISOTP_OPTS: one broadcast flag**

- **Behaviour:** Only one of CAN_ISOTP_SF_BROADCAST, CAN_ISOTP_CF_BROADCAST and CAN_ISOTP_MF_BROADCAST may be set (else EINVAL). A rejected CAN_ISOTP_OPTS call leaves all options unchanged.
- **Code:** isotp.c:isotp_setsockopt_locked() hweight32(ISOTP_ALL_BC_FLAGS)

### API-OPT-005

**CAN_ISOTP_OPTS: frame_txtime**

- **Behaviour:** frame_txtime (N_As/N_Ar) is limited to the N_As/N_Ar timeout of 1 s (else EINVAL, options unchanged). 0xFFFFFFFF (CAN_ISOTP_FRAME_TXTIME_ZERO) selects 0 ns, 0 keeps the current internal value. getsockopt() returns the struct as given by the last successful setsockopt() (incl. 0 / ZERO).
- **Code:** isotp.c:isotp_setsockopt_locked()

### API-OPT-006

**CAN_ISOTP_OPTS: rx_ext_address**

- **Behaviour:** Without CAN_ISOTP_RX_EXT_ADDR the rx_ext_address is set to ext_address (visible with getsockopt). With the flag both addresses are kept independently.
- **Code:** isotp.c:isotp_setsockopt_locked()

### API-OPT-013

**CAN_ISOTP_OPTS: padding check flags**

- **Behaviour:** CAN_ISOTP_CHK_PAD_DATA needs CAN_ISOTP_RX_PADDING (rxpad_content), else EINVAL and the options are unchanged (also together with CAN_ISOTP_CHK_PAD_LEN). CAN_ISOTP_CHK_PAD_LEN without RX_PADDING (optimized frame length check) is accepted.
- **Code:** isotp.c:isotp_setsockopt_locked() CAN_ISOTP_OPTS

### API-OPT-008

**CAN_ISOTP_RECV_FC values**

- **Behaviour:** CAN_ISOTP_RECV_FC stores bs and wftmax without checks. The reserved STmin values (0x80..0xF0, 0xFA..0xFF) are rejected with EINVAL and leave the stored values unchanged.
- **Code:** isotp.c:isotp_setsockopt_locked() CAN_ISOTP_RECV_FC

### API-OPT-009

**CAN_ISOTP_TX_STMIN / RX_STMIN values**

- **Behaviour:** CAN_ISOTP_TX_STMIN and CAN_ISOTP_RX_STMIN accept any u32 nanosecond value.
- **Code:** isotp.c:isotp_setsockopt_locked()

### API-OPT-010

**CAN_ISOTP_LL_OPTS validation**

- **Behaviour:** LL mtu must be 16 (CAN_MTU) or 72 (CANFD_MTU). tx_dl must be a CAN FD DLC length (8,12,16,20,24,32,48,64); with mtu 16 only tx_dl 8 and tx_flags 0 are valid, with mtu 72 only the tx_flags CANFD_BRS and CANFD_FDF (CANFD_ESI and undefined bits are rejected). For mtu 72 CANFD_FDF is always added to the stored tx_flags (visible with getsockopt). Rejected values leave the LL options unchanged (EINVAL).
- **Code:** isotp.c:isotp_setsockopt_locked() CAN_ISOTP_LL_OPTS

### API-OPT-011

**CAN_ISOTP_XL_OPTS validation**

- **Behaviour:** XL mode is enabled with CANXL_XLF in tx_flags. Then tx_flags and rx_flags may only contain XLF\|SEC\|RRS (rx_flags must contain XLF), tx_dl must be 8..2048, tx_addr/rx_addr must be valid 11/29 bit CAN IDs and sdt_mode must be 6, 7 or 9 (else EINVAL, options unchanged). VCIDs are not checked. The reserved bytes (__res[3], struct size 20) must be zero, also when disabling the XL mode (else EINVAL); getsockopt() returns them as zero. Without XLF the call disables XL mode without further checks and only clears the stored tx_flags.
- **Code:** isotp.c:isotp_setsockopt_locked() CAN_ISOTP_XL_OPTS

### API-OPT-012

**socket options on bound sockets**

- **Behaviour:** All socket options are rejected with EISCONN after bind() (the size check comes first). getsockopt() still works.
- **Code:** isotp.c:isotp_setsockopt_locked()

### API-BIND-001

**bind(): address checks**

- **Behaviour:** bind() requires an address length >= 16 and AF_CAN (else EINVAL). A second bind() fails with EINVAL.
- **Code:** isotp.c:isotp_bind()

### API-BIND-002

**bind(): CAN ID validation**

- **Behaviour:** tx_id and rx_id must be valid 11 bit or 29 bit (with CAN_EFF_FLAG) CAN IDs without RTR/ERR flags (else EINVAL).
- **Code:** isotp.c:isotp_invalid_canid()

### API-BIND-003

**bind(): rx_id with broadcast flags**

- **Behaviour:** With SF/CF/MF broadcast flags the rx_id is not used: it is not validated and may be equal to tx_id.
- **Code:** isotp.c:isotp_bind(), protocolrx.c:isotp_register_rxid()

### API-BIND-004

**bind(): rx_id equals tx_id**

- **Behaviour:** rx_id == tx_id is rejected with EADDRNOTAVAIL (11 bit and 29 bit IDs with the same numeric value are different).
- **Code:** isotp.c:isotp_bind()

### API-BIND-005

**bind(): interface checks**

- **Behaviour:** ifindex 0, a non existing interface or a non-CAN interface fail with ENODEV.
- **Code:** isotp.c:isotp_bind()

### API-BIND-006

**bind(): interface MTU**

- **Behaviour:** The interface MTU must be >= the LL mtu: a CAN FD socket on a CAN CC interface fails with EINVAL, a CAN CC socket on a CAN FD interface and a CAN FD socket on a CAN XL interface are accepted.
- **Code:** isotp.c:isotp_bind() dev->mtu < so->ll.mtu

### API-BIND-007

**bind(): padding and LL_DL**

- **Behaviour:** Padding is only defined for CAN CC/FD N_PDUs: with LL mtu 72 (CAN FD N_PDU) the effective TX_DL (also from CAN_ISOTP_XL_OPTS) must be a CAN FD DLC length; with LL mtu 16 CAN_ISOTP_TX_PADDING requires a TX_DL of 8 (CAN CC N_PDU), a CAN XL N_PDU (TX_DL > 8) is not padded (else EINVAL at bind()).
- **Code:** isotp.c:isotp_bind() fd_pdu()

### API-BIND-008

**bind(): CAN XL settings**

- **Behaviour:** In XL mode tx_id/rx_id must be 11 bit IDs (XL priority), SDT 7 requires LL mtu 72, SDT 6 requires LL mtu 16 and a TX_DL of 8 (else EINVAL). These checks come before the interface lookup.
- **Code:** isotp.c:isotp_bind(), isotp_bind_xl()

### API-BIND-009

**bind() to an interface which is down**

- **Behaviour:** bind() to a CAN interface which is down succeeds and reports ENETDOWN as socket error. send() fails synchronously with ENETDOWN and the socket stays usable.
- **Code:** isotp.c:isotp_bind() notify_enetdown, protocoltx.c:isotp_sendmsg() can_send()

### API-BIND-010

**bind() of XL socket to CC interface**

- **Behaviour:** bind() of a socket in XL mode to an interface without CAN XL support (MTU < CANXL_MIN_MTU) fails with EINVAL.
- **Code:** isotp.c:isotp_bind() isotp_req_mtu()

### API-IO-001

**send()/recv() on unbound socket**

- **Behaviour:** send() and recv() on an unbound socket fail with EADDRNOTAVAIL.
- **Code:** protocoltx.c:isotp_sendmsg(), isotp.c:isotp_recvmsg()

### API-IO-002

**recv() flags**

- **Behaviour:** recv() only accepts MSG_DONTWAIT, MSG_TRUNC, MSG_PEEK and MSG_CMSG_COMPAT (else EINVAL). An empty queue with MSG_DONTWAIT returns EAGAIN.
- **Code:** isotp.c:isotp_recvmsg()

### API-IO-003

**send() PDU size limits**

- **Behaviour:** send() with length 0 or more than max_pdu_size (module parameter, default 8300) fails with EINVAL. max_pdu_size bytes can be sent.
- **Code:** protocoltx.c:isotp_sendmsg()

### API-IO-004

**recv() truncation, MSG_PEEK, address**

- **Behaviour:** A PDU is a datagram: with a short buffer the remaining bytes are discarded and MSG_TRUNC is set in msg_flags, with MSG_TRUNC recv() returns the full PDU length, MSG_PEEK keeps the PDU. msg_name gets 16 bytes with AF_CAN and the receiving ifindex (tp IDs zero).
- **Code:** isotp.c:isotp_recvmsg(), protocolrx.c:isotp_rcv_skb()

### API-IO-005

**PDU receive queue order**

- **Behaviour:** Received PDUs are queued and delivered in order of reception.
- **Code:** protocolrx.c:isotp_rcv_skb()

### API-IO-006

**PDU timestamp**

- **Behaviour:** The receive timestamp of a PDU (SO_TIMESTAMPNS) is the timestamp of the last received CAN frame of the PDU.
- **Code:** protocolrx.c:isotp_rcv_cf() nskb->tstamp = skb->tstamp

### API-IO-007

**poll()**

- **Behaviour:** poll() reports POLLOUT only when no transfer is active, POLLIN when a PDU is queued and POLLERR when a socket error is pending.
- **Code:** isotp.c:isotp_poll()

### API-IO-008

**send() while a transfer is active**

- **Behaviour:** Only one PDU can be sent at a time: send() with MSG_DONTWAIT fails with EAGAIN, a blocking send() waits until the active transfer is finished.
- **Code:** protocoltx.c:isotp_sendmsg()

### API-IO-009

**asynchronous tx error reporting**

- **Behaviour:** Without CAN_ISOTP_WAIT_TX_DONE send() returns the length immediately. A transfer error is reported via the socket error (SO_ERROR/POLLERR) and is returned by the next send() which then sends nothing. The error is cleared afterwards.
- **Code:** protocolrx.c:isotp_rcv_fc(), sock_alloc_send_skb() sock_error()

### API-IO-010

**rx error reporting via recv()**

- **Behaviour:** A reception error (e.g. EILSEQ) is returned once by the next recv().
- **Code:** protocolrx.c:isotp_rcv_cf()

### API-IO-012

**invalid user space buffers**

- **Behaviour:** send() with an invalid buffer fails with EFAULT without sending a frame and leaves the socket idle. recv() with an invalid buffer fails with EFAULT and the PDU is consumed.
- **Code:** protocoltx.c:isotp_sendmsg() memcpy_from_msg(), isotp.c:isotp_recvmsg() memcpy_to_msg()

### API-IO-011

**close() during a transfer**

- **Behaviour:** close() waits for the end of an active transfer (here the N_Bs timeout of 1 s after a FF without FC).
- **Code:** isotp.c:isotp_release()
- **Flags:** slow

## tx

### TX-SEG-CC8-PLAIN .. TX-SEG-XL7-64BRS-AEPAD (96 variants)

**segmentation CC8 PLAIN**

- **Variants:** `TX-SEG-CC8-PLAIN`, `TX-SEG-CC8-AE`, `TX-SEG-CC8-PAD`, `TX-SEG-CC8-AEPAD`, `TX-SEG-FD8-PLAIN`, `TX-SEG-FD8-AE`, `TX-SEG-FD8-PAD`, `TX-SEG-FD8-AEPAD`, `TX-SEG-FD12-PLAIN`, `TX-SEG-FD12-AE`, `TX-SEG-FD12-PAD`, `TX-SEG-FD12-AEPAD`, `TX-SEG-FD16-PLAIN`, `TX-SEG-FD16-AE`, `TX-SEG-FD16-PAD`, `TX-SEG-FD16-AEPAD`, `TX-SEG-FD20-PLAIN`, `TX-SEG-FD20-AE`, `TX-SEG-FD20-PAD`, `TX-SEG-FD20-AEPAD`, `TX-SEG-FD24-PLAIN`, `TX-SEG-FD24-AE`, `TX-SEG-FD24-PAD`, `TX-SEG-FD24-AEPAD`, `TX-SEG-FD32-PLAIN`, `TX-SEG-FD32-AE`, `TX-SEG-FD32-PAD`, `TX-SEG-FD32-AEPAD`, `TX-SEG-FD48-PLAIN`, `TX-SEG-FD48-AE`, `TX-SEG-FD48-PAD`, `TX-SEG-FD48-AEPAD`, `TX-SEG-FD64-PLAIN`, `TX-SEG-FD64-AE`, `TX-SEG-FD64-PAD`, `TX-SEG-FD64-AEPAD`, `TX-SEG-FD64BRS-PLAIN`, `TX-SEG-FD64BRS-AE`, `TX-SEG-FD64BRS-PAD`, `TX-SEG-FD64BRS-AEPAD`, `TX-SEG-XL9-8-PLAIN`, `TX-SEG-XL9-8-AE`, `TX-SEG-XL9-8-PAD`, `TX-SEG-XL9-8-AEPAD`, `TX-SEG-XL9-9-PLAIN`, `TX-SEG-XL9-9-AE`, `TX-SEG-XL9-12-PLAIN`, `TX-SEG-XL9-12-AE`, `TX-SEG-XL9-64-PLAIN`, `TX-SEG-XL9-64-AE`, `TX-SEG-XL9-65-PLAIN`, `TX-SEG-XL9-65-AE`, `TX-SEG-XL9-255-PLAIN`, `TX-SEG-XL9-255-AE`, `TX-SEG-XL9-256-PLAIN`, `TX-SEG-XL9-256-AE`, `TX-SEG-XL9-1000-PLAIN`, `TX-SEG-XL9-1000-AE`, `TX-SEG-XL9-2048-PLAIN`, `TX-SEG-XL9-2048-AE`, `TX-SEG-XL9-2048-SEC-VCID-PLAIN`, `TX-SEG-XL9-2048-SEC-VCID-AE`, `TX-SEG-XL9-100-RRS-PLAIN`, `TX-SEG-XL9-100-RRS-AE`, `TX-SEG-XL9-512-IF512-PLAIN`, `TX-SEG-XL9-512-IF512-AE`, `TX-SEG-XL9-256-IF256-PLAIN`, `TX-SEG-XL9-256-IF256-AE`, `TX-SEG-XL9FD-12-PLAIN`, `TX-SEG-XL9FD-12-AE`, `TX-SEG-XL9FD-12-PAD`, `TX-SEG-XL9FD-12-AEPAD`, `TX-SEG-XL9FD-64-PLAIN`, `TX-SEG-XL9FD-64-AE`, `TX-SEG-XL9FD-64-PAD`, `TX-SEG-XL9FD-64-AEPAD`, `TX-SEG-XL6-8-PLAIN`, `TX-SEG-XL6-8-AE`, `TX-SEG-XL6-8-PAD`, `TX-SEG-XL6-8-AEPAD`, `TX-SEG-XL7-8-PLAIN`, `TX-SEG-XL7-8-AE`, `TX-SEG-XL7-8-PAD`, `TX-SEG-XL7-8-AEPAD`, `TX-SEG-XL7-12-PLAIN`, `TX-SEG-XL7-12-AE`, `TX-SEG-XL7-12-PAD`, `TX-SEG-XL7-12-AEPAD`, `TX-SEG-XL7-64-PLAIN`, `TX-SEG-XL7-64-AE`, `TX-SEG-XL7-64-PAD`, `TX-SEG-XL7-64-AEPAD`, `TX-SEG-XL7-64BRS-PLAIN`, `TX-SEG-XL7-64BRS-AE`, `TX-SEG-XL7-64BRS-PAD`, `TX-SEG-XL7-64BRS-AEPAD`
- **Behaviour:** The DUT segments PDUs of all relevant lengths (1, 2, SF boundaries, FF with 1..n CFs, SN wrap around, 4095 (12 bit FF_DL), 4096 (32 bit FF_DL escape), 8300) into SF/FF/CF frames with the exact layout of the reference encoder: SF with 4 bit SF_DL for TX_DL 8 or SF_DL <= 7-ae, else SF with escape (0x00 + SF_DL byte for CAN FD PDUs, 0x08\|SF_DL>>8 + low byte for CAN XL PDUs); FF uses the full TX_DL with 12 bit FF_DL (<= 4095) or 32 bit FF_DL; CFs carry SN 1..15,0,.. and use TX_DL except the last one; the last CF/SF is padded to the next CAN FD DLC length with CAN_ISOTP_TX_PADDING (content txpad_content) or for CAN FD PDUs > 8 byte (content 0xCC). Block size (FC.BS) is honoured. With CAN_ISOTP_WAIT_TX_DONE send() returns the PDU length after the last frame was sent. CAN FD frames carry FDF\|ll.tx_flags, CAN XL frames the configured prio/VCID/flags/SDT/AF.
- **Code:** protocoltx.c:isotp_sendmsg(), isotp_sf_ff_pci(), isotp_ff_pci(), isotp_send_cframe(), get_padlength(), isotp_fill_frame_head(), protocolrx.c:isotp_rcv_fc(), isotp_rcv_echo()

### TX-PAD-001

**mandatory CAN FD padding content**

- **Behaviour:** Without CAN_ISOTP_TX_PADDING CAN FD frames > 8 byte are padded with 0xCC (not txpad_content), frames <= 8 byte are not padded.
- **Code:** protocoltx.c:get_padlength()

### TX-FC-001-CC8 .. TX-FC-001-XL9-256 (3 variants)

**FC block size CC8**

- **Variants:** `TX-FC-001-CC8`, `TX-FC-001-FD64`, `TX-FC-001-XL9-256`
- **Behaviour:** After a FC with BS = n the DUT sends n CFs and waits for the next FC before sending the next block.
- **Code:** protocolrx.c:isotp_rcv_fc(), protocoltx.c:isotp_rcv_echo()

### TX-FC-002

**BS/STmin only from the first FC**

- **Behaviour:** Without CAN_ISOTP_DYN_FC_PARMS BS and STmin are taken from the first FC of a transfer only, the values in later FCs are ignored.
- **Code:** protocolrx.c:isotp_rcv_fc() ISOTP_WAIT_FIRST_FC

### TX-FC-003

**dynamic BS/STmin (DYN_FC_PARMS)**

- **Behaviour:** With CAN_ISOTP_DYN_FC_PARMS BS and STmin are taken from every FC.
- **Code:** protocolrx.c:isotp_rcv_fc() CAN_ISOTP_DYN_FC_PARMS

### TX-FC-004

**FC wait (WT)**

- **Behaviour:** FC.WT stops the sender until a FC.CTS arrives; each FC.WT restarts the N_Bs timer.
- **Code:** protocolrx.c:isotp_rcv_fc() ISOTP_FC_WT

### TX-FC-006

**N_Bs timeout after FC.WT**

- **Behaviour:** Without a further FC after FC.WT the transfer is aborted after N_Bs (1 s) with ECOMM.
- **Code:** protocolrx.c:isotp_rcv_fc(), hrtimer.c:isotp_tx_timeout()
- **Flags:** slow

### TX-FC-007

**FC overflow on first FC**

- **Behaviour:** FC.OVFLW aborts the transfer with EMSGSIZE, no CF is sent. The socket can be used for the next PDU.
- **Code:** protocolrx.c:isotp_rcv_fc() ISOTP_FC_OVFLW

### TX-FC-009

**reserved flow status**

- **Behaviour:** A FC with reserved flow status 3..15 aborts the transfer with EBADMSG.
- **Code:** protocolrx.c:isotp_rcv_fc() default case

### TX-FC-010-plain .. TX-FC-010-ae (2 variants)

**FC too short**

- **Variants:** `TX-FC-010-plain`, `TX-FC-010-ae`
- **Behaviour:** A frame without N_PCI (CAN_DL < 1, +1 with extended addressing) is no N_PDU and is ignored. A FC with N_PCI and CAN_DL < 3 (+1 with extended addressing) aborts the transfer with EBADMSG. Data bytes beyond CAN_DL are not used.
- **Code:** protocolrx.c:isotp_rcv() N_PCI length check, isotp_rcv_fc()
- **ISO 15765-2:** DEVIATION (if observed): a FC without N_PCI is processed with data beyond CAN_DL (EBADMSG), fixed by xl-isotp split_v2 patch 17.

### TX-FC-011

**FC padding checks**

- **Behaviour:** With CAN_ISOTP_CHK_PAD_LEN (without RX_PADDING) a FC must have the optimized length 3 (+ae). With RX_PADDING\|CHK_PAD_LEN the FC length must be a valid CAN FD DLC length >= 8. With RX_PADDING\|CHK_PAD_DATA all bytes behind the FC content must be rxpad_content. CHK_PAD_DATA without RX_PADDING is rejected by CAN_ISOTP_OPTS (API-OPT-013). The checks also apply to FCs of CAN XL N_PDUs (e.g. RX_PADDING\|CHK_PAD_LEN rejects CAN_DL 100), without checks any CAN_DL is accepted. Failing FCs abort the transfer with EBADMSG.
- **Code:** protocolrx.c:isotp_rcv_fc(), chk_pad_fail(), chk_optimized_fail()

### TX-FC-012

**FC in idle state**

- **Behaviour:** FC frames received without an active transfer are ignored silently.
- **Code:** protocolrx.c:isotp_rcv_fc()

### TX-FC-013

**FC while sending CFs**

- **Behaviour:** FC frames received while the sender is not waiting for a FC (sending CFs) are ignored silently.
- **Code:** protocolrx.c:isotp_rcv_fc()
- **ISO 15765-2:** NOTE: matches ISO 15765-2 (an unexpected FC is a N_UNEXP_PDU and is ignored).

### TX-FC-014-plain .. TX-FC-014-ae (2 variants)

**FC CAN ID filter**

- **Variants:** `TX-FC-014-plain`, `TX-FC-014-ae`
- **Behaviour:** Only FC frames with exactly the rx_id (no EFF/RTR variants) and the rx extended address are processed.
- **Code:** af_can.c:can_rcv_filter(), protocolrx.c:isotp_check_frame_head(), isotp_rcv()

### TX-FC-015

**FC frame type (MTU) filter**

- **Behaviour:** A CAN CC socket ignores CAN FD FC frames and a CAN FD socket ignores CAN CC FC frames (strict separation by the LL mtu).
- **Code:** protocolrx.c:isotp_check_frame_head()

### TX-FC-016

**N_Bs timeout after FF**

- **Behaviour:** Without FC after the FF the transfer is aborted with ECOMM after N_Bs (1 s + frame_txtime). A late FC is ignored.
- **Code:** protocoltx.c:isotp_sendmsg(), hrtimer.c:isotp_tx_timeout()
- **Flags:** slow

### TX-FC-017

**N_Bs timeout after a block**

- **Behaviour:** Without FC after a block the transfer is aborted with ECOMM after N_Bs (1 s).
- **Code:** protocoltx.c:isotp_rcv_echo(), hrtimer.c:isotp_tx_timeout()
- **Flags:** slow

### TX-BC-CF-CC8 .. TX-BC-MF-XL9-2048 (6 variants)

**CF broadcast segmentation CC8**

- **Variants:** `TX-BC-CF-CC8`, `TX-BC-CF-FD64`, `TX-BC-CF-XL9-2048`, `TX-BC-MF-CC8`, `TX-BC-MF-FD64`, `TX-BC-MF-XL9-2048`
- **Behaviour:** With CAN_ISOTP_CF_BROADCAST (FF N_PCI 0x1) or CAN_ISOTP_MF_BROADCAST (multicast FF N_PCI 0x4) all CFs are sent without waiting for FC frames (separation time = frame_txtime, plus the CAN_ISOTP_TX_STMIN socket option value with the FORCE_TXSTMIN flag). SFs are sent normally.
- **Code:** protocoltx.c:isotp_sendmsg() CF/MF broadcast, isotp_ff_pci()

### TX-BC-SF-CC8 .. TX-BC-SF-XL9-2048 (3 variants)

**SF broadcast CC8**

- **Variants:** `TX-BC-SF-CC8`, `TX-BC-SF-FD64`, `TX-BC-SF-XL9-2048`
- **Behaviour:** With CAN_ISOTP_SF_BROADCAST only PDUs fitting into a single frame can be sent, larger PDUs are rejected with EINVAL without sending a frame.
- **Code:** protocoltx.c:isotp_sendmsg()

### TX-BC-001

**broadcast sockets do not receive**

- **Behaviour:** Sockets with SF/CF/MF broadcast flags do not register the rx_id: no PDU reception and no FC frames.
- **Code:** protocolrx.c:isotp_register_rxid(), isotp.c:isotp_bind()

### TX-BC-002

**CF broadcast ignores FC frames**

- **Behaviour:** A CF broadcast transfer is not influenced by FC frames.
- **Code:** protocolrx.c:isotp_register_rxid()

### TX-HD-001

**full duplex: SF reception during tx**

- **Behaviour:** Without CAN_ISOTP_HALF_DUPLEX a SF is received while a transmission waits for a FC.
- **Code:** protocolrx.c:isotp_rcv()

### TX-HD-002

**half duplex: no reception during tx**

- **Behaviour:** With CAN_ISOTP_HALF_DUPLEX all non-FC frames are dropped while a transmission is active.
- **Code:** protocolrx.c:isotp_rcv() CAN_ISOTP_HALF_DUPLEX

### TX-HD-003

**full duplex: FC during reception**

- **Behaviour:** Without CAN_ISOTP_HALF_DUPLEX a FC for the own transmission is processed while a reception is active.
- **Code:** protocolrx.c:isotp_rcv()

### TX-HD-004

**half duplex: no FC during reception**

- **Behaviour:** With CAN_ISOTP_HALF_DUPLEX FC frames are dropped while a reception is active and CFs are dropped while a transmission is active. Simultaneous transfers in both directions therefore block each other until both time out (tx: ECOMM, rx: ETIMEDOUT overwritten by the later ECOMM socket error).
- **Code:** protocolrx.c:isotp_rcv() CAN_ISOTP_HALF_DUPLEX
- **Flags:** slow

### TX-ID-001-CC8 .. TX-ID-001-FD64 (2 variants)

**29 bit CAN IDs CC8**

- **Variants:** `TX-ID-001-CC8`, `TX-ID-001-FD64`
- **Behaviour:** 29 bit CAN IDs (CAN_EFF_FLAG) are used for tx_id and rx_id.
- **Code:** protocoltx.c:isotp_fill_frame_head()

### TX-FL-001

**CAN FD tx_flags**

- **Behaviour:** The LL tx_flags (only CANFD_BRS and CANFD_FDF are accepted, CANFD_ESI and undefined bits are rejected with EINVAL) are copied into each CAN FD frame (CANFD_FDF is added by the CAN core).
- **Code:** isotp.c:isotp_setsockopt_locked(), protocoltx.c:isotp_fill_frame_head(), af_can.c:can_send()

### TX-WTD-001

**WAIT_TX_DONE blocks until done**

- **Behaviour:** With CAN_ISOTP_WAIT_TX_DONE send() blocks until the transfer is complete and returns the PDU length.
- **Code:** protocoltx.c:isotp_sendmsg() wait_tx_done

### TX-WTD-002

**send() without WAIT_TX_DONE**

- **Behaviour:** Without CAN_ISOTP_WAIT_TX_DONE send() returns the PDU length immediately after the first frame was sent.
- **Code:** protocoltx.c:isotp_sendmsg()

### TX-WTD-003

**WAIT_TX_DONE error results**

- **Behaviour:** With CAN_ISOTP_WAIT_TX_DONE transfer errors (EMSGSIZE, EBADMSG) are returned by send() and the pending socket error is cleared. A SF send() returns after the local echo.
- **Code:** protocoltx.c:isotp_sendmsg() isotp_get_tx_result(), sock_error()

### TX-SIG-001

**signal during WAIT_TX_DONE**

- **Behaviour:** A signal interrupting send() while waiting for the end of the own transfer (CAN_ISOTP_WAIT_TX_DONE) aborts the transfer: send() returns EINTR, the timers are stopped, later FCs are ignored and the socket is idle.
- **Code:** protocoltx.c:isotp_sendmsg() err_event_drop

### TX-SIG-002

**signal while waiting for a busy socket**

- **Behaviour:** A signal interrupting a send() which waits for the end of another transfer returns EINTR without sending; the active transfer continues.
- **Code:** protocoltx.c:isotp_sendmsg() wait_event_interruptible() in the claim loop

## rx

### RX-SEG-CC8-PLAIN .. RX-SEG-XL7-64BRS-AEPAD (90 variants)

**reassembly CC8 PLAIN**

- **Variants:** `RX-SEG-CC8-PLAIN`, `RX-SEG-CC8-AE`, `RX-SEG-CC8-PAD`, `RX-SEG-CC8-AEPAD`, `RX-SEG-FD8-PLAIN`, `RX-SEG-FD8-AE`, `RX-SEG-FD8-PAD`, `RX-SEG-FD8-AEPAD`, `RX-SEG-FD12-PLAIN`, `RX-SEG-FD12-AE`, `RX-SEG-FD12-PAD`, `RX-SEG-FD12-AEPAD`, `RX-SEG-FD16-PLAIN`, `RX-SEG-FD16-AE`, `RX-SEG-FD16-PAD`, `RX-SEG-FD16-AEPAD`, `RX-SEG-FD20-PLAIN`, `RX-SEG-FD20-AE`, `RX-SEG-FD20-PAD`, `RX-SEG-FD20-AEPAD`, `RX-SEG-FD24-PLAIN`, `RX-SEG-FD24-AE`, `RX-SEG-FD24-PAD`, `RX-SEG-FD24-AEPAD`, `RX-SEG-FD32-PLAIN`, `RX-SEG-FD32-AE`, `RX-SEG-FD32-PAD`, `RX-SEG-FD32-AEPAD`, `RX-SEG-FD48-PLAIN`, `RX-SEG-FD48-AE`, `RX-SEG-FD48-PAD`, `RX-SEG-FD48-AEPAD`, `RX-SEG-FD64-PLAIN`, `RX-SEG-FD64-AE`, `RX-SEG-FD64-PAD`, `RX-SEG-FD64-AEPAD`, `RX-SEG-XL9-8-PLAIN`, `RX-SEG-XL9-8-AE`, `RX-SEG-XL9-8-PAD`, `RX-SEG-XL9-8-AEPAD`, `RX-SEG-XL9-9-PLAIN`, `RX-SEG-XL9-9-AE`, `RX-SEG-XL9-12-PLAIN`, `RX-SEG-XL9-12-AE`, `RX-SEG-XL9-64-PLAIN`, `RX-SEG-XL9-64-AE`, `RX-SEG-XL9-65-PLAIN`, `RX-SEG-XL9-65-AE`, `RX-SEG-XL9-255-PLAIN`, `RX-SEG-XL9-255-AE`, `RX-SEG-XL9-1000-PLAIN`, `RX-SEG-XL9-1000-AE`, `RX-SEG-XL9-2048-PLAIN`, `RX-SEG-XL9-2048-AE`, `RX-SEG-XL9-2048-SEC-VCID-PLAIN`, `RX-SEG-XL9-2048-SEC-VCID-AE`, `RX-SEG-XL9-100-RRS-PLAIN`, `RX-SEG-XL9-100-RRS-AE`, `RX-SEG-XL9-512-IF512-PLAIN`, `RX-SEG-XL9-512-IF512-AE`, `RX-SEG-XL9-256-IF256-PLAIN`, `RX-SEG-XL9-256-IF256-AE`, `RX-SEG-XL9FD-12-PLAIN`, `RX-SEG-XL9FD-12-AE`, `RX-SEG-XL9FD-12-PAD`, `RX-SEG-XL9FD-12-AEPAD`, `RX-SEG-XL9FD-64-PLAIN`, `RX-SEG-XL9FD-64-AE`, `RX-SEG-XL9FD-64-PAD`, `RX-SEG-XL9FD-64-AEPAD`, `RX-SEG-XL6-8-PLAIN`, `RX-SEG-XL6-8-AE`, `RX-SEG-XL6-8-PAD`, `RX-SEG-XL6-8-AEPAD`, `RX-SEG-XL7-8-PLAIN`, `RX-SEG-XL7-8-AE`, `RX-SEG-XL7-8-PAD`, `RX-SEG-XL7-8-AEPAD`, `RX-SEG-XL7-12-PLAIN`, `RX-SEG-XL7-12-AE`, `RX-SEG-XL7-12-PAD`, `RX-SEG-XL7-12-AEPAD`, `RX-SEG-XL7-64-PLAIN`, `RX-SEG-XL7-64-AE`, `RX-SEG-XL7-64-PAD`, `RX-SEG-XL7-64-AEPAD`, `RX-SEG-XL7-64BRS-PLAIN`, `RX-SEG-XL7-64BRS-AE`, `RX-SEG-XL7-64BRS-PAD`, `RX-SEG-XL7-64BRS-AEPAD`
- **Behaviour:** The DUT reassembles PDUs of all relevant lengths sent with the DUT TX_DL as LL_DL and the DUT rx addressing/padding settings. After a FF the DUT sends FC.CTS with BS/STmin from CAN_ISOTP_RECV_FC (ext_address and TX_PADDING as for all tx frames) and after every BS CFs another FC. The PDU is delivered with recv() after the last CF without socket error. Variants: plain (BS 0), ae (BS 3), pad (BS 1, RX_PADDING\|CHK_PAD_LEN\|CHK_PAD_DATA), aepad (BS 15).
- **Code:** protocolrx.c:isotp_rcv(), isotp_rcv_sf(), isotp_rcv_ff(), isotp_rcv_cf(), protocoltx.c:isotp_send_fc()

### RX-LL-001 .. RX-LL-004 (4 variants)

**any sender LL_DL (CAN FD)**

- **Variants:** `RX-LL-001`, `RX-LL-002`, `RX-LL-003`, `RX-LL-004`
- **Behaviour:** The receiver accepts PDUs with any sender LL_DL (taken from the FF CAN_DL), independent of its own TX_DL: all CAN FD DLC lengths for CAN FD, any length >= 8 for CAN XL.
- **Code:** protocolrx.c:isotp_rcv_ff() so->rx.ll_dl

### RX-SF-001

**CAN CC SF valid**

- **Behaviour:** A CAN CC SF with SF_DL 1..7 is accepted with any CAN_DL >= SF_DL+1 (no padding checks configured); the bytes behind SF_DL are ignored.
- **Code:** protocolrx.c:isotp_rcv() N_PCI_SF, isotp_rcv_sf()

### RX-SF-002

**CAN CC SF invalid SF_DL**

- **Behaviour:** A SF with SF_DL 0 or SF_DL > CAN_DL-1 (incl. 8..15) is ignored silently (no PDU, no error).
- **Code:** protocolrx.c:isotp_rcv_sf()

### RX-SF-003 .. RX-SF-004 (2 variants)

**CAN_DL 0 frame with stale N_PCI**

- **Variants:** `RX-SF-003`, `RX-SF-004`
- **Behaviour:** Expected (ISO): a frame without N_PCI byte (CAN_DL 0) is ignored. Observed behaviour is reported.
- **Code:** protocolrx.c:isotp_rcv() reads data[ae] without CAN_DL check, isotp_rcv_sf() 'sf_dl > datalen - pcilen' unsigned underflow
- **ISO 15765-2:** DEVIATION (if observed): frames shorter than the N_PCI are processed with data beyond CAN_DL (see test output).

### RX-SF-005

**ext. addressing: CAN_DL 1 frame**

- **Behaviour:** Expected (ISO): a frame with only the address extension (CAN_DL 1) is ignored. Observed behaviour is reported.
- **Code:** protocolrx.c:isotp_rcv_sf() unsigned underflow of datalen - pcilen
- **ISO 15765-2:** DEVIATION (if observed): frames shorter than AE + N_PCI are processed with data beyond CAN_DL.

### RX-SF-006

**SF with extended addressing**

- **Behaviour:** With extended addressing only frames with data[0] == rx_ext_address are processed, the SF_DL maximum is 6 for CAN_DL 8.
- **Code:** protocolrx.c:isotp_rcv()

### RX-SF-007

**SF with separate rx address**

- **Behaviour:** With CAN_ISOTP_RX_EXT_ADDR the rx_ext_address (not ext_address) is expected in received frames.
- **Code:** protocolrx.c:isotp_rcv(), isotp.c:isotp_setsockopt_locked()

### RX-SF-008

**CAN FD SF valid**

- **Behaviour:** CAN FD SF with CAN_DL <= 8 use the 4 bit SF_DL; with CAN_DL > 8 the escape sequence (N_PCI 0x00 + SF_DL byte) is accepted for all SF_DL values which need this CAN_DL.
- **Code:** protocolrx.c:isotp_rcv() N_PCI_SF can_is_canfd_skb()
- **ISO 15765-2:** NOTE: SF_DL values which would fit into a shorter CAN FD frame (e.g. SF_DL 1 in CAN_DL 64) are not checked (fault tolerant reception allowed).

### RX-SF-009

**CAN FD SF invalid**

- **Behaviour:** CAN FD SF with CAN_DL > 8 and a non-zero low nibble (no escape), escape with SF_DL 0 or SF_DL > CAN_DL-2, and the escape in CAN_DL <= 8 are ignored silently.
- **Code:** protocolrx.c:isotp_rcv(), isotp_rcv_sf()

### RX-SF-010

**CAN FD frames with non-DLC length**

- **Behaviour:** Without padding checks CAN FD SFs with a CAN_DL that is no CAN FD DLC length (e.g. 9..11, only possible on virtual CAN) are accepted.
- **Code:** protocolrx.c:isotp_rcv()

### RX-SF-011

**SF padding checks**

- **Behaviour:** CHK_PAD_LEN without RX_PADDING requires the optimized length (CC: exact, FD: next DLC length after the data); RX_PADDING\|CHK_PAD_LEN requires a valid CAN FD DLC length >= 8; RX_PADDING\|CHK_PAD_DATA requires rxpad_content in all bytes after the data; CHK_PAD_DATA without RX_PADDING is rejected by CAN_ISOTP_OPTS (API-OPT-013). Failures are reported as EBADMSG and the PDU is dropped.
- **Code:** protocolrx.c:isotp_rcv_sf(), chk_pad_fail(), chk_optimized_fail()

### RX-SF-012

**valid SF during reception**

- **Behaviour:** A valid SF received during a segmented reception is delivered and terminates the reception silently (remaining CFs are ignored, no error).
- **Code:** protocolrx.c:isotp_rcv_sf()
- **ISO 15765-2:** NOTE: ISO 15765-2 indicates the terminated reception with N_UNEXP_PDU. The socket API has no indication for a discarded PDU, the new PDU is delivered.

### RX-SF-013

**invalid SF during reception**

- **Behaviour:** An invalid SF (SF_DL 0 or SF_DL > CAN_DL - 1) received during a segmented reception is ignored: the reception continues and the PDU is completed by the remaining CFs.
- **Code:** protocolrx.c:isotp_rcv_sf() SF_DL check before terminating the reception

### RX-SF-014

**no N_Cr timeout after terminated reception**

- **Behaviour:** After the reception was terminated by a SF no N_Cr timeout error is reported.
- **Code:** protocolrx.c:isotp_rcv_sf() hrtimer_cancel(&so->rxtimer)
- **Flags:** slow

### RX-FF-001

**FF with CAN_DL < 8**

- **Behaviour:** A FF with CAN_DL < 8 is ignored (no FC).
- **Code:** protocolrx.c:isotp_rcv_ff()

### RX-FF-002

**CAN FD FF length / CF length**

- **Behaviour:** A CAN FD FF must have a CAN FD DLC length (else ignored). The FF CAN_DL defines the sender LL_DL; longer CFs are ignored and the reception continues.
- **Code:** protocolrx.c:isotp_rcv_ff(), isotp_rcv_cf()

### RX-FF-003

**32 bit FF_DL escape**

- **Behaviour:** A FF with FF_DL escape (12 bit FF_DL 0) and a 32 bit FF_DL <= 4095 is ignored, FF_DL 4096 is accepted.
- **Code:** protocolrx.c:isotp_rcv_ff()

### RX-FF-004-CC8 .. RX-FF-004-XL9-2048 (4 variants)

**FF_DL minimum CC8**

- **Variants:** `RX-FF-004-CC8`, `RX-FF-004-CC8-ae`, `RX-FF-004-FD64`, `RX-FF-004-XL9-2048`
- **Behaviour:** A FF with FF_DL < FF_DLmin (the PDU fits into a SF of the sender LL_DL: 7-ae for LL_DL 8, LL_DL-2-ae else) is ignored, FF_DL >= FF_DLmin is answered with a FC.
- **Code:** protocolrx.c:isotp_rcv_ff() FF_DLmin check
- **ISO 15765-2:** DEVIATION (if observed): CAN CC FF_DL 7 (normal) / 6 (extended addressing) is accepted although it fits into a SF (ISO 15765-2 FF_DLmin 8 / 7), fixed by xl-isotp split_v2 patch 19.

### RX-FF-005

**FF_DL > max_pdu_size**

- **Behaviour:** A FF with FF_DL > max_pdu_size is answered with FC.OVFLW, the following CFs are ignored and no error is reported. FF_DL == max_pdu_size is answered with FC.CTS.
- **Code:** protocolrx.c:isotp_rcv_ff()

### RX-FF-006

**FF_DL > max_pdu_size in listen mode**

- **Behaviour:** Expected: in CAN_ISOTP_LISTEN_MODE no frames are sent. Observed behaviour for a FF with FF_DL > max_pdu_size is reported.
- **Code:** protocolrx.c:isotp_rcv_ff() isotp_send_fc(OVFLW) before the LISTEN_MODE check
- **ISO 15765-2:** DEVIATION (if observed): a FC.OVFLW is sent in listen mode, which can abort transfers between other nodes (fixed by xl-isotp split_v2 patch 21).

### RX-FF-011 .. RX-FF-011-ae (2 variants)

**FF_DL close to 2^32**

- **Variants:** `RX-FF-011`, `RX-FF-011-ae`
- **Behaviour:** Expected: all FF_DL values > max_pdu_size (up to 0xFFFFFFFF) are answered with FC.OVFLW. Observed behaviour is reported.
- **Code:** protocolrx.c:isotp_rcv_ff() 'so->rx.len + ae + ff_pci_sz <= so->rx.ll_dl' (u32 arithmetic)
- **ISO 15765-2:** DEVIATION (if observed): FF_DL >= 0xFFFFFFFA (0xFFFFFFF9 with ext. addressing) wraps around in the single FF check and the FF is ignored without FC.OVFLW.

### RX-FF-007

**FF during reception**

- **Behaviour:** A valid FF during a reception restarts the reception with the new PDU (new FC), the old PDU is discarded silently.
- **Code:** protocolrx.c:isotp_rcv_ff()
- **ISO 15765-2:** NOTE: ISO 15765-2 indicates the terminated reception with N_UNEXP_PDU. The socket API has no indication for a discarded PDU, the new PDU is received.

### RX-FF-008

**invalid FF during reception**

- **Behaviour:** An invalid FF (CAN_DL < 8, FF_DL < FF_DLmin, unneeded 32 bit FF_DL escape) received during a reception is ignored: LL_DL and FF_DL of the ongoing reception are kept and the PDU is completed by the remaining CFs.
- **Code:** protocolrx.c:isotp_rcv_ff() checks before terminating the reception

### RX-FF-009

**FC content from RECV_FC**

- **Behaviour:** The FC.CTS contains BS and STmin from CAN_ISOTP_RECV_FC (reserved STmin values are rejected by the socket option).
- **Code:** protocoltx.c:isotp_send_fc(), isotp.c:isotp_setsockopt_locked()
- **ISO 15765-2:** NOTE: N_WFTmax / FC.WT on the receiver side (CAN_ISOTP_RECV_FC.wftmax) are not checked.

### RX-FF-010-CC8 .. RX-FF-010-XL9-2048 (3 variants)

**listen mode reception CC8**

- **Variants:** `RX-FF-010-CC8`, `RX-FF-010-FD64`, `RX-FF-010-XL9-2048`
- **Behaviour:** In CAN_ISOTP_LISTEN_MODE PDUs are received without sending FC frames (BS is ignored).
- **Code:** protocolrx.c:isotp_rcv_ff(), isotp_rcv_cf()

### RX-CF-001

**wrong sequence number**

- **Behaviour:** A CF with a wrong SN aborts the reception with EILSEQ; the remaining CFs are ignored.
- **Code:** protocolrx.c:isotp_rcv_cf()

### RX-CF-002

**CF without reception**

- **Behaviour:** CFs without an active reception are ignored silently.
- **Code:** protocolrx.c:isotp_rcv_cf()

### RX-CF-003 .. RX-CF-004 (2 variants)

**CF shorter than LL_DL (CC)**

- **Variants:** `RX-CF-003`, `RX-CF-004`
- **Behaviour:** A CF shorter than LL_DL which is not the last CF is ignored, the reception continues.
- **Code:** protocolrx.c:isotp_rcv_cf()

### RX-CF-005

**last CF longer than needed**

- **Behaviour:** The last CF may contain more bytes than needed (without padding checks); only FF_DL bytes are delivered.
- **Code:** protocolrx.c:isotp_rcv_cf()

### RX-CF-006

**CAN_DL 0 frame with stale CF N_PCI**

- **Behaviour:** Expected (ISO): a frame without N_PCI (CAN_DL 0) is ignored and the PDU completes. Observed behaviour is reported.
- **Code:** protocolrx.c:isotp_rcv() / isotp_rcv_cf() no minimum CAN_DL check
- **ISO 15765-2:** DEVIATION (if observed): a CAN_DL 0 frame is processed as (empty) CF and advances the SN (see test output).

### RX-CF-014

**short last CF lacking bytes**

- **Behaviour:** Only the last CF may be shorter than LL_DL and it has to contain all remaining bytes of the PDU. A short CF lacking bytes (here 3 of 7) is ignored and the reception continues with the correct CF.
- **Code:** protocolrx.c:isotp_rcv_cf() last CF length check
- **ISO 15765-2:** DEVIATION (if observed): the short CF is accepted, consumes a SN and the reception waits for further CFs (fixed by xl-isotp split_v2 patch 20).

### RX-CF-015

**CF with N_PCI only**

- **Behaviour:** A CF with only the N_PCI (no data) is a short CF lacking bytes and is ignored; the reception continues with the correct CF.
- **Code:** protocolrx.c:isotp_rcv_cf() last CF length check
- **ISO 15765-2:** DEVIATION (if observed): the empty CF is accepted and consumes a SN (fixed by xl-isotp split_v2 patch 20).

### RX-CF-007-CC8 .. RX-CF-007-FD64 (2 variants)

**block size handling CC8**

- **Variants:** `RX-CF-007-CC8`, `RX-CF-007-FD64`
- **Behaviour:** The receiver sends a FC after every BS CFs (BS 1..255).
- **Code:** protocolrx.c:isotp_rcv_cf() so->rxfc.bs

### RX-CF-008

**last CF padding checks**

- **Behaviour:** The padding checks are applied to the last CF (rules as for SF); failures are reported with EBADMSG and the PDU is dropped.
- **Code:** protocolrx.c:isotp_rcv_cf() chk_pad_fail()

### RX-CF-009-CC8 .. RX-CF-009-FD64 (2 variants)

**RX STmin enforcement CC8**

- **Variants:** `RX-CF-009-CC8`, `RX-CF-009-FD64`
- **Behaviour:** With CAN_ISOTP_FORCE_RXSTMIN CFs received with a timestamp gap < CAN_ISOTP_RX_STMIN are dropped silently, which leads to EILSEQ for the next CF. CFs with larger gaps are accepted. The gap is measured to the last accepted CF. (CF sequences sent with CAN_BCM)
- **Code:** protocolrx.c:isotp_rcv_cf() CAN_ISOTP_FORCE_RXSTMIN

### RX-CF-010

**RX STmin reset by FC**

- **Behaviour:** The RX STmin reference timestamp is reset by each sent FC: the first CF after a FC is always accepted.
- **Code:** protocoltx.c:isotp_send_fc() lastrxcf_tstamp

### RX-CF-011

**N_Cr timeout after FF**

- **Behaviour:** Without CF after the FC the reception is aborted after N_Cr (1 s + frame_txtime) with ETIMEDOUT; later CFs are ignored.
- **Code:** protocoltx.c:isotp_send_fc(), hrtimer.c:isotp_rx_timer_handler()
- **Flags:** slow

### RX-CF-012

**N_Cr timeout after CF**

- **Behaviour:** Without further CF the reception is aborted after N_Cr (1 s) with ETIMEDOUT.
- **Code:** protocolrx.c:isotp_rcv_cf(), hrtimer.c:isotp_rx_timer_handler()
- **Flags:** slow

### RX-CF-013

**N_Cr timeout in listen mode**

- **Behaviour:** In listen mode a FF without CFs leads to ETIMEDOUT after 1 s.
- **Code:** protocolrx.c:isotp_rcv_ff() hrtimer_start(rxtimer)
- **Flags:** slow

### RX-ID-001

**CAN ID filter**

- **Behaviour:** Only frames with exactly the rx_id are processed (no other ID, no EFF with the same value, no RTR, not the own tx_id); own sent PDUs are not received.
- **Code:** isotp.c:isotp_bind() can_rx_register(SINGLE_MASK), protocolrx.c:isotp_check_frame_head()

### RX-ID-002

**29 bit CAN ID filter**

- **Behaviour:** A 29 bit rx_id only matches 29 bit frames with the same ID (no RTR).
- **Code:** isotp.c:isotp_bind() SINGLE_MASK

### RX-ID-003

**frame type (MTU) filter**

- **Behaviour:** A CAN CC socket only processes CAN CC frames and a CAN FD socket (also with TX_DL 8) only CAN FD frames.
- **Code:** protocolrx.c:isotp_check_frame_head() skb->len != so->ll.mtu

### RX-ID-004

**CAN FD flags not checked**

- **Behaviour:** The CAN FD flags (BRS, ESI, ..) of received frames are not checked.
- **Code:** protocolrx.c:isotp_check_frame_head()

### RX-MF-001

**MF ignored without listen mode**

- **Behaviour:** Multicast first frames (N_PCI 0x4) are ignored by sockets without CAN_ISOTP_LISTEN_MODE (no FC, no PDU).
- **Code:** protocolrx.c:isotp_rcv() N_PCI_MF

### RX-MF-002

**MF reception in listen mode**

- **Behaviour:** Sockets with CAN_ISOTP_LISTEN_MODE receive PDUs started with a multicast first frame (12 and 32 bit FF_DL) without sending FC frames.
- **Code:** protocolrx.c:isotp_rcv() N_PCI_MF => isotp_rcv_ff()

### RX-PCI-001

**reserved N_PCI types**

- **Behaviour:** Frames with N_PCI types 0x5..0xF are ignored silently.
- **Code:** protocolrx.c:isotp_rcv()

### RX-PCI-002

**reserved N_PCI types (listen mode)**

- **Behaviour:** Frames with N_PCI types 0x5..0xF are ignored silently in listen mode.
- **Code:** protocolrx.c:isotp_rcv()

## xl

### XL-HDR-001

**CAN XL tx frame header**

- **Behaviour:** CAN XL frames (SF, FF, CF, FC) carry prio = tx_id (11 bit) \| tx_vcid << 16, flags = tx_flags (XLF + SEC/RRS), sdt = sdt_mode, len = exact frame length and af = tx_addr where a 29 bit tx_addr is marked with bit 29 (instead of CAN_EFF_FLAG); in SDT 7 mode with CANFD_BRS in the LL tx_flags bit 30 of the AF is set.
- **Code:** protocoltx.c:isotp_fill_frame_head(), isotp.c:isotp_bind_xl()

### XL-HDR-002

**CAN XL rx header filter**

- **Behaviour:** A CAN XL frame is only processed if prio & 0x7FF == rx_id, VCID == rx_vcid, flags == rx_flags (exact match), (af & 0x3FFFFFFF) == rx_addr (29 bit address with bit 29) and sdt == sdt_mode. CAN CC/FD frames are ignored by CAN XL sockets.
- **Code:** protocolrx.c:isotp_check_frame_head()

### XL-HDR-003

**AF bits 30/31 ignored (SDT 9)**

- **Behaviour:** In SDT 9 mode the AF bits 31/30 are reserved: they are sent as 0 (see XL-HDR-001) and ignored at reception time (forward compatibility).
- **Code:** protocolrx.c:isotp_check_frame_head() CAN_CIA_ADDR_MASK

### XL-HDR-004

**AF bits 30/31 (SDT 7)**

- **Behaviour:** In SDT 7 (CAN FD tunnel) mode the AF bit 30 (BRS) is ignored at reception time, frames with AF bit 31 (CiA 611-1 ZDLC, zero data length) are dropped.
- **Code:** protocolrx.c:isotp_check_frame_head() CAN_CIA_SDT_ZDLC
- **ISO 15765-2:** DEVIATION (if observed): tunneled ZDLC frames are processed (fixed by xl-isotp split_v2 patch 35).

### XL-HDR-005

**11 bit AF**

- **Behaviour:** An 11 bit rx_addr is used as AF without bit 29; frames with the same address and bit 29 are ignored.
- **Code:** isotp.c:isotp_bind_xl(), protocolrx.c:isotp_check_frame_head()

### XL-HDR-006

**CC/FD sockets ignore CAN XL frames**

- **Behaviour:** CAN CC and CAN FD sockets bound to a CAN XL interface ignore CAN XL frames.
- **Code:** protocolrx.c:isotp_check_frame_head()

### XL-HDR-007

**AF bits 30/31 (SDT 6)**

- **Behaviour:** In SDT 6 (CAN CC tunnel) mode frames with AF bit 30 (CiA 611-1 RTR) or bit 31 (ZDLC, zero data length) are dropped.
- **Code:** protocolrx.c:isotp_check_frame_head() CAN_CIA_SDT6_RTR, CAN_CIA_SDT_ZDLC
- **ISO 15765-2:** DEVIATION (if observed): tunneled RTR/ZDLC frames are processed (fixed by xl-isotp split_v2 patch 35).

### XL-SF-001

**CAN XL SF format**

- **Behaviour:** CAN XL N_PDUs (SDT 9, no CAN FD LL) use the 4 bit SF_DL for CAN_DL <= 8. For CAN_DL > 8 the N_PCI is 0x08 \| SF_DL bits 10..8 followed by SF_DL bits 7..0 (SF_DL 1..CAN_DL-2). Like for CAN CC/FD only the presence of the SF data is checked, not the exact CAN_DL. The CAN FD escape (0x00) and 4 bit SF_DL are ignored for CAN_DL > 8.
- **Code:** protocolrx.c:isotp_rcv() N_PCI_XL_SF, isotp_rcv_sf()

### XL-SF-002

**CAN XL N_PDUs with padding checks**

- **Behaviour:** Enabled rx padding checks (RX_PADDING/CHK_PAD_*) keep their CAN CC/FD semantics also for CAN XL N_PDUs (LL mtu 16): with RX_PADDING\|CHK_PAD_LEN a SF with CAN_DL > 8 must have a CAN FD DLC length (else EBADMSG) and CHK_PAD_DATA checks the bytes behind the data. A SF with CAN_DL > 8 always needs the XL SF PCI flag (the CAN FD escape 0x00 is ignored).
- **Code:** protocolrx.c:isotp_rcv() N_PCI_XL_SF, chk_pad_fail()

### XL-CF-001

**CAN XL last CF length**

- **Behaviour:** Like for CAN CC/FD only the presence of the PDU data is checked: a last CF of a CAN XL N_PDU (RX_DL > 8) with more bytes than the missing PDU data (also with CAN_DL <= 8) completes the PDU.
- **Code:** protocolrx.c:isotp_rcv_cf()

### XL-SDT6-001

**SDT 6 reception of long frames**

- **Behaviour:** Expected: a CAN CC tunnel (SDT 6) socket only processes frames with CAN_DL <= 8. Observed behaviour is reported.
- **Code:** protocolrx.c:isotp_rcv(), isotp_rcv_ff() (no SDT 6 specific length check)
- **ISO 15765-2:** DEVIATION (if observed): SDT 6 sockets accept SF/FF/CF with CAN_DL > 8 (fixed by xl-isotp split_v2 patch 35).

### XL-SDT7-001

**SDT 7 reception**

- **Behaviour:** A CAN FD tunnel (SDT 7) socket uses CAN FD PDU rules: FF must have a CAN FD DLC length, SF > 8 byte use the CAN FD escape, any sender LL_DL <= 64.
- **Code:** protocolrx.c:isotp_rcv_ff() fd_pdu(), isotp_rcv()

### XL-SDT7-002

**SDT 7 SF length**

- **Behaviour:** Expected: a CAN FD tunnel (SDT 7) socket only processes frames with a CAN FD data length (<= 8 or a DLC length up to 64). Observed behaviour for SF in the CAN XL SF format with CAN_DL 100 and 13 is reported; a valid CAN FD SF is received.
- **Code:** protocolrx.c:isotp_check_frame_head() tunnel length check, isotp_rcv() N_PCI_XL_SF
- **ISO 15765-2:** DEVIATION (if observed): SDT 7 sockets accept SF with CAN_DL > 64 or without CAN FD DLC length (fixed by xl-isotp split_v2 patch 35).

### XL-SDT7-003

**SDT 7 SF with N_PCI 0x08**

- **Behaviour:** A CAN FD tunnel (SDT 7) SF with CAN_DL 12 and N_PCI 0x08 0x0A is ignored, CAN FD only defines N_PCI 0x00 for the SF_DL escape.
- **Code:** protocolrx.c:isotp_rcv() fd_pdu()

### XL-SDT9-001

**CAN FD N_PDUs in SDT 9**

- **Behaviour:** A SDT 9 socket with LL mtu 72 handles CAN FD N_PDUs: SF with CAN_DL > 8 need the CAN FD escape (0x00) and a CAN FD length <= 64, FF with other lengths are ignored, PDUs with any CAN FD sender LL_DL are received.
- **Code:** protocolrx.c:isotp_check_frame_head() fd_pdu(), isotp_rcv()

### XL-OPT-001

**LL_OPTS after XL_OPTS**

- **Behaviour:** The effective TX_DL is set at bind() time independent of the order of the socket options: in XL mode the tx_dl from CAN_ISOTP_XL_OPTS (as returned by getsockopt()), else the tx_dl from CAN_ISOTP_LL_OPTS.
- **Code:** isotp.c:isotp_bind() so->tx.ll_dl

### XL-OPT-002

**disabling XL mode**

- **Behaviour:** Disabling the XL mode restores the LL tx_dl and CAN CC/FD frames are sent.
- **Code:** isotp.c:isotp_setsockopt_locked() CAN_ISOTP_XL_OPTS

### XL-MTU-001

**TX_DL larger than interface MTU**

- **Behaviour:** In XL mode bind() requires an interface MTU >= CANXL_HDR_SIZE + TX_DL and >= CANXL_MIN_MTU (CAN XL capable interface), else EINVAL.
- **Code:** isotp.c:isotp_bind() isotp_req_mtu()

## e2e

### E2E-CC8-PLAIN .. E2E-CC8-AEPAD (4 variants)

**end-to-end CC8 PLAIN**

- **Variants:** `E2E-CC8-PLAIN`, `E2E-CC8-AE`, `E2E-CC8-PAD`, `E2E-CC8-AEPAD`
- **Behaviour:** Two CAN_ISOTP sockets with swapped CAN IDs (and swapped address extensions/padding content) exchange PDUs of all relevant lengths in both directions and in full duplex (simultaneous transfers) without errors.
- **Code:** protocoltx.c, protocolrx.c, hrtimer.c

### E2E-CC8-FCPARM

**end-to-end CC8 BS 3 STmin 100us**

- **Behaviour:** Like the end-to-end test with BS 3 and STmin 0xF1 (100 us) in the FC frames of both sockets.
- **Code:** protocoltx.c, protocolrx.c, hrtimer.c

### E2E-FD8-PLAIN .. E2E-FD64-AEPAD (8 variants)

**end-to-end FD8 PLAIN**

- **Variants:** `E2E-FD8-PLAIN`, `E2E-FD8-PAD`, `E2E-FD24-PLAIN`, `E2E-FD24-AEPAD`, `E2E-FD64-PLAIN`, `E2E-FD64-AE`, `E2E-FD64-PAD`, `E2E-FD64-AEPAD`
- **Behaviour:** Two CAN_ISOTP sockets with swapped CAN IDs (and swapped address extensions/padding content) exchange PDUs of all relevant lengths in both directions and in full duplex (simultaneous transfers) without errors.
- **Code:** protocoltx.c, protocolrx.c, hrtimer.c

### E2E-FD64-FCPARM

**end-to-end FD64 BS 3 STmin 100us**

- **Behaviour:** Like the end-to-end test with BS 3 and STmin 0xF1 (100 us) in the FC frames of both sockets.
- **Code:** protocoltx.c, protocolrx.c, hrtimer.c

### E2E-FD64BRS-PLAIN .. E2E-XL9-2048-AE (11 variants)

**end-to-end FD64BRS PLAIN**

- **Variants:** `E2E-FD64BRS-PLAIN`, `E2E-XL9-8-PLAIN`, `E2E-XL9-12-PLAIN`, `E2E-XL9-64-PLAIN`, `E2E-XL9-64-AE`, `E2E-XL9FD-12-PAD`, `E2E-XL9FD-64-AEPAD`, `E2E-XL9-65-AE`, `E2E-XL9-255-PLAIN`, `E2E-XL9-2048-PLAIN`, `E2E-XL9-2048-AE`
- **Behaviour:** Two CAN_ISOTP sockets with swapped CAN IDs (and swapped address extensions/padding content) exchange PDUs of all relevant lengths in both directions and in full duplex (simultaneous transfers) without errors.
- **Code:** protocoltx.c, protocolrx.c, hrtimer.c

### E2E-XL9-2048-FCPARM

**end-to-end XL9-2048 BS 3 STmin 100us**

- **Behaviour:** Like the end-to-end test with BS 3 and STmin 0xF1 (100 us) in the FC frames of both sockets.
- **Code:** protocoltx.c, protocolrx.c, hrtimer.c

### E2E-XL9-2048-SEC-VCID-PLAIN .. E2E-XL7-64BRS-AEPAD (8 variants)

**end-to-end XL9-2048-SEC-VCID PLAIN**

- **Variants:** `E2E-XL9-2048-SEC-VCID-PLAIN`, `E2E-XL9-100-RRS-AE`, `E2E-XL9-512-IF512-PLAIN`, `E2E-XL9-256-IF256-PLAIN`, `E2E-XL6-8-PLAIN`, `E2E-XL6-8-PAD`, `E2E-XL7-64-PLAIN`, `E2E-XL7-64BRS-AEPAD`
- **Behaviour:** Two CAN_ISOTP sockets with swapped CAN IDs (and swapped address extensions/padding content) exchange PDUs of all relevant lengths in both directions and in full duplex (simultaneous transfers) without errors.
- **Code:** protocoltx.c, protocolrx.c, hrtimer.c

### E2E-MIX-FD64-FD8 .. E2E-MIX-XL7-64-XL7-8 (5 variants)

**end-to-end FD64 <-> FD8**

- **Variants:** `E2E-MIX-FD64-FD8`, `E2E-MIX-FD12-FD48`, `E2E-MIX-XL9-2048-XL9-64`, `E2E-MIX-XL9-9-XL9-1000`, `E2E-MIX-XL7-64-XL7-8`
- **Behaviour:** Two sockets with different TX_DL settings communicate: the receiver accepts the sender LL_DL (taken from the FF).
- **Code:** protocoltx.c, protocolrx.c, hrtimer.c

### E2E-HD-001

**end-to-end half duplex**

- **Behaviour:** Two sockets with CAN_ISOTP_HALF_DUPLEX exchange PDUs in both directions (sequentially).
- **Code:** protocolrx.c:isotp_rcv() CAN_ISOTP_HALF_DUPLEX

### E2E-MC-CF-CC8 .. E2E-MC-CF-XL9-2048 (3 variants)

**CF broadcast to n receivers CC8**

- **Variants:** `E2E-MC-CF-CC8`, `E2E-MC-CF-FD64`, `E2E-MC-CF-XL9-2048`
- **Behaviour:** A CF broadcast sender transmits to two listen mode receivers and one normal receiver (whose FCs are ignored by the sender); all receive the PDUs.
- **Code:** protocoltx.c:isotp_sendmsg() CF broadcast

### E2E-MC-MF-CC8 .. E2E-MC-MF-XL9-2048 (3 variants)

**MF multicast to n receivers CC8**

- **Variants:** `E2E-MC-MF-CC8`, `E2E-MC-MF-FD64`, `E2E-MC-MF-XL9-2048`
- **Behaviour:** A MF multicast sender transmits to two listen mode receivers which receive the segmented PDUs; a normal receiver only receives SF PDUs and ignores MF started transfers.
- **Code:** protocoltx.c:isotp_ff_pci() N_PCI_MF, protocolrx.c:isotp_rcv()

### E2E-MC-SF-CC8 .. E2E-MC-SF-FD64 (2 variants)

**SF broadcast to n receivers CC8**

- **Variants:** `E2E-MC-SF-CC8`, `E2E-MC-SF-FD64`
- **Behaviour:** A SF broadcast sender (functional addressing) transmits SF PDUs to normal and listen mode receivers.
- **Code:** protocoltx.c:isotp_sendmsg() SF broadcast

### E2E-SNIFF-CC8 .. E2E-SNIFF-XL9-2048 (3 variants)

**listen mode sniffer CC8**

- **Variants:** `E2E-SNIFF-CC8`, `E2E-SNIFF-FD64`, `E2E-SNIFF-XL9-2048`
- **Behaviour:** Listen mode sockets with the receiver settings receive the PDUs of an ongoing point-to-point communication (BS 2) without disturbing it.
- **Code:** protocolrx.c CAN_ISOTP_LISTEN_MODE

## timing

### TIM-STM-001 .. TIM-STM-019 (19 variants)

**burst (STmin 0, frame_txtime 0)**

- **Variants:** `TIM-STM-001`, `TIM-STM-002`, `TIM-STM-003`, `TIM-STM-004`, `TIM-STM-005`, `TIM-STM-006`, `TIM-STM-007`, `TIM-STM-008`, `TIM-STM-009`, `TIM-STM-010`, `TIM-STM-011`, `TIM-STM-012`, `TIM-STM-013`, `TIM-STM-014`, `TIM-STM-015`, `TIM-STM-016`, `TIM-STM-017`, `TIM-STM-018`, `TIM-STM-019`
- **Behaviour:** The gap between consecutive frames is frame_txtime (N_As, default 50 us) + STmin from the first FC: 0x00..0x7F => 0..127 ms, 0xF1..0xF9 => 100..900 us, reserved values (0x80..0xF0, 0xFA..0xFF) => 127 ms. With CAN_ISOTP_FORCE_TXSTMIN the CAN_ISOTP_TX_STMIN value (ns) replaces the FC STmin. Without any gap the CFs are sent in burst mode (no timer).
- **Code:** protocolrx.c:isotp_rcv_fc() tx_gap, protocoltx.c:isotp_rcv_echo(), hrtimer.c:isotp_txfr_timer_handler()
- **Flags:** timing

### TIM-BC-001 .. TIM-BC-003 (3 variants)

**CF broadcast gap (frame_txtime 5 ms)**

- **Variants:** `TIM-BC-001`, `TIM-BC-002`, `TIM-BC-003`
- **Behaviour:** In CF/MF broadcast mode (no FC) the gap between all frames is frame_txtime, plus the value of the CAN_ISOTP_TX_STMIN socket option when the FORCE_TXSTMIN flag is set.
- **Code:** protocoltx.c:isotp_sendmsg() tx_gap
- **Flags:** timing

### TIM-NBS-001 .. TIM-NBS-002 (2 variants)

**N_Bs after FF**

- **Variants:** `TIM-NBS-001`, `TIM-NBS-002`
- **Behaviour:** The FC timeout after the FF is 1 s + frame_txtime (ECOMM).
- **Code:** protocoltx.c:isotp_sendmsg() hrtimer_start(txtimer)
- **Flags:** slow timing

### TIM-NBS-003

**N_Bs after a block**

- **Behaviour:** The FC timeout after a block of CFs is 1 s (ECOMM, frame_txtime 0).
- **Code:** protocoltx.c:isotp_rcv_echo() hrtimer_start(txtimer)
- **ISO 15765-2:** NOTE: whether frame_txtime is added to N_Bs after a block is not checked.
- **Flags:** slow timing

### TIM-NBS-004

**N_Bs after FC.WT (frame_txtime 100 ms)**

- **Behaviour:** The FC timeout after a FC.WT is 1 s without frame_txtime (ECOMM).
- **Code:** protocolrx.c:isotp_rcv_fc() ISOTP_FC_WT
- **Flags:** slow timing

### TIM-NCR-001 .. TIM-NCR-002 (2 variants)

**N_Cr after FC**

- **Variants:** `TIM-NCR-001`, `TIM-NCR-002`
- **Behaviour:** The CF timeout after a sent FC is 1 s + frame_txtime (ETIMEDOUT).
- **Code:** protocoltx.c:isotp_send_fc()
- **Flags:** slow timing

### TIM-NCR-003

**N_Cr after CF (frame_txtime 100 ms)**

- **Behaviour:** The CF timeout after a received CF (no block end) is 1 s without frame_txtime (ETIMEDOUT).
- **Code:** protocolrx.c:isotp_rcv_cf() hrtimer_start(rxtimer)
- **Flags:** slow timing

### TIM-NCR-004

**N_Cr after block FC (frame_txtime 100 ms)**

- **Behaviour:** The CF timeout after the FC at a block end is 1 s + frame_txtime (ETIMEDOUT).
- **Code:** protocoltx.c:isotp_send_fc()
- **Flags:** slow timing

### TIM-NCR-005

**N_Cr in listen mode (frame_txtime 100 ms)**

- **Behaviour:** In listen mode the CF timeout after the FF is 1 s without frame_txtime (ETIMEDOUT).
- **Code:** protocolrx.c:isotp_rcv_ff() hrtimer_start(rxtimer)
- **Flags:** slow timing

### TIM-ECHO-001

**echo timeout SF (WAIT_TX_DONE)**

- **Behaviour:** vcan with echo=1 and netem loss 100%: when the local echo of a SF does not arrive, the transfer is aborted after 2 s + frame_txtime and send() with CAN_ISOTP_WAIT_TX_DONE returns ECOMM; the socket error is cleared and the socket is idle again.
- **Code:** protocoltx.c:isotp_sendmsg() echotimer, hrtimer.c:isotp_echo_timer_handler(), isotp_tx_timeout()
- **Flags:** slow timing

### TIM-ECHO-002

**echo timeout SF (asynchronous)**

- **Behaviour:** vcan with echo=1 and netem loss 100%: without CAN_ISOTP_WAIT_TX_DONE send() returns immediately; while waiting for the echo the socket is not writable and further send() calls fail with EAGAIN (MSG_DONTWAIT). After 2 s + frame_txtime the socket error ECOMM is reported and the socket is idle again.
- **Code:** protocoltx.c:isotp_sendmsg() echotimer, hrtimer.c:isotp_echo_timer_handler()
- **Flags:** slow timing

### TIM-ECHO-003

**echo timeout CF broadcast FF**

- **Behaviour:** vcan with echo=1 and netem loss 100%: in CF broadcast mode the echo of the FF is monitored; without echo the transfer is aborted after 2 s + frame_txtime with ECOMM.
- **Code:** protocoltx.c:isotp_sendmsg() CF broadcast cfecho, hrtimer.c:isotp_echo_timer_handler()
- **Flags:** slow timing

### TIM-ECHO-004

**FF without echo**

- **Behaviour:** vcan with echo=1 and netem loss 100%: when the local echo of a FF (with FC) does not arrive, the transfer is aborted with ECOMM.
- **Code:** protocoltx.c:isotp_sendmsg() txtimer for ISOTP_WAIT_FIRST_FC
- **ISO 15765-2:** NOTE: the timeout value (N_Bs 1 s + frame_txtime or echo timeout 2 s + frame_txtime) is not checked.
- **Flags:** slow timing

### TIM-ECHO-005

**late echo after echo timeout**

- **Behaviour:** vcan with echo=1 and netem delay 3000ms: a SF whose echo arrives after 3 s is aborted after 2 s + frame_txtime with ECOMM. The late echo arriving during the next SF transfer does not complete that transfer (echo identified by the skb uid), which is aborted with ECOMM as well.
- **Code:** protocoltx.c:isotp_rcv_echo() cfecho / can_skb_uid check
- **Flags:** slow timing

### TIM-ECHO-006

**netem delayed echo (STmin 10 ms)**

- **Behaviour:** vcan with echo=1 and netem delay 100ms: a SF send() with WAIT_TX_DONE returns after the delayed echo. Expected: the separation time between CFs (STmin + frame_txtime) starts at the echo of the previous CF (gap = echo delay + STmin + frame_txtime). Observed behaviour is reported.
- **Code:** protocoltx.c:isotp_send_cframe() alloc_skb()/can_skb_set_owner(), isotp_rcv_echo() skb->sk check, sch_netem.c:netem_enqueue(), sock.c:skb_orphan_partial()
- **ISO 15765-2:** FINDING (if observed): netem with delay orphans the CF skbs (sock_efree destructor), the CF echo is not recognized and the transfer is aborted with ECOMM. Cause in net/core: skb_orphan_partial() does not keep already partially orphaned (sock_efree) skbs.
- **Flags:** timing

### TIM-ECHO-007

**netem delayed echo (CF broadcast)**

- **Behaviour:** vcan with echo=1 and netem delay 100ms: expected: in CF broadcast mode each frame (incl. the FF) is sent after the echo of the previous frame + frame_txtime. Observed behaviour is reported.
- **Code:** protocoltx.c:isotp_send_cframe() alloc_skb()/can_skb_set_owner(), isotp_rcv_echo() skb->sk check, sch_netem.c:netem_enqueue(), sock.c:skb_orphan_partial()
- **ISO 15765-2:** FINDING (if observed): netem with delay orphans the CF skbs (sock_efree destructor), the CF echo is not recognized and the transfer is aborted with ECOMM. Cause in net/core: skb_orphan_partial() does not keep already partially orphaned (sock_efree) skbs.
- **Flags:** timing

### TIM-ECHO-008

**slow bus paces CFs (tbf, STmin 0)**

- **Behaviour:** vcan with echo=1 and tbf rate 2kbit (64 ms per CAN CC frame): the transfer completes and the CFs are paced by the transmission confirmation (echo): gap = max(frame time, STmin + frame_txtime) = 64 ms.
- **Code:** protocoltx.c:isotp_rcv_echo()
- **Flags:** timing

### TIM-ECHO-009

**slow bus paces CFs (tbf, STmin 100 ms)**

- **Behaviour:** vcan with echo=1 and tbf rate 2kbit (64 ms per CAN CC frame): with STmin 100 ms > frame time the gap between CFs is STmin + frame_txtime, measured from the echo of the previous CF.
- **Code:** protocoltx.c:isotp_rcv_echo() txfrtimer start
- **Flags:** timing

### TIM-ECHO-010

**slow bus paces CF broadcast (tbf)**

- **Behaviour:** vcan with echo=1 and tbf rate 2kbit (64 ms per CAN CC frame): in CF broadcast mode the CFs are paced by the transmission confirmation (gap between the CFs = frame time).
- **Code:** protocoltx.c:isotp_rcv_echo()
- **Flags:** timing

