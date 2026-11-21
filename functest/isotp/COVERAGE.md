# CAN_ISOTP code path coverage

Mapping of the branches and error paths of the patched CAN_ISOTP
implementation (xl-isotp `split`, patches 1..29: `net/can/isotp/*.c`) to
the test cases of this suite. Paths marked *n/c* are not covered by
intention: memory allocation failures, network device events
(NETDEV_DOWN / NETDEV_UNREGISTER on a bound socket), race conditions and
paths that are not reachable with virtual CAN interfaces.

## protocolrx.c

| Function | Code path | Test cases |
|---|---|---|
| `isotp_register_rxid()` | broadcast flags => no rx_id registration | API-BIND-003, TX-BC-001, TX-BC-002 |
| `isotp_rcv_skb()` | queue PDU / drop on full receive buffer | all RX tests / *n/c* (receive buffer full) |
| `padlen()` | all lengths 0..64 | TX-SEG-*-PAD/AEPAD, TX-SEG-FD*, RX-SF-011 |
| `chk_optimized_fail()` | CAN_DL <= 8 | TX-FC-011, RX-SF-011, RX-CF-008 |
| | CAN_DL > 8 (next DLC length) | TX-FC-011 (FD), RX-SF-011 (FD) |
| `chk_pad_fail()` | CHK_PAD_LEN without RX_PADDING | TX-FC-011, RX-SF-011, RX-CF-008 |
| | CHK_PAD_DATA without RX_PADDING (always fail) | TX-FC-011, RX-SF-011, RX-CF-008 |
| | RX_PADDING + CHK_PAD_LEN length fail | TX-FC-011, RX-SF-011, RX-CF-008, XL-SF-002 |
| | RX_PADDING + CHK_PAD_DATA content fail | TX-FC-011, RX-SF-011, RX-CF-008 |
| `isotp_rcv_fc()` | not waiting for FC (idle / sending CFs) | TX-FC-012, TX-FC-013 |
| | state changed during hrtimer_cancel() | *n/c* (race) |
| | CAN_DL < ae + 3 => EBADMSG | TX-FC-010-plain, TX-FC-010-ae |
| | padding check fail => EBADMSG | TX-FC-011 |
| | BS/STmin from first FC only | TX-FC-002 |
| | BS/STmin from every FC (DYN_FC_PARMS) | TX-FC-003 |
| | reserved STmin => 0x7F | TIM-STM-009..012 |
| | FORCE_TXSTMIN | TIM-STM-013..015 |
| | STmin 0x00..0x7F / 0xF1..0xF9 | TIM-STM-002..008 |
| | frame_txtime in tx_gap | TIM-STM-016..019 |
| | FC.CTS | TX-SEG-*, TX-FC-001 |
| | FC.WT (restart N_Bs) | TX-FC-004, TX-FC-005, TX-FC-006, TIM-NBS-004 |
| | FC.OVFLW => EMSGSIZE | TX-FC-007, TX-FC-008, TX-WTD-003, API-IO-009 |
| | reserved flow status => EBADMSG | TX-FC-009, TX-WTD-003 |
| `isotp_rcv_sf()` | SF_DL 0 / SF_DL > CAN_DL - PCI | RX-SF-002, RX-SF-009, XL-SF-001 |
| | unsigned underflow (CAN_DL < AE + PCI) | RX-SF-003, RX-SF-004, RX-SF-005 (DEVIATION) |
| | padding check fail => EBADMSG | RX-SF-011, XL-SF-002 |
| | CAN XL N_PDUs: no padding checks | XL-SF-002 |
| | CAN XL N_PDUs: exact SF / last CF / FC length | XL-SF-001, XL-SF-002, XL-CF-001, TX-FC-011 |
| | terminates an ongoing reception | RX-SF-012, RX-SF-013, RX-SF-014 |
| | alloc_skb() failure | *n/c* |
| `isotp_rcv_ff()` | CAN_DL < 8 | RX-FF-001, RX-FF-008 |
| | CAN FD: CAN_DL is no DLC length | RX-FF-002, XL-SDT7-001 |
| | 12 bit FF_DL | RX-SEG-* |
| | 32 bit FF_DL | RX-SEG-* (4096, 8300), RX-FF-003, RX-MF-002 |
| | 32 bit FF_DL <= 4095 | RX-FF-003 |
| | FF_DL < FF_DLmin (PDU fits into a SF) | RX-FF-004-* |
| | u32 wrap around of FF_DL + PCI + AE | RX-FF-011, RX-FF-011-ae (DEVIATION) |
| | FF_DL > static buffer => kmalloc(max_pdu_size) | *n/c* with default max_pdu_size (needs module parameter > 8300) |
| | FF_DL > max_pdu_size => FC.OVFLW | RX-FF-005, RX-FF-006 |
| | LISTEN_MODE: no FC | RX-FF-010-*, RX-MF-002, E2E-SNIFF-*, E2E-MC-* |
| | sender LL_DL from FF | RX-LL-001..004, E2E-MIX-* |
| | FF during reception (restart) | RX-FF-007, RX-FF-008 |
| `isotp_rcv_cf()` | CAN_DL > LL_DL | RX-FF-002 |
| | CAN_DL < LL_DL for a non-last CF | RX-CF-003, RX-CF-004 |
| | short last CF lacking bytes / CF with N_PCI only | RX-CF-014, RX-CF-015 |
| | no active reception | RX-CF-002, RX-SF-012, RX-FF-005 |
| | FORCE_RXSTMIN drop / accept | RX-CF-009-*, RX-CF-010 |
| | state changed during hrtimer_cancel() | *n/c* (race) |
| | wrong SN => EILSEQ | RX-CF-001, RX-CF-006, API-IO-010 |
| | SN wrap around | RX-SEG-*, TX-SEG-* |
| | last CF padding check => EBADMSG | RX-CF-008 |
| | last CF longer than needed | RX-CF-005 |
| | alloc_skb() failure | *n/c* |
| | block size => FC | RX-CF-007-*, RX-SEG-*-AE/PAD/AEPAD |
| | LISTEN_MODE: no FC after block | RX-FF-010-* |
| `isotp_check_frame_head()` | XL: no CAN XL frame | XL-HDR-002 |
| | XL: prio / flags / AF / SDT mismatch | XL-HDR-002, XL-HDR-005 |
| | XL: AF bits 30/31 ignored (SDT 9), BRS ignored (SDT 7) | XL-HDR-003, XL-HDR-004 |
| | XL: tunneled ZDLC / RTR (SDT 6) frames dropped | XL-HDR-004, XL-HDR-007 |
| | XL: VCID mismatch | XL-HDR-002 |
| | XL: tunneled CC/FD frame length (SDT 6/7) | XL-SDT6-001, XL-SDT7-002 |
| | CC/FD: CAN ID or frame type mismatch | RX-ID-003, TX-FC-015, XL-HDR-006 |
| | CC/FD: invalid frame content (len > 8/64) | *n/c* (rejected by CAN_RAW/vcan) |
| `isotp_rcv()` | CAN_DL < AE + N_PCI (no N_PDU) | RX-SF-003..005, RX-CF-006, TX-FC-010-* |
| | extended address mismatch | RX-SF-006, RX-SF-007, TX-FC-014-ae |
| | HALF_DUPLEX: non-FC during tx | TX-HD-002, TX-HD-004, E2E-HD-001 |
| | HALF_DUPLEX: FC during rx | TX-HD-004 |
| | SF CAN_DL <= 8 | RX-SF-001, RX-SF-002 |
| | SF CAN XL N_PDU: N_PCI bit 3 | XL-SF-001, XL-SF-002, TX-SEG-XL9-* (rx: RX-SEG-XL9-*) |
| | SF CAN FD N_PDU in CAN XL: escape only | XL-SDT7-003, XL-SDT9-001 |
| | SF CAN FD escape | RX-SF-008, RX-SF-009, RX-SF-010 |
| | MF without LISTEN_MODE ignored | RX-MF-001, E2E-MC-MF-* |
| | MF with LISTEN_MODE | RX-MF-002, E2E-MC-MF-* |
| | reserved N_PCI types | RX-PCI-001, RX-PCI-002 |

## protocoltx.c

| Function | Code path | Test cases |
|---|---|---|
| `isotp_get_tx_result()` | tx_result slot reused | *n/c* (race) |
| `isotp_tx_skb_len()` | CAN XL / CAN CC/FD | TX-SEG-*, XL-HDR-001 |
| `isotp_fill_frame_head()` | CAN XL header incl. VCID | XL-HDR-001, TX-SEG-XL* |
| | CAN CC/FD header incl. tx_flags | TX-SEG-*, TX-FL-001, TX-ID-001-* |
| `isotp_req_pad()` / `get_padlength()` | TX_PADDING | TX-SEG-*-PAD/AEPAD |
| | mandatory CAN FD padding (0xCC) | TX-SEG-FD*, TX-SEG-XL7-*, TX-PAD-001 |
| | no padding | TX-SEG-*-PLAIN/AE |
| `isotp_send_fc()` | FC with TX_PADDING (8 byte) | RX-SEG-*-PAD/AEPAD |
| | FC with extended address | RX-SEG-*-AE/AEPAD |
| | FC content BS/STmin | RX-FF-009 |
| | N_Cr restart with frame_txtime | TIM-NCR-001, TIM-NCR-002, TIM-NCR-004 |
| | alloc / device lookup failure, can_send() error | *n/c* |
| `isotp_send_cframe()` | CF layout, padding of the last CF | TX-SEG-* |
| | device / alloc failure, can_send() error | *n/c* |
| `isotp_ff_pci()` | 12 / 32 bit FF_DL | TX-SEG-* |
| | MF N_PCI | TX-BC-MF-*, E2E-MC-MF-* |
| `isotp_sf_ff_pci()` | TX_DL 8: SF / FF | TX-SEG-CC8-*, TX-SEG-FD8-*, TX-SEG-XL9-8-* |
| | TX_DL > 8: FF / 4 bit SF / escape SF | TX-SEG-FD*, TX-SEG-XL* |
| | CAN XL SF flag (N_PCI bit 3) | TX-SEG-XL9-*, TX-SEG-XL6-* |
| `isotp_rcv_echo()` | foreign skb (other socket) | TX-FC-014-*, E2E-MC-*, E2E-SNIFF-* |
| | no can_skb_ext | *n/c* (WARN) |
| | echo of a FF (no cfecho) | all segmented TX tests |
| | late echo of a timed out transfer (uid mismatch) | TIM-ECHO-005 |
| | echo delay paces the CFs (txfrtimer starts at the echo) | TIM-ECHO-008..010 (tbf), TIM-ECHO-006/007 (netem, FINDING: CF echo not recognized, cause net/core skb_orphan_partial()) |
| | not in SENDING state | *n/c* (race) |
| | transfer complete | TX-SEG-*, TX-WTD-* |
| | block size reached => wait for FC | TX-FC-001-*, TX-FC-017, TIM-NBS-003 |
| | burst mode (tx_gap 0) | TIM-STM-001, TIM-STM-014 |
| | txfrtimer for STmin | TIM-STM-002..019, TIM-BC-* |
| `isotp_sendmsg()` | unbound | API-IO-001 |
| | busy + MSG_DONTWAIT => EAGAIN | API-IO-008 |
| | busy, blocking: wait / interrupted by signal | API-IO-008, TX-SIG-002 |
| | SHUTDOWN while waiting, unbound during claim | *n/c* (race with close()/device removal) |
| | size > static buffer => kmalloc(max_pdu_size) | API-IO-003 (only with max_pdu_size > 8300) |
| | size 0 / > max_pdu_size => EINVAL | API-IO-003 |
| | memcpy_from_msg() fault => EFAULT | API-IO-012 |
| | SF_BROADCAST and no SF => EINVAL | TX-BC-SF-* |
| | device lookup failure (ENXIO) | *n/c* (device removal) |
| | pending socket error (sock_alloc_send_skb) | API-IO-009 |
| | SF | TX-SEG-* |
| | FF with CF/MF broadcast (tx_gap, no FC) | TX-BC-CF-*, TX-BC-MF-*, TIM-BC-* |
| | FF with FC | TX-SEG-* |
| | SHUTDOWN after the claim | *n/c* (race with close()) |
| | can_send() error (ENETDOWN, EMSGSIZE) | API-BIND-009, API-BIND-010, XL-MTU-001 |
| | WAIT_TX_DONE result | TX-WTD-001, TX-WTD-003, TX-FC-006/007/008/009/016/017 |
| | WAIT_TX_DONE interrupted by signal | TX-SIG-001 |
| | WAIT_TX_DONE and SHUTDOWN | *n/c* (race with close()) |
| | asynchronous result (no WAIT_TX_DONE) | TX-WTD-002, API-IO-009 |

## hrtimer.c

| Function | Code path | Test cases |
|---|---|---|
| `isotp_rx_timer_handler()` | N_Cr timeout => ETIMEDOUT | RX-CF-011..013, TIM-NCR-* |
| | not in WAIT_DATA | *n/c* (race) |
| `isotp_tx_timeout()` | N_Bs timeout => ECOMM | TX-FC-006, TX-FC-016, TX-FC-017, TIM-NBS-*, API-IO-011 |
| | IDLE / SHUTDOWN / state changed | *n/c* (race) |
| `isotp_echo_timer_handler()` | missing local echo => ECOMM | TIM-ECHO-001..003 (vcan echo=1 + netem loss) |
| `isotp_txfr_timer_handler()` | send next CF after tx_gap | TIM-STM-*, TIM-BC-* |

## isotp.c

| Function | Code path | Test cases |
|---|---|---|
| `isotp_recvmsg()` | invalid flags => EINVAL | API-IO-002 |
| | unbound => EADDRNOTAVAIL | API-IO-001 |
| | no data (MSG_DONTWAIT) / pending error | API-IO-002, API-IO-010 |
| | truncation, MSG_TRUNC, MSG_PEEK, msg_name | API-IO-004 |
| | memcpy_to_msg() fault => EFAULT | API-IO-012 |
| `isotp_release()` | wait for active transfer | API-IO-011 |
| | interrupted wait, busy notifier | *n/c* |
| `isotp_invalid_canid()` | SFF / EFF / RTR / ERR | API-BIND-002, API-OPT-011 |
| `isotp_bind_xl()` | 29 bit AF translation | XL-HDR-001, XL-HDR-002, XL-HDR-005 |
| | SDT 7 without CAN FD LL | API-BIND-008 |
| | SDT 7 BRS in AF | XL-HDR-001, TX-SEG-XL7-64BRS-* |
| | CAN FD N_PDUs in SDT 9 (LL mtu 72) | XL-SDT9-001, TX-SEG-XL9FD-*, RX-SEG-XL9FD-*, E2E-XL9FD-* |
| | SDT 6 without CAN CC LL / TX_DL != 8 | API-BIND-008 |
| `isotp_bind()` | address length / family | API-BIND-001 |
| | invalid tx_id / rx_id | API-BIND-002, API-BIND-003 |
| | padding and TX_DL (no padding for CAN XL N_PDUs) | API-BIND-007 |
| | effective TX_DL (XL_OPTS / LL_OPTS) at bind() | XL-OPT-001 |
| | XL interface MTU (CANXL_HDR_SIZE + TX_DL, CANXL_MIN_MTU) | XL-MTU-001, API-BIND-010 |
| | XL with 29 bit CAN IDs | API-BIND-008 |
| | ifindex 0 | API-BIND-005 |
| | already bound | API-BIND-001 |
| | transfer still active (EAGAIN) | *n/c* (needs NETDEV_UNREGISTER) |
| | rx_id == tx_id | API-BIND-004 |
| | no / non-CAN device | API-BIND-005 |
| | device MTU < LL mtu | API-BIND-006 |
| | can_rx_register() failure | *n/c* |
| | interface down => ENETDOWN | API-BIND-009 |
| `isotp_getname()` | peer => EOPNOTSUPP, local address | API-SOCK-002, API-SOCK-004 |
| `isotp_setsockopt_locked()` | bound => EISCONN | API-OPT-012 |
| | transfer still active (EAGAIN) | *n/c* (needs NETDEV_UNREGISTER) |
| | CAN_ISOTP_OPTS checks / rx_ext_address / frame_txtime | API-OPT-004..007, TIM-STM-016..019 |
| | CAN_ISOTP_RECV_FC | API-OPT-008, RX-FF-009 |
| | CAN_ISOTP_TX_STMIN / RX_STMIN | API-OPT-009, TIM-STM-013..015, RX-CF-009 |
| | CAN_ISOTP_LL_OPTS checks | API-OPT-010 |
| | CAN_ISOTP_XL_OPTS checks / disable | API-OPT-011, XL-OPT-001, XL-OPT-002 |
| | default => ENOPROTOOPT | unreachable (checked in `isotp_setsockopt()`) |
| `isotp_setsockopt()` | level / option name / optlen / EFAULT | API-OPT-003 |
| `isotp_getsockopt()` | level / optlen / option name / EFAULT | API-OPT-001, API-OPT-002 |
| `isotp_notify()` | NETDEV_DOWN / NETDEV_UNREGISTER | *n/c* (device events) |
| `isotp_poll()` | POLLOUT only when idle | API-IO-007 |
| `isotp_sock_no_ioctlcmd()` | ENOIOCTLCMD | API-SOCK-003 |
