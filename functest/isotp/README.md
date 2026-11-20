# CAN_ISOTP functional test suite

Functional tests for the Linux CAN_ISOTP protocol (ISO 15765-2) including
the CAN XL extensions (`CAN_ISOTP_XL_OPTS`, CiA 611-1 SDT 6/7/9) and the
multicast first frame (`CAN_ISOTP_MF_BROADCAST`) as implemented by the
patch series in https://github.com/hartkopp/xl-isotp (branch `split`,
patches 1..29, `net/can/isotp/*.c`).

The goal is a complete functional characterization of the implementation
(send path, receive path, configuration and all functional error paths)
for CAN CC, CAN FD and CAN XL with different link layer data lengths, so
that a specification can be derived from the code and compared with
ISO 15765-2.

Memory allocation failures, network device events (NETDEV_DOWN /
NETDEV_UNREGISTER while bound) and race conditions are out of scope.

## Quick start

```bash
make
```

```bash
sudo ./setup_vcan.sh -r up
```

```bash
./run_tests.sh
```

`run_tests.sh` writes one log per suite to `logs/<date>-<time>/` and packs
the directory into `logs/<date>-<time>.tar.gz`.

## Files

| File | Content |
|---|---|
| `Makefile` | builds the test programs (`make`), regenerates `TESTCASES.md` (`make doc`) |
| `setup_vcan.sh` | creates the virtual CAN interfaces (root) |
| `run_tests.sh` | runs all suites as normal user and collects the logs |
| `gen_testcases.sh` | creates the test case catalog from the test programs |
| `TESTCASES.md` | test case catalog (generated, do not edit) |
| `COVERAGE.md` | mapping of the implementation code paths to test cases |
| `lib/ft.[ch]` | test framework, CAN_RAW peer, CAN_BCM sender, reference encoder |
| `tst-isotp-api.c` | socket API, all socket options, bind() |
| `tst-isotp-tx.c` | transmission path: segmentation, FC handling, broadcast modes |
| `tst-isotp-rx.c` | reception path: SF/FF/CF checks, padding checks, timeouts |
| `tst-isotp-xl.c` | CAN XL header, filter, SF formats, SDT 6/7, XL MTUs |
| `tst-isotp-e2e.c` | CAN_ISOTP socket to CAN_ISOTP socket, 1-to-n, sniffers |
| `tst-isotp-timing.c` | STmin / frame_txtime gaps, N_Bs / N_Cr timeouts |

## Interfaces

`setup_vcan.sh` creates these interfaces (the names do not collide with
existing `vcanX` interfaces):

| Interface | MTU | Usage |
|---|---|---|
| vcaniso0 | 16 | CAN CC |
| vcaniso1 | 72 | CAN FD |
| vcaniso2 | 2060 | CAN XL (2048 byte data) |
| vcaniso3 | 524 | CAN XL (512 byte data) |
| vcaniso4 | 268 | CAN XL (256 byte data) |
| vcaniso5 | 16 | CAN CC, interface down (ENETDOWN tests) |
| vcaniso6..8 | 16 | optional, vcan echo=1 + netem (`setup_vcan.sh -e`, see below) |

Other interface names can be given with the environment variables
`FT_IF_CC`, `FT_IF_FD`, `FT_IF_XL`, `FT_IF_XL512`, `FT_IF_XL256` and
`FT_IF_DOWN`. Test cases for missing interfaces are skipped.

### Echo timeout: vcan echo=1 + netem

Without the vcan module parameter `echo=1` the CAN core creates the local
echo directly after the frame is queued, so it can not be delayed or
suppressed. With `echo=1` the vcan driver creates the echo after the
frame has passed the qdisc, and a netem qdisc can drop or delay it:

```bash
sudo ./setup_vcan.sh -e up
```

| Interface | qdisc | Usage |
|---|---|---|
| vcaniso6 | netem loss 100% | echo never arrives (like a missing ACK) |
| vcaniso7 | netem delay 3000ms | echo arrives after the 2 s echo timeout |
| vcaniso8 | netem delay 100ms | slow transmission confirmation |

The `echo` parameter applies to all vcan interfaces of the system. The
script reloads the vcan module only if no other vcan interfaces than
`vcaniso*` exist (`-f` forces the reload and removes all vcan
interfaces). All other test cases work with `echo=1` as well. The test
cases `TIM-ECHO-001..007` are skipped without these interfaces.

### Optional real CAN interface (echo timeout)

The test cases `TIM-ECHO-HW-*` (timing suite) run the echo timeout tests
on a real CAN interface when `FT_IF_HW` names such an interface:

- the interface is configured (bitrate) and up, its driver supports
  `IFF_ECHO` (echo after successful transmission),
- **no other node is connected** (or the bus is not terminated), so the
  frames are never acknowledged.

```bash
FT_IF_HW=can0 ./run_tests.sh -s timing -t 'TIM-ECHO-HW-*'
```

The unacknowledged frames stay pending in the CAN controller / tx queue.
Restart the interface afterwards (as root: `ip link set can0 down` and
`ip link set can0 up`) before using it for other purposes.

`setup_vcan.sh -r` raises `net.core.rmem_max` to 8 MByte. The CAN_RAW
peer records all frames in a background thread; a larger receive buffer
avoids frame drops on slow or loaded systems (drops are detected via
`SO_RXQ_OVFL` and reported as failures).

## Running tests

Each test program can be run directly:

```bash
./tst-isotp-rx -t 'RX-SF-*' -v
```

| Option | Meaning |
|---|---|
| `-t <patterns>` | run only test cases matching the comma separated shell patterns |
| `-x <patterns>` | exclude test cases |
| `-q` | quick mode: skip test cases running into 1 s protocol timeouts |
| `-v` | print the trace of all test cases (`-vv`: all CAN frames) |
| `-T <ms>` | tolerance for timing upper bounds (default 20 ms) |
| `-W <s>` | watchdog per test case (default 120 s) |
| `-l` | list test cases |
| `-m` | print the test case catalog in markdown |

`run_tests.sh` accepts `-q`, `-v`, `-T`, `-t`, `-x`, `-s <suites>` and
`-o <logdir>`.

## Output

The output follows the TAP format. Every test case runs in its own
process (with a watchdog). Failed test cases print their trace (sent and
received CAN frames, socket calls, the failing check with file:line).

```
ok 12 - RX-SF-002 CAN CC SF invalid SF_DL
ok 13 - RX-SF-003 CAN_DL 0 frame with stale N_PCI # DEVIATION
ok 21 - RX-SF-012 valid SF during reception # REVIEW
not ok 22 - RX-SF-013 invalid SF during reception
```

- `ok`: the implementation behaves as described in the test case.
- `not ok`: the implementation does not behave as described (bug in the
  implementation or in the test case - to be analysed).
- `# DEVIATION`: the checked behaviour differs from ISO 15765-2. Some
  test cases check the ISO behaviour and report the observed deviation in
  the trace instead of failing.
- `# REVIEW`: the behaviour is implementation specific or has to be
  checked against the ISO 15765-2 text.
- `# SKIP`: interface missing or slow test case in quick mode.

The last line of each suite contains the totals.

## Test method

- The **DUT** is a CAN_ISOTP socket configured with all socket options.
- The **peer** is a CAN_RAW socket on the same virtual CAN interface
  (CAN FD and CAN XL frames enabled, VCID pass through). It records all
  frames with their timestamps in a background thread, compares the DUT
  frames byte by byte (CAN ID / XL priority+VCID, flags, SDT, AF, length,
  data) and sends valid and malformed frames to the DUT.
- The **reference encoder** (`ft_enc_*()`) creates the frame layout of
  SF/FF/CF/FC frames for a given configuration (TX_DL, addressing,
  padding, CAN FD/XL PDU type, MF). The DUT output must match exactly;
  the same encoder creates the frames for the reception tests.
- **CAN_BCM** sends CF sequences with exact frame gaps (RX STmin tests).
- The **end-to-end** tests use two or more CAN_ISOTP sockets with swapped
  IDs/addresses on the same interface.

All test cases are parameterized over link layer modes
(`ft_modes[]` in `lib/ft.c`):

| Mode | Meaning |
|---|---|
| `CC8` | CAN CC, TX_DL 8 |
| `FD8` .. `FD64`, `FD64BRS` | CAN FD with TX_DL 8..64 (BRS) |
| `XL9-<n>` | CAN XL SDT 9 (native ISO 15765-2), TX_DL n (8..2048) |
| `XL9-2048-SEC-VCID`, `XL9-100-RRS` | CAN XL with SEC/RRS flags and VCIDs |
| `XL9-512-IF512`, `XL9-256-IF256` | CAN XL on interfaces with smaller MTU |
| `XL6-8` | CAN XL SDT 6 (CAN CC tunnel) |
| `XL7-<n>`, `XL7-64BRS` | CAN XL SDT 7 (CAN FD tunnel), BRS in AF |

and variants: `PLAIN`, `AE` (extended addressing), `PAD` (TX padding
0x55, RX padding checks 0xAA), `AEPAD` (separate rx address extension +
padding).

## Notes

- The virtual CAN interfaces accept CAN FD frames with a length that is
  no CAN FD DLC length and CAN CC frames with data beyond CAN_DL. Some
  receive path tests use this to reach the length checks.
- The timing tests check lower bounds strictly (hrtimers never expire
  early) and upper bounds with the tolerance `-T`.
- `max_pdu_size` (module parameter of can-isotp) is read from sysfs; the
  tests use the default 8300 byte buffer size otherwise.
