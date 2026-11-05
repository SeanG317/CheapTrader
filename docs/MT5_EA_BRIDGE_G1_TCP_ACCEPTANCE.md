# CheapTrader MT5 EA Bridge G1-TCP Acceptance

**Decision: `G1_TCP_IMPLEMENTATION_PASS`. Automated protocol, local TCP and Windows CI gates pass. MetaEditor compilation, actual Python/MQL5 interoperability and real MT5 Demo acceptance remain open; `G1_PASS` is not claimed.**

This branch migrates the G1 read-only transport from Windows Named Pipes to an
IPv4 TCP listener bound only to `127.0.0.1:47631` by default. The native EA is
the only formal broker-state source. Python authenticates, validates, persists
and coordinates state. There is no trade request path in this bridge. The old
Named Pipe code remains available as a reference implementation and is not
started by the TCP host.

The branch starts from frozen G1 commit
`4d386abf98295a9ac99904aed20b63cfd1928c31`. The original G1 branch and Draft
PR #3 are not modified by this work.

## Architecture and wire behavior

`CheapTraderBridge.mq5` uses MetaQuotes native socket APIs through
`TcpTransport.mqh`. The EA initiates the connection; the Python server rejects
non-loopback bind configuration and peers. Both sides exchange bounded UTF-8
JSON Lines frames with LF delimiters. TCP partial writes and arbitrary read
fragmentation are handled as byte streams. The MQL5 reader applies a monotonic
absolute message deadline; receiving more bytes does not reset the ACK or
handshake budget. The initial defaults are 1 s connect/send/receive, 3 s
handshake and ACK deadline, 2 s snapshot cadence, 8 s stale threshold, 2–30 s
reconnect backoff and 1 MiB maximum frame. Input ranges are bounded. Socket
timeouts are not claimed to be hard real-time guarantees.

The receiver retains the CTEA2 canonical JSON/HMAC-SHA256 message protocol,
session/account binding, DPAPI-protected host credential, revocation check,
persisted cursor recovery, stable deal de-duplication and signed ACK. The ACK
is produced only after the full snapshot is validated and persisted. HMAC
authenticates/integrity-protects frames; it does **not** encrypt them. A
malicious process on the same Windows user/session may observe or interfere
with local traffic, and compromise of the EA input/shared key permits
impersonation until host-side revocation/rotation. EA Inputs are terminal-local
configuration and are not production-grade secret storage. This stage is Demo
only.

## Windows Demo installation and runbook

These are manual steps. The repository does not edit MT5 security settings,
install an EA, set Algo Trading, or launch a terminal automatically.

1. In MT5, select **File → Open Data Folder**. Under `MQL5\Experts`, create
   `CheapTraderBridge` and copy both `CheapTraderBridge.mq5` and
   `TcpTransport.mqh` there.
2. Open `CheapTraderBridge.mq5` in MetaEditor and compile it. Resolve any
   compiler diagnostic before attaching. Record the MT5 terminal build and
   MetaEditor compiler output. This repository environment has no MetaEditor;
   compilation is currently **not verified**.
3. In MT5, open **Tools → Options → Expert Advisors** and manually add
   `127.0.0.1` to the allowed network addresses for MQL5 socket connections.
   Do not add a public or LAN address. The current terminal build's actual
   allow-list behavior must be confirmed during Demo verification.
4. Confirm the selected account is Demo. Attach `CheapTraderBridge` to a Demo
   chart. Do not save the shared key in a `.set` file. Leave Algo Trading
   settings as they are; this read-only EA does not need trading permission.
5. In PowerShell, provision the receiver's local DPAPI credential for the
   exact Demo login and broker server. Run this from the checked-out repo:

   ```powershell
   Set-Location .\research\mt5_ea_g1
   py -3 .\tcp_host.py provision --login <DEMO_LOGIN> --server "<EXACT_SERVER_NAME>"
   ```

   Copy the one-time 64-hex-character secret directly into the EA's
   `InpSharedKeyHex` input. Do not save it to a `.set` file, source control,
   logs, screenshots, or support tickets.
6. Start the host in a second PowerShell window, from the same directory:

   ```powershell
   py -3 -u .\tcp_host.py serve --host 127.0.0.1 --port 47631
   ```

   If the port is occupied, the host reports a bind error and exits. It does
   not select another interface or silently choose another port. Use
   `--state-file` to select a protected state path if needed.
7. Check the host's `tcp_listening`, `authenticated`, `snapshot` and ACK
   progression logs and the EA Experts log. Confirm account login/server,
   positions, pending orders and recent deals against the same Demo terminal.
   On disconnect, wait for stale status, restore the connection, and confirm a
   new authenticated session recovers from the host's persisted cursor.
8. To revoke, stop the host and run
   `py -3 .\tcp_host.py revoke`; then clear the EA input and remove the EA from
   the chart. Provision a new key for any later session.

## Retained G1 correctness constraints

1. The EA advances only a pending `(time_msc,ticket)` deal cursor while
   constructing a snapshot. The receiver ACKs after persistence; reconnect
   `AUTH_OK` supplies the durable cursor. ACK loss is recovered by reconnect
   and replay/de-duplication, not by trusting EA memory.
2. BUY/SELL_STOP_LIMIT retains `ORDER_PRICE_OPEN` as trigger price and
   `ORDER_PRICE_STOPLIMIT` as the separate limit price.
3. History selection, totals, ticket, time and required properties are checked.
   Rows are explicitly sorted by `(time_msc,ticket)` and batched at 512. Any
   necessary read failure aborts the batch; more than 100,000 selected history
   records is rejected for operator recovery rather than silently truncated.
4. TCP accept/client failures are isolated to that session; only a narrow
   connection-abort whitelist is treated as recoverable at accept. Unknown
   listener errors remain fatal and visible. Per-client frame, handshake and
   I/O limits are bounded.
5. The EA checks `TERMINAL_CONNECTED` and its pinned Demo login/server around
   collection. Python tracks IPC state separately and expires snapshots using
   its own receipt clock even when a socket remains open.
6. Failed position/order selection, unknown order type, duplicate ticket,
   source count mismatch, or a changed count rejects the whole snapshot.
   Zero-position/zero-order snapshots remain valid.

Python cache is stale after process startup and becomes fresh only after a
complete authenticated broker-connected snapshot is persisted. A broker or
transport failure preserves the last trusted data as stale rather than
replacing it with empty data.

## Persistence guarantee and limitations

The host encrypts a same-directory temporary state file, flushes it, and then
atomically replaces the destination. Windows requests `FlushFileBuffers` and
`MoveFileExW(MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)` before ACK.
This is the durability level reported by Windows APIs; it cannot guarantee
survival of physical media failure or storage hardware/controller caches that
misreport flush completion. A failed persistence/replacement path must not
advance in-memory state or emit ACK. Power-loss behavior requires Windows
fault-injection validation on the target filesystem.

## Acceptance evidence (separate gates)

| Gate | Current status | Evidence / missing evidence |
|---|---|---|
| Python protocol/unit tests | Pass locally | Full backend suite, run from `backend/`: **690 passed, 26 skipped** (119.60s). Focused TCP/protocol/ACL suite: **25 passed, 4 skipped**; skips are Windows-only cases on this Linux host. |
| Real Windows TCP/Winsock and listener recovery | Pass | GitHub Actions run `42028691242`, Windows Server 2025: **716 passed in 214.05s**. This runs the new real Winsock loopback fragmentation/coalescing, bounded failure, partial-write injection, repeated short-client recovery, ACK loss/restart cursor and Windows process-handle release tests. The run also executes historical Pipe/ACL tests; those are reported separately and do not substitute for TCP evidence. Earlier Windows run failures were corrected in later commits. |
| Real Windows Named Pipe/ACL tests | Reference only | The existing G1 CI checked Windows pipe/ACL behavior. Those results do not validate the TCP transport and are not a G1-TCP pass gate. |
| Python/MQL5 actual interoperability | Not run | No MetaEditor or MT5 terminal in this environment. Python reference-protocol tests are not MQL5 interoperability evidence. |
| MetaEditor compilation | Not run | No MetaEditor compiler available. The `.mq5` and `.mqh` must be compiled in the target Windows terminal installation. |
| Real MT5 Demo end-to-end | Not run | Requires the actual Demo account and terminal: broker state comparison, reconnects, account switch rejection, ACK loss/timeout, receiver and terminal restart, and 60-minute run with three independent restart rounds. |
| Frontend regression | Pass locally | No frontend files changed. 144 tests passed; TypeScript check and production build passed (existing Vite chunk-size advisory only). |

### Local performance observations

Record environment-specific observations here after running the benchmark on
the target Windows machine. Do not treat CI timing as a hard real-time
guarantee. No fabricated sample values are accepted.

| Metric | Linux local loopback | Windows CI | Real MT5 Demo |
|---|---|---|---|
| TCP connect latency p50/p95/p99 | 0.054 / 0.226 / 0.810 ms (40 loopback connections) | Pending | Pending |
| Python reference HMAC handshake p50/p95/p99 | 0.506 / 0.761 / 0.910 ms (40 synthetic Python clients) | Pending | Pending |
| Synthetic snapshot-to-ACK RTT p50/p95/p99 | 0.162 / 0.322 / 0.371 ms (40 snapshots, in-memory test store) | Pending | Pending |
| Longest observed EA blocking / ACK deadline overshoot | Not measurable without EA | Pending | Pending |
| Reconnect time and resource/leak observation | Functional recovery test only | Pending | Pending |

The Linux measurements above are observed samples from a single local run,
not load or Windows measurements. The ACK sample used a memory-only test
store; it excludes DPAPI encryption, filesystem flush/replacement and EA-side
serialization. They must not be presented as production latency.

## Named Pipe migration differences

The old `pipe_host.py`, Win32 ACL implementation and `CheapTraderEAG1.mq5`
remain for G1 comparison/regression reference. The TCP branch adds a transport
interface and transport-neutral CTEA2 session coordinator. `tcp_host.py` is the
only host entry point for this branch's formal G1-TCP path. It binds one IPv4
loopback listener and does not apply or claim Named Pipe DACL semantics. No
Python MT5 Adapter, execution worker, Chart Trader, frontend or production
trade lifecycle is changed.

## Known security and verification risks

- TCP loopback provides no encryption. Local administrators/processes can
  inspect or interfere with local traffic; HMAC does not hide payloads.
- The secret is manually copied into a terminal Input for Demo testing and can
  persist in terminal configuration or be exposed to a local user.
- MT5 network address allow-list behavior and socket timeout overshoot vary by
  terminal build; measure on the selected build.
- Code generation and Python tests cannot validate MQL5 compiler compatibility
  or actual broker state semantics.
- A snapshot with more than 100,000 selected history rows is rejected; recovery
  requires an operator-defined safe history/cursor recovery procedure.

## Final classification

Current classification is `G1_TCP_IMPLEMENTATION_PASS`: Python protocol and
local TCP tests pass, and Windows CI passed on the current branch head. MQL5
compilation and interoperability are still unverified because MetaEditor and
MT5 are unavailable here. `G1_PASS` requires the actual MetaEditor compile,
Python/MQL5 interoperability, and all listed MT5 Demo end-to-end and restart
acceptance evidence.
