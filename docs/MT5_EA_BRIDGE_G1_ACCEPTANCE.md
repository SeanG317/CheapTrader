# MT5 EA Bridge G1 Acceptance Record

**Current decision: G1_REMEDIATION_BLOCKED.** The six reviewed defects have
code changes and regression coverage in this branch, but the mandatory bounded
EA ACK wait cannot be implemented through the documented MQL5 named-pipe file
API without expanding the EA into native DLL IPC. MetaEditor and real MT5 Demo
are also unavailable here. This record does not claim `G1_CODE_REMEDIATION_PASS`
or `G1_PASS` until those gates are resolved.

## Scope and architecture

The formal G1 snapshot source remains the native MQL5 EA inside an MT5 Demo
terminal. The independent Python host authenticates, strictly validates,
persists and coordinates state. It does not import the Python `MetaTrader5`
package. The existing `backend/app/broker/mt5_adapter.py` and its connection
lifecycle, trading worker, frontend, and all production trade paths are outside
this change. `adapter_comparison.py` remains an optional, separate, read-only
comparison utility. No order, modify, cancel, close or trade authorization
capability was added.

The named source document `docs/MT5_EA_BRIDGE_EXPERIMENT.md` is not present in
the checked-out branch or its tracked history in this workspace. The available
G1 design context is the G0 design commit `56f3278` and the current G1 README;
this missing source document is recorded as an evidence limitation rather
than inferred or reconstructed.

## Finding-by-finding remediation evidence

| Finding | Change | Regression evidence | Remaining limit |
|---|---|---|---|
| P1: cursor advanced before persistence acknowledgement | EA keeps committed and pending cursors separately; host ACK is HMAC-bound to session, sequence, snapshot ID and persisted cursor, sent only after persistence. Reconnect cursor comes from persisted receiver state. | Protocol tests inject persistence failure (no ACK), ACK loss then reconnect (cursor recovery), and duplicate resend (idempotent re-ACK). | Real EA restart/ACK loss remains to test on Demo. |
| P1: Stop Limit omitted | EA maps BUY/SELL_STOP_LIMIT; `price` preserves `ORDER_PRICE_OPEN` trigger and `price_stop_limit` preserves `ORDER_PRICE_STOPLIMIT`. Protocol and comparison schema include the second field. | Unit tests accept both Stop Limit sides and reject incomplete collection counts. | MetaEditor and actual broker records not available. |
| P1: history read failure skipped | MQL5 checks required history ticket/property getters and aborts the batch on any failure; explicitly sorts `(time_msc,ticket)`, scan bound 100,000 and page size 512. | Reference paging unit tests cover unordered records, 513 rows, same-millisecond tickets, failed rows and ticket conflicts. | Reference tests do not execute MQL5 APIs; native history fault injection remains a terminal gate. |
| P1: pipe short connection terminates host | `serve()` recovers only Win32 109/232/233 and recreates pipe instances; unknown errors are diagnosed and raised. Overlapped cancellations are completed before event/pipe closure. | Linux tests cover lifecycle seam; new Windows test injects a real client disconnect before `ConnectNamedPipe` and expects ERROR_NO_DATA=232, then checks accept loop continues. | Native test must run in Windows CI. |
| P1: broker disconnect marked Fresh | EA checks `TERMINAL_CONNECTED` and pinned Demo login/server before and after collection; disconnect closes IPC. Host marks cached state stale on disconnect/rejection; startup cache is stale. | Unit test sends broker-disconnected snapshot and verifies rejection/no ACK/stale cache. | Actual network drop, recovery and account switch require MT5 Demo. |
| P2: failed position/order selects silently skipped | EA aborts on zero ticket, failed required getters, duplicate ticket, unknown order type, count mismatch or before/after total change. | Snapshot source-count validation and incomplete-count regression. | Getters cannot be fault-injected in Python unit tests; actual terminal validation remains. |

## Evidence gates (kept separate)

| Gate | Status | Evidence |
|---|---|---|
| Python protocol/unit tests | Pass locally | Full backend suite: **681 passed, 25 skipped** (116.61s), run from `backend/` so `asyncio_mode=auto` is loaded. Focused G1 suite: **16 passed, 3 skipped**; Windows-only cases are skipped on Linux. |
| Real Windows Win32 pipe and ACL tests | Pending CI run for this revision | Tests use the Windows kernel, actual named-pipe ACL/token checks, remote-client rejection configuration, and injected pre-accept disconnect. Linux skips are not evidence for this gate. |
| Python/MQL5 actual interoperability | Not run | Python reference protocol tests are not MQL5 interoperability. Requires MetaEditor build and actual EA/host handshake, HMAC/canonical frame verification. |
| Real MT5 Demo end-to-end | Not run | Requires native account/position/order/deal comparison, both Stop Limit types if available, disconnect/reconnect, account switch rejection, persisted cursor restart, and receiver restart checks. |

## Persistence and protocol limits

The receiver writes an encrypted same-directory temporary state, flushes the
file, atomically replaces the destination, and only then sends `SNAPSHOT_ACK`.
On Windows it invokes `FlushFileBuffers` and `MoveFileExW` with
`MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH`. This is the persistence
level the OS reports as complete; it cannot promise survival against storage
hardware/controller caches that misreport flush completion or physical media
failure. A failed write/replace sends no ACK and leaves in-memory state
unchanged. Startup-loaded state is stale until a fresh complete snapshot is
persisted.

The shared secret is Demo-only. Putting it in an EA Input means it can be saved
in terminal-local configuration or exposed to users with access to the
terminal. The current scheme is not claimed to be production-grade secret
storage. Revoke by removing the receiver DPAPI credential and clearing the EA
input/chart instance.

The documented MQL5 `FileReadArray()` call exposes no timeout argument for a
named-pipe read; `FileOpen` documents the required `FileFlush`/`FileSeek`
turnaround, not cancellation. Python connect/read/write calls are bounded, but
that cannot enforce a deadline inside a synchronous EA read if the receiver
stalls during durable persistence. This work does not import a DLL because that
would expand the EA native-code trust boundary. As a result the requirement to
bound ACK wait in the EA remains unresolved and blocks code-remediation PASS.

## Local verification record

- Backend full suite from `backend/`: `681 passed, 25 skipped` (116.61s).
- Focused G1 protocol/native-platform suite: `16 passed, 3 skipped` on Linux.
- Frontend regression: `144 passed`; TypeScript lint passed; production build
  passed with the existing Vite >500 kB chunk advisory.
- Ruff checks, Python bytecode compilation and `git diff --check` passed.
- Earlier PR CI run `41983913106` predates this remediation and is not counted
  as evidence for this revision. New Windows CI is required.
- MetaEditor compilation and real MT5 Demo execution have not been run.
