# CheapTrader MT5 EA bridge — G1 (isolated, read-only)

Branch: `research/mt5-ea-bridge-g1`, based on `security/hardening`.
Design baseline: `docs/MT5_EA_BRIDGE_EXPERIMENT.md` and the read-only G0 pipe
probe in `research/mt5_ea_pipe_poc` on the separate G0 experiment branch.

## Authority and scope

The **formal G1 snapshot source is the MQL5 EA running inside the MT5 Demo
terminal**. `CheapTraderEAG1.mq5` reads account properties, open positions,
pending orders, and selected deal history using native MQL5 APIs, then sends
authenticated snapshots over the local Windows named pipe. `pipe_host.py` is a
separate receiver; it does not import the Python `MetaTrader5` package, open a
terminal connection, or dispatch commands. The authenticated wire messages
are `CHALLENGE`, `AUTH`, `AUTH_OK`, `SNAPSHOT`, and `SNAPSHOT_ACK`.

The original adapter remains the production app's existing connection and
execution path. `adapter_comparison.py` is an optional, independent comparison
source for reconciling observed EA data against the Python MT5 view; it is not
imported by the G1 host and must not be started as part of G1 collection. It
uses the adapter's existing read-only accessors and raw read-only pending-order
records solely for comparison, including both Stop Limit prices. No production
adapter lifecycle, trading worker, setting, UI, or order path is modified.

There are no order-send, modify, close, or generic command handlers in the G1
EA or receiver. This branch is not an execution bridge and must never be used
with a funded terminal.

## Authentication and framing

Each line is canonical UTF-8 JSON followed by LF, maximum 1 MiB. Objects use
sorted keys, compact separators, `ensure_ascii=False`, and reject non-finite
JSON numbers. The MAC is lowercase hexadecimal HMAC-SHA256 over the canonical
object with its `mac` member omitted. Numeric floating-point account/price
values are carried as decimal strings to keep Python and MQL5 canonical bytes
identical; the receiver validates every field/type/range before accepting a
snapshot.

1. Host → EA signed `CHALLENGE`: a fresh CSPRNG session ID and server nonce
   bound to the configured Demo login and UTF-8 server identity encoded as hex.
2. EA validates terminal connectivity, Demo mode, account identity and the
   challenge MAC, then returns signed `AUTH` bound to that challenge.
3. Host sends signed `AUTH_OK` with its persisted `(time_msc,ticket)` deal
   cursor. That cursor is authoritative after EA/host restart or reconnection.
4. EA sends a signed full current-state snapshot and up to 512 history deals.
   It holds the candidate cursor and exact frame pending until a signed
   `SNAPSHOT_ACK` matches session, sequence, snapshot ID and persisted cursor.
5. Host validates the whole snapshot, persists it, then sends `SNAPSHOT_ACK`.
   On persistence failure it sends no ACK. If an ACK is lost, the exact frame
   can be re-ACKed in-session; after restart, `AUTH_OK` restores the durable
   cursor. History is explicitly sorted by `(time_msc,ticket)` and read errors
   fail the full batch. Stop Limit trigger and limit prices are separate fields.

The cache uses same-directory temporary files, file flush, atomic replacement,
and Windows `FlushFileBuffers` plus `MoveFileExW(MOVEFILE_WRITE_THROUGH)`. This
is the durability level acknowledged by Windows; it cannot guarantee survival
of power loss or a storage device/controller that reports a flush before data
reaches nonvolatile media. A cache loaded at host startup is stale until a new
complete, authenticated, broker-connected snapshot is persisted.

The transport is duplex only for challenge, authentication, recovery cursor,
and persistence acknowledgement. It has no command schema. The EA uses
`FileOpen(FILE_READ|FILE_WRITE|FILE_BIN)` and applies `FileFlush` / `FileSeek`
between direction changes, following MetaQuotes' named-pipe contract.

**Known limitation:** MQL5's documented `FileReadArray()` on named pipes has no
timeout argument, and the file API provides no documented cancellation handle.
The Python side bounds connect/read/write operations and disconnects inactive
sessions, but an EA blocked inside a synchronous read can still wait without a
documented upper bound if the host stalls while persisting or the pipe stack
fails abnormally. No DLL workaround has been added because that would expand
the EA's native-code trust boundary. Bounded ACK wait remains an explicit gate
for MetaEditor/MT5 review or a separately approved IPC change.

## Windows security and credentials

The host creates the pipe with a custom DACL scoped to the current Windows
logon SID (plus SYSTEM and Administrators maintenance access) and sets
`PIPE_REJECT_REMOTE_CLIENTS`. The ACE spells out the pipe rights; it does not
hide the named-pipe `FILE_APPEND_DATA` / `FILE_CREATE_PIPE_INSTANCE` alias
inside `GENERIC_WRITE`. Same-logon processes can still interfere or deny
service; HMAC does not protect a key from same-user malware.

Credential commands, run from this directory on Windows:

```powershell
py -3 .\pipe_host.py provision --login <DEMO_LOGIN> --server <DEMO_SERVER>
py -3 .\pipe_host.py serve
py -3 .\pipe_host.py revoke
```

The receiver key and account pin are protected with current-user DPAPI. The
provision command prints the 256-bit key once so it can be entered into
`InpSharedKeyHex` on a **Demo** chart. Do not save chart inputs as `.set`, add
the key to source control, or paste it into logs/issues. Revocation removes the
host credential; also clear the EA input and remove the EA from the chart.

## Evidence gates

- **Protocol unit tests** cover MAC/canonicalization, nonce binding, replay,
  identity changes, malformed frames, schema bounds, stale timestamps, and
  snapshot schema validation and durable reconciliation behavior.
- **Windows native pipe tests** run on Windows CI. They exercise the actual
  Win32 named-pipe kernel, scoped DACL, duplex client access, remote-rejection
  flag, ERROR_NO_DATA short-client recovery, and host reconnection. These use
  synthetic Python clients, not the MT5 EA.
- **Python/MQL5 interoperability** is not established by the Python reference
  protocol tests. It requires compiling/running the EA against the real host
  and checking HMAC/canonical UTF-8 frames in both directions.
- **Real MT5 Demo end-to-end test** requires MetaEditor/MT5 on the target
  Windows machine. It must compile this EA and compare account, positions,
  pending orders and deals against an independently read-only view; test
  terminal/account/receiver restarts; and confirm the EA contains no trade
  calls. Unit or Windows pipe CI cannot substitute for this gate.

Until all three evidence groups are recorded, status remains **G1 INCOMPLETE**.
