# CheapTrader MT5 EA bridge — G1-TCP (isolated, read-only)

Branch: `research/mt5-ea-bridge-g1-tcp`, based on the reviewed G1 commit
`4d386abf98295a9ac99904aed20b63cfd1928c31`. See
`docs/MT5_EA_BRIDGE_G1_TCP_ACCEPTANCE.md` for the runbook, evidence gates and
limitations. The original Named Pipe experiment is retained for comparison.

## Authority and scope

The **formal G1 snapshot source is the MQL5 EA running inside the MT5 Demo
terminal**. `CheapTraderBridge.mq5` reads account properties, open positions,
pending orders, and selected deal history using native MQL5 APIs, then sends
authenticated snapshots over TCP to the Python host bound only to
`127.0.0.1:47631`. `tcp_host.py` is a separate receiver; it does not import the
Python `MetaTrader5` package, open a terminal connection, or dispatch commands. The authenticated wire messages
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
and persistence acknowledgement. It has no command schema. `TcpTransport.mqh`
uses native MetaQuotes sockets and handles TCP partial writes, fragmented
reads, LF framing, UTF-8 validation and absolute monotonic message deadlines.
The ACK and handshake budgets are configurable, but their real upper bounds
must be measured on the target terminal build; no hard real-time guarantee is
claimed. TCP loopback is not encrypted. HMAC protects authenticity and
integrity, not confidentiality.

## Windows security and credentials

The TCP host binds only IPv4 `127.0.0.1`, rejects any other configured address,
and checks the accepted peer. It does not claim the historical Named Pipe DACL
as TCP access control. Same-host processes may still observe or interfere with
local traffic; HMAC does not encrypt payloads or protect the secret from local
malware. The secret is Demo-only and EA Inputs can persist in terminal-local
configuration.

Credential commands, run from this directory on Windows:

```powershell
py -3 .\tcp_host.py provision --login <DEMO_LOGIN> --server "<EXACT_SERVER_NAME>"
py -3 -u .\tcp_host.py serve --host 127.0.0.1 --port 47631
py -3 .\tcp_host.py revoke
```

The receiver key and account pin are protected with current-user DPAPI. The
provision command prints the 256-bit key once so it can be entered into
`InpSharedKeyHex` on a **Demo** chart. Manually allow `127.0.0.1` under MT5
Tools → Options → Expert Advisors. Copy both `CheapTraderBridge.mq5` and
`TcpTransport.mqh` to a folder under `MQL5\\Experts`, compile in MetaEditor,
then attach to a Demo chart. Do not save chart inputs as `.set`, add the key to
source control, or paste it into logs/issues. Revocation removes the host
credential; also clear the EA input and remove the EA from the chart. The host
fails clearly if the port is occupied and never falls back to another address.

## Evidence gates

- **Protocol unit tests** cover MAC/canonicalization, nonce binding, replay,
  identity changes, malformed frames, schema bounds, stale timestamps, and
  snapshot schema validation and durable reconciliation behavior.
- **Windows native TCP tests** must run on Windows CI. They exercise real
  Winsock loopback clients and server sockets, fragmented/coalesced frames,
  session failure recovery and timeout behavior. They do not inherit or claim
  the former Named Pipe DACL protections. The retained Windows pipe/ACL tests
  validate only the historical pipe implementation. Tests use synthetic
  Python clients, not the MT5 EA.
- **Python/MQL5 interoperability** is not established by the Python reference
  protocol tests. It requires compiling/running the EA against the real host
  and checking HMAC/canonical UTF-8 frames in both directions.
- **Real MT5 Demo end-to-end test** requires MetaEditor/MT5 on the target
  Windows machine. It must compile this EA and compare account, positions,
  pending orders and deals against an independently read-only view; test
  terminal/account/receiver restarts; and confirm the EA contains no trade
  calls. Unit or Windows pipe CI cannot substitute for this gate.

Until Python, Windows TCP, actual Python/MQL5 interoperability and real MT5 Demo
gates are complete, the bridge must not be described as `G1_PASS`. The current
highest possible result after automated tests is `G1_TCP_IMPLEMENTATION_PASS`.
