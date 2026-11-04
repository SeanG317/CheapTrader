# MT5 native EA bridge — isolated experiment (NOT LIVE)
Status: DESIGN / NO TRADING ENABLED
Base: `security/hardening` at `7fcf3c84872caf3a0d0fbe3fd37cb095396f4b3d`
Experiment branch: `research/mt5-ea-bridge-poc-20261104`

## Non-negotiable scope

- **No modifications** to React, charts, Chart Trader, CSS, existing desktop window, or `main`.
- Existing Python `MetaTrader5` trading adapter remains the only execution path in the main application. The bridge is **standalone and observation-only** until a separately reviewed authorization + execution + reconciliation design passes demo testing.
- Do not enable real accounts, migrate production orders, or merge this experiment into `main`.
- Do not auto-install an EA into terminals or modify MT5 Algo Trading permissions during the probe.

## Transport decision

**First experiment: MQL5 EA client → Windows named-pipe server hosted by CheapTrader.**
Official MQL5 `FileOpen("\\\\.\\pipe\\...")` can connect to named pipes without a DLL; unlike MQL5 SocketConnect, this approach does not use MT5's network-address allowlist. This is a *hypothesis to verify on the installed MT5 build*, not proof of production readiness.

- Prototype is **one-way, read-only heartbeat only**. It must not expose an order endpoint.
- Server pipe must reject remote clients (`PIPE_REJECT_REMOTE_CLIENTS`) and ultimately have an explicit restrictive DACL for the current logon session (Microsoft documents that default named-pipe ACLs may permit Everyone/anonymous reads).
- Production bridge additionally requires authenticated session handshakes, account login+server identity binding, protocol versioning, length bounds, replay controls, and startup/restart recovery.
- If the pipe interoperability test fails reliably, compare **localhost TCP** as a fallback; TCP adds a manual MT5 network allowlist requirement and must never open beyond loopback.

## Required execution design before enabling any order

1. Only one writer for a given MT5 account: switch from Python order_send to EA orders only **after** verified cutover. Never dual-write.
2. Explicit order-intent ledger before dispatch; unique intent ID with durable state machine: PREPARED → SENT → ACKED → RECONCILED or UNKNOWN. A timeout/connection loss is **UNKNOWN**, never proof of failure. No blind re-submit.
3. Verify the active `ACCOUNT_LOGIN` and `ACCOUNT_SERVER` in the EA immediately before every future trade operation; refuse mismatches and all commands when local authentication is invalid.
4. Broker state (orders, deals, positions) is authoritative; after timeout/restart reconcile from terminal history and open positions before accepting new intents.
5. `OnTradeTransaction` must perform only lightweight buffering/notification, not blocking pipe I/O. MetaQuotes documents unordered event arrival and a finite 1,024-event queue. Periodic full reconciliation is mandatory.
6. Preserve server-side SL/TP when the UI/backend disconnects. Never infer “executed” solely from `OrderSend()` returning true.
7. Drop commands on malformed/unauthenticated protocol, mismatched account, unknown schema, stale timestamp, replayed intent, closed trading gate, or unavailable bridge. Fail closed.
8. Local process security: pipe DACL + remote-client rejection + application authentication. Same-Windows-user malware remains outside the claim of isolation; a pipe name by itself is not authentication.

## Incremental acceptance gates

**G0 — transport probe (no orders)**: MQL5 probe compiles in MetaEditor; receives 60 minutes of heartbeat under Windows 11; restart pipe host and MT5 individually; process recovery succeeds without manually reattaching EA; log that no trade function is called; no local-network exposure.

**G1 — authenticated, read-only broker state**: restrictive DACL, credential provisioning/revocation, replay rejection, identity verification, snapshots and broker-state reconciliation; deny all commands while unauthenticated.

**G2 — demo execution shadow**: build a separate, *disabled by default* EA execution adapter; deterministic idempotency and ambiguous-outcome tests, recorded live/demo MT5 broker retcodes, no double submission.

**G3 — comparative fault-injection and longevity**: same account, MT5 version, broker server, symbols and periods for Python and EA; 72-hour soak plus 100 restart/network fault injections; zero wrong-account orders, zero duplicate orders, zero silent resubmission, all ambiguous outcomes reconciled or marked UNKNOWN; compare missed data, median/p95/p99 latency and recovery time. These are project-defined gates, not official guarantees.

Only after a separate security review and successful Windows demo validation may a proposed cutover be discussed.

## Official technical references

- MQL5 named pipes in FileOpen: https://www.mql5.com/en/docs/files/fileopen
- MQL5 named-pipe example without DLLs: https://www.mql5.com/en/articles/503
- MQL5 SocketConnect allowlist: https://www.mql5.com/en/docs/network/socketconnect
- Windows named-pipe access control: https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights
- Windows remote rejection: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipea
- MQL5 trade event caveats: https://www.mql5.com/en/docs/event_handlers/ontradetransaction
- MQL5 OrderSend outcome caveats: https://www.mql5.com/en/docs/trading/ordersend
