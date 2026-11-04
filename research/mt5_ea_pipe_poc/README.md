# CheapTrader MT5 named-pipe probe (no trading)

This is an **isolated, observation-only experiment**. It is not integrated into CheapTrader, cannot submit orders, and must only be tested on a demo terminal. No existing UI, desktop window or Python MT5 trading adapter is changed.

## Evidence already available

- Cross-platform parser, faulty-client recovery, timeout and heartbeat metrics tests: `python -m unittest -v test_pipe_probe_host.py`.
- Independent **real Windows kernel named-pipe** integration: `python -m unittest -v test_pipe_win32.py`. Tests a malformed client followed by a valid client, and an 8-second stalled client followed by a valid client. This uses synthetic Python clients, **not MQL5**.
- The separate GitHub Actions workflow `.github/workflows/mt5-pipe-probe.yml` runs the offline tests on Windows/Linux and the native Win32 tests on Windows.
- All messages are read-only `CTEA1|PING` frames. The process accepts no trade instruction, writes no bytes to MT5, and cannot place orders.

**Passing these CI tests does not satisfy G0.** We have no documented MetaEditor compilation or real MT5 terminal runtime evidence.

## Windows MT5 demo procedure (G0)

1. Start the receiver from the repository root using `python research/mt5_ea_pipe_poc/pipe_probe_host.py`.
2. Open a **demo** MT5 terminal → File → Open Data Folder. Copy `CheapTraderPipeProbe.mq5` into `MQL5/Experts`, then compile in MetaEditor. Save the compiler version, MT5 build and full error/warning output.
3. Attach the EA to a demo chart with `InpPipeName` unchanged and `InpHeartbeatSeconds=2`. There are no order functions, DLL imports, TCP listeners or automated installation steps in this probe.
4. Collect the receiver's JSON-lines output. Every valid heartbeat logs UTC receive time, sequential heartbeat ID, sequence gaps and monotonic gap length; each disconnection logs its cause, duration and maximum gap.
5. Run the host and demo MT5 continuously for **60 minutes**. Pre-register a target of no unplanned disconnects, no lost sequence IDs, and no valid-heartbeat silence reaching the configured **8-second** timeout under idle conditions. MT5 timer events can be dropped under load, so report any exceptions, not just a pass/fail.
6. Restart the receiver and restart MT5 separately at least three times each. Measure reconnection from process readiness to first valid heartbeat; target **≤60 seconds** without manually reattaching the EA (subject to how MT5 restores its workspace).
7. Using separate synthetic clients, inject malformed frames, repeated sequence IDs and a client that connects but sends no heartbeat. Confirm that each is disconnected without blocking the legitimate EA's subsequent connection.
8. Remove the probe EA from the chart when finished. Do not install on a funded account.

**2026-11-04 real-MT5 troubleshooting:** MetaEditor successfully compiled and MT5 loaded the original EA, but `FileOpen(FILE_WRITE|FILE_BIN)` returned MQL5 error **5022** even while a separately launched PowerShell `NamedPipeClientStream` reported **PIPE_TEST_OK** against the Python receiver. This confirms that a Windows native client can reach the host but does **not** yet establish MQL5 interoperability.

**Compatibility patch (not yet verified in actual MetaEditor/MT5):** To follow the [official MetaQuotes named-pipe sample](https://www.mql5.com/en/articles/503), EA `v1.002` now calls `FileOpen(InpPipeName, FILE_READ|FILE_WRITE|FILE_BIN)` and the Win32 receiver creates `PIPE_ACCESS_DUPLEX` (previously `PIPE_ACCESS_INBOUND`). The Python application **does not implement any pipe write or order-command processing**. The pipe transport is duplex-capable solely for compatibility; its default ACL and absent authentication are still unsuitable for trading. Native CI additionally opens a Win32 client with `GENERIC_READ|GENERIC_WRITE`.

**Updating a local checkout:** A pre-existing Python process retains the old one-way named-pipe instance, and the old EA retains its prior compiled flags. Refresh the branch with `git pull --ff-only`, stop the old Python receiver with Ctrl+C and restart it, replace and compile `CheapTraderPipeProbe.mq5` via MetaEditor/F7, then remove/re-attach the EA to the **demo** chart. Both sides must run the new versions. If error 5022 remains, record the new EA initialization line (must include `v1.002`), the full `FileOpen FAILED` line, MT5 build, and receiver JSONL log. Do **not** infer that a passing synthetic test means G0 passed.

## Security boundary

The host sets `PIPE_REJECT_REMOTE_CLIENTS`, but **no restrictive custom DACL and no handshake authentication** are provided. A same-user local process may connect. This is acceptable only for the observation-only probe, not an order execution bridge. The pipe name is not a credential.

The Win32 receiver uses overlapped I/O and requests cancellation of operations that exceed their deadline; cancellation completion and latency still require stress verification on real Windows. Do not infer production-grade latency or availability from these tests.

For the full architecture and release gates, see `docs/MT5_EA_BRIDGE_EXPERIMENT.md`.
