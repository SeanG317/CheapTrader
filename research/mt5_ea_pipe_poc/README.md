# CheapTrader MT5 named-pipe probe (no trading)

This is an **isolated, observation-only experiment**. It is not integrated into CheapTrader, cannot submit orders, and must only be tested on a demo terminal. It does **not** modify the existing UI, desktop window or Python MT5 adapter.

## Windows demo procedure

1. Start the receiver from this repository root with `python research/mt5_ea_pipe_poc/pipe_probe_host.py`. The process runs until terminated; it never sends commands or connects to MT5 by itself.
2. In a **demo** MetaTrader 5 terminal, open File → Open Data Folder. Copy `CheapTraderPipeProbe.mq5` into `MQL5/Experts`, open in MetaEditor, and compile. Capture the compiler version and warnings/errors.
3. Attach the compiled probe EA to a demo chart. Keep `InpPipeName` at its default and `InpHeartbeatSeconds=2`. The EA does not request trading or load DLLs.
4. Confirm the receiver prints monotonic heartbeat sequence numbers. Restart the receiver and then restart MT5 separately; verify that heartbeats resume automatically. Exercise a 60-minute idle soak; capture any MT5 journal errors and disconnect/reconnect timings.
5. Run parser tests from this directory: `python -m unittest -v test_pipe_probe_host.py`.
6. Remove the probe EA from the chart after the test. It is not intended for production installation.

The MQL5 official `FileOpen` documentation confirms access to local named pipes. **Actual compatibility of FILE_WRITE + FILE_BIN and graceful reconnect on this MT5 build is not yet verified.** If this specific access mode fails, record the exact error and MT5 build before changing flags or introducing a TCP fallback.

## Security boundary

The receiver rejects remote pipe clients but **does not yet apply a custom restrictive DACL or handshake authentication**. This is deliberate: it receives only harmless probe heartbeats and has no output/trading API. It must not be extended to accept trade commands without implementing those controls and independently reviewing them. Do not use the pipe name as a credential.

For full architecture and pass/fail gates, see `docs/MT5_EA_BRIDGE_EXPERIMENT.md`.
