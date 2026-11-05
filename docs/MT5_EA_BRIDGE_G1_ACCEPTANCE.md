# MT5 EA Bridge G1 Acceptance Record

**Status: G1 INCOMPLETE.** This record separates protocol tests, native Windows
pipe tests, and the real MT5 Demo end-to-end gate. Passing one group does not
stand in for another.

## Architecture review

The G0 experiment document defines an observation-only progression and
requires G1 authentication, identity binding, replay controls, restrictive
pipe access, credential revocation, and reconciliation. The G1 authority is
the MQL5 EA inside MT5 Demo: it reads account data, positions, pending orders,
and deal history with native APIs and sends full snapshots through the local
named pipe. The independent Python host verifies and stores those snapshots;
it does not import `MetaTrader5` or the CheapTrader broker adapter.

The existing `mt5_adapter.py` and its connection lifecycle remain untouched.
`adapter_comparison.py` is a standalone optional comparison source and is not
part of formal G1 collection. No order, modify, or close path was added or
enabled.

## Evidence gates

| Evidence group | Result | Evidence and limits |
|---|---|---|
| Protocol unit tests | Pass locally | Focused G1 suite: **8 passed**. Canonical JSON/HMAC, bidirectional nonce handshake, identity binding, replay and timestamp rejection, snapshot schema, reconciliation, and credential-rotation session rejection. |
| Windows native named-pipe tests | Pass in Windows CI | CI run **41983913106**, `Backend tests` on `windows-latest`: full pytest job succeeded. The two Windows-only ACL tests ran on this Windows runner; the focused Linux run skips them because Win32 kernel/token APIs are unavailable. |
| Real MT5 Demo end-to-end | Not run | Requires MetaEditor/MT5 on the target Windows machine. EA compilation, native account/position/order/deal comparison, and restart recovery remain outstanding. |

The G1 EA has not been compiled by MetaEditor in this environment. A source
inspection for order execution calls is not a substitute for that compilation
or for the target-terminal E2E run. Therefore G1 is **not PASS**.

## Local verification record

- Backend full suite: `673 passed, 24 skipped` (118.73s). Existing Windows-only tests are skipped on this Linux host.
- Focused G1 suite: `8 passed, 2 skipped`; both skips are the Windows native pipe/ACL tests.
- Frontend suite: **144 passed**; `npm run lint` and production build passed (Vite reported the existing >500 kB chunk-size advisory).
- Targeted Ruff checks and Python bytecode compilation passed; `git diff --check` passed.
- GitHub Actions run **41983913106**: both `Backend tests` (`windows-latest`) and `Page tests and build` (`ubuntu-latest`) succeeded. On Windows, the native ACL tests are enabled and were included in the successful backend job.
- MQL5 MetaEditor compilation and real MT5 Demo execution have not been run.
