# MT5 execution and security contract

Scope: CheapTrader fork, baseline REDIN14/CheapTrader v0.2.4 (commit `4c0b322eb5739a01362520051b1cf2a0416f82db`).

This is a specification and acceptance checklist, **not** a claim of live-broker compatibility. Any code that sends real orders must pass simulated failure-path tests and broker-specific demo-account verification before production use.

## Primary sources (official MetaQuotes references)

1. [MetaTrader5 Python `order_send` / MqlTradeRequest](https://www.mql5.com/en/docs/python_metatrader5/mt5ordersend_py)
2. [Trade-server return codes](https://www.mql5.com/en/docs/constants/errorswarnings/enum_trade_return_codes)
3. [`order_check`](https://www.mql5.com/en/docs/python_metatrader5/mt5ordercheck_py)
4. [`terminal_info`](https://www.mql5.com/en/docs/python_metatrader5/mt5terminalinfo_py)
5. [`account_info`](https://www.mql5.com/en/docs/python_metatrader5/mt5accountinfo_py)
6. [`positions_get`](https://www.mql5.com/en/docs/python_metatrader5/mt5positionsget_py)
7. [Order execution and fill policies](https://www.mql5.com/en/docs/constants/tradingconstants/orderproperties)
8. [`order_calc_profit`](https://www.mql5.com/en/docs/python_metatrader5/mt5ordercalcprofit_py)
9. [`order_calc_margin`](https://www.mql5.com/en/docs/python_metatrader5/mt5ordercalcmargin_py)

Security reference: [OWASP Cross-Site Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html).

## 1. Broker mutations are opt-in

Mutating a real MT5 account requires an explicit local authorization gate. It must cover *all* operations, not only opening: place, change, cancel, SL/TP modify and position close. Disable = fail closed for **all** mutations, including emergency closes. Show that implication in UI. Emergency management must remain possible through native MT5; never pretend the app's off switch protects against actions sent directly through MT5, other EAs or other apps.

Status: REST order endpoints gated in `backend/app/api/routes.py`. Still required: make broker-worker enforcement independent of HTTP paths, binding to the intended MT5 account login/server, authenticated local API, and reconciliation under session changes. Authorization check then order dispatch must be reviewed for time-of-check/time-of-use account swaps.

## 2. Retcode interpretation is not binary success/failure

Per MetaQuotes:
- `10009 / TRADE_RETCODE_DONE`: requested operation completed.
- `10008 / TRADE_RETCODE_PLACED`: order placed, **not proof of a fully filled market trade**. For an accepted pending-order placement, consider the placement successful; retain the returned order ticket.
- `10010 / TRADE_RETCODE_DONE_PARTIAL`: partial execution. Retain returned volume/order/deal and reconcile with broker state. Do **not** classify as a full fill or automatically resubmit the original size.
- `10012 / TRADE_RETCODE_TIMEOUT`: uncertain state. Query orders, positions, history and deals before considering retry.
- `10025 / TRADE_RETCODE_NO_CHANGES`: accepted as a no-op only for modification actions, not a newly sent market trade.
- Handle `10027` (client Algo Trading disabled), `10026` (server disables), `10030` (invalid filling), `10018` (market closed), `10019` (insufficient money), `10024` (too frequent requests), `10029` (frozen) explicitly in user-visible diagnostics.

Current code retains `OrderResult.ok` as a **full-completion** flag for market DEAL. It is insufficient for eventual asynchronous placement/partial fill. Future UI and API must expose separate status states before live deployment.

## 3. Account and instrument-specific rules

- Verify the current account login and server before *every* real trade; `terminal_info()` and `account_info()` expose trading permission flags, which may change.
- Honor volume min/max/step, symbol trading and stop/freeze levels, quote freshness, execution mode, and account netting/hedging semantics.
- `ORDER_FILLING_RETURN` is not allowed in Market Execution; fill policies vary by symbol and execution mode. For pending orders, MetaQuotes specifies RETURN regardless of execution mode. Do not guess fallback policies or blindly retry for other orders.
- Use the correct position ticket when modifying SL/TP or closing an open position.

## 4. Account-currency risk and margin numbers

- Estimate SL/TP money exposure with **`order_calc_profit`**, which returns an amount in the current account currency. Treat as a snapshot estimate (may exclude commissions, swap and later slippage), not a guaranteed final P/L.
- Estimate standalone initial margin with **`order_calc_margin`**, which explicitly excludes consideration of existing pending/open positions.
- Use `order_check` for preflight validation while recognizing a favorable check is not a guarantee that `order_send` will succeed.
- If any required calculation fails (None/error), show 'unavailable' rather than fabricate a money amount or use a hard-coded tick-value rule.

## 5. Local attack surface and untrusted code

- Bind only to loopback but do not treat loopback as authentication; other local processes can call an unauthenticated HTTP API.
- Apply a session/operation authorization model and CSRF mitigations (Origin, Host, Fetch Metadata, token/custom-header as appropriate) to **every** state-changing HTTP/WebSocket route.
- User-provided Python indicator code must be treated as fully untrusted. Blocking `import os` is not an OS sandbox; disable execution until isolated with OS-enforced file/process/network controls.
- Production version must disable automatic executable installation and verify every distributed binary against an independently controlled build/provenance process.

## Required acceptance gates

- [x] REST endpoints for real account mutations share authorization guard (static code review).
- [x] Synthetic tests added for 5 mutation endpoints × 3 permission states.
- [x] Synthetic tests added for relevant retcodes including pending PLACED, partial fill, timeout and no-op.
- [ ] Tests actually run and pass in a pinned environment; fork CI not yet verified.
- [ ] MT5 broker-worker level authorization and account binding independently checked.
- [ ] Proper local API authentication and indicator isolation verified.
- [ ] Demo broker cases cover instant/market execution, FOK/IOC/RETURN, invalid fill, partial fill, requotes, freeze/stops, netting and hedging.
- [ ] Live execution with actual funds authorized only after independent review and a separate user decision.

No real MT5 credentials should be committed to this repository.
