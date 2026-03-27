# Slither Static Analysis Report - Chainlink Payment Abstraction V2

**Date:** 2026-03-27
**Tool:** Slither v0.11.5
**Solc Version:** 0.8.26
**Compiler:** Foundry (forge 1.4.4-stable)
**Target:** `/home/madhav/Desktop/security/2026-03-chainlink`

---

## Summary

| Severity | Count |
|----------|-------|
| High | 0 |
| Medium | 15 |
| Low | 17 |
| Informational | 18 |
| **Total** | **50** |

**Contracts analyzed:** 65 (32 source + 33 dependencies)
**Source SLOC:** 2,244

### In-Scope Files

- `src/AuctionBidder.sol`
- `src/BaseAuction.sol`
- `src/Caller.sol`
- `src/GPV2CompatibleAuction.sol`
- `src/PriceManager.sol`
- `src/WorkflowRouter.sol`
- `src/interfaces/IAuctionCallback.sol`
- `src/interfaces/IBaseAuction.sol`
- `src/interfaces/IGPV2CompatibleAuction.sol`
- `src/interfaces/IGPV2Settlement.sol`
- `src/interfaces/IPriceManager.sol`
- `src/libraries/Errors.sol`
- `src/libraries/Roles.sol`

---

## MEDIUM SEVERITY FINDINGS

### M-1: Divide Before Multiply (Precision Loss)

**Detector:** `divide-before-multiply`
**Impact:** Medium
**Confidence:** Medium

Two locations perform division before multiplication, which can cause precision loss due to integer truncation.

**Location 1:** `PriceManager.transmit(bytes[])` (src/PriceManager.sol#133-183)
```
- usdPrice = (usdPrice * 10 ** (PRICE_DECIMALS - feedDecimals)) (line 169)
- usdPrice = (usdPrice / 10 ** (feedDecimals - PRICE_DECIMALS)) (line 171)
```

**Location 2:** `PriceManager._getAssetPrice(address,bool)` (src/PriceManager.sol#372-419)
```
- price = (price * 10 ** (PRICE_DECIMALS - decimals)) (line 397)
- price = (price / 10 ** (decimals - PRICE_DECIMALS)) (line 399)
```

**Note:** These are conditional branches (if/else) so the divide and multiply may not execute on the same value in sequence. Requires manual review to confirm whether actual precision loss occurs.

**Reference:** https://github.com/crytic/slither/wiki/Detector-Documentation#divide-before-multiply

---

### M-2: Reentrancy (Non-ETH) in BaseAuction.bid()

**Detector:** `reentrancy-no-eth`
**Impact:** Medium
**Confidence:** Medium

**Location:** `BaseAuction.bid(address,uint256,bytes)` (src/BaseAuction.sol#410-458)

External calls are made before the reentrancy guard (`s_entered`) is reset:
```
External calls:
  1. IERC20(asset).safeTransfer(msg.sender, amount)           (line 444)
  2. IAuctionCallback(msg.sender).auctionCallback(...)         (line 449)
  3. IERC20(assetOut).safeTransferFrom(msg.sender, ...)        (line 453)

State variables written AFTER the calls:
  - s_entered = false                                          (line 457)
```

Cross-function reentrancy risk: `s_entered` (src/BaseAuction.sol#157) is used in:
- `BaseAuction.bid()`

**Analysis:** The `bid()` function uses a custom reentrancy guard (`s_entered`). The guard is set to `true` at entry and `false` at exit. Between these, three external calls are made. While the guard prevents re-entering `bid()` itself, the external calls (especially the `auctionCallback`) execute before the guard is released. The callback to `msg.sender` allows the bidder to execute arbitrary logic before `safeTransferFrom` pulls payment.

---

### M-3: Reentrancy (Non-ETH) in BaseAuction.performUpkeep()

**Detector:** `reentrancy-no-eth`
**Impact:** Medium
**Confidence:** Medium

**Location:** `BaseAuction.performUpkeep(bytes)` (src/BaseAuction.sol#305-370)

```
External calls:
  1. s_feeAggregator.transferForSwap(address(this), eligibleAssets)  (line 321)
  2. IERC20(asset).safeTransfer(s_assetOutReceiver, ...)              (line 351)

State variables written AFTER the calls:
  - s_auctionStarts[asset] = block.timestamp                        (line 353)
```

Cross-function reentrancy: `s_auctionStarts` (src/BaseAuction.sol#170) is used in:
- `_applyAssetParamsUpdates()`
- `_liveAuctionExists()`
- `_onFeedInfoUpdate()`
- `bid()`
- `checkUpkeep()`
- `getAssetOutAmount()`
- `getAuctionStart()`
- `performUpkeep()`

**Analysis:** `s_auctionStarts` is written after external calls. If any of the called contracts re-enter, they could read stale auction start times. However, `performUpkeep` is access-controlled (Automation/forwarder only), which limits exploitability. Manual review needed to determine if `transferForSwap` or the ERC20 token can be attacker-controlled.

---

### M-4: Reentrancy (Benign) in PriceManager.transmit()

**Detector:** `reentrancy-benign`
**Impact:** Medium
**Confidence:** Medium

**Location:** `PriceManager.transmit(bytes[])` (src/PriceManager.sol#133-183)

```
External calls:
  - verifiedReports = i_streamsVerifierProxy.verifyBulk(
      unverifiedReports, abi.encode(i_linkToken)
    )                                                                (line 153)

State variables written AFTER the call:
  - s_dataStreamsPrice[asset] = DataStreamsPriceInfo({
      usdPrice: usdPrice.toUint224(),
      timestamp: report.observationsTimestamp
    })                                                               (lines 178-179)
```

**Analysis:** The streams verifier proxy is called before updating the price data. If the verifier proxy is compromised or calls back, stale price data would be visible. However, the verifier proxy is a trusted Chainlink infrastructure component, reducing practical risk.

---

### M-5: Uninitialized Local Variables

**Detector:** `uninitialized-local`
**Impact:** Medium
**Confidence:** Medium

**Location 1:** `BaseAuction.performUpkeep(bytes).assetOutPrice` (src/BaseAuction.sol#312)
- Local variable `assetOutPrice` is never initialized.

**Location 2:** `AuctionBidder.bid(address,uint256,Caller.Call[]).data` (src/AuctionBidder.sol#73)
- Local variable `data` is never initialized.

**Analysis:** Solidity initializes local variables to their default values (0 for uint, empty bytes for bytes). These may be intentional defaults, but should be verified. In particular, `assetOutPrice` being 0 could affect price calculations if the intended logic was to fetch a price.

---

## LOW SEVERITY FINDINGS

### L-1: Unused Return Values

**Detector:** `unused-return`
**Impact:** Medium
**Confidence:** Medium

Multiple functions ignore return values from EnumerableSet operations and oracle data feeds:

| Function | Ignored Return | Location |
|----------|---------------|----------|
| `PriceManager._getAssetPrice()` | `latestRoundData()` return values (roundId, startedAt, answeredInRound) | src/PriceManager.sol#386 |
| `WorkflowRouter.applyAllowlistedWorkflowsUpdates()` | `s_allowlistedWorkflowIds.remove(workflowId)` | src/WorkflowRouter.sol#147 |
| `WorkflowRouter.applyAllowlistedWorkflowsUpdates()` | `s_allowlistedWorkflowIds.add(workflowId_scope_1)` | src/WorkflowRouter.sol#159 |
| `WorkflowRouter._applyAllowlistedTargetsUpdates()` | `s_workflowInfos[workflowId].allowlistedTargets.remove(target)` | src/WorkflowRouter.sol#206 |
| `WorkflowRouter._applyAllowlistedTargetsUpdates()` | `s_workflowInfos[workflowId].allowlistedTargets.add(target_scope_1)` | src/WorkflowRouter.sol#218 |

**Note for PriceManager:** Ignoring `answeredInRound` from `latestRoundData()` is a known pattern, but ignoring all ancillary return values means the code may miss stale or incomplete oracle rounds. The `dataFeedUpdatedAt` timestamp is captured, so staleness is partially addressed.

**Reference:** https://github.com/crytic/slither/wiki/Detector-Documentation#unused-return

---

### L-2: Calls Inside a Loop

**Detector:** `calls-loop`
**Impact:** Low
**Confidence:** Medium

Multiple external calls are made inside loops, which can lead to DoS if any call reverts or if gas limits are exceeded:

| Function | External Call | Location |
|----------|--------------|----------|
| `Caller._call()` | `target.call(data)` | src/Caller.sol#27 |
| `PriceManager._getAssetPrice()` | `feedInfo.usdDataFeed.latestRoundData()` | src/PriceManager.sol#386 |
| `PriceManager._getAssetPrice()` | `feedInfo.usdDataFeed.decimals()` | src/PriceManager.sol#394 |
| `BaseAuction.checkUpkeep()` | `IERC20(asset).balanceOf(address(this))` | src/BaseAuction.sol#247 |
| `BaseAuction.checkUpkeep()` | `IERC20(asset).balanceOf(feeAggregator)` | src/BaseAuction.sol#257 |
| `BaseAuction.performUpkeep()` | `IERC20(asset).safeTransfer(...)` | src/BaseAuction.sol#351 |
| `GPV2CompatibleAuction._onAuctionStart()` | `IERC20(asset).forceApprove(...)` | src/GPV2CompatibleAuction.sol#92 |
| `BaseAuction._onAuctionEnd()` | `IERC20(asset).balanceOf(...)` | src/BaseAuction.sol#388 |
| `BaseAuction._onAuctionEnd()` | `IERC20(s_assetOut).balanceOf(...)` | src/BaseAuction.sol#393 |
| `BaseAuction._applyAssetParamsUpdates()` | `IERC20Metadata(asset).decimals()` | src/BaseAuction.sol#636 |
| `GPV2CompatibleAuction.invalidateOrders()` | `i_gpV2Settlement.invalidateOrder(orderUids[i])` | src/GPV2CompatibleAuction.sol#184 |

**Analysis:** The `Caller._call()` loop is particularly notable -- it allows arbitrary external calls in a loop via `AuctionBidder.auctionCallback()`. If one call in the multicall sequence fails, the entire bid callback reverts. The `checkUpkeep` and `performUpkeep` loops iterate over assets, so a malicious/reverting ERC20 token could block the entire auction process.

**Reference:** https://github.com/crytic/slither/wiki/Detector-Documentation/#calls-inside-a-loop

---

### L-3: Reentrancy (Event Emission After External Call)

**Detector:** `reentrancy-events`
**Impact:** Low
**Confidence:** Medium

Events are emitted after external calls, which could lead to incorrect event ordering if reentrancy occurs:

**Location 1:** `BaseAuction.bid()` (src/BaseAuction.sol#410-458)
```
External calls:
  - IERC20(asset).safeTransfer(msg.sender, amount)
  - IAuctionCallback(msg.sender).auctionCallback(...)
  - IERC20(assetOut).safeTransferFrom(msg.sender, ...)
Event emitted AFTER:
  - AuctionBidSettled(msg.sender, asset, amount, assetOutAmount)
```

**Location 2:** `BaseAuction.performUpkeep()` (src/BaseAuction.sol#305-370)
```
External calls:
  - s_feeAggregator.transferForSwap(...)
  - IERC20(asset).safeTransfer(...)
Event emitted AFTER:
  - AuctionStarted(asset)
```

**Location 3:** `PriceManager.transmit()` (src/PriceManager.sol#133-183)
```
External calls:
  - i_streamsVerifierProxy.verifyBulk(...)
Event emitted AFTER:
  - PriceTransmitted(asset, usdPrice)
```

**Reference:** https://github.com/crytic/slither/wiki/Detector-Documentation#reentrancy-vulnerabilities-4

---

### L-4: Costly Operations Inside Loop

**Detector:** `costly-loop`
**Impact:** Low (Gas)
**Confidence:** Medium

**Location:** `BaseAuction.performUpkeep(bytes)` (src/BaseAuction.sol#305-370)
```
- delete s_auctionStarts[asset_scope_1]   (line 367)
```

Storage deletion inside a loop increases gas cost per iteration.

**Reference:** https://github.com/crytic/slither/wiki/Detector-Documentation#costly-operations-inside-a-loop

---

## INFORMATIONAL FINDINGS

### I-1: Assembly Usage

**Detector:** `assembly`
**Impact:** Informational
**Confidence:** High

Inline assembly is used in the following in-scope locations:

| Function | Location |
|----------|----------|
| `BaseAuction.checkUpkeep(bytes)` | src/BaseAuction.sol#275-278, #281-284 |
| `Caller._call(address,bytes)` | src/Caller.sol#33-37 |
| `WorkflowRouter.onReport(bytes,bytes)` | src/WorkflowRouter.sol#106-108 |
| `WorkflowRouter._applyAllowlistedTargetsUpdates()` | src/WorkflowRouter.sol#201-203 |
| `WorkflowRouter.getAllowlistedSelectors()` | src/WorkflowRouter.sol#316-318 |
| `EnumerableBytesSet.values()` | src/libraries/EnumerableBytesSet.sol#155-157 |

**Analysis:** Assembly usage bypasses Solidity's safety checks. Each instance should be carefully reviewed for correctness, especially memory handling and potential overflow.

---

### I-2: Low-Level Calls

**Detector:** `low-level-calls`
**Impact:** Informational
**Confidence:** High

| Function | Call | Location |
|----------|------|----------|
| `Caller._call(address,bytes)` | `target.call(data)` | src/Caller.sol#27 |

**Analysis:** `Caller._call()` performs an arbitrary low-level call to a target address. The target and data are provided by the caller (via `AuctionBidder.auctionCallback`). While the contract checks for success and has allowlist controls via `WorkflowRouter`, the raw `.call()` provides no type safety guarantees.

---

### I-3: High Cyclomatic Complexity

**Detector:** `cyclomatic-complexity`
**Impact:** Informational
**Confidence:** High

| Function | Complexity | Location |
|----------|-----------|----------|
| `BaseAuction._applyAssetParamsUpdates()` | 14 | src/BaseAuction.sol#598-664 |
| `GPV2CompatibleAuction.isValidSignature()` | 14 | src/GPV2CompatibleAuction.sol#119-176 |
| `PriceManager._applyFeedInfoUpdates()` | 15 | src/PriceManager.sol#209-303 |

**Analysis:** High complexity increases the likelihood of logical errors and makes testing more difficult. `isValidSignature()` is particularly critical as it controls CoW Protocol order validation.

---

### I-4: Unindexed Event Address Parameters (In-Scope)

**Detector:** `unindexed-event-address`
**Impact:** Informational
**Confidence:** High

The following events in in-scope contracts have address parameters that are not indexed:

| Event | Location |
|-------|----------|
| `PriceManager.AssetAddedToAllowlist(address)` | src/PriceManager.sol#29 |
| `PriceManager.AssetRemovedFromAllowlist(address)` | src/PriceManager.sol#32 |
| `PriceManager.VerifierProxySet(address)` | src/PriceManager.sol#35 |

Indexing address parameters enables efficient off-chain filtering of events.

---

## TARGETED HIGH-SEVERITY DETECTOR SCAN

The following high-severity detectors were run with **no path filtering**:

| Detector | Result |
|----------|--------|
| `reentrancy-eth` | **No findings** |
| `uninitialized-state` | **No findings** |
| `arbitrary-send-erc20-permit` | **No findings** |
| `suicidal` | **No findings** |
| `controlled-delegatecall` | **No findings** |
| `unchecked-transfer` | **No findings** |

Only `reentrancy-no-eth` and `reentrancy-benign` produced findings (documented above as M-2, M-3, and M-4).

---

## CONTRACT SUMMARY TABLE

| Contract | Functions | ERCs | Complex Code | Features |
|----------|-----------|------|--------------|----------|
| AuctionBidder | 96 | ERC165 | No | Send ETH, Tokens, Assembly |
| GPV2CompatibleAuction | 148 | ERC165 | Yes | Send ETH, Tokens, Assembly |
| WorkflowRouter | 96 | ERC165 | Yes | Assembly |

---

## KEY OBSERVATIONS FOR MANUAL REVIEW

1. **BaseAuction.bid() Reentrancy Pattern (M-2):** The bid function sends the asset to the bidder, then calls `auctionCallback`, then pulls payment via `safeTransferFrom`. This is an intentional "optimistic transfer" pattern (send first, callback, then pull payment). The custom `s_entered` guard prevents re-entering `bid()`, but the bidder has execution control between receiving assets and paying. The callback allows the bidder to perform arbitrary operations (via `Caller._multiCall`). Verify that:
   - The reentrancy guard is sufficient to prevent cross-function attacks
   - A malicious bidder cannot benefit from the window between receiving assets and paying

2. **Caller._call() Arbitrary External Calls (I-2, L-2):** The `Caller` contract makes raw `.call()` to arbitrary targets. While presumably controlled by allowlists in `WorkflowRouter`, verify that the allowlist cannot be bypassed and that the call targets cannot be manipulated.

3. **PriceManager Precision (M-1):** The divide-before-multiply pattern in price calculations could lead to precision loss. While the branches appear mutually exclusive (if/else based on decimal comparison), verify that price normalization is correct across all decimal combinations.

4. **performUpkeep() State Updates After External Calls (M-3):** `s_auctionStarts` is written after external token transfers. If the fee aggregator or ERC20 token contract can re-enter, stale auction start times could be observed.

5. **GPV2CompatibleAuction.isValidSignature() Complexity:** With cyclomatic complexity of 14, this function validates CoW Protocol orders. Any logical error here could allow invalid orders to be approved or valid orders to be rejected.

---

## RAW SLITHER OUTPUT

### Run 1: Default Config (`slither.config.json`)

```
'forge clean' running (wd: /home/madhav/Desktop/security/2026-03-chainlink)
'forge config --json' running
'forge build --build-info --skip ./test/** ./script/** --force' running (wd: /home/madhav/Desktop/security/2026-03-chainlink)
INFO:Detectors:
Detector: divide-before-multiply
PriceManager.transmit(bytes[]) (src/PriceManager.sol#133-183) performs a multiplication on the result of a division:
	- usdPrice = (usdPrice * 10 ** (PRICE_DECIMALS - feedDecimals)) (src/PriceManager.sol#169)
	- usdPrice = (usdPrice / 10 ** (feedDecimals - PRICE_DECIMALS)) (src/PriceManager.sol#171)
PriceManager._getAssetPrice(address,bool) (src/PriceManager.sol#372-419) performs a multiplication on the result of a division:
	- price = (price * 10 ** (PRICE_DECIMALS - decimals)) (src/PriceManager.sol#397)
	- price = (price / 10 ** (decimals - PRICE_DECIMALS)) (src/PriceManager.sol#399)
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#divide-before-multiply
INFO:Detectors:
Detector: incorrect-equality
NativeTokenReceiver.deposit() (src/NativeTokenReceiver.sol#37-43) uses a dangerous strict equality:
	- address(this).balance == 0 (src/NativeTokenReceiver.sol#38)
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#dangerous-strict-equalities
INFO:Detectors:
Detector: reentrancy-no-eth
Reentrancy in BaseAuction.bid(address,uint256,bytes) (src/BaseAuction.sol#410-458):
	External calls:
	- IERC20(asset).safeTransfer(msg.sender,amount) (src/BaseAuction.sol#444)
	- IAuctionCallback(msg.sender).auctionCallback(msg.sender,assetOut,assetOutAmount,data) (src/BaseAuction.sol#449)
	- IERC20(assetOut).safeTransferFrom(msg.sender,address(this),assetOutAmount) (src/BaseAuction.sol#453)
	State variables written after the call(s):
	- s_entered = false (src/BaseAuction.sol#457)
	BaseAuction.s_entered (src/BaseAuction.sol#157) can be used in cross function reentrancies:
	- BaseAuction.bid(address,uint256,bytes) (src/BaseAuction.sol#410-458)
Reentrancy in BaseAuction.performUpkeep(bytes) (src/BaseAuction.sol#305-370):
	External calls:
	- s_feeAggregator.transferForSwap(address(this),eligibleAssets) (src/BaseAuction.sol#321)
	- IERC20(asset).safeTransfer(s_assetOutReceiver,IERC20(asset).balanceOf(address(this))) (src/BaseAuction.sol#351)
	State variables written after the call(s):
	- s_auctionStarts[asset] = block.timestamp (src/BaseAuction.sol#353)
	BaseAuction.s_auctionStarts (src/BaseAuction.sol#170) can be used in cross function reentrancies:
	- BaseAuction._applyAssetParamsUpdates(BaseAuction.ApplyAssetParamsUpdate[],address[]) (src/BaseAuction.sol#598-664)
	- BaseAuction._liveAuctionExists() (src/BaseAuction.sol#676-683)
	- BaseAuction._onFeedInfoUpdate(address,bool) (src/BaseAuction.sol#688-697)
	- BaseAuction.bid(address,uint256,bytes) (src/BaseAuction.sol#410-458)
	- BaseAuction.checkUpkeep(bytes) (src/BaseAuction.sol#216-294)
	- BaseAuction.getAssetOutAmount(address,uint256,uint256) (src/BaseAuction.sol#749-767)
	- BaseAuction.getAuctionStart(address) (src/BaseAuction.sol#732-736)
	- BaseAuction.performUpkeep(bytes) (src/BaseAuction.sol#305-370)
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#reentrancy-vulnerabilities-2
INFO:Detectors:
Detector: uninitialized-local
BaseAuction.performUpkeep(bytes).assetOutPrice (src/BaseAuction.sol#312) is a local variable never initialized
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#uninitialized-local-variables
INFO:Detectors:
Detector: unused-return
PausableWithAccessControl._grantRole(bytes32,address) (src/PausableWithAccessControl.sol#77-86) ignores return value by s_roleMembers[role].add(account) (src/PausableWithAccessControl.sol#83)
PausableWithAccessControl._revokeRole(bytes32,address) (src/PausableWithAccessControl.sol#89-98) ignores return value by s_roleMembers[role].remove(account) (src/PausableWithAccessControl.sol#95)
FeeAggregator.applyAllowlistedReceiverUpdates(FeeAggregator.AllowlistedReceivers[],FeeAggregator.AllowlistedReceivers[]) (src/FeeAggregator.sol#398-445) ignores return value by s_allowlistedDestinationChains.remove(destChainSelector) (src/FeeAggregator.sol#415)
PriceManager._getAssetPrice(address,bool) (src/PriceManager.sol#372-419) ignores return value by (None,answer,None,dataFeedUpdatedAt,None) = feedInfo.usdDataFeed.latestRoundData() (src/PriceManager.sol#386)
WorkflowRouter.applyAllowlistedWorkflowsUpdates(bytes32[],WorkflowRouter.AllowlistedWorkflow[]) (src/WorkflowRouter.sol#134-162) ignores return value by s_allowlistedWorkflowIds.remove(workflowId) (src/WorkflowRouter.sol#147)
WorkflowRouter.applyAllowlistedWorkflowsUpdates(bytes32[],WorkflowRouter.AllowlistedWorkflow[]) (src/WorkflowRouter.sol#134-162) ignores return value by s_allowlistedWorkflowIds.add(workflowId_scope_1) (src/WorkflowRouter.sol#159)
WorkflowRouter._applyAllowlistedTargetsUpdates(bytes32,address[],WorkflowRouter.TargetSelectors[]) (src/WorkflowRouter.sol#184-221) ignores return value by s_workflowInfos[workflowId].allowlistedTargets.remove(target) (src/WorkflowRouter.sol#206)
WorkflowRouter._applyAllowlistedTargetsUpdates(bytes32,address[],WorkflowRouter.TargetSelectors[]) (src/WorkflowRouter.sol#184-221) ignores return value by s_workflowInfos[workflowId].allowlistedTargets.add(target_scope_1) (src/WorkflowRouter.sol#218)
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#unused-return
INFO:Detectors:
Detector: calls-loop
Caller._call(address,bytes) (src/Caller.sol#21-44) has external calls inside a loop: (success,response) = target.call(data) (src/Caller.sol#27)
	Calls stack containing the loop:
		AuctionBidder.auctionCallback(address,address,uint256,bytes)
		Caller._multiCall(Caller.Call[])
PriceManager._getAssetPrice(address,bool) (src/PriceManager.sol#372-419) has external calls inside a loop: (None,answer,None,dataFeedUpdatedAt,None) = feedInfo.usdDataFeed.latestRoundData() (src/PriceManager.sol#386)
	Calls stack containing the loop:
		BaseAuction.checkUpkeep(bytes)
PriceManager._getAssetPrice(address,bool) (src/PriceManager.sol#372-419) has external calls inside a loop: decimals = feedInfo.usdDataFeed.decimals() (src/PriceManager.sol#394)
	Calls stack containing the loop:
		BaseAuction.checkUpkeep(bytes)
BaseAuction.checkUpkeep(bytes) (src/BaseAuction.sol#216-294) has external calls inside a loop: assetBalance = IERC20(asset).balanceOf(address(this)) (src/BaseAuction.sol#247)
BaseAuction.checkUpkeep(bytes) (src/BaseAuction.sol#216-294) has external calls inside a loop: availableBalance = IERC20(asset).balanceOf(feeAggregator) (src/BaseAuction.sol#257)
BaseAuction.performUpkeep(bytes) (src/BaseAuction.sol#305-370) has external calls inside a loop: IERC20(asset).safeTransfer(s_assetOutReceiver,IERC20(asset).balanceOf(address(this))) (src/BaseAuction.sol#351)
GPV2CompatibleAuction._onAuctionStart(address) (src/GPV2CompatibleAuction.sol#86-93) has external calls inside a loop: IERC20(asset).forceApprove(i_gpV2VaultRelayer,IERC20(asset).balanceOf(address(this))) (src/GPV2CompatibleAuction.sol#92)
	Calls stack containing the loop:
		BaseAuction.performUpkeep(bytes)
BaseAuction._onAuctionEnd(address,bool) (src/BaseAuction.sol#383-397) has external calls inside a loop: assetBalance = IERC20(asset).balanceOf(address(this)) (src/BaseAuction.sol#388)
	Calls stack containing the loop:
		BaseAuction.performUpkeep(bytes)
		GPV2CompatibleAuction._onAuctionEnd(address,bool)
BaseAuction._onAuctionEnd(address,bool) (src/BaseAuction.sol#383-397) has external calls inside a loop: assetOutBalance = IERC20(s_assetOut).balanceOf(address(this)) (src/BaseAuction.sol#393)
	Calls stack containing the loop:
		BaseAuction.performUpkeep(bytes)
		GPV2CompatibleAuction._onAuctionEnd(address,bool)
BaseAuction._applyAssetParamsUpdates(BaseAuction.ApplyAssetParamsUpdate[],address[]) (src/BaseAuction.sol#598-664) has external calls inside a loop: assetDecimals = IERC20Metadata(asset_scope_1).decimals() (src/BaseAuction.sol#636)
	Calls stack containing the loop:
		BaseAuction.applyAssetParamsUpdates(BaseAuction.ApplyAssetParamsUpdate[],address[])
GPV2CompatibleAuction.invalidateOrders(bytes[]) (src/GPV2CompatibleAuction.sol#180-186) has external calls inside a loop: i_gpV2Settlement.invalidateOrder(orderUids[i]) (src/GPV2CompatibleAuction.sol#184)
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation/#calls-inside-a-loop
INFO:Detectors:
Detector: reentrancy-benign
Reentrancy in PriceManager.transmit(bytes[]) (src/PriceManager.sol#133-183):
	External calls:
	- verifiedReports = i_streamsVerifierProxy.verifyBulk(unverifiedReports,abi.encode(i_linkToken)) (src/PriceManager.sol#153)
	State variables written after the call(s):
	- s_dataStreamsPrice[asset] = DataStreamsPriceInfo({usdPrice:usdPrice.toUint224(),timestamp:report.observationsTimestamp}) (src/PriceManager.sol#178-179)
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#reentrancy-vulnerabilities-3
INFO:Detectors:
Detector: reentrancy-events
Reentrancy in BaseAuction.bid(address,uint256,bytes) (src/BaseAuction.sol#410-458):
	External calls:
	- IERC20(asset).safeTransfer(msg.sender,amount) (src/BaseAuction.sol#444)
	- IAuctionCallback(msg.sender).auctionCallback(msg.sender,assetOut,assetOutAmount,data) (src/BaseAuction.sol#449)
	- IERC20(assetOut).safeTransferFrom(msg.sender,address(this),assetOutAmount) (src/BaseAuction.sol#453)
	Event emitted after the call(s):
	- AuctionBidSettled(msg.sender,asset,amount,assetOutAmount) (src/BaseAuction.sol#455)
Reentrancy in EmergencyWithdrawer.emergencyWithdrawNative(address,uint256) (src/EmergencyWithdrawer.sol#61-67):
	External calls:
	- _transferNative(to,amount) (src/EmergencyWithdrawer.sol#65)
		- (success,data) = to.call{value: amount}() (src/EmergencyWithdrawer.sol#85)
	Event emitted after the call(s):
	- AssetEmergencyWithdrawn(to,address(0),amount) (src/EmergencyWithdrawer.sol#66)
Reentrancy in BaseAuction.performUpkeep(bytes) (src/BaseAuction.sol#305-370):
	External calls:
	- s_feeAggregator.transferForSwap(address(this),eligibleAssets) (src/BaseAuction.sol#321)
	- IERC20(asset).safeTransfer(s_assetOutReceiver,IERC20(asset).balanceOf(address(this))) (src/BaseAuction.sol#351)
	Event emitted after the call(s):
	- AuctionStarted(asset) (src/BaseAuction.sol#355)
Reentrancy in PriceManager.transmit(bytes[]) (src/PriceManager.sol#133-183):
	External calls:
	- verifiedReports = i_streamsVerifierProxy.verifyBulk(unverifiedReports,abi.encode(i_linkToken)) (src/PriceManager.sol#153)
	Event emitted after the call(s):
	- PriceTransmitted(asset,usdPrice) (src/PriceManager.sol#181)
Reentrancy in FeeAggregator.withdrawNative(address,uint256) (src/FeeAggregator.sol#379-391):
	External calls:
	- _transferNative(to,amount) (src/FeeAggregator.sol#389)
		- (success,data) = to.call{value: amount}() (src/EmergencyWithdrawer.sol#85)
	Event emitted after the call(s):
	- NonAllowlistedAssetWithdrawn(to,address(0),amount) (src/FeeAggregator.sol#390)
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#reentrancy-vulnerabilities-4
INFO:Detectors:
Detector: assembly
BaseAuction.checkUpkeep(bytes) (src/BaseAuction.sol#216-294) uses assembly
	- INLINE ASM (src/BaseAuction.sol#275-278)
	- INLINE ASM (src/BaseAuction.sol#281-284)
Caller._call(address,bytes) (src/Caller.sol#21-44) uses assembly
	- INLINE ASM (src/Caller.sol#33-37)
WorkflowRouter.onReport(bytes,bytes) (src/WorkflowRouter.sol#86-118) uses assembly
	- INLINE ASM (src/WorkflowRouter.sol#106-108)
WorkflowRouter._applyAllowlistedTargetsUpdates(bytes32,address[],WorkflowRouter.TargetSelectors[]) (src/WorkflowRouter.sol#184-221) uses assembly
	- INLINE ASM (src/WorkflowRouter.sol#201-203)
WorkflowRouter.getAllowlistedSelectors(bytes32,address) (src/WorkflowRouter.sol#311-321) uses assembly
	- INLINE ASM (src/WorkflowRouter.sol#316-318)
EnumerableBytesSet.values(EnumerableBytesSet.BytesSet) (src/libraries/EnumerableBytesSet.sol#149-160) uses assembly
	- INLINE ASM (src/libraries/EnumerableBytesSet.sol#155-157)
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#assembly-usage
INFO:Detectors:
Detector: costly-loop
BaseAuction.performUpkeep(bytes) (src/BaseAuction.sol#305-370) has costly operations inside a loop:
	- delete s_auctionStarts[asset_scope_1] (src/BaseAuction.sol#367)
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#costly-operations-inside-a-loop
INFO:Detectors:
Detector: cyclomatic-complexity
BaseAuction._applyAssetParamsUpdates(BaseAuction.ApplyAssetParamsUpdate[],address[]) (src/BaseAuction.sol#598-664) has a high cyclomatic complexity (14).
GPV2CompatibleAuction.isValidSignature(bytes32,bytes) (src/GPV2CompatibleAuction.sol#119-176) has a high cyclomatic complexity (14).
PriceManager._applyFeedInfoUpdates(PriceManager.ApplyFeedInfoUpdateParams[],address[]) (src/PriceManager.sol#209-303) has a high cyclomatic complexity (15).
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#cyclomatic-complexity
INFO:Detectors:
Detector: low-level-calls
Low level call in Caller._call(address,bytes) (src/Caller.sol#21-44):
	- (success,response) = target.call(data) (src/Caller.sol#27)
Low level call in EmergencyWithdrawer._transferNative(address,uint256) (src/EmergencyWithdrawer.sol#74-90):
	- (success,data) = to.call{value: amount}() (src/EmergencyWithdrawer.sol#85)
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#low-level-calls
INFO:Detectors:
Detector: unindexed-event-address
Event FeeAggregator.AssetRemovedFromAllowlist(address) (src/FeeAggregator.sol#44) has address parameters but no indexed parameters
Event FeeAggregator.AssetAddedToAllowlist(address) (src/FeeAggregator.sol#47) has address parameters but no indexed parameters
Event NativeTokenReceiver.WrappedNativeTokenSet(address) (src/NativeTokenReceiver.sol#13) has address parameters but no indexed parameters
Event PriceManager.AssetAddedToAllowlist(address) (src/PriceManager.sol#29) has address parameters but no indexed parameters
Event PriceManager.AssetRemovedFromAllowlist(address) (src/PriceManager.sol#32) has address parameters but no indexed parameters
Event PriceManager.VerifierProxySet(address) (src/PriceManager.sol#35) has address parameters but no indexed parameters
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#unindexed-event-address-parameters
INFO:Slither:. analyzed (65 contracts with 96 detectors), 49 result(s) found
```

### Run 2: Targeted High-Severity Detectors (No Path Filtering)

```
'forge clean' running (wd: /home/madhav/Desktop/security/2026-03-chainlink)
'forge config --json' running
'forge build --build-info --skip ./test/** ./script/** --force' running (wd: /home/madhav/Desktop/security/2026-03-chainlink)
INFO:Detectors:
Detector: reentrancy-benign
Reentrancy in PriceManager.transmit(bytes[]) (src/PriceManager.sol#133-183):
	External calls:
	- verifiedReports = i_streamsVerifierProxy.verifyBulk(unverifiedReports,abi.encode(i_linkToken)) (src/PriceManager.sol#153)
	State variables written after the call(s):
	- s_dataStreamsPrice[asset] = DataStreamsPriceInfo({usdPrice:usdPrice.toUint224(),timestamp:report.observationsTimestamp}) (src/PriceManager.sol#178-179)
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#reentrancy-vulnerabilities-3
INFO:Detectors:
Detector: reentrancy-no-eth
Reentrancy in BaseAuction.bid(address,uint256,bytes) (src/BaseAuction.sol#410-458):
	External calls:
	- IERC20(asset).safeTransfer(msg.sender,amount) (src/BaseAuction.sol#444)
	- IAuctionCallback(msg.sender).auctionCallback(msg.sender,assetOut,assetOutAmount,data) (src/BaseAuction.sol#449)
	- IERC20(assetOut).safeTransferFrom(msg.sender,address(this),assetOutAmount) (src/BaseAuction.sol#453)
	State variables written after the call(s):
	- s_entered = false (src/BaseAuction.sol#457)
	BaseAuction.s_entered (src/BaseAuction.sol#157) can be used in cross function reentrancies:
	- BaseAuction.bid(address,uint256,bytes) (src/BaseAuction.sol#410-458)
Reentrancy in BaseAuction.performUpkeep(bytes) (src/BaseAuction.sol#305-370):
	External calls:
	- s_feeAggregator.transferForSwap(address(this),eligibleAssets) (src/BaseAuction.sol#321)
	- IERC20(asset).safeTransfer(s_assetOutReceiver,IERC20(asset).balanceOf(address(this))) (src/BaseAuction.sol#351)
	State variables written after the call(s):
	- s_auctionStarts[asset] = block.timestamp (src/BaseAuction.sol#353)
	BaseAuction.s_auctionStarts (src/BaseAuction.sol#170) can be used in cross function reentrancies:
	- BaseAuction._applyAssetParamsUpdates(BaseAuction.ApplyAssetParamsUpdate[],address[]) (src/BaseAuction.sol#598-664)
	- BaseAuction._liveAuctionExists() (src/BaseAuction.sol#676-683)
	- BaseAuction._onFeedInfoUpdate(address,bool) (src/BaseAuction.sol#688-697)
	- BaseAuction.bid(address,uint256,bytes) (src/BaseAuction.sol#410-458)
	- BaseAuction.checkUpkeep(bytes) (src/BaseAuction.sol#216-294)
	- BaseAuction.getAssetOutAmount(address,uint256,uint256) (src/BaseAuction.sol#749-767)
	- BaseAuction.getAuctionStart(address) (src/BaseAuction.sol#732-736)
	- BaseAuction.performUpkeep(bytes) (src/BaseAuction.sol#305-370)
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#reentrancy-vulnerabilities-2
INFO:Slither:. analyzed (65 contracts with 8 detectors), 3 result(s) found
```

### Run 3: All Detectors Without AuctionBidder Filter

```
'forge clean' running (wd: /home/madhav/Desktop/security/2026-03-chainlink)
'forge config --json' running
'forge build --build-info --skip ./test/** ./script/** --force' running (wd: /home/madhav/Desktop/security/2026-03-chainlink)

Additional finding (not in Run 1 due to path filter):

Detector: uninitialized-local
AuctionBidder.bid(address,uint256,Caller.Call[]).data (src/AuctionBidder.sol#73) is a local variable never initialized

INFO:Slither:. analyzed (65 contracts with 96 detectors), 50 result(s) found
```

---

## CONFIGURATION NOTES

The project's `slither.config.json` excludes:
- **Detectors excluded:** `conformance-to-solidity-naming-conventions`, `solc-version`, `block-timestamp`, `arbitrary-send-eth`, `arbitrary-send-erc20`
- **Paths filtered:** `node_modules`, `src/vendor`, `src/AuctionBidder.sol`

**Important:** `src/AuctionBidder.sol` is in-scope but was filtered by the project's default config. Run 3 above includes its findings.

---

*Report generated by Slither v0.11.5 on 2026-03-27*
