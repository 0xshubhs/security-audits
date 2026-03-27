# Chainlink Payment Abstraction V2 - Comprehensive Security Audit Report

**Auditor**: Automated Multi-Agent Security Analysis
**Target**: Chainlink Payment Abstraction V2 (Code4rena Competitive Audit)
**Scope**: 1,060 nSLOC across 13 files
**Date**: March 27, 2026

---

## Executive Summary

The Chainlink Payment Abstraction V2 system implements a permissionless Dutch auction mechanism for converting fee tokens into LINK. The system is well-designed with proper access controls and rounding in the protocol's favor. However, several medium-severity issues were identified relating to CowSwap integration gaps, atomic operation failures, and potential operational disruptions.

---

## HIGH SEVERITY FINDINGS

### [H-01] `isValidSignature` Missing `minBidUsdValue` Check Enables CowSwap Dust-Fill Attacks

**Severity**: High
**Contract**: `GPV2CompatibleAuction.sol`
**Function**: `isValidSignature()`
**Lines**: L119-L176

**Description**:
The `bid()` function in `BaseAuction.sol` (L430-L435) enforces a minimum bid USD value:

```solidity
uint256 bidUsdValue = (amount * assetPrice) / (10 ** assetParams.decimals);
if (bidUsdValue < minBidUsdValue) {
    revert BidValueTooLow(bidUsdValue, minBidUsdValue);
}
```

However, `isValidSignature()` in `GPV2CompatibleAuction.sol` has NO equivalent check. It only requires `order.sellAmount > 0` (L141-L143). Since CowSwap orders are validated as `partiallyFillable` (L168-L170), a CowSwap solver can execute arbitrarily small partial fills.

**Impact**:
- A malicious solver can execute many micro-fills (even 1 wei) that individually provide proportional fair value but collectively drain the auction balance below `minAuctionSizeUsd`.
- When the balance drops below the threshold, `checkUpkeep()` flags the auction for early termination.
- The remaining balance is returned to the FeeAggregator without conversion, requiring a new auction cycle.
- On low-gas L2 chains, this griefing attack is cheaply sustainable.
- This directly violates the design goal: "Any vector that may block auction participation."

**Proof of Concept**:
1. Auction starts for 100,000 USDC with `minAuctionSizeUsd = 1000e18` and `minBidUsdValue = 100e18`
2. Attacker submits CowSwap order with `sellAmount = 1e6` (1 USDC, worth $1)
3. `isValidSignature` validates: `sellAmount > 0` ✓, `buyAmount >= minBuyAmount` ✓
4. CowSwap settlement fills the order - 1 USDC transferred, proportional LINK received
5. Attacker repeats with hundreds of micro-fills
6. Balance drops below `minAuctionSizeUsd` → `checkUpkeep` triggers early auction end
7. Direct bidders are unable to participate in the prematurely ended auction

**Recommendation**:
Add a `minBidUsdValue` check in `isValidSignature()`:

```solidity
uint256 bidUsdValue = (order.sellAmount * sellTokenUsdPrice) / (10 ** assetParams.decimals);
if (bidUsdValue < s_minBidUsdValue) {
    revert BidValueTooLow(bidUsdValue, s_minBidUsdValue);
}
```

---

### [H-02] Atomic `performUpkeep` Failure - Single Stale Price Blocks All Auction Operations

**Severity**: High
**Contract**: `BaseAuction.sol`
**Function**: `performUpkeep()`
**Lines**: L305-L370

**Description**:
`performUpkeep()` processes both eligible assets (to start auctions) and ended auctions (to close them) in a single atomic transaction. For each eligible asset, it calls `_getAssetPrice(asset, true)` which reverts on stale prices:

```solidity
for (uint256 i; i < eligibleAssets.length; ++i) {
    // ...
    (assetPrice,,) = _getAssetPrice(asset, true);  // REVERTS if stale
    // ...
}
```

If ANY single eligible asset has a stale price (both Data Streams and Data Feed), the ENTIRE `performUpkeep` call reverts, preventing:
1. All other eligible auctions from starting
2. ALL ended auctions from being closed
3. Accumulated LINK in ended auctions from being sent to the receiver

**Impact**:
- A single problematic price feed can DoS the entire auction system
- LINK accumulated from bids during live auctions remains locked in the contract
- Ended auctions cannot be finalized, blocking configuration changes that require `_whenNoLiveAuctions()`
- The CRE workflow typically calls `checkUpkeep` → `performUpkeep` atomically without filtering individual assets

**Proof of Concept**:
1. Three assets (WETH, USDC, DAI) are configured with auctions
2. WETH and USDC auctions have ended (duration elapsed)
3. DAI is eligible for a new auction
4. DAI's Data Streams price becomes stale AND its Data Feed is also stale
5. `checkUpkeep` returns all three in `performData`
6. `performUpkeep` processes eligible assets first → hits DAI → `_getAssetPrice(DAI, true)` reverts
7. Entire transaction reverts - WETH and USDC auctions remain "live" (can't be ended)
8. LINK from WETH/USDC bids is stuck until DAI's price is refreshed

**Recommendation**:
Option A: Process ended auctions BEFORE eligible assets, so auction endings are not blocked by new auction start failures.

Option B: Allow the AUCTION_WORKER_ROLE to pass separate `performData` for starts and ends:
```solidity
// Separate into two calls
function performUpkeepStart(bytes calldata startData) external;
function performUpkeepEnd(bytes calldata endData) external;
```

Option C: Use try/catch for individual asset price fetches in the eligible assets loop.

---

### [H-03] CowSwap `isValidSignature` Validates Price at Settlement Time But Approval is Fixed at Auction Start

**Severity**: High
**Contract**: `GPV2CompatibleAuction.sol`
**Functions**: `_onAuctionStart()`, `isValidSignature()`
**Lines**: L86-L93, L119-L176

**Description**:
In `_onAuctionStart()`, the CowSwap vault relayer is approved for the EXACT balance at auction start:

```solidity
IERC20(asset).forceApprove(i_gpV2VaultRelayer, IERC20(asset).balanceOf(address(this)));
```

When direct `bid()` calls reduce the balance, the approval remains unchanged. However, `isValidSignature()` validates `order.sellAmount <= assetInBalance` using the CURRENT balance (L144-L147):

```solidity
uint256 assetInBalance = order.sellToken.balanceOf(address(this));
if (order.sellAmount > assetInBalance) {
    revert InsufficientAssetInBalance(...);
}
```

This creates a scenario where `isValidSignature` validates an order for the remaining balance, but the vault relayer's approval is still set to the original (larger) amount. If new tokens are deposited to the auction contract (as acknowledged in known issues), the vault relayer can transfer UP TO the original approval amount - potentially more than what was validated.

While the known issues mention "arbitrary deposits," the combination with stale approvals creates a window where CowSwap solvers can access more tokens than intended.

**Impact**:
- CowSwap approval is never decreased during the auction lifecycle (only set at start and revoked at end)
- If tokens are directly deposited during an auction AND the deposit amount is within the original approval, CowSwap solvers can access them without proper auction curve validation for the full amount
- The `isValidSignature` validation at settlement time may use different prices than when the order was first created

**Recommendation**:
Reduce the vault relayer approval after each direct `bid()`:

```solidity
// In bid(), after the transfer:
IERC20(asset).safeTransfer(msg.sender, amount);
// Reduce CowSwap approval to match remaining balance
IERC20(asset).forceApprove(i_gpV2VaultRelayer, IERC20(asset).balanceOf(address(this)));
```

---

## MEDIUM SEVERITY FINDINGS

### [M-01] `bid()` Function Lacks Explicit Slippage Protection for Direct Bidders

**Severity**: Medium
**Contract**: `BaseAuction.sol`
**Function**: `bid()`
**Lines**: L410-L458

**Description**:
The `bid()` function computes `assetOutAmount` on-chain based on the current price and elapsed time, but provides no `maxAssetOutAmount` parameter for the bidder to limit their cost:

```solidity
uint256 assetOutAmount = _getAssetOutAmount(assetParams, assetPrice, amount, elapsedTime, true);
IERC20(asset).safeTransfer(msg.sender, amount);
// ... callback ...
IERC20(assetOut).safeTransferFrom(msg.sender, address(this), assetOutAmount);
```

Between transaction submission and execution:
- A new Data Streams price could be transmitted (via PRICE_ADMIN_ROLE)
- Block timestamp advances, changing the price multiplier

While the Dutch auction design means prices generally decrease over time, a fresh price transmission could increase the `assetInUsdPrice` or decrease the `assetOutUsdPrice`, resulting in a higher `assetOutAmount`.

**Impact**:
- Bidders may pay more LINK than expected
- MEV searchers could sandwich bids by manipulating the timing of price transmissions (if they have PRICE_ADMIN access or can influence it)
- Unlike CowSwap orders which specify a minimum buy amount, direct bidders have no explicit price cap

**Recommendation**:
Add a `maxAssetOutAmount` parameter:

```solidity
function bid(
    address asset,
    uint256 amount,
    uint256 maxAssetOutAmount, // NEW
    bytes calldata data
) external whenNotPaused {
    // ...
    uint256 assetOutAmount = _getAssetOutAmount(...);
    if (assetOutAmount > maxAssetOutAmount) {
        revert SlippageExceeded(assetOutAmount, maxAssetOutAmount);
    }
    // ...
}
```

---

### [M-02] `_setAssetOut` Deletes Old AssetOut Params But Doesn't Remove From Allowlist

**Severity**: Medium
**Contract**: `BaseAuction.sol`
**Function**: `_setAssetOut()`
**Lines**: L500-L516

**Description**:
When changing the `assetOut`, the old asset's params are deleted but it remains in the `s_allowlistedAssets` set:

```solidity
function _setAssetOut(address assetOut) private {
    _whenNoLiveAuctions();
    // ...
    s_assetOut = assetOut;
    delete s_assetParams[currentAssetOut];  // Params deleted
    // s_allowlistedAssets still contains currentAssetOut!
}
```

**Impact**:
- The old assetOut remains in the allowlist, meaning `checkUpkeep()` and `_liveAuctionExists()` iterate over it unnecessarily
- `checkUpkeep` skips it (decimals == 0) but gas is wasted
- If the old assetOut is re-configured as a regular auction asset, its params were deleted and need to be re-added
- The allowlist grows unboundedly if `setAssetOut` is called multiple times with different tokens

**Recommendation**:
Consider whether the old assetOut should be removed from the allowlist when `setAssetOut` is called, or document that the admin must manually clean up via `applyFeedInfoUpdates`.

---

### [M-03] `getAssetOutAmount` View Function Returns Values Based on Potentially Stale Prices

**Severity**: Medium
**Contract**: `BaseAuction.sol`
**Function**: `getAssetOutAmount()`
**Lines**: L749-L767

**Description**:
The external `getAssetOutAmount()` calls `_getAssetPrice(assetIn, false)` and `_getAssetOutAmount(..., false)` - both with `withValidation=false`. This means it can return amounts based on stale or zero prices without reverting:

```solidity
(uint256 assetInUsdPrice,,) = _getAssetPrice(assetIn, false);  // No validation
return _getAssetOutAmount(assetInParams, assetInUsdPrice, amount, timestamp - auctionStart, false);
```

**Impact**:
- Off-chain systems (CRE workflows, UIs, bots) relying on this function may receive incorrect price quotes
- The `AuctionBidder.bid()` no-solution path uses this function to set the approval amount (L78), which could be wrong if prices are stale (though the actual `bid()` would revert, no funds are lost)
- CowSwap order relayer workflow may post orders with incorrect prices to the CowSwap API

**Recommendation**:
Add a `withValidation` parameter to `getAssetOutAmount()`, or document clearly that the returned value may be based on stale data.

---

### [M-04] `WorkflowRouter.onReport` No Metadata Length Validation

**Severity**: Medium
**Contract**: `WorkflowRouter.sol`
**Function**: `onReport()`
**Lines**: L86-L118

**Description**:
The `onReport` function slices `metadata` without checking its length:

```solidity
bytes32 workflowId = bytes32(metadata[:32]);
```

If `metadata.length < 32`, this will revert with an unhelpful out-of-bounds error rather than a descriptive custom error.

Additionally, the function decodes `report` as `(address target, bytes data)` without validating the decoded `data` has at least 4 bytes for the selector extraction:

```solidity
(address target, bytes memory data) = abi.decode(report, (address, bytes));
bytes4 selector;
assembly ("memory-safe") {
    selector := mload(add(data, 32))
}
```

If `data.length < 4`, the selector read will include garbage bytes.

**Impact**:
- Malformed reports from the FORWARDER_ROLE cause unhelpful reverts
- Potential for selector mismatch with very short `data` payloads

**Recommendation**:
Add explicit length checks:
```solidity
if (metadata.length < 32) revert InvalidMetadata();
// After decode:
if (data.length < 4) revert InvalidCallData();
```

---

### [M-05] `transmit()` Verifies All Reports in Bulk But Processes Sequentially - Partial Failure Blocks All Updates

**Severity**: Medium
**Contract**: `PriceManager.sol`
**Function**: `transmit()`
**Lines**: L133-L183

**Description**:
`transmit()` verifies all reports atomically via `verifyBulk`, then processes each sequentially. If any single report has a stale `observationsTimestamp`, the entire batch fails:

```solidity
bytes[] memory verifiedReports = i_streamsVerifierProxy.verifyBulk(unverifiedReports, abi.encode(i_linkToken));
for (uint256 i; i < verifiedReports.length; ++i) {
    // ...
    if (report.observationsTimestamp < block.timestamp - feedInfo.stalenessThreshold) {
        revert Errors.StaleFeedData();  // ONE stale report blocks ALL
    }
    // ...
}
```

**Impact**:
- One stale Data Streams report prevents ALL price updates in the batch
- Critical prices (e.g., assetOut/LINK) cannot be updated because an unrelated asset's report is stale
- Combined with H-02, this can cascade into a complete system DoS

**Recommendation**:
Use try/catch or process each report independently, skipping stale ones:
```solidity
for (uint256 i; i < verifiedReports.length; ++i) {
    if (report.observationsTimestamp < block.timestamp - feedInfo.stalenessThreshold) {
        emit StaleReportSkipped(report.dataStreamsFeedId);
        continue;  // Skip instead of revert
    }
    // ... store price ...
}
```

---

### [M-06] Potential Price Discrepancy Between Data Streams and Data Feed Fallback Due to Different Decimal Handling

**Severity**: Medium
**Contract**: `PriceManager.sol`
**Function**: `_getAssetPrice()`
**Lines**: L372-L419

**Description**:
Data Streams prices use `feedInfo.dataStreamsFeedDecimals` (set at configuration time), while Data Feed prices use `feedInfo.usdDataFeed.decimals()` (queried at runtime):

```solidity
// Data Streams (in transmit):
uint8 feedDecimals = feedInfo.dataStreamsFeedDecimals;  // Stored value

// Data Feed fallback (in _getAssetPrice):
uint8 decimals = feedInfo.usdDataFeed.decimals();  // Runtime query
```

If the Data Feed contract is upgraded and its `decimals()` return value changes (e.g., from 8 to 18), the fallback price would be incorrectly scaled, potentially orders of magnitude off.

**Impact**:
- Price discontinuity when falling back from Data Streams to Data Feed
- Could result in auction prices that are significantly too high or too low
- Bidders could extract value or be overcharged during the fallback period

**Recommendation**:
Store the expected Data Feed decimals at configuration time and validate at query time:
```solidity
uint8 storedDecimals = feedInfo.dataFeedDecimals; // New stored field
uint8 currentDecimals = feedInfo.usdDataFeed.decimals();
if (storedDecimals != currentDecimals) revert DataFeedDecimalsMismatch();
```

---

## LOW SEVERITY / QA FINDINGS

### [L-01] `_liveAuctionExists()` Iterates Entire Allowlist - Gas Concern

**Contract**: `BaseAuction.sol`
**Lines**: L676-L683

The function iterates ALL allowlisted assets to check if any auction is live. As the allowlist grows, this becomes increasingly expensive. Called by `_whenNoLiveAuctions()` which gates configuration changes.

**Recommendation**: Maintain a counter of live auctions instead of iterating.

---

### [L-02] `checkUpkeep` Uses Stale Price For Balance USD Calculation When Price is Invalid

**Contract**: `BaseAuction.sol`
**Lines**: L248-L254

When checking if an auction should end due to low balance, `checkUpkeep` uses whatever price is returned (even stale) for the USD calculation, but gates the check behind `isPriceValid`:

```solidity
uint256 assetBalanceUsdValue = (assetBalance * assetPrice) / (10 ** assetParams.decimals);
if (
    auctionStart + assetParams.auctionDuration < block.timestamp
    || (isPriceValid && assetBalanceUsdValue < assetParams.minAuctionSizeUsd)
)
```

If the price is invalid, the balance-based end check is skipped, meaning an auction with dust balance but no valid price won't be flagged for ending until the duration expires.

---

### [L-03] `AuctionBidder.auctionCallback` Approves Exact `amountOut` But Doesn't Revoke After

**Contract**: `AuctionBidder.sol`
**Lines**: L97-L112

After the callback, the approval to the auction contract remains at `amountOut`. While `safeTransferFrom` in `bid()` will consume this approval, if the bid fails after the callback, the approval persists. The next `bid()` call overwrites it, so the risk is minimal.

---

### [L-04] `performUpkeep` Allows Ending Auctions Without Duration/Balance Validation

**Contract**: `BaseAuction.sol`
**Lines**: L359-L369

The trusted AUCTION_WORKER_ROLE can end any live auction without checking if the duration has elapsed or balance is below minimum. This is by design (documented as "forced endings") but should be noted as a trust assumption.

---

### [L-05] `_applyAssetParamsUpdates` Skips Price Multiplier Validation for AssetOut

**Contract**: `BaseAuction.sol`
**Lines**: L646-L658

When `asset == s_assetOut`, the `auctionDuration`, `startingPriceMultiplier`, and `endingPriceMultiplier` validations are skipped. While the assetOut is never auctioned (sent directly to receiver), setting zero multipliers creates confusing state.

---

### [L-06] `Caller._call` Does Not Validate Target is Not `address(0)`

**Contract**: `Caller.sol`
**Lines**: L21-L44

`_call` performs a low-level call without checking if `target` is `address(0)`. A call to the zero address succeeds with empty return data, which could mask misconfiguration errors.

---

### [L-07] `WorkflowRouter` Selector Storage Uses `bytes32` for `bytes4` Values

**Contract**: `WorkflowRouter.sol`
**Lines**: L283, L316-L318

Function selectors (4 bytes) are stored in `EnumerableSet.Bytes32Set`. The assembly cast:
```solidity
assembly ("memory-safe") {
    selectors := allowlistedSelectors
}
```
Works because both are 32-byte memory slots, but the upper 28 bytes of each Bytes32Set entry are always zero. This wastes storage space.

---

## INFORMATIONAL FINDINGS

### [I-01] Trust Model Centralization Risks

The following trusted roles have significant power:
- **PRICE_ADMIN_ROLE**: Can manipulate prices within Data Streams verification constraints
- **AUCTION_WORKER_ROLE**: Can force-end any live auction, can choose which assets to include in `performUpkeep`
- **DEFAULT_ADMIN_ROLE**: Full control over all configuration
- **FORWARDER_ROLE**: Controls all data flowing through WorkflowRouter

All critical roles are granted to the WorkflowRouter (except DEFAULT_ADMIN). A compromise of the CRE forwarder would give broad system control.

### [I-02] No Events Emitted for Price Fallback Usage

When `_getAssetPrice` falls back from Data Streams to Data Feed, no event is emitted. Monitoring systems have no on-chain signal that the primary price source became stale.

### [I-03] `minBidUsdValue` Type Limitation

`s_minBidUsdValue` is `uint88`, capping at ~309,485 with 18 decimals (~$309k). For high-value auctions, this may be insufficient.

---

## Invariant Analysis

### Core Invariant: Auction Curve Price Floor
**Status: HOLDS**

The price multiplier formula:
```
priceMultiplier = start - mulDiv((start - end) * elapsed, duration)
```

Using `mulDiv` (rounds DOWN) for the subtracted term means less is subtracted → higher multiplier → bidder pays more. The multiplier is bounded between `startingPriceMultiplier` and `endingPriceMultiplier`, which is >= `i_minPriceMultiplier`. The invariant holds for both `bid()` and `isValidSignature()`.

### Rounding Direction: Protocol-Favorable
**Status: HOLDS**

All critical math uses `mulDivUp` and `mulWadUp` in `_getAssetOutAmount`, ensuring the bidder always pays at least the fair curve price (rounded up).

### Reentrancy Protection
**Status: HOLDS**

The `s_entered` flag prevents re-entry to `bid()` and `isValidSignature()` during callback execution. Access control prevents callback-based calls to `performUpkeep` or `transmit`.

---

## Recommendations Summary

| Priority | Finding | Recommendation |
|----------|---------|----------------|
| Critical | H-01 | Add `minBidUsdValue` check to `isValidSignature` |
| Critical | H-02 | Separate auction start/end processing or add per-asset error handling |
| High | H-03 | Reduce CowSwap approval after direct bids |
| Medium | M-01 | Add `maxAssetOutAmount` slippage parameter to `bid()` |
| Medium | M-05 | Skip stale reports in `transmit()` instead of reverting |
| Low | Multiple | Various gas optimizations and validation improvements |
