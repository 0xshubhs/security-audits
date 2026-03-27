# PriceManager Security Audit Findings

**Auditor**: Security Research
**Date**: 2026-03-27
**Scope**: PriceManager.sol, BaseAuction.sol, and related interfaces/libraries
**Protocol**: Chainlink Payment Abstraction V2

---

## Table of Contents

| ID | Title | Severity |
|----|-------|----------|
| H-01 | Data Streams `dataStreamsFeedDecimals` is not validated against the actual feed decimals, enabling price inflation/deflation | High |
| H-02 | Data Streams report `expiresAt` and `validFromTimestamp` fields are never checked, allowing expired/premature reports | High |
| M-01 | Stale Data Streams price can be replayed with an older `observationsTimestamp` to overwrite a fresher price | Medium |
| M-02 | Fallback data feed `latestRoundData` return values lack `roundId` and `answeredInRound` validation | Medium |
| M-03 | `_getAssetPrice` fallback logic uses a strict `<` comparison for timestamp tie-breaking, silently preferring stale Data Streams price over fresher Data Feed price | Medium |
| M-04 | Price scaled to zero after division for high-decimal feeds passes the zero check only after truncation, losing precision | Medium |
| M-05 | No upper bound on `stalenessThreshold` allows effectively disabling staleness protection | Medium |
| L-01 | `transmit()` performs allowlist check on unverified report data that can differ from verified report data | Low |
| L-02 | Feed configuration allows `dataStreamsFeedDecimals` to be set for a Data-Feed-only asset, creating an unused/misleading parameter | Low |
| L-03 | `_getAssetPrice` underflows if `block.timestamp < feedInfo.stalenessThreshold` (early deployment edge case) | Low |
| L-04 | No L2 sequencer uptime check despite the comment acknowledging the need | Low |
| QA-01 | Missing event emission when Data Streams price falls back to Data Feed price | QA |
| QA-02 | `transmit()` does not validate that `unverifiedReports` and `verifiedReports` arrays have the same length | QA |
| QA-03 | `DataStreamsPriceInfo.timestamp` is `uint32` and will overflow in year 2106 | QA |

---

## [H-01] Data Streams `dataStreamsFeedDecimals` is not validated against the actual feed decimals, enabling price inflation/deflation

**Severity**: High
**Contract**: PriceManager.sol
**Function**: `_applyFeedInfoUpdates()`, `transmit()`
**Lines**: L233-L302 (configuration), L155-L182 (transmit)

**Description**:
When configuring a feed via `_applyFeedInfoUpdates()`, the `dataStreamsFeedDecimals` parameter is accepted as a raw user-supplied `uint8` value. The only validation is that it is not zero (L253). Unlike the Chainlink Data Feed fallback path where `feedInfo.usdDataFeed.decimals()` is called on-chain to get the actual decimals (L394), the Data Streams `dataStreamsFeedDecimals` is entirely trusted from the admin-supplied configuration.

In `transmit()`, this admin-specified `dataStreamsFeedDecimals` is used to scale the price to 18 decimals (L167-L172):

```solidity
uint8 feedDecimals = feedInfo.dataStreamsFeedDecimals;
if (feedDecimals < PRICE_DECIMALS) {
    usdPrice = (usdPrice * 10 ** (PRICE_DECIMALS - feedDecimals));
} else if (feedDecimals > PRICE_DECIMALS) {
    usdPrice = (usdPrice / 10 ** (feedDecimals - PRICE_DECIMALS));
}
```

If `dataStreamsFeedDecimals` is set incorrectly -- for example, set to 8 when the actual Data Streams feed reports in 18 decimals -- the price will be scaled up by `10^10`, inflating it by 10 billion times. Conversely, setting it too high will truncate the price down.

There is no on-chain mechanism to validate the `dataStreamsFeedDecimals` against the actual Data Streams report's precision because Data Streams feeds do not expose a `decimals()` getter like Aggregator feeds do. This creates a critical single point of misconfiguration failure.

**Impact**:
An incorrect `dataStreamsFeedDecimals` configuration (whether by admin error or a compromised ASSET_ADMIN) directly distorts all price calculations downstream. In the auction system (BaseAuction), this would cause:
- **Inflated prices**: Bidders receive far fewer assets than they should for their payment (protocol profits unjustly)
- **Deflated prices**: Bidders receive far more assets than they should (protocol loses funds)

Since `ASSET_ADMIN_ROLE` can update feed info at any time (outside of live auctions), a single misconfiguration transaction immediately impacts all subsequent auctions for that asset.

**Proof of Concept**:
1. ASSET_ADMIN configures asset WETH with `dataStreamsFeedDecimals = 8` (incorrect; actual Data Streams feed uses 18 decimals)
2. PRICE_ADMIN transmits a Data Streams report with `price = 4000e18` (4000 USD in 18 decimals)
3. In `transmit()`, `feedDecimals = 8 < 18`, so: `usdPrice = 4000e18 * 10^10 = 4000e28`
4. This inflated price is stored and used in auction calculations
5. Bidders attempting to buy WETH in the auction would need to pay `10^10` times too much assetOut, or the auction pricing becomes nonsensical

**Recommendation**:
Since Data Streams feeds do not expose an on-chain decimals getter, consider one or more of the following mitigations:
1. Add a two-step configuration process with a timelock for feed info changes, giving time for off-chain monitoring to detect misconfigurations
2. Add a sanity check that compares the `dataStreamsFeedDecimals` against the corresponding `usdDataFeed.decimals()` when both are configured (they typically report in the same precision)
3. Add a reasonable bounds check on the resulting scaled price (e.g., ensure it falls within a plausible range relative to the data feed price)

---

## [H-02] Data Streams report `expiresAt` and `validFromTimestamp` fields are never checked, allowing expired/premature reports

**Severity**: High
**Contract**: PriceManager.sol
**Function**: `transmit()`
**Lines**: L155-L182

**Description**:
The `ReportV3` struct contains three temporal fields:
- `validFromTimestamp` (L59): Start timestamp of price validity period
- `observationsTimestamp` (L60): End timestamp of price validity period
- `expiresAt` (L63): Timestamp when this report expires

In `transmit()`, only `observationsTimestamp` is validated against `stalenessThreshold` (L162). The `expiresAt` and `validFromTimestamp` fields are completely ignored.

This means:
1. A report that has already expired (`expiresAt < block.timestamp`) can still be accepted and its price stored
2. A report whose validity period has not yet started (`validFromTimestamp > block.timestamp`) can be accepted
3. The `observationsTimestamp` staleness check alone is insufficient because a report could have `observationsTimestamp` within the staleness window but `expiresAt` in the past

**Impact**:
- **Expired reports**: A PRICE_ADMIN (or the automation system calling via WorkflowRouter) could submit reports that the Data Streams network considers expired. Since the VerifierProxy only validates the cryptographic signature (not temporal validity), the expired price gets stored and used for auction calculations.
- **Premature reports**: Reports with future `validFromTimestamp` could be accepted before their intended validity window, potentially using a price that was calculated under different market conditions.
- In volatile markets, using an expired report's price (even one that passes the staleness check) could result in materially incorrect auction pricing, as the actual market may have moved significantly since the report's `expiresAt` time.

**Proof of Concept**:
1. At time T=1000, a Data Streams report is generated with:
   - `validFromTimestamp = 900`
   - `observationsTimestamp = 950`
   - `expiresAt = 1000`
   - `price = 4000e18`
2. PRICE_ADMIN holds the report and submits it at T=1500
3. If `stalenessThreshold = 3600` (1 hour), the check `950 < 1500 - 3600` evaluates to `950 < -2100` which, due to unsigned underflow considerations is actually fine (no underflow because both sides are uint256 and 1500 > 3600 would underflow -- but in practice stalenessThreshold would be configured so this doesn't underflow. With a real scenario: stalenessThreshold=3600, blockTimestamp=4550, check: 950 < 4550-3600 = 950 < 950, which is false, so it passes)
4. The expired report's price is accepted and stored despite `expiresAt=1000` having long passed

**Recommendation**:
Add validation for `expiresAt` and `validFromTimestamp`:
```solidity
if (block.timestamp > report.expiresAt) {
    revert Errors.StaleFeedData();
}
if (block.timestamp < report.validFromTimestamp) {
    revert Errors.PrematureReport();
}
```

---

## [M-01] Stale Data Streams price can be replayed with an older `observationsTimestamp` to overwrite a fresher price

**Severity**: Medium
**Contract**: PriceManager.sol
**Function**: `transmit()`
**Lines**: L155-L182

**Description**:
The `transmit()` function does not check whether the new report's `observationsTimestamp` is more recent than the currently stored `s_dataStreamsPrice[asset].timestamp`. It only checks that the report is not stale relative to the staleness threshold:

```solidity
if (report.observationsTimestamp < block.timestamp - feedInfo.stalenessThreshold) {
    revert Errors.StaleFeedData();
}
```

This means any report whose `observationsTimestamp` falls within the staleness window can overwrite a previously stored price, even if the previously stored price was more recent.

**Impact**:
A PRICE_ADMIN with access to multiple valid signed reports within the staleness window can selectively replay an older (but still within the staleness threshold) report to overwrite a more recent price. In the context of the auction:
- If the older report has a lower price, the bidder gets a discount on the auctioned asset
- If the older report has a higher price, the protocol extracts more value from bidders
- Since PRICE_ADMIN is described as potentially being an automation system (via WorkflowRouter), a compromised or malfunctioning automation node could submit older reports

For example, with a 1-hour staleness threshold, any report from the last hour could be used to overwrite the latest price. In volatile markets, prices can move significantly within an hour.

**Proof of Concept**:
1. At T=100, PRICE_ADMIN transmits report with `observationsTimestamp=100, price=4000e18`. Stored price: 4000e18 at T=100
2. At T=150, PRICE_ADMIN transmits report with `observationsTimestamp=150, price=4500e18`. Stored price: 4500e18 at T=150
3. At T=200, PRICE_ADMIN replays the first report (still within 1-hour staleness window): `observationsTimestamp=100, price=4000e18`
4. Since `100 >= 200 - 3600`, the staleness check passes, and the stored price is overwritten back to 4000e18 at T=100
5. Bidders now see a price ~11% lower than the actual market, getting a discount on auctioned assets

**Recommendation**:
Add a monotonicity check to ensure only newer prices are accepted:
```solidity
if (report.observationsTimestamp <= s_dataStreamsPrice[asset].timestamp) {
    revert Errors.StaleReport();
}
```

---

## [M-02] Fallback data feed `latestRoundData` return values lack `roundId` and `answeredInRound` validation

**Severity**: Medium
**Contract**: PriceManager.sol
**Function**: `_getAssetPrice()`
**Lines**: L385-L401

**Description**:
When the Data Streams price is stale and the fallback Chainlink Data Feed is used, `_getAssetPrice()` calls `latestRoundData()` but only uses the `answer` and `updatedAt` values:

```solidity
(, int256 answer,, uint256 dataFeedUpdatedAt,) = feedInfo.usdDataFeed.latestRoundData();
```

Standard Chainlink data feed best practices recommend validating:
1. `answer > 0` (handled implicitly via `toUint256()` which will revert on negative, and the `price == 0` check later)
2. `updatedAt > 0` (not checked -- a zero `updatedAt` from a misconfigured or uninitialized feed would pass)
3. `answeredInRound >= roundId` (not checked -- ensures the answer was provided in the current round and not carried over from a previous incomplete round)

The `answeredInRound` check is particularly important: if `answeredInRound < roundId`, it indicates the oracle has not updated its answer for the current round, and the price data may be stale or unreliable despite `updatedAt` appearing recent.

**Impact**:
Using stale or incomplete round data from a Chainlink data feed could result in incorrect pricing for auction operations. While the staleness threshold provides some protection, the `answeredInRound` issue is independent of time -- it indicates oracle consensus failure. In edge cases (e.g., during oracle network issues), a carried-over answer from a previous round could be used for auction pricing without detection.

**Proof of Concept**:
1. Data Streams price becomes stale (older than `stalenessThreshold`)
2. The Chainlink data feed enters a state where `roundId = 5` but `answeredInRound = 3` (oracle hasn't updated for 2 rounds)
3. `latestRoundData()` returns a potentially outdated `answer` from round 3 with a `dataFeedUpdatedAt` that may still be within the staleness window
4. `_getAssetPrice()` accepts this potentially stale answer without checking `answeredInRound`

**Recommendation**:
Add full validation of `latestRoundData` return values:
```solidity
(uint80 roundId, int256 answer,, uint256 dataFeedUpdatedAt, uint80 answeredInRound) =
    feedInfo.usdDataFeed.latestRoundData();
if (answeredInRound < roundId) {
    // Price data is stale/incomplete
    // Either skip this fallback or handle accordingly
}
if (dataFeedUpdatedAt == 0) {
    revert Errors.ZeroFeedData();
}
```

---

## [M-03] `_getAssetPrice` fallback logic uses a strict `<` comparison for timestamp tie-breaking, silently preferring stale Data Streams price over fresher Data Feed price

**Severity**: Medium
**Contract**: PriceManager.sol
**Function**: `_getAssetPrice()`
**Lines**: L380-L401

**Description**:
The fallback mechanism in `_getAssetPrice()` first checks if the Data Streams price is stale, then falls back to the Data Feed. It uses the "most recent" price between the two:

```solidity
// L390: Use the most recent timestamp between Data Streams and Data Feed
if (updatedAt < dataFeedUpdatedAt) {
    updatedAt = dataFeedUpdatedAt;
    price = answer.toUint256();
    // ... decimal scaling
}
```

The comparison uses strict `<`, meaning when both timestamps are equal (`updatedAt == dataFeedUpdatedAt`), the Data Streams price is preferred. This is the correct intent (as confirmed by the test on L199). However, the more subtle issue is the order of operations:

The fallback to the Data Feed is only triggered when `updatedAt < minTimestamp` (L385). But once triggered, it compares `updatedAt < dataFeedUpdatedAt`. If the Data Feed's `dataFeedUpdatedAt` is also stale but slightly less stale than the Data Streams timestamp, the Data Feed price is used. However, the `isValid` flag still correctly marks it as stale.

The real concern is that this fallback logic runs during `_getAssetPrice(asset, true)` (with validation), where both sources might have different prices and the selection is purely based on timestamp freshness, not price reasonableness. An attacker who can influence the Data Feed's `updatedAt` timestamp (e.g., by triggering a feed update at a specific time) could selectively ensure the Data Feed price is chosen over the Data Streams price.

**Impact**:
In scenarios where both Data Streams and Data Feed are near the staleness boundary, the price selection becomes sensitive to minor timestamp differences. An actor who understands the exact staleness thresholds and Data Feed update patterns could predict and potentially exploit which price source will be used for an auction bid.

**Proof of Concept**:
1. Asset has `stalenessThreshold = 3600`
2. Data Streams report has `observationsTimestamp = T-3601` (just barely stale), price = 4000e18
3. Data Feed returns `dataFeedUpdatedAt = T-3599` (just barely fresh), price = 3800e18
4. Since Data Streams is stale (`T-3601 < T-3600`), fallback is triggered
5. Since `T-3601 < T-3599`, the Data Feed price (3800) is selected
6. The 5% price difference directly impacts auction economics

**Recommendation**:
Consider adding a deviation check between the two price sources when a fallback occurs. If the prices deviate significantly, it may indicate a manipulated or lagging feed:
```solidity
if (updatedAt < dataFeedUpdatedAt) {
    uint256 dataFeedPrice = answer.toUint256();
    // scale dataFeedPrice...
    // Check deviation
    uint256 deviation = dataFeedPrice > price
        ? (dataFeedPrice - price) * 1e18 / price
        : (price - dataFeedPrice) * 1e18 / dataFeedPrice;
    if (deviation > MAX_DEVIATION) {
        // Handle divergence
    }
    updatedAt = dataFeedUpdatedAt;
    price = dataFeedPrice;
}
```

---

## [M-04] Price scaled to zero after division for high-decimal feeds passes the zero check only after truncation, losing precision

**Severity**: Medium
**Contract**: PriceManager.sol
**Function**: `transmit()`
**Lines**: L166-L176

**Description**:
In `transmit()`, when a Data Streams feed has more than 18 decimals, the price is scaled down by division:

```solidity
} else if (feedDecimals > PRICE_DECIMALS) {
    usdPrice = (usdPrice / 10 ** (feedDecimals - PRICE_DECIMALS));
}
```

The zero check occurs after the scaling:

```solidity
if (usdPrice == 0) {
    revert Errors.ZeroFeedData();
}
```

For feeds with very high decimals (e.g., 24 decimals), small but valid prices could be truncated to zero during the division. For example, a legitimate price of `999999` in a 24-decimal feed would be divided by `10^6`, yielding `0` after integer truncation. The zero check catches this, but it means the `transmit()` transaction reverts entirely, potentially blocking price updates for other assets in the same batch.

More importantly, in the fallback path (`_getAssetPrice()` L398-L399), the same scaling is applied to Data Feed prices:
```solidity
} else if (decimals > PRICE_DECIMALS) {
    price = (price / 10 ** (decimals - PRICE_DECIMALS));
}
```

Here, if the division truncates a small-but-valid price to zero, and `withValidation` is false (as in `getAssetPrice()` or `checkUpkeep()`), the function returns `price = 0` and `isValid = false` without reverting. This could silently cause auction operations to use a zero price.

**Impact**:
- In `transmit()`: Reverting on a zero price after truncation could block batch price updates for multiple assets if one asset has a very small legitimate price in a high-decimal feed.
- In `_getAssetPrice()` without validation: A zero price after truncation leads to `isValid = false`, which could prevent auction starts for legitimate assets, or in `checkUpkeep()`, cause incorrect USD value calculations (`assetBalance * 0 = 0`).

**Proof of Concept**:
1. Configure a feed with `dataStreamsFeedDecimals = 24`
2. Data Streams report arrives with `price = 500000` (a valid small price in 24-decimal notation, representing 0.0000000000000000005 USD)
3. Scaling: `500000 / 10^6 = 0` (integer truncation)
4. In `transmit()`: reverts with `ZeroFeedData`, blocking the entire batch
5. In `_getAssetPrice()` fallback with `withValidation = false`: returns `price = 0, isValid = false`

**Recommendation**:
For `transmit()`, consider checking for zero price before scaling, or scale using a different method that detects precision loss:
```solidity
if (report.price == 0) {
    revert Errors.ZeroFeedData();
}
uint256 usdPrice = int256(report.price).toUint256();
// Scale after initial zero check
```

Also consider whether rounding up instead of truncating is more appropriate for the division case, or add a minimum price threshold that accounts for decimal scaling.

---

## [M-05] No upper bound on `stalenessThreshold` allows effectively disabling staleness protection

**Severity**: Medium
**Contract**: PriceManager.sol
**Function**: `_applyFeedInfoUpdates()`
**Lines**: L243-L248

**Description**:
The `stalenessThreshold` in `FeedInfo` is a `uint32`, which has a maximum value of ~4.29 billion seconds (~136 years). The only validation is that it is not zero (L244). An ASSET_ADMIN could set it to `type(uint32).max`, effectively disabling all staleness checks, since `block.timestamp - type(uint32).max` would underflow (in unchecked math) or always be less than any `updatedAt`.

In practice, even setting it to a very large but more "reasonable" value like `365 days` would mean prices up to a year old are considered valid, which defeats the purpose of freshness checks in a trading/auction context.

**Impact**:
Without an upper bound, an excessively large `stalenessThreshold` would:
1. Accept extremely old Data Streams reports in `transmit()`
2. Accept extremely old Data Feed prices in `_getAssetPrice()` fallback
3. Report old prices as `isValid = true`
4. Allow auctions to proceed with outdated pricing, causing incorrect asset valuations

**Proof of Concept**:
1. ASSET_ADMIN sets `stalenessThreshold = type(uint32).max` (4294967295 seconds)
2. A Data Streams price from 1 year ago is still in storage with `timestamp = T - 31536000`
3. Staleness check: `T - 31536000 >= T - 4294967295` is true, so the year-old price is considered valid
4. Auction starts with a year-old price, which could be orders of magnitude different from the current market

**Recommendation**:
Add a maximum staleness threshold constant and validate against it:
```solidity
uint32 constant MAX_STALENESS_THRESHOLD = 1 days; // or appropriate value

if (feedInfo.stalenessThreshold > MAX_STALENESS_THRESHOLD) {
    revert InvalidStalenessThreshold();
}
```

---

## [L-01] `transmit()` performs allowlist check on unverified report data that can differ from verified report data

**Severity**: Low
**Contract**: PriceManager.sol
**Function**: `transmit()`
**Lines**: L140-L153

**Description**:
The `transmit()` function has two loops. The first loop (L140-L150) decodes the `dataStreamsFeedId` from the *unverified* report data and checks the allowlist. The second loop (L155-L182) processes the *verified* report data returned by `verifyBulk()`.

```solidity
// First loop: decode from unverified data
(, bytes memory reportData,,,) =
    abi.decode(unverifiedReports[i], (bytes32[3], bytes, bytes32[], bytes32[], bytes32));
bytes32 dataStreamsFeedId = bytes32(reportData);

if (s_dataStreamsFeedIdToAsset[dataStreamsFeedId] == address(0)) {
    revert FeedNotAllowlisted(dataStreamsFeedId);
}

// ... later ...

// Second loop: decode from verified data
ReportV3 memory report = abi.decode(verifiedReports[i], (ReportV3));
address asset = s_dataStreamsFeedIdToAsset[report.dataStreamsFeedId];
```

The unverified report data that is checked in the first loop is the raw input before cryptographic verification. The `verifyBulk()` function is trusted (per the scope -- "the actual cryptographic verification of the submitted reports is delegated to an external contract which is not in scope"), but there is no guarantee that the feed ID extracted from unverified data matches the feed ID in the verified data.

In the normal case, `verifyBulk` would reject reports with tampered data (the cryptographic signature covers the report content). However, this creates a disconnect: the allowlist check validates one set of data, while the price storage uses another. If `verifyBulk` has any edge case where the verified output differs from the input's embedded data (e.g., report transformation, version differences), the allowlist check could be bypassed.

**Impact**:
In practice, since the VerifierProxy's cryptographic verification should ensure data integrity, this is a defense-in-depth concern. However, the pattern of checking unverified data and then acting on different verified data is a code smell that could become exploitable if the VerifierProxy behavior changes.

**Proof of Concept**:
1. Attacker constructs an unverified report where the raw `reportData` starts with an allowlisted `dataStreamsFeedId`
2. The same unverified report, when verified by `verifyBulk()`, produces a verified report with a different `dataStreamsFeedId`
3. The first loop's allowlist check passes, but the second loop processes a non-allowlisted feed
4. `s_dataStreamsFeedIdToAsset[report.dataStreamsFeedId]` returns `address(0)`, so `asset = address(0)`, and the price is stored for the zero address

**Recommendation**:
Add an allowlist check in the second loop as well, or move the entire allowlist check to after verification:
```solidity
for (uint256 i; i < verifiedReports.length; ++i) {
    ReportV3 memory report = abi.decode(verifiedReports[i], (ReportV3));
    address asset = s_dataStreamsFeedIdToAsset[report.dataStreamsFeedId];
    if (asset == address(0)) {
        revert FeedNotAllowlisted(report.dataStreamsFeedId);
    }
    // ... rest of processing
}
```

---

## [L-02] Feed configuration allows `dataStreamsFeedDecimals` to be set for a Data-Feed-only asset, creating an unused/misleading parameter

**Severity**: Low
**Contract**: PriceManager.sol
**Function**: `_applyFeedInfoUpdates()`
**Lines**: L243-L299

**Description**:
When `dataStreamsFeedId == bytes32(0)` (i.e., the asset is configured to use only the Chainlink Data Feed without Data Streams), the `dataStreamsFeedDecimals` field is still accepted and stored in `s_feedInfo`. The validation at L253 only checks `dataStreamsFeedDecimals` when `dataStreamsFeedId != bytes32(0)`:

```solidity
if (feedInfo.dataStreamsFeedId != bytes32(0)) {
    if (feedInfo.dataStreamsFeedDecimals == 0) {
        revert InvalidFeedDecimals(dataStreamsFeedId);
    }
    // ...
}
```

This means an admin could configure:
```solidity
FeedInfo({
    dataStreamsFeedId: bytes32(0),        // No Data Streams
    usdDataFeed: someAggregator,          // Data Feed only
    dataStreamsFeedDecimals: 42,          // Nonsensical but accepted
    stalenessThreshold: 3600
})
```

**Impact**:
The unused `dataStreamsFeedDecimals` does not directly cause harm since it is only used when Data Streams prices are processed. However, it could mislead future configuration changes -- if a Data Streams feed is later added for this asset, the stale `dataStreamsFeedDecimals` from the previous configuration could be incorrectly carried over or create confusion.

**Recommendation**:
When `dataStreamsFeedId == bytes32(0)`, enforce that `dataStreamsFeedDecimals == 0` to avoid storing misleading configuration data.

---

## [L-03] `_getAssetPrice` underflows if `block.timestamp < feedInfo.stalenessThreshold` (early deployment edge case)

**Severity**: Low
**Contract**: PriceManager.sol
**Function**: `_getAssetPrice()`
**Lines**: L378

**Description**:
The staleness boundary is computed as:

```solidity
uint256 minTimestamp = block.timestamp - feedInfo.stalenessThreshold;
```

If the contract is deployed very early (e.g., on a test chain where `block.timestamp` is small) and `stalenessThreshold` is large (e.g., 1 day = 86400), then `block.timestamp - stalenessThreshold` would underflow. In Solidity 0.8.x, this would cause a revert due to the arithmetic underflow check.

Similarly, in `transmit()` at L162:
```solidity
if (report.observationsTimestamp < block.timestamp - feedInfo.stalenessThreshold) {
```

This would also revert due to underflow.

**Impact**:
On mainnet, this is practically a non-issue because `block.timestamp` is well above any reasonable `stalenessThreshold`. However, on testnets, local forks, or chains with custom timestamp handling, this could cause the contract to be unusable immediately after deployment. The BaseUnitTest explicitly calls `skip(1 weeks)` in the constructor (BaseUnitTest.t.sol L53) to avoid this.

**Proof of Concept**:
1. Deploy the contract on a local chain where `block.timestamp = 100`
2. Configure `stalenessThreshold = 86400` (1 day)
3. Call `_getAssetPrice()`: `100 - 86400` underflows, reverting the transaction
4. All price queries and auction operations are blocked until `block.timestamp > stalenessThreshold`

**Recommendation**:
Use a safe subtraction that floors at zero:
```solidity
uint256 minTimestamp = block.timestamp > feedInfo.stalenessThreshold
    ? block.timestamp - feedInfo.stalenessThreshold
    : 0;
```

---

## [L-04] No L2 sequencer uptime check despite the comment acknowledging the need

**Severity**: Low
**Contract**: PriceManager.sol
**Function**: `_getAssetPrice()`
**Lines**: L362-L363

**Description**:
The NatSpec comment on `_getAssetPrice()` states:

```solidity
/// @dev This function is virtual as some additional checks may be warranted on certain chains, e.g.
/// sequencer uptime checks on L2s.
```

The function is marked `virtual`, implying that L2 deployments should override it with sequencer uptime checks. However, there is no concrete implementation in the codebase for any L2 chain, and if the base `PriceManager` or `BaseAuction` is deployed directly on an L2 (Arbitrum, Optimism, etc.) without this override, no sequencer uptime check would be performed.

**Impact**:
On L2 chains, when the sequencer goes down and comes back up, there is a brief window where Chainlink data feed prices may be stale but appear fresh (because `updatedAt` reflects the last update before the downtime). Without a sequencer uptime check, auctions could use stale prices during this recovery period. This is a well-known issue documented by Chainlink themselves.

**Recommendation**:
For any L2 deployment, implement the override with the Chainlink sequencer uptime feed check. Additionally, consider adding a deployment check or initializer that enforces sequencer feed configuration on known L2 chains.

---

## [QA-01] Missing event emission when Data Streams price falls back to Data Feed price

**Severity**: QA
**Contract**: PriceManager.sol
**Function**: `_getAssetPrice()`
**Lines**: L385-L401

**Description**:
When the Data Streams price is stale and the function falls back to the Chainlink Data Feed, no event is emitted to indicate this fallback occurred. The `PriceTransmitted` event is only emitted during `transmit()` for Data Streams prices.

Off-chain monitoring systems that rely on events to track price updates would not be able to detect when the fallback path is being used, making it harder to identify situations where Data Streams are consistently stale.

**Recommendation**:
This is a view function, so events cannot be emitted. Consider adding a getter that returns the current price source (Data Streams vs Data Feed) for monitoring purposes, or emit a diagnostic event in `transmit()` when a Data Streams price is detected as stale before the fallback.

---

## [QA-02] `transmit()` does not validate that `unverifiedReports` and `verifiedReports` arrays have the same length

**Severity**: QA
**Contract**: PriceManager.sol
**Function**: `transmit()`
**Lines**: L140-L182

**Description**:
The `transmit()` function iterates over `unverifiedReports` in the first loop and `verifiedReports` in the second loop. There is no explicit check that `verifiedReports.length == unverifiedReports.length`. If the `verifyBulk()` call returns fewer verified reports than the number of unverified reports sent (e.g., if some reports fail verification silently), the second loop would process fewer reports than expected, potentially missing price updates.

Conversely, if `verifyBulk()` returns more reports than sent (highly unlikely but theoretically possible with a malicious VerifierProxy), extra iterations would be processed.

**Impact**:
Given that the VerifierProxy is out of scope and trusted, this is a defensive coding concern. The practical risk is very low, but the asymmetry between the two loops creates a subtle inconsistency.

**Recommendation**:
Add an assertion after `verifyBulk()`:
```solidity
if (verifiedReports.length != unverifiedReports.length) {
    revert ReportLengthMismatch();
}
```

---

## [QA-03] `DataStreamsPriceInfo.timestamp` is `uint32` and will overflow in year 2106

**Severity**: QA
**Contract**: PriceManager.sol
**Lines**: L86

**Description**:
The `DataStreamsPriceInfo.timestamp` field is stored as `uint32`, which has a maximum value of 4,294,967,295 (corresponding to February 7, 2106). While this is far in the future, using `uint32` for timestamps in new protocol development is a known anti-pattern given that many protocols aim for long-term operation. The `ReportV3` struct also uses `uint32` for its timestamp fields, which is dictated by the Data Streams specification. However, the storage struct is under the protocol's control.

**Impact**:
No practical impact in the foreseeable future. This is a code quality observation.

**Recommendation**:
If gas savings from the `uint32` packing are not critical, consider using `uint48` or `uint64` for the stored timestamp. Given that `usdPrice` is `uint224`, a `uint32` timestamp gives perfect 256-bit slot packing, so the current design is gas-optimal and the `uint32` choice is justified for the next 80 years.
