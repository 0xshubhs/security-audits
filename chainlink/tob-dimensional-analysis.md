# Dimensional Analysis: Chainlink Payment Abstraction V2

**Auditor:** Trail of Bits Dimensional Analysis Skill
**Date:** 2026-03-28
**Scope:** `BaseAuction.sol`, `PriceManager.sol`, `GPV2CompatibleAuction.sol`

---

## Unit System Reference

| Symbol | Meaning | Example |
|---|---|---|
| `USD_18` | USD value with 18 decimals | `1e18` = $1.00 |
| `ASSET_N` | Asset amount with N decimals (varies per token) | USDC: N=6, WETH: N=18 |
| `LINK_18` | LINK amount with 18 decimals | `1e18` = 1 LINK |
| `MULTIPLIER_18` | Price multiplier, 18 decimal fixed-point | `1.1e18` = 110% |
| `PRICE_18` | USD price per 1 whole token, 18 decimals | `2000e18` = $2000 |
| `SECONDS` | Time in seconds | `3600` = 1 hour |
| `DIMENSIONLESS` | Pure scalar | `10 ** N` |

### Library Semantics (Solady FixedPointMathLib)

| Function | Formula | Unit Behavior |
|---|---|---|
| `mulDiv(x, y, d)` | `floor(x * y / d)` | `[x] * [y] / [d]` |
| `mulDivUp(x, y, d)` | `ceil(x * y / d)` | `[x] * [y] / [d]` |
| `mulWad(x, y)` | `floor(x * y / 1e18)` | `[x] * [y] / WAD` |
| `mulWadUp(x, y)` | `ceil(x * y / 1e18)` | `[x] * [y] / WAD` |

---

## 1. `_getAssetOutAmount` (BaseAuction.sol L777-803)

This is the core pricing function. It converts an `amountIn` of an auctioned asset into an equivalent `assetOutAmount` at the current auction price.

### 1.1 Price Multiplier Calculation (L793-795)

```solidity
uint256 priceMultiplier = assetInParams.startingPriceMultiplier
  - uint256(assetInParams.startingPriceMultiplier - assetInParams.endingPriceMultiplier)
    .mulDiv(elapsedTime, assetInParams.auctionDuration);
```

**Dimensional trace:**

| Expression | Type | Unit |
|---|---|---|
| `startingPriceMultiplier` | `uint64` | `MULTIPLIER_18` |
| `endingPriceMultiplier` | `uint64` | `MULTIPLIER_18` |
| `startingPriceMultiplier - endingPriceMultiplier` | `uint64` (cast to `uint256`) | `MULTIPLIER_18` |
| `elapsedTime` | `uint256` | `SECONDS` |
| `auctionDuration` | `uint24` | `SECONDS` |
| `.mulDiv(elapsedTime, auctionDuration)` | `uint256` | `MULTIPLIER_18 * SECONDS / SECONDS = MULTIPLIER_18` |
| `startingPriceMultiplier - [result]` | `uint256` | `MULTIPLIER_18 - MULTIPLIER_18 = MULTIPLIER_18` |

**Result: CONSISTENT.** The `priceMultiplier` is correctly `MULTIPLIER_18`.

**Precision note:** `startingPriceMultiplier` and `endingPriceMultiplier` are stored as `uint64`. Max `uint64` = ~18.44e18. Since these represent multipliers around 1e18 (e.g., `1.1e18`, `0.98e18`), the max representable multiplier is ~18.44x. This is more than sufficient. The subtraction `start - end` fits in uint64 and the cast to uint256 before `mulDiv` prevents overflow in the intermediate multiplication. **No issue.**

### 1.2 Auction USD Value (L799)

```solidity
uint256 auctionUsdValue = amountIn.mulDivUp(assetInUsdPrice, 10 ** assetInParams.decimals).mulWadUp(priceMultiplier);
```

**Step 1: `amountIn.mulDivUp(assetInUsdPrice, 10 ** assetInParams.decimals)`**

| Expression | Unit |
|---|---|
| `amountIn` | `ASSET_N` (N = assetInParams.decimals) |
| `assetInUsdPrice` | `PRICE_18` (USD per 1 whole token, 18 decimals) |
| `10 ** assetInParams.decimals` | `DIMENSIONLESS` (= 10^N) |
| Result | `ASSET_N * PRICE_18 / 10^N` |

Expanding the units:

```
ASSET_N = [raw amount] where 1 whole token = 10^N
PRICE_18 = [USD per whole token] * 10^18

Result = [raw_amount] * [USD_per_token * 10^18] / 10^N
       = [raw_amount / 10^N] * [USD_per_token] * 10^18
       = [# of whole tokens] * [USD_per_token] * 10^18
       = USD_18
```

**Result of Step 1: `USD_18`.** Correct.

**Step 2: `.mulWadUp(priceMultiplier)`**

| Expression | Unit |
|---|---|
| Input (from Step 1) | `USD_18` |
| `priceMultiplier` | `MULTIPLIER_18` |
| `mulWadUp` divides by `1e18` | Division by WAD |
| Result | `USD_18 * MULTIPLIER_18 / 1e18 = USD_18` |

Since `MULTIPLIER_18` is a dimensionless ratio scaled to 1e18, `mulWadUp` correctly de-scales:

```
USD_18 * MULTIPLIER_18 / WAD = USD_18 * (ratio * 1e18) / 1e18 = USD_18 * ratio
```

**Result of Step 2: `USD_18`.** Correct. `auctionUsdValue` is `USD_18`.

### 1.3 Final Conversion to Asset Out (L802)

```solidity
return auctionUsdValue.mulDivUp(10 ** s_assetParams[s_assetOut].decimals, assetOutUsdPrice);
```

| Expression | Unit |
|---|---|
| `auctionUsdValue` | `USD_18` |
| `10 ** s_assetParams[s_assetOut].decimals` | `DIMENSIONLESS` (= 10^M, where M = assetOut decimals) |
| `assetOutUsdPrice` | `PRICE_18` |
| Result | `USD_18 * 10^M / PRICE_18` |

Expanding:

```
= [usd_value * 1e18] * 10^M / [usd_per_token * 1e18]
= [usd_value] * 10^M / [usd_per_token]
= [# of whole tokens] * 10^M
= ASSET_M
```

**Result: `ASSET_M` (asset out amount in native decimals).** Correct.

### 1.4 Rounding Direction Analysis

All three operations use rounding-up variants (`mulDivUp`, `mulWadUp`). This means the computed `assetOutAmount` will be **rounded up** at each step.

**FINDING [INFO-1]: Rounding favors the protocol (auction seller), not the bidder.**

The auction is selling `assetIn` and receiving `assetOut`. A higher `assetOutAmount` means the bidder pays **more** `assetOut` for the `assetIn` they receive. Rounding up all intermediate steps compounds to produce a slightly higher cost to the bidder. This is **intentional** — the protocol is the seller, so rounding in its favor is standard practice. However, with three chained rounding-up operations, in extreme edge cases (very small amounts with low-decimal tokens), the cumulative rounding could be up to 3 units of the smallest denomination.

---

## 2. `bid` Price Calculation (BaseAuction.sol L429-430)

```solidity
(uint256 assetPrice,,) = _getAssetPrice(asset, true);
uint256 bidUsdValue = (amount * assetPrice) / (10 ** assetParams.decimals);
```

**Dimensional trace:**

| Expression | Unit |
|---|---|
| `amount` | `ASSET_N` |
| `assetPrice` | `PRICE_18` (from `_getAssetPrice`, always scaled to 18 decimals) |
| `10 ** assetParams.decimals` | `DIMENSIONLESS` (= 10^N) |
| `amount * assetPrice` | `ASSET_N * PRICE_18` |
| `/ (10 ** assetParams.decimals)` | `/ 10^N` |
| Result | `ASSET_N * PRICE_18 / 10^N = USD_18` |

Expanding:

```
[raw_amount] * [usd_per_token * 1e18] / 10^N
= [raw_amount / 10^N] * [usd_per_token * 1e18]
= [# whole tokens] * USD_18
= USD_18
```

**Result: `USD_18`.** Correct. The `bidUsdValue` is in USD with 18 decimals.

**Comparison target:** `s_minBidUsdValue` is `uint88`, documented as "The minimum bid USD value in 18 decimals." Both sides are `USD_18`. **CONSISTENT.**

### 2.1 Rounding Direction

This uses plain Solidity `/` (truncation / round-down). This means the computed `bidUsdValue` is rounded **down**, making it slightly harder for a bid to pass the `minBidUsdValue` threshold. This is conservative / correct — prevents dust bids from being considered valid.

### 2.2 Potential Precision Loss

**FINDING [INFO-2]: Plain Solidity multiplication before division — intermediate overflow risk is mitigated by Solidity 0.8.26 checked arithmetic.**

The expression `amount * assetPrice` could theoretically overflow for very large token amounts. However:
- `amount` is bounded by `IERC20(asset).balanceOf(address(this))` (L437-439), which is limited by the token's total supply.
- `assetPrice` is `uint224` stored (L85 of PriceManager), cast from `int192` data stream report.
- The product fits in `uint256` as long as `amount * assetPrice < 2^256`. With `assetPrice` at most `uint224` (~2.7e67) and typical balances well below `uint256`, this is safe in practice.

**No overflow concern for realistic values.**

---

## 3. `checkUpkeep` Value Calculations (BaseAuction.sol L248, L258)

### 3.1 Asset Balance USD Value (L248)

```solidity
uint256 assetBalance = IERC20(asset).balanceOf(address(this));
uint256 assetBalanceUsdValue = (assetBalance * assetPrice) / (10 ** assetParams.decimals);
```

**Dimensional trace:** Identical to Section 2.

| Expression | Unit |
|---|---|
| `assetBalance` | `ASSET_N` |
| `assetPrice` | `PRICE_18` |
| Result | `ASSET_N * PRICE_18 / 10^N = USD_18` |

**Result: `USD_18`.** Correct.

**Comparison:** `assetBalanceUsdValue < assetParams.minAuctionSizeUsd` (L251)

`minAuctionSizeUsd` is `uint96`, documented as "The minimum swap size expressed in USD feed decimals" (L136). However, the comment says "USD feed decimals" which is ambiguous.

**FINDING [PRECISION-1]: `minAuctionSizeUsd` comment says "USD feed decimals" but it is compared to `USD_18` values.**

Looking at the code: `assetBalanceUsdValue` is computed as `USD_18` (18 decimal places). For the comparison `assetBalanceUsdValue < assetParams.minAuctionSizeUsd` to be correct, `minAuctionSizeUsd` MUST also be in `USD_18` (18 decimals). The struct comment says "USD feed decimals" which could be interpreted as 8 decimals (typical Chainlink feed precision). However, since prices are explicitly normalized to 18 decimals throughout PriceManager (see `PRICE_DECIMALS = 18` at L92), and `minBidUsdValue` is explicitly documented as "18 decimals" (L44, L158), `minAuctionSizeUsd` must also be in 18 decimals for the comparison to be dimensionally correct.

**Verdict:** The comment is misleading but the code is **CONSISTENT** assuming `minAuctionSizeUsd` is configured in `USD_18`. If an operator misconfigures it in 8-decimal format (reading the comment literally), all USD thresholds would be wrong by a factor of 10^10. This is a **documentation/config risk**, not a code bug.

### 3.2 Available Asset USD Value (L258)

```solidity
uint256 availableBalance = IERC20(asset).balanceOf(feeAggregator);
uint256 availableAssetUsdValue = (availableBalance * assetPrice) / (10 ** assetParams.decimals);
```

Same pattern. **Result: `USD_18`.** Correct. Comparison to `assetParams.minAuctionSizeUsd` at L261 is consistent (assuming both are `USD_18`).

### 3.3 `performUpkeep` USD Value (L344)

```solidity
uint256 availableAssetUsdValue = (eligibleAssets[i].amount * assetPrice) / (10 ** assetDecimals);
```

Same formula. **Result: `USD_18`.** Correct.

---

## 4. `transmit` Price Scaling (PriceManager.sol L167-172)

```solidity
uint8 feedDecimals = feedInfo.dataStreamsFeedDecimals;
if (feedDecimals < PRICE_DECIMALS) {
    usdPrice = (usdPrice * 10 ** (PRICE_DECIMALS - feedDecimals));
} else if (feedDecimals > PRICE_DECIMALS) {
    usdPrice = (usdPrice / 10 ** (feedDecimals - PRICE_DECIMALS));
}
```

**Dimensional trace:**

| Expression | Unit | Value |
|---|---|---|
| `usdPrice` (before) | `PRICE_feedDecimals` | Price with `feedDecimals` decimal places |
| `PRICE_DECIMALS` | `DIMENSIONLESS` | `18` |
| `10 ** (PRICE_DECIMALS - feedDecimals)` | `DIMENSIONLESS` | Scaling factor |

**Case 1: `feedDecimals < 18` (e.g., feedDecimals = 8, the common case)**

```
usdPrice_new = usdPrice_old * 10^(18 - 8) = usdPrice_old * 10^10
```

This scales from 8-decimal precision to 18-decimal precision. **Correct.**

**Case 2: `feedDecimals > 18` (uncommon)**

```
usdPrice_new = usdPrice_old / 10^(feedDecimals - 18)
```

This truncates precision from feedDecimals to 18. **Correct but lossy** (round-down truncation).

**Case 3: `feedDecimals == 18`**

No scaling needed. `usdPrice` is already `PRICE_18`. **Correct.**

**Result: After scaling, `usdPrice` is always `PRICE_18`.** Correct.

**FINDING [INFO-3]: When `feedDecimals > 18`, the division truncates (rounds down), which could slightly undervalue the price. This is unlikely in practice since Data Streams feeds typically use 8 or 18 decimals.**

---

## 5. `_getAssetPrice` Data Feed Fallback (PriceManager.sol L394-400)

```solidity
uint8 decimals = feedInfo.usdDataFeed.decimals();

if (decimals < PRICE_DECIMALS) {
    price = (price * 10 ** (PRICE_DECIMALS - decimals));
} else if (decimals > PRICE_DECIMALS) {
    price = (price / 10 ** (decimals - PRICE_DECIMALS));
}
```

**Dimensional trace:** Identical pattern to Section 4 but sourced from a Chainlink Data Feed (`AggregatorV3Interface`) rather than Data Streams.

| Expression | Unit |
|---|---|
| `price` (before) | `PRICE_decimals` (typically 8 for Chainlink feeds) |
| `decimals` | Data feed's native precision (typically 8) |
| `PRICE_DECIMALS` | `18` |

**For typical 8-decimal Chainlink feeds:**

```
price_new = price_old * 10^(18 - 8) = price_old * 10^10
```

**Result: `PRICE_18`.** Correct.

**FINDING [INFO-4]: Data feed `decimals()` is read live from the on-chain contract, NOT from stored `feedInfo.dataStreamsFeedDecimals`. This is correct — the Data Streams feed decimals and the Data Feed decimals are independent configurations. However, there is no validation that the Data Feed's decimals match any stored value during `_applyFeedInfoUpdates`. If the Data Feed is upgraded to report different decimals, the live read will automatically adapt. This is a safe design choice.**

**FINDING [CRITICAL-NOTE]: The `dataStreamsFeedDecimals` field (stored in `FeedInfo`) is used only for Data Streams reports in `transmit()`. The Data Feed fallback reads decimals fresh from the on-chain contract. These are two independent decimal sources for two independent price sources. If they report different decimal bases for the same asset price (e.g., Data Streams uses 18 decimals, Data Feed uses 8), the normalization logic correctly handles both cases independently.**

---

## 6. `isValidSignature` (GPV2CompatibleAuction.sol L148-156)

```solidity
uint256 elapsedTime = block.timestamp - auctionStart;
AssetParams memory assetParams = s_assetParams[address(order.sellToken)];
if (elapsedTime > assetParams.auctionDuration) {
    revert InvalidAuction(address(order.sellToken));
}
(uint256 sellTokenUsdPrice,,) = _getAssetPrice(address(order.sellToken), true);
uint256 minBuyAmount = _getAssetOutAmount(assetParams, sellTokenUsdPrice, order.sellAmount, elapsedTime, true);
if (order.buyAmount < minBuyAmount) {
    revert InsufficientBuyAmount(order.buyAmount, minBuyAmount);
}
```

**Dimensional trace of the call to `_getAssetOutAmount`:**

| Parameter | Value | Unit |
|---|---|---|
| `assetInParams` | `s_assetParams[sellToken]` | Struct |
| `assetInUsdPrice` | `sellTokenUsdPrice` | `PRICE_18` |
| `amountIn` | `order.sellAmount` | `ASSET_N` (N = sellToken decimals) |
| `elapsedTime` | `block.timestamp - auctionStart` | `SECONDS` |
| `withValidation` | `true` | Boolean |

The function delegates to `_getAssetOutAmount` (analyzed in Section 1). The return value `minBuyAmount` is in `ASSET_M` (M = assetOut decimals). This is compared to `order.buyAmount`, which is the CowProtocol order's buy amount — also denominated in `assetOut` (the `buyToken`) in its native decimals.

**Result: `ASSET_M` compared to `ASSET_M`.** Correct. **CONSISTENT.**

### 6.1 Order Validation Completeness

The signature validation checks:
- `order.sellToken` has a live auction (L131-133)
- `order.buyToken == s_assetOut` (L135-136)
- `order.receiver == address(this)` (L138-139) -- **NOTE:** receiver is the auction contract, not `s_assetOutReceiver`. This is because CowSwap sends buyToken to the receiver, and the auction contract needs to receive it before forwarding.
- `order.sellAmount <= assetInBalance` (L144-146)
- `order.buyAmount >= minBuyAmount` (L155-156) -- key price check
- `order.validTo >= block.timestamp` (L158-159)
- `order.feeAmount == 0` (L162-163)
- `order.kind == KIND_SELL` (L165-166)
- `order.partiallyFillable == true` (L168-169)
- ERC20 balances (L171-172)

**All dimensional checks pass.**

---

## 7. Cross-Function Consistency Analysis

### 7.1 Price Flow: `_getAssetPrice` -> All Consumers

```
Data Streams Report (int192, feedDecimals) --[transmit/L167-172]--> PRICE_18
Data Feed (int256, live decimals()) --[_getAssetPrice/L394-400]--> PRICE_18
```

All consumers of `_getAssetPrice` receive `PRICE_18`:

| Consumer | Location | Expected Unit | Actual Unit | Match? |
|---|---|---|---|---|
| `bid()` | L429 | `PRICE_18` | `PRICE_18` | YES |
| `checkUpkeep()` | L238 | `PRICE_18` | `PRICE_18` | YES |
| `performUpkeep()` | L315, L342 | `PRICE_18` | `PRICE_18` | YES |
| `_getAssetOutAmount()` | L798 (assetOut) | `PRICE_18` | `PRICE_18` | YES |
| `getAssetOutAmount()` | L764 (assetIn) | `PRICE_18` | `PRICE_18` | YES |
| `isValidSignature()` | L153 | `PRICE_18` | `PRICE_18` | YES |

### 7.2 USD Value Computation Consistency

Three patterns compute USD values:

**Pattern A (plain Solidity, rounds down):**
```solidity
usdValue = (amount * assetPrice) / (10 ** decimals)
// Used in: bid() L430, checkUpkeep() L248/L258, performUpkeep() L344
```

**Pattern B (Solady, rounds up):**
```solidity
usdValue = amountIn.mulDivUp(assetInUsdPrice, 10 ** decimals).mulWadUp(priceMultiplier)
// Used in: _getAssetOutAmount() L799
```

Both produce `USD_18`. The difference is rounding direction:
- **Pattern A** rounds down: used for **threshold checks** (bid USD value, auction eligibility). Conservative — user needs slightly more to pass threshold.
- **Pattern B** rounds up: used for **pricing the trade**. The protocol gets slightly more `assetOut` from the bidder.

**FINDING [INFO-5]: Rounding direction is consistently chosen to favor the protocol across all computations. This is standard defensive practice. No unit mismatch.**

### 7.3 `minAuctionSizeUsd` Type Constraint

`minAuctionSizeUsd` is `uint96`. Max value: ~79.2 billion USD (in `USD_18` encoding: `~79.228e27`). This caps the configurable minimum auction size at ~$79.2B. **Sufficient for any realistic use case.**

### 7.4 `minBidUsdValue` Type Constraint

`minBidUsdValue` is `uint88`. Max value: ~$309.5M (in `USD_18` encoding: `~3.09e26`). **Sufficient.**

### 7.5 `startingPriceMultiplier` / `endingPriceMultiplier` as `uint64`

Max value: `~18.44e18` => max multiplier of ~18.44x. The multiplier represents a price premium/discount (e.g., 1.1e18 = 10% premium, 0.98e18 = 2% discount). A max of ~18.44x means the auction can start at up to ~1744% premium. **Sufficient for all practical auction configurations.**

---

## 8. Summary of Findings

### Confirmed Correct

| ID | Location | Description |
|---|---|---|
| OK-1 | `_getAssetOutAmount` L793-795 | Price multiplier linear decay: `MULTIPLIER_18 = MULTIPLIER_18 - MULTIPLIER_18 * SECONDS / SECONDS`. Units consistent. |
| OK-2 | `_getAssetOutAmount` L799 | USD value: `USD_18 = ASSET_N * PRICE_18 / 10^N` then `USD_18 = USD_18 * MULTIPLIER_18 / WAD`. Units consistent. |
| OK-3 | `_getAssetOutAmount` L802 | Asset conversion: `ASSET_M = USD_18 * 10^M / PRICE_18`. Units consistent. |
| OK-4 | `bid()` L430 | Bid USD value: `USD_18 = ASSET_N * PRICE_18 / 10^N`. Units consistent. |
| OK-5 | `checkUpkeep()` L248, L258 | Same pattern as OK-4. Units consistent. |
| OK-6 | `transmit()` L167-172 | Decimal normalization to 18. Correct scaling in both directions. |
| OK-7 | `_getAssetPrice()` L394-400 | Data Feed fallback decimal normalization. Correct. Independent from Data Streams decimals. |
| OK-8 | `isValidSignature()` L148-156 | Delegates to `_getAssetOutAmount` with correct units. `ASSET_M` compared to `ASSET_M`. |
| OK-9 | `performUpkeep()` L344 | Same USD pattern as OK-4. Units consistent. |

### Informational Findings

| ID | Severity | Location | Description |
|---|---|---|---|
| INFO-1 | Informational | `_getAssetOutAmount` L799-802 | Three chained round-up operations (`mulDivUp`, `mulWadUp`, `mulDivUp`) compound to slightly overcharge bidders. Intentional protocol-favoring rounding. Max cumulative error: 3 units of smallest denomination. |
| INFO-2 | Informational | `bid()` L430 | Plain Solidity `*` then `/` -- no overflow risk for realistic token supplies due to Solidity 0.8.26 checked arithmetic. |
| INFO-3 | Informational | `transmit()` L171 | When `feedDecimals > 18` (uncommon), division truncates. Slight price undervaluation. |
| INFO-4 | Informational | `_getAssetPrice()` L394 | Data Feed `decimals()` read live (not cached). Self-adapting design, safe. |
| INFO-5 | Informational | Various | All rounding directions consistently favor the protocol. |

### Potential Issues

| ID | Severity | Location | Description |
|---|---|---|---|
| PRECISION-1 | Low | `AssetParams.minAuctionSizeUsd` (L136) | The struct comment says "The minimum swap size expressed in USD feed decimals" but the value is compared against `USD_18` computed values. If an operator interprets "feed decimals" as 8 (typical Chainlink feed precision) and configures accordingly, all auction size thresholds will be wrong by a factor of 10^10 (too small by 10 orders of magnitude). The comment should say "18 decimals" to match `minBidUsdValue`'s documentation. **This is a documentation/configuration risk, not a code logic bug.** |

---

## 9. Full Derivation Chain: End-to-End Bid Flow

For a concrete example, tracing a bid for WETH (18 decimals) being auctioned for LINK (18 decimals):

```
Given:
  WETH price  = $2000 => assetInUsdPrice = 2000e18     [PRICE_18]
  LINK price  = $15   => assetOutUsdPrice = 15e18       [PRICE_18]
  amountIn    = 1e18  (1 WETH)                          [ASSET_18]
  priceMultiplier = 1.05e18 (5% premium)                [MULTIPLIER_18]

Step 1: amountIn.mulDivUp(assetInUsdPrice, 10^18)
  = ceil(1e18 * 2000e18 / 1e18)
  = 2000e18                                             [USD_18] ($2000)

Step 2: .mulWadUp(priceMultiplier)
  = ceil(2000e18 * 1.05e18 / 1e18)
  = 2100e18                                             [USD_18] ($2100)

Step 3: auctionUsdValue.mulDivUp(10^18, assetOutUsdPrice)
  = ceil(2100e18 * 1e18 / 15e18)
  = 140e18                                              [ASSET_18] (140 LINK)

Result: Bidder pays 140 LINK for 1 WETH at 5% premium. Correct.
```

For a low-decimal token example (USDC, 6 decimals) auctioned for LINK (18 decimals):

```
Given:
  USDC price  = $1    => assetInUsdPrice = 1e18         [PRICE_18]
  LINK price  = $15   => assetOutUsdPrice = 15e18       [PRICE_18]
  amountIn    = 1000e6 (1000 USDC)                      [ASSET_6]
  priceMultiplier = 1e18 (no premium, fair price)       [MULTIPLIER_18]

Step 1: amountIn.mulDivUp(assetInUsdPrice, 10^6)
  = ceil(1000e6 * 1e18 / 1e6)
  = 1000e18                                             [USD_18] ($1000)

Step 2: .mulWadUp(priceMultiplier)
  = ceil(1000e18 * 1e18 / 1e18)
  = 1000e18                                             [USD_18] ($1000)

Step 3: auctionUsdValue.mulDivUp(10^18, assetOutUsdPrice)
  = ceil(1000e18 * 1e18 / 15e18)
  = ceil(66.666...e18)
  = 66666666666666666667                                [ASSET_18] (~66.67 LINK)

Result: Bidder pays ~66.67 LINK for 1000 USDC. Correct. Rounding up by 1 wei of LINK.
```

---

## 10. Conclusion

The dimensional analysis of all mathematical operations in `BaseAuction.sol`, `PriceManager.sol`, and `GPV2CompatibleAuction.sol` reveals **no unit mismatches or formula bugs** in the price/auction calculations. All unit conversions are consistent, decimal normalizations are correct, and rounding directions uniformly favor the protocol.

The single actionable finding is **PRECISION-1**: the misleading comment on `minAuctionSizeUsd` that says "USD feed decimals" when it should say "18 decimals." This creates a configuration risk if operators follow the comment rather than the code.
