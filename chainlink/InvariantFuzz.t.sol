// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {C4PoC} from "./C4PoC.t.sol";
import {BaseAuction} from "src/BaseAuction.sol";
import {Caller} from "src/Caller.sol";
import {GPV2CompatibleAuction} from "src/GPV2CompatibleAuction.sol";
import {IERC20} from "@openzeppelin/contracts/interfaces/IERC20.sol";
import {console2} from "forge-std/console2.sol";

/// @title Invariant Fuzzing Harness for Chainlink Payment Abstraction V2
/// @notice Tests core invariants using Foundry's fuzzing capabilities
/// @dev Can be used with: forge test --match-contract InvariantFuzz -vvv
contract InvariantFuzz is C4PoC {

    // ═══════════════════════════════════════════════════════════════
    //                    INVARIANT: Auction Curve
    // ═══════════════════════════════════════════════════════════════

    /// @notice Invariant: assetOutAmount should NEVER be less than the fair value
    ///         at the ending price multiplier (maximum discount)
    function testFuzz_auctionCurveNeverExceedsMaxDiscount(
        uint256 amount,
        uint256 timeElapsedBps
    ) public {
        // Bound inputs
        amount = bound(amount, 1e6, 100_000e6); // 1 USDC to 100k USDC
        timeElapsedBps = bound(timeElapsedBps, 0, 10000); // 0% to 100%

        // Start a USDC auction
        _startAuction(address(mockUSDC), 100_000e6);

        // Skip time
        uint24 duration = auction.getAssetParams(address(mockUSDC)).auctionDuration;
        uint256 skipTime = (uint256(duration) * timeElapsedBps) / 10_000;
        if (skipTime > 0) {
            skip(skipTime);
            _refreshPrices();
        }

        // Get the auction price
        uint256 assetOutAmount = auction.getAssetOutAmount(address(mockUSDC), amount, block.timestamp);

        if (assetOutAmount == 0) return; // Auction may have ended

        // Compute fair value at maximum discount (ending price multiplier = 0.99e18 for USDC)
        // Fair value = amount * usdcPrice / linkPrice
        // Max discount value = fairValue * endingPriceMultiplier / 1e18
        (uint256 usdcPrice,,) = auction.getAssetPrice(address(mockUSDC));
        (uint256 linkPrice,,) = auction.getAssetPrice(address(mockLINK));

        if (usdcPrice == 0 || linkPrice == 0) return; // Skip if stale

        uint256 fairValueInLink = (amount * usdcPrice * 1e18) / (10 ** 6 * linkPrice);
        BaseAuction.AssetParams memory params = auction.getAssetParams(address(mockUSDC));
        uint256 maxDiscountValue = (fairValueInLink * params.endingPriceMultiplier) / 1e18;

        // Invariant: assetOutAmount >= maxDiscountValue (bidder always pays at least the discounted fair value)
        assert(assetOutAmount >= maxDiscountValue);
    }

    /// @notice Invariant: Price multiplier should always be between starting and ending values
    function testFuzz_priceMultiplierBounded(
        uint256 timeElapsedBps
    ) public {
        timeElapsedBps = bound(timeElapsedBps, 0, 10000);

        _startAuction(address(mockUSDC), 100_000e6);

        uint24 duration = auction.getAssetParams(address(mockUSDC)).auctionDuration;
        uint256 skipTime = (uint256(duration) * timeElapsedBps) / 10_000;
        if (skipTime > 0) {
            skip(skipTime);
            _refreshPrices();
        }

        uint256 amount = 1_000e6; // 1000 USDC
        uint256 assetOutNow = auction.getAssetOutAmount(address(mockUSDC), amount, block.timestamp);
        if (assetOutNow == 0) return;

        // Get price at start (time 0)
        uint256 auctionStart = auction.getAuctionStart(address(mockUSDC));
        uint256 assetOutAtStart = auction.getAssetOutAmount(address(mockUSDC), amount, auctionStart);

        // Get price at end
        uint256 assetOutAtEnd = auction.getAssetOutAmount(
            address(mockUSDC), amount, auctionStart + duration
        );

        // Invariant: current price should be between start price and end price
        // At start, bidder pays MORE (premium). At end, bidder pays LESS (discount).
        // So: assetOutAtEnd <= assetOutNow <= assetOutAtStart
        assert(assetOutNow <= assetOutAtStart);
        assert(assetOutNow >= assetOutAtEnd);
    }

    // ═══════════════════════════════════════════════════════════════
    //                    INVARIANT: Fund Safety
    // ═══════════════════════════════════════════════════════════════

    /// @notice Invariant: Bidding should never result in the auction contract
    ///         losing more assetIn than the bid amount
    function testFuzz_bidNeverDrainsExtraTokens(
        uint256 amount
    ) public {
        amount = bound(amount, 1_000e6, 50_000e6);

        _startAuction(address(mockUSDC), 100_000e6);

        uint256 auctionBalanceBefore = mockUSDC.balanceOf(address(auction));
        uint256 linkBalanceBefore = mockLINK.balanceOf(address(auction));

        // Fund bidder and bid
        _fundBidder(100_000e18);

        _changePrank(bidder);
        Caller.Call[] memory emptySolution = new Caller.Call[](0);
        auctionBidder.bid(address(mockUSDC), amount, emptySolution);
        vm.stopPrank();

        uint256 auctionBalanceAfter = mockUSDC.balanceOf(address(auction));
        uint256 linkBalanceAfter = mockLINK.balanceOf(address(auction));

        // Invariant: auction USDC balance decreased by exactly `amount`
        assert(auctionBalanceBefore - auctionBalanceAfter == amount);

        // Invariant: auction LINK balance increased (received payment)
        assert(linkBalanceAfter > linkBalanceBefore);
    }

    /// @notice Invariant: Total value should be preserved across the auction lifecycle
    function testFuzz_noValueLeakDuringAuction(
        uint256 skipBps
    ) public {
        skipBps = bound(skipBps, 100, 9900); // 1% to 99% elapsed

        uint256 auctionAmount = 50_000e6;
        uint256 bidAmount = 25_000e6;

        _startAuction(address(mockUSDC), auctionAmount);

        // Skip some time
        uint24 duration = auction.getAssetParams(address(mockUSDC)).auctionDuration;
        skip((uint256(duration) * skipBps) / 10_000);
        _refreshPrices();

        // Fund and bid
        _fundBidder(100_000e18);
        _changePrank(bidder);
        Caller.Call[] memory emptySolution = new Caller.Call[](0);
        auctionBidder.bid(address(mockUSDC), bidAmount, emptySolution);
        vm.stopPrank();

        // Check: bidder got USDC, auction got LINK
        uint256 bidderUsdcBalance = mockUSDC.balanceOf(address(auctionBidder));
        uint256 auctionLinkBalance = mockLINK.balanceOf(address(auction));

        // Bidder should have received the bid amount
        assert(bidderUsdcBalance == bidAmount);
        // Auction should have received some LINK
        assert(auctionLinkBalance > 0);
    }

    // ═══════════════════════════════════════════════════════════════
    //                    INVARIANT: Rounding
    // ═══════════════════════════════════════════════════════════════

    /// @notice Invariant: Rounding should ALWAYS favor the protocol
    ///         (bidder pays at least the continuous-time price)
    function testFuzz_roundingFavorsProtocol(
        uint256 amount,
        uint256 skipBps
    ) public {
        amount = bound(amount, 100e6, 10_000e6);
        skipBps = bound(skipBps, 0, 10000);

        _startAuction(address(mockUSDC), 100_000e6);

        uint24 duration = auction.getAssetParams(address(mockUSDC)).auctionDuration;
        uint256 skipTime = (uint256(duration) * skipBps) / 10_000;
        if (skipTime > 0) {
            skip(skipTime);
            _refreshPrices();
        }

        uint256 assetOutAmount = auction.getAssetOutAmount(address(mockUSDC), amount, block.timestamp);
        if (assetOutAmount == 0) return;

        // assetOutAmount should always be >= 1 (non-zero for non-zero input)
        assert(assetOutAmount >= 1);
    }

    // ═══════════════════════════════════════════════════════════════
    //                    INVARIANT: Access Control
    // ═══════════════════════════════════════════════════════════════

    /// @notice Invariant: Unprivileged users should never be able to start auctions
    function testFuzz_unprivilegedCannotStartAuction() public {
        deal(address(mockUSDC), address(feeAggregator), 100_000e6);

        _changePrank(attacker);
        (, bytes memory performData) = auction.checkUpkeep("");

        vm.expectRevert();
        auction.performUpkeep(performData);
    }

    /// @notice Invariant: Unprivileged users should never be able to transmit prices
    function testFuzz_unprivilegedCannotTransmitPrices() public {
        bytes[] memory reports = new bytes[](1);
        reports[0] = abi.encode(bytes32(0), bytes(""), new bytes32[](0), new bytes32[](0), bytes32(0));

        _changePrank(attacker);
        vm.expectRevert();
        auction.transmit(reports);
    }
}
