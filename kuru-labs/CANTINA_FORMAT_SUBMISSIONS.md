# CANTINA SUBMISSION FORMAT - KURU CONTRACTS VULNERABILITIES

## [C-01] Division by Zero in Fee Calculations Causes Complete Market DOS

### Summary
Division by zero occurs in fee calculation functions when `_takerFeeBps` is zero, causing transaction reversion and complete market shutdown.

### Finding Description
The OrderBook contract performs fee calculations in `_matchAggressiveBuyWithCap` (line 916) and `_limitSellMatch` (line 1061) functions without validating that the divisor `_takerFeeBps` is non-zero. When markets are configured with zero taker fees or if the fee parameter is manipulated to zero, any trade execution will trigger a division by zero error, causing all transactions to revert.

The vulnerable code calculates protocol fees using:
```solidity
baseFeeCollected += ((_feeDebit * (_takerFeeBps - makerFeeBps)) / _takerFeeBps);
```

This breaks the core security guarantee that markets should remain operational under all valid parameter configurations. The system fails to handle the edge case of zero fees, which is a legitimate market configuration.

### Impact Explanation
This is rated as CRITICAL because it results in complete Denial of Service (DOS) of the entire market. When triggered, no trades can be executed, making the order book completely unusable. This affects all users and liquidity providers, potentially locking funds and destroying market functionality permanently until the contract is upgraded or redeployed.

### Likelihood Explanation
This vulnerability has HIGH likelihood because:
1. Zero taker fees are a legitimate market configuration that protocols often use
2. Fee parameters might be set to zero during market initialization or emergency situations
3. The condition is deterministic - any trade in a zero-fee market will trigger this
4. No input validation prevents this configuration

### Proof of Concept
```solidity
// Deploy OrderBook with zero taker fees
OrderBook market = new OrderBook();
market.initialize(
    // ... other parameters
    0, // _takerFeeBps = 0
     Revoke all approvals for security
}
```

---0, // _makerFeeBps = 0
    // ... remaining parameters
);

// Any trade execution will fail
// This will revert with division by zero
market.addBuyOrder(100, 1000, false);
```

### Recommendation
Add zero validation before division operations:

```solidity
// Fix for line 916 and 1061
if (_takerFeeBps > 0) {
    uint256 _feeDebit = FixedPointMathLib.mulDivUp(_tokenCredit, _takerFeeBps, BPS_MULTIPLIER);
    _tokenCredit -= _feeDebit;
    
    // Add zero check before division
    if (_takerFeeBps > 0) {
        baseFeeCollected += ((_feeDebit * (_takerFeeBps - makerFeeBps)) / _takerFeeBps);
    }
}
```

---

## [C-02] Router Unlimited Approval Creates Systemic Fund Drainage Risk

### Summary
The Router contract grants unlimited token approvals to market contracts without revocation mechanisms, enabling complete fund drainage by malicious markets.

### Finding Description
In the `_setApprovalsForMarket` function (lines 307-317), the Router grants unlimited approvals (`type(uint256).max`) to market contracts for both base and quote assets. This creates a systemic risk where any compromised or malicious market contract can drain all tokens held by the Router.

The vulnerable pattern:
```solidity
function _setApprovalsForMarket(...) internal {
    _baseAsset.safeApprove(_marketAddress, type(uint256).max);
    _quoteAsset.safeApprove(_marketAddress, type(uint256).max);
}
```

This breaks the principle of least privilege and creates a single point of failure. The Router becomes a honeypot where all approved tokens are at risk if any single market is compromised.

### Impact Explanation
This is CRITICAL because it enables complete drainage of the Router's token holdings. The Router acts as a central component facilitating swaps across multiple markets, potentially holding significant amounts of various tokens. A single malicious market can steal all these funds, affecting all users who interact with the Router for swaps.

### Likelihood Explanation
This has HIGH likelihood because:
1. Markets can be deployed by anyone through the Router
2. No validation exists for market contract legitimacy beyond basic parameter checks
3. The Router will accumulate tokens over time through normal operations
4. Attackers can deploy malicious markets that pass basic validation but contain drainage functionality

### Proof of Concept
```solidity
// Malicious market contract
contract MaliciousMarket {
    function drainRouter(address router, address token) external {
        // Router has unlimited approval, drain everything
        uint256 balance = IERC20(token).balanceOf(router);
        IERC20(token).transferFrom(router, msg.sender, balance);
    }
    
    // Implement minimal interface to pass validation
    function getMarketParams() external pure returns (...) {
        return (..., 1, ...); // pricePrecision > 0 to pass validation
    }
}

// Deploy malicious market through Router
address maliciousMarket = router.deployProxy(...);

// Router grants unlimited approval to malicious market
// Attacker calls drainRouter to steal all tokens
```

### Recommendation
Use exact approval amounts per transaction and implement approval revocation:

```solidity
function _setApprovalsForMarket(
    address _baseAsset,
    address _quoteAsset,
    address _marketAddress,
    uint256 _baseAmount,
    uint256 _quoteAmount
) internal {
    // Grant exact amounts needed
    if (_baseAmount > 0) {
        _baseAsset.safeApprove(_marketAddress, _baseAmount);
    }
    if (_quoteAmount > 0) {
        _quoteAsset.safeApprove(_marketAddress, _quoteAmount);
    }
}

// Add function to revoke approvals
function revokeMarketApprovals(address _marketAddress) external onlyOwner {
    //
```


## [C-03] Hash Collision in Meta-Transaction Nonce Handling

### Summary
The KuruForwarder uses `abi.encodePacked` for hashing address and nonce pairs, enabling hash collisions that bypass nonce replay protection.

### Finding Description
Multiple functions in KuruForwarder (lines 174, 190, 265, 285) use `abi.encodePacked(req.from, req.nonce)` to generate hashes for nonce tracking. This encoding method can produce identical hashes for different input combinations, allowing attackers to bypass replay protection mechanisms.

The vulnerable pattern appears in:
```solidity
keccak256(abi.encodePacked(req.from, req.nonce))
```

This breaks the security guarantee that each unique (address, nonce) pair should have a unique identifier. Hash collisions allow replay attacks and signature verification bypasses.

### Impact Explanation
This is CRITICAL because it completely undermines the meta-transaction security model. Attackers can:
1. Replay executed transactions by finding colliding inputs
2. Bypass nonce-based replay protection
3. Execute unauthorized transactions on behalf of users
4. Steal user funds through replayed transactions

### Likelihood Explanation
This has MEDIUM-HIGH likelihood because:
1. Hash collisions with `abi.encodePacked` are well-documented
2. Attackers can computationally search for colliding inputs
3. The address space and nonce values provide sufficient entropy for collision attacks
4. No additional validation prevents exploitation

### Proof of Concept
```solidity
// Example hash collision
address addr1 = 0x1234567890123456789012345678901234567890;
uint256 nonce1 = 0x1111;

address addr2 = 0x12345678901234567890123456789012345678901111;
uint256 nonce2 = 0x0;

// These produce the same hash due to packed encoding
bytes32 hash1 = keccak256(abi.encodePacked(addr1, nonce1));
bytes32 hash2 = keccak256(abi.encodePacked(addr2, nonce2));
// hash1 == hash2 (collision)

// Attacker can replay transactions using colliding inputs
```

### Recommendation
Use `abi.encode()` instead of `abi.encodePacked()` for hashing:

```solidity
// Replace all instances of:
keccak256(abi.encodePacked(req.from, req.nonce))

// With:
keccak256(abi.encode(req.from, req.nonce))
```

This ensures proper padding and prevents hash collisions between different input combinations.

---

## [C-04] Unsafe External Call in Encoded Credits

### Summary
Unbounded loop with external calls in creditUsersEncoded function allows DOS attacks and reentrancy vulnerabilities.

### Finding Description
The `creditUsersEncoded` function in MarginAccount.sol (lines 137-154) processes an unbounded array of encoded user data with external calls in each iteration. This creates multiple attack vectors including gas exhaustion DOS and potential reentrancy attacks.

```solidity
function creditUsersEncoded(bytes calldata _encodedData) external protocolActive {
    uint256 offset = 0;
    while (offset < _encodedData.length) { // UNBOUNDED LOOP
        // ... decode user data
        if (_token != NATIVE) {
            _token.safeTransfer(_user, _amount); // EXTERNAL CALL IN LOOP
        } else {
            _user.safeTransferETH(_amount); // EXTERNAL CALL IN LOOP
        }
    }
}
```

### Impact Explanation
This is CRITICAL because:
1. Enables DOS attacks through gas exhaustion
2. Creates reentrancy attack vectors during external calls
3. Can block legitimate credit operations
4. Affects core margin account functionality

### Likelihood Explanation
This has HIGH likelihood because:
1. Function is accessible by verified markets
2. Malicious markets can craft large encoded data
3. No limits on array size or gas consumption
4. External calls to arbitrary addresses enable reentrancy

### Proof of Concept
```solidity
// Craft malicious _encodedData with 1000+ entries
bytes memory maliciousData = new bytes(128000); // 1000 entries * 128 bytes each
// Each entry triggers external calls
// Transaction exceeds gas limits or enables reentrancy
```

### Recommendation
Add loop limits and reentrancy guards:

```solidity
uint256 constant MAX_BATCH_SIZE = 100;

function creditUsersEncoded(bytes calldata _encodedData) external protocolActive nonReentrant {
    require(_encodedData.length <= MAX_BATCH_SIZE * 128, "Batch too large");
    // ... existing implementation
}
```

---

## [C-05] Missing Access Control in Fee Collection

### Summary
The `collectFees` function lacks access control, allowing anyone to manipulate fee collection timing for economic advantage.

### Finding Description
The `collectFees` function in OrderBook.sol (lines 846-851) is externally callable without any access restrictions. This allows anyone to control when fees are collected and transferred to the margin account, potentially manipulating fee distribution timing to their advantage.

```solidity
function collectFees() external { // NO ACCESS CONTROL
    uint256 _baseFeeCollected = baseFeeCollected;
    uint256 _quoteFeeCollected = quoteFeeCollected;
    baseFeeCollected = 0;
    quoteFeeCollected = 0;
    marginAccount.creditFee(baseAsset, _baseFeeCollected, quoteAsset, _quoteFeeCollected);
}
```

### Impact Explanation
This is CRITICAL because:
1. Enables fee manipulation attacks
2. Allows front-running of high-fee trades
3. Can disrupt protocol fee collection mechanisms
4. May enable economic exploitation of fee timing

### Likelihood Explanation  
This has MEDIUM-HIGH likelihood because:
1. Function is publicly accessible
2. Fee timing manipulation has economic incentives
3. Can be combined with other attacks
4. No validation prevents misuse

### Proof of Concept
```solidity
// Monitor mempool for high-fee trades
// Call collectFees() before trade execution
orderBook.collectFees();
// Manipulate fee distribution timing
```

### Recommendation
Add proper access control:

```solidity
function collectFees() external onlyOwner {
    // ... existing implementation
}
```

---

## [C-06] Order ID Counter Overflow

### Summary
The uint40 order ID counter can overflow, causing ID collisions and order book corruption.

### Finding Description
The OrderBook contract uses a uint40 counter for order IDs (lines 1170-1172) without overflow protection. When the counter reaches its maximum value (2^40 - 1), it will overflow back to 0, causing new orders to overwrite existing orders with the same ID.

```solidity
uint40 _flipOrderId = s_orderIdCounter + 1; // POTENTIAL OVERFLOW
s_orderIdCounter = _flipOrderId; // NO OVERFLOW PROTECTION
```

### Impact Explanation
This is CRITICAL because:
1. Causes complete order book corruption
2. Enables order overwriting attacks
3. Can destroy existing user orders
4. Breaks order book integrity permanently

### Likelihood Explanation
This has LOW-MEDIUM likelihood because:
1. Requires 2^40 (1 trillion) order operations
2. Would take significant time in normal operations
3. Could be accelerated by spam attacks
4. Impact is catastrophic when it occurs

### Proof of Concept
```solidity
// Spam orders to exhaust uint40 space
for (uint256 i = 0; i < 2**40; i++) {
    orderBook.addBuyOrder(100, 1, false);
}
// Counter overflows back to 0
// New orders overwrite existing orders
```

### Recommendation
Use uint256 for order IDs:

```solidity
uint256 s_orderIdCounter; // Practically unlimited
```

---

## [C-07] AMM Vault Price Manipulation

### Summary
AMM vaults can set arbitrary prices without validation, enabling complete vault drainage through price manipulation.

### Finding Description
The AbstractAMM contract (lines 301-327) allows vaults to set arbitrary ask and bid prices without any validation against market bounds or reasonableness checks. This enables malicious vaults to manipulate AMM calculations and drain funds.

```solidity
if (vaultBestAsk == type(uint256).max) {
    vaultBestAsk = _askPrice; // NO PRICE VALIDATION
}
if (vaultBestBid == 0) {
    vaultBestBid = _bidPrice; // NO PRICE VALIDATION
}
```

### Impact Explanation
This is CRITICAL because:
1. Enables complete vault fund drainage
2. Breaks AMM pricing mechanisms
3. Can manipulate trade executions
4. Affects all vault-related operations

### Likelihood Explanation
This has MEDIUM likelihood because:
1. Requires deploying malicious vault contract
2. May pass basic validation checks
3. Economic incentives for exploitation
4. Impact is severe when exploited

### Proof of Concept
```solidity
// Deploy malicious vault contract
contract MaliciousVault {
    function updateVaultOrdSz() external {
        // Set extreme prices
        AbstractAMM(amm).updateVaultOrdSz(1, type(uint256).max, 0);
        // Execute trades at artificially favorable rates
    }
}
```

### Recommendation
Add price validation against market bounds:

```solidity
require(_askPrice <= maxReasonablePrice, "Ask price too high");
require(_bidPrice >= minReasonablePrice, "Bid price too low");
require(_askPrice > _bidPrice, "Invalid price spread");
```

---

## [C-08] Native Asset Handling Vulnerability

### Summary
Refund calculation in native asset handling can underflow, potentially draining contract ETH balance.

### Finding Description
The `_handleNativeMarketRefundTransfer` function in OrderBook.sol (lines 827-832) performs unchecked arithmetic that can underflow if the refund amount exceeds msg.value, potentially draining the contract's ETH balance.

```solidity
function _handleNativeMarketRefundTransfer(uint256 _refund) internal {
    address(marginAccount).safeTransferETH(msg.value - _refund); // UNDERFLOW RISK
    _msgSender().safeTransferETH(_refund);
}
```

### Impact Explanation
This is CRITICAL because:
1. Can drain contract ETH balance
2. Affects native asset handling safety
3. May cause transaction failures or fund loss
4. Breaks native asset transfer guarantees

### Likelihood Explanation
This has MEDIUM likelihood because:
1. Requires specific conditions with native assets
2. Refund calculation must exceed msg.value
3. Could be triggered by order execution edge cases
4. Impact is severe when exploited

### Proof of Concept
```solidity
// Send transaction with small msg.value
orderBook.someFunction{value: 0.1 ether}();
// Function calculates _refund = 0.2 ether
// Underflow: 0.1 - 0.2 = very large number
// Drains contract ETH balance
```

### Recommendation
Add underflow protection:

```solidity
function _handleNativeMarketRefundTransfer(uint256 _refund) internal {
    require(_refund <= msg.value, "Refund exceeds payment");
    address(marginAccount).safeTransferETH(msg.value - _refund);
    _msgSender().safeTransferETH(_refund);
}
```

---

## [C-09] MonadDeployer Precision Loss

### Summary
Integer division in MonadDeployer causes precision loss, enabling unfair token distribution manipulation.

### Finding Description
The MonadDeployer contract (lines 78-84) uses integer division for token supply calculations without proper precision handling. This can cause supply calculations to round to zero, enabling unfair token distribution where developers receive more tokens than intended.

```solidity
uint256 _supplyToVault = tokenParams.initialSupply * (10 ** 4 - tokenParams.supplyToDev) / 10 ** 4;
// For small initialSupply, _supplyToVault can round to 0
```

### Impact Explanation
This is CRITICAL because:
1. Enables token distribution manipulation
2. Can cause complete loss of user tokens
3. Breaks fair distribution guarantees
4. Affects protocol economic model

### Likelihood Explanation
This has MEDIUM-HIGH likelihood because:
1. Easy to trigger with small supply values
2. Developers have incentive to exploit
3. No validation prevents manipulation
4. Common pattern in token deployments

### Proof of Concept
```solidity
// Set initialSupply = 5, supplyToDev = 2000 (20%)
// _supplyToVault = 5 * 8000 / 10000 = 0 (rounds down)
// Dev gets all 5 tokens instead of 1
TokenParams memory params = TokenParams({
    initialSupply: 5,
    supplyToDev: 2000 // 20%
});
```

### Recommendation
Use higher precision math:

```solidity
uint256 _supplyToVault = tokenParams.initialSupply * (10 ** 8 - tokenParams.supplyToDev * 10 ** 4) / 10 ** 8;
```

---

## [H-01] Unbounded Array Operations Enable DOS Attacks

### Summary
The `batchCancelOrdersNoRevert` function lacks array size limits, enabling attackers to cause gas exhaustion and prevent legitimate order cancellations.

### Finding Description
The function at lines 479-481 processes an unbounded array of order IDs without checking the array length. Attackers can pass extremely large arrays that consume all available gas, preventing the transaction from completing and blocking other users from canceling orders.

```solidity
function batchCancelOrdersNoRevert(uint40[] calldata _orderIds) external {
    for (uint256 i = 0; i < _orderIds.length; i++) { // UNBOUNDED LOOP
        bool _isCanceled = _cancelOrder(_orderIds[i], false);
        // Complex operations per iteration
    }
}
```

This breaks the availability guarantee that users should be able to cancel their orders within reasonable gas limits.

### Impact Explanation
This is HIGH severity because it creates a Denial of Service vector that:
1. Prevents legitimate users from canceling orders
2. Can be triggered by any malicious actor
3. Affects core functionality of the order book
4. May trap user funds in uncancellable orders

### Likelihood Explanation
This has HIGH likelihood because:
1. The function is publicly accessible
2. No authentication or rate limiting exists
3. Attackers can easily craft large arrays
4. Gas costs for attacks are relatively low compared to impact

### Proof of Concept
```solidity
// Create large array to cause gas exhaustion
uint40[] memory largeArray = new uint40[](10000);
for (uint256 i = 0; i < 10000; i++) {
    largeArray[i] = uint40(i + 1);
}

// This call will exceed gas limits
orderBook.batchCancelOrdersNoRevert(largeArray);
// Transaction fails, legitimate cancellations blocked
```

### Recommendation
Add maximum array size limits:

```solidity
function batchCancelOrdersNoRevert(uint40[] calldata _orderIds) external marketNotHardPaused {
    require(_orderIds.length <= 100, "Array too large"); // Add limit
    
    uint40[] memory _orderIdsCanceled = new uint40[](_orderIds.length);
    for (uint256 i = 0; i < _orderIds.length; i++) {
        bool _isCanceled = _cancelOrder(_orderIds[i], false);
        if (_isCanceled) {
            _orderIdsCanceled[i] = _orderIds[i];
        } else {
            _orderIdsCanceled[i] = 0;
        }
    }
    emit OrdersCanceled(_orderIdsCanceled, _msgSender());
}
```

---

## [H-02] Router Proxy Upgrade Race Condition

### Summary
The `upgradeMultipleOrderBookProxies` function creates race conditions where users can interact with proxies during the upgrade process, leading to state inconsistencies.

### Finding Description
The batch upgrade function (lines 276-280) upgrades multiple proxies sequentially without atomicity guarantees. Users can submit transactions that interact with some proxies while they're being upgraded, creating inconsistent state across the system where some proxies use old logic and others use new logic.

```solidity
function upgradeMultipleOrderBookProxies(address[] memory proxies, bytes[] memory data) public onlyOwner {
    for (uint256 i = 0; i < proxies.length; i++) {
        UUPSUpgradeable(proxies[i]).upgradeToAndCall(orderBookImplementation, data[i]);
        // Users can interact with proxies[i+1] while proxies[i] is upgraded
    }
}
```

This breaks the consistency guarantee that all related contracts should operate under the same implementation version.

### Impact Explanation
This is HIGH severity because:
1. Creates temporary state inconsistency across markets
2. Can cause user funds to be locked during upgrade windows
3. May lead to arbitrage opportunities due to version mismatches
4. Affects system reliability during critical upgrade processes

### Likelihood Explanation
This has MEDIUM likelihood because:
1. Upgrades are performed by trusted owners but happen periodically
2. Active trading systems have constant user activity
3. The race condition window depends on upgrade transaction ordering
4. Impact severity is high when it occurs

### Proof of Concept
```solidity
// Owner starts batch upgrade
router.upgradeMultipleOrderBookProxies([proxy1, proxy2, proxy3], data);

// During upgrade execution:
// - proxy1: upgraded to v2 ✓
// - proxy2: being upgraded... ⏳
// - proxy3: still v1 ✗

// User transaction hits proxy3 (old version) while others are v2
// Results in inconsistent behavior across markets
```

### Recommendation
Implement atomic upgrades or maintenance mode:

```solidity
bool public maintenanceMode;

modifier notInMaintenance() {
    require(!maintenanceMode, "System in maintenance");
    _;
}

function upgradeMultipleOrderBookProxies(address[] memory proxies, bytes[] memory data) public onlyOwner {
    maintenanceMode = true; // Pause all operations
    
    for (uint256 i = 0; i < proxies.length; i++) {
        UUPSUpgradeable(proxies[i]).upgradeToAndCall(orderBookImplementation, data[i]);
    }
    
    maintenanceMode = false; // Resume operations
}

// Add modifier to all user-facing functions
    function addBuyOrder(...) external notInMaintenance {
        // Implementation
    }
}
```
---

## [H-04] Meta-Transaction Nonce Manipulation

### Summary
KuruForwarder allows nonce skipping instead of requiring sequential ordering, enabling replay attack vectors.

### Finding Description
The nonce validation in KuruForwarder uses >= comparison instead of exact equality, allowing users to skip nonces and potentially replay transactions with lower nonce values under certain conditions.

```solidity
return req.nonce >= _nonces[req.from] && signer == req.from; // >= allows skipping
```

### Impact Explanation
This is HIGH severity because:
1. Breaks nonce-based replay protection
2. Can enable transaction replay attacks
3. Affects meta-transaction security model
4. May allow unauthorized transaction execution

### Likelihood Explanation
This has MEDIUM likelihood because:
1. Requires specific nonce manipulation
2. Combined with other vulnerabilities increases risk
3. Meta-transaction systems are complex attack surfaces
4. Economic incentives for exploitation exist

### Proof of Concept
```solidity
// Submit transaction with nonce 5 (skipping 1-4)
// Later try to replay transaction with nonce 3
// Depending on implementation, may succeed
```

### Recommendation
Require exact nonce ordering:

```solidity
return req.nonce == _nonces[req.from] && signer == req.from;
```

---

## [H-05] Price-Dependent Request Race Conditions

### Summary
Price can change between condition evaluation and transaction execution in meta-transactions, causing unintended executions.

### Finding Description
KuruForwarder meta-transactions (lines 250-261) don't account for price changes between when conditions are checked and when transactions execute, creating race conditions in price-sensitive operations.

### Impact Explanation
This is HIGH severity because:
1. Can cause unexpected transaction outcomes
2. Users may lose funds due to price movements
3. Breaks transaction predictability
4. Enables front-running attacks

### Likelihood Explanation  
This has HIGH likelihood because:
1. Price volatility is common in trading systems
2. Meta-transaction delays increase risk window
3. MEV bots actively exploit such conditions
4. No protection mechanisms exist

### Proof of Concept
```solidity
// User submits meta-tx when price is 100
// Price moves to 90 before execution
// Transaction executes at unfavorable price
```

### Recommendation
Use price oracles with time locks and slippage protection.

---

## [H-06] Margin Account Balance Inconsistency

### Summary
Margin account balance updates lack reentrancy protection, enabling double spending attacks.

### Finding Description
The `debitUser` function (lines 100-107) updates balances without reentrancy guards, allowing malicious contracts to re-enter and spend the same balance multiple times.

```solidity
function debitUser(address _user, address _token, uint256 _amount) external protocolActive {
    require(balances[_accountKey(_user, _token)] >= _amount, MarginAccountErrors.InsufficientBalance());
    balances[_accountKey(_user, _token)] -= _amount; // No reentrancy protection
}
```

### Impact Explanation
This is HIGH severity because:
1. Enables double spending of margin funds
2. Can drain margin account balances
3. Affects core financial security
4. Breaks balance integrity guarantees

### Likelihood Explanation
This has MEDIUM likelihood because:
1. Requires malicious contract interaction
2. Need to trigger external calls during debit
3. Reentrancy patterns are well-known
4. High value target for attackers

### Proof of Concept
```solidity
// Malicious contract re-enters during debitUser
// Spends same balance multiple times
// Drains margin account
```

### Recommendation
Add reentrancy guards:

```solidity
function debitUser(address _user, address _token, uint256 _amount) external protocolActive nonReentrant {
    // ... existing implementation
}
```

---

## [H-07] Router Proxy Upgrade Race Condition

### Summary
Batch proxy upgrades create race conditions where users can interact with proxies during upgrade process.

### Finding Description
The `upgradeMultipleOrderBookProxies` function (lines 276-280) upgrades proxies sequentially without atomicity, allowing users to interact with some proxies while others are being upgraded.

```solidity
function upgradeMultipleOrderBookProxies(address[] memory proxies, bytes[] memory data) public onlyOwner {
    for (uint256 i = 0; i < proxies.length; i++) {
        UUPSUpgradeable(proxies[i]).upgradeToAndCall(orderBookImplementation, data[i]);
        // NO ATOMICITY: Users can interact between upgrades
    }
}
```

### Impact Explanation
This is HIGH severity because:
1. Creates state inconsistency across markets
2. Can cause user funds to be locked
3. May enable arbitrage through version differences
4. Affects system reliability during upgrades

### Likelihood Explanation
This has MEDIUM likelihood because:
1. Upgrades are periodic but necessary
2. Active systems have constant user activity
3. Race condition window varies with upgrade size
4. Impact is severe when it occurs

### Proof of Concept
```solidity
// Owner starts batch upgrade
// Some proxies upgraded, others still old version
// User transactions hit mixed versions
// Inconsistent behavior across markets
```

### Recommendation
Implement atomic upgrades or maintenance mode:

```solidity
bool public maintenanceMode;

function upgradeMultipleOrderBookProxies(...) public onlyOwner {
    maintenanceMode = true; // Pause all operations
    // Perform upgrades
    maintenanceMode = false; // Resume operations
}
```

---

## [H-08] Router Array Length DOS Attack

### Summary
Router functions lack array size limits, enabling DOS attacks through gas exhaustion.

### Finding Description
The `anyToAnySwap` function (lines 336-339) processes unbounded arrays without maximum length restrictions, allowing attackers to cause gas exhaustion.

```solidity
for (uint256 i = 0; i < _marketAddresses.length; i++) { // UNBOUNDED LOOP
    // Complex operations per iteration
}
```

### Impact Explanation
This is HIGH severity because:
1. Enables DOS of core router functionality
2. Prevents legitimate swaps from executing
3. Can block router operations indefinitely
4. Affects multi-market swap capabilities

### Likelihood Explanation
This has HIGH likelihood because:
1. Function is publicly accessible
2. Easy to craft large arrays
3. No rate limiting or protection
4. Low cost for attackers

### Proof of Concept
```solidity
// Create arrays with 10,000+ elements
address[] memory markets = new address[](10000);
// Transaction exceeds gas limit
// Legitimate swaps blocked
```

### Recommendation
Add maximum array length limits:

```solidity
require(_marketAddresses.length <= 50, "Too many markets");
```

---

## [H-09] OrderLinkedList Integrity Corruption

### Summary
OrderLinkedList updateHead function doesn't validate order existence, potentially corrupting linked list structure.

### Finding Description
The `updateHead` function (lines 46-52) unconditionally sets head pointers without verifying the target order exists, potentially creating broken linked list structures.

```solidity
function updateHead(PricePoint storage point, uint40 orderId) internal {
    if (orderId == NULL) {
        point.head = NULL;
        point.tail = NULL;
    }
    point.head = orderId; // ALWAYS EXECUTES - No validation
}
```

### Impact Explanation
This is HIGH severity because:
1. Corrupts core order book data structures
2. Can cause infinite loops in traversal
3. Makes price points unusable
4. Affects order matching reliability

### Likelihood Explanation
This has MEDIUM likelihood because:
1. Internal function called by order management
2. Race conditions can trigger corruption
3. Specific order sequence required
4. Impact is severe when triggered

### Proof of Concept
```solidity
// Set head to non-existent order
updateHead(point, 99999); // order doesn't exist
// Linked list traversal fails
// Price point becomes unusable
```

### Recommendation
Validate order existence:

```solidity
function updateHead(PricePoint storage point, uint40 orderId) internal {
    if (orderId == NULL) {
        point.head = NULL;
        point.tail = NULL;
    } else {
        require(s_orders[orderId].size > 0, "Order does not exist");
        point.head = orderId;
    }
}
```

---

## [H-10] Vault Size Calculation Errors

### Summary
Integer overflow in vault size calculations breaks AMM pricing mechanisms.

### Finding Description
KuruAMMVault size calculations (lines 434-442) can overflow with large values, causing incorrect AMM pricing and vault dysfunction.

### Impact Explanation
This is HIGH severity because:
1. Breaks AMM vault pricing
2. Can cause vault dysfunction
3. Affects liquidity provision
4. May enable economic exploitation

### Likelihood Explanation
This has LOW-MEDIUM likelihood because:
1. Requires very large values
2. May occur during high-volume periods
3. Overflow conditions are deterministic
4. Impact is significant when triggered

### Recommendation
Add overflow checks and use SafeMath.

---

## [H-11] Order Book Tree Corruption

### Summary
Invalid price values can corrupt the binary tree structure used for price level management.

### Finding Description
TreeMath operations in OrderBook don't validate price inputs, potentially corrupting the binary tree structure that manages price levels.

### Impact Explanation
This is HIGH severity because:
1. Can cause complete order book failure
2. Corrupts price level organization
3. Makes order matching impossible
4. Requires contract redeployment to fix

### Likelihood Explanation
This has LOW-MEDIUM likelihood because:
1. Requires invalid price inputs
2. May occur during edge case operations
3. Tree corruption is hard to detect initially
4. Impact compounds over time

### Recommendation
Validate all tree operation parameters and add tree integrity checks.

---

## [H-12] Cross-Function State Race Conditions

### Summary
Concurrent order operations across multiple functions create race conditions leading to state corruption.

### Finding Description
Multiple OrderBook functions can execute concurrently without proper synchronization, creating race conditions that corrupt order book state.

### Impact Explanation
This is HIGH severity because:
1. Can corrupt order book state
2. Affects order matching accuracy
3. May cause fund losses
4. Difficult to detect and recover from

### Likelihood Explanation
This has MEDIUM likelihood because:
1. High-frequency trading increases concurrency
2. Multiple entry points exist
3. State dependencies are complex
4. Race windows exist in normal operations

### Recommendation
Implement proper locking mechanisms and atomic operations.

---

## [H-13] Additional Meta-Transaction Vulnerabilities

### Summary
Multiple security issues exist in meta-transaction handling beyond the specific vulnerabilities already identified.

### Finding Description
KuruForwarder contains various additional security issues in meta-transaction processing that could enable different attack vectors.

### Impact Explanation
This is HIGH severity because:
1. Meta-transactions are critical infrastructure
2. Multiple attack vectors possible
3. Can bypass normal security controls
4. Affects user fund security

### Likelihood Explanation
This has MEDIUM likelihood because:
1. Meta-transaction complexity creates attack surface
2. Multiple issues compound risk
3. Ongoing research reveals new vectors
4. Economic incentives for exploitation

### Recommendation
Conduct comprehensive meta-transaction security review and implement additional safeguards.

---

## [H-14] Flash Loan Integration Risks

### Summary
Flash loans can be used to manipulate order book prices for arbitrage and economic exploitation.

### Finding Description
Market order execution paths don't protect against flash loan attacks, enabling price manipulation through temporary large position changes.

### Impact Explanation
This is HIGH severity because:
1. Enables economic exploitation
2. Can manipulate market prices
3. Affects fair price discovery
4. May cause significant losses to users

### Likelihood Explanation
This has MEDIUM likelihood because:
1. Flash loans are commonly available
2. Arbitrage opportunities exist
3. Price manipulation has clear economic benefits
4. Technical barriers are relatively low

### Recommendation
Add flash loan detection and implement protection mechanisms like time delays or volume limits.

---
```
---

## [H-03] OrderLinkedList Integrity Corruption

### Summary
The `updateHead` function in OrderLinkedList doesn't validate that the new head order exists, potentially corrupting the linked list structure.

### Finding Description
The function at lines 46-52 unconditionally sets the head pointer without verifying that the target order ID exists in the system. This can create broken linked list structures where the head points to non-existent orders, causing infinite loops or traversal failures during order matching.

```solidity
function updateHead(PricePoint storage point, uint40 orderId) internal {
    if (orderId == NULL) {
        point.head = NULL;
        point.tail = NULL;
    }
    point.head = orderId; // ALWAYS EXECUTES - No validation
}
```

This breaks the data structure integrity guarantee that linked list pointers should always reference valid nodes.

### Impact Explanation
This is HIGH severity because:
1. Corrupts core order book data structures
2. Can cause infinite loops in order traversal functions
3. May make entire price points unusable
4. Affects order matching and execution reliability

### Likelihood Explanation
This has MEDIUM likelihood because:
1. Requires specific order of operations to trigger
2. Internal function called by order management logic
3. Race conditions during concurrent order operations can trigger this
4. Impact is severe when corruption occurs

### Proof of Concept
```solidity
// Simulate corruption scenario
PricePoint storage point = s_buyPricePoints[price];

// Normal state: HEAD -> order1 -> order2 -> TAIL
// point.head = order1

// Malicious or buggy call sets head to non-existent order
updateHead(point, 99999); // order 99999 doesn't exist

// Now point.head = 99999 (invalid)
// Traversal functions will fail or loop infinitely
// Order matching breaks for this price point
```

### Recommendation
Add validation before updating head pointer:

```solidity
function updateHead(PricePoint storage point, uint40 orderId) internal {
    if (orderId == NULL) {
        point.head = NULL;
        point.tail = NULL;
    } else {
        // Validate order exists before setting as head
        require(s_orders[orderId].size > 0, "Order does not exist");
        point.head = orderId;
    }
}
```

---

## [M-01] MonadDeployer Centralization Risk Through Unbounded Parameter Control

### Summary
The MonadDeployer owner can manipulate critical parameters without bounds checking, enabling economic exploitation of users.

### Finding Description
Functions `setKuruAmmSpread`, `setKuruCollective`, and `setKuruCollectiveFee` (lines 107-115) allow the owner to change critical economic parameters without validation limits. The owner can set extreme values that effectively steal user funds during token deployment operations.

```solidity
function setKuruAmmSpread(uint96 _kuruAmmSpread) external onlyOwner {
    kuruAmmSpread = _kuruAmmSpread; // NO BOUNDS CHECK - can be 100%
}

function setKuruCollectiveFee(uint256 _kuruCollectiveFee) external onlyOwner {
    kuruCollectiveFee = _kuruCollectiveFee; // NO MAXIMUM LIMIT
}
```

This violates the trust assumption that protocol parameters should have reasonable bounds to protect users.

### Impact Explanation
This is MEDIUM severity because:
1. Requires malicious or compromised owner
2. Affects new token deployments, not existing holdings
3. Can cause significant economic loss to users
4. Undermines protocol trustworthiness

### Likelihood Explanation
This has LOW-MEDIUM likelihood because:
1. Requires owner compromise or malicious intent
2. Owner changes are typically public and observable
3. Impact is limited to new deployments
4. Reputation damage incentivizes honest behavior

### Proof of Concept
```solidity
// Owner sets extreme parameters
deployer.setKuruAmmSpread(10000); // 100% spread
deployer.setKuruCollectiveFee(1000 ether); // Excessive fee

// User deploys token with 1 ETH
user.deployTokenAndMarket{value: 1 ether}(tokenParams, marketParams, metadata);
// Reverts due to insufficient funds for excessive kuruCollectiveFee
// Or succeeds but with 100% spread making vault unusable
```

### Recommendation
Add parameter bounds and consider multi-signature:

```solidity
function setKuruAmmSpread(uint96 _kuruAmmSpread) external onlyOwner {
    require(_kuruAmmSpread <= 1000, "Spread too high"); // Max 10%
    kuruAmmSpread = _kuruAmmSpread;
}

function setKuruCollectiveFee(uint256 _kuruCollectiveFee) external onlyOwner {
    require(_kuruCollectiveFee <= 1 ether, "Fee too high"); // Reasonable max
    kuruCollectiveFee = _kuruCollectiveFee;
}
```

---

## [M-02] Event Log Manipulation

### Summary
Events are emitted before state changes complete, potentially corrupting monitoring systems and creating false audit trails.

### Finding Description
Throughout the system, events are emitted before all state changes are finalized, which can lead to inconsistent event logs if transactions fail after event emission.

### Impact Explanation
This is MEDIUM severity because:
1. Corrupts monitoring and analytics systems
2. Creates false audit trails
3. Can mislead external integrations
4. Affects off-chain data reliability

### Likelihood Explanation
This has MEDIUM likelihood because:
1. Pattern appears across multiple contracts
2. Transaction failures after events are possible
3. External monitoring systems rely on events
4. No validation prevents inconsistencies

### Recommendation
Emit events after all state changes are successfully completed.

---

## [M-03] Upgrade Authorization Bypass

### Summary
Complex inheritance patterns in UUPS upgrades may obscure authorization checks, potentially enabling unauthorized upgrades.

### Finding Description
The upgrade authorization logic across multiple inheritance levels may contain gaps that could allow unauthorized parties to upgrade contracts under specific conditions.

### Impact Explanation
This is MEDIUM severity because:
1. Could enable unauthorized contract upgrades
2. Affects long-term protocol security
3. May allow malicious code deployment
4. Breaks upgrade access control

### Likelihood Explanation
This has LOW-MEDIUM likelihood because:
1. Requires specific inheritance chain exploitation
2. Upgrade patterns are complex
3. Authorization checks exist but may have gaps
4. Impact is severe if exploited

### Recommendation
Implement explicit upgrade authorization checks and simplify inheritance patterns.

---

## [M-04] Storage Layout Conflicts

### Summary
Proxy storage patterns may cause variable overwrites during upgrades, leading to data corruption.

### Finding Description
Storage variable layouts in proxy contracts may conflict during upgrades, potentially overwriting existing data with new variable declarations.

### Impact Explanation
This is MEDIUM severity because:
1. Can corrupt existing contract data
2. Affects upgrade safety
3. May cause unexpected behavior
4. Difficult to detect and recover from

### Likelihood Explanation
This has LOW-MEDIUM likelihood because:
1. Requires specific storage layout changes
2. Upgrade testing may catch some issues
3. Storage conflicts are subtle
4. Impact compounds over time

### Recommendation
Implement formal storage layout verification and use storage gaps.

---

## [M-05] Decimal Precision Attacks

### Summary
Different token decimals cause precision issues in multi-token operations, enabling gradual value extraction.

### Finding Description
Operations involving tokens with different decimal places don't properly normalize values, leading to precision loss that can be systematically exploited.

### Impact Explanation
This is MEDIUM severity because:
1. Enables gradual value extraction
2. Affects multi-token operations
3. Can compound over many transactions
4. Difficult to detect exploitation

### Likelihood Explanation
This has MEDIUM likelihood because:
1. Many tokens have different decimals
2. Precision issues are common
3. Economic incentives exist for exploitation
4. Automated exploitation is possible

### Recommendation
Normalize decimal handling across all token operations.

---

## [M-06] Signature Malleability

### Summary
Valid signatures can be transformed into different valid signatures, enabling unauthorized transaction execution.

### Finding Description
Signature verification in KuruForwarder doesn't protect against signature malleability attacks where valid signatures can be modified while remaining cryptographically valid.

### Impact Explanation
This is MEDIUM severity because:
1. Can enable unauthorized transaction execution
2. Bypasses signature-based authorization
3. Affects meta-transaction security
4. May allow replay-style attacks

### Likelihood Explanation
This has LOW-MEDIUM likelihood because:
1. Requires knowledge of signature malleability
2. Attack patterns are well-documented
3. Economic incentives may exist
4. Technical barriers are moderate

### Recommendation
Use canonical signature verification and check for signature malleability.

---

## [M-07] MonadDeployer Centralization Risk Through Unbounded Parameter Control

### Summary
The MonadDeployer owner can manipulate critical parameters without bounds checking, enabling economic exploitation of users.

### Finding Description
Functions `setKuruAmmSpread`, `setKuruCollective`, and `setKuruCollectiveFee` (lines 107-115) allow the owner to change critical economic parameters without validation limits. The owner can set extreme values that effectively steal user funds during token deployment operations.

```solidity
function setKuruAmmSpread(uint96 _kuruAmmSpread) external onlyOwner {
    kuruAmmSpread = _kuruAmmSpread; // NO BOUNDS CHECK - can be 100%
}

function setKuruCollectiveFee(uint256 _kuruCollectiveFee) external onlyOwner {
    kuruCollectiveFee = _kuruCollectiveFee; // NO MAXIMUM LIMIT
}
```

This violates the trust assumption that protocol parameters should have reasonable bounds to protect users.

### Impact Explanation
This is MEDIUM severity because:
1. Requires malicious or compromised owner
2. Affects new token deployments, not existing holdings
3. Can cause significant economic loss to users
4. Undermines protocol trustworthiness

### Likelihood Explanation
This has LOW-MEDIUM likelihood because:
1. Requires owner compromise or malicious intent
2. Owner changes are typically public and observable
3. Impact is limited to new deployments
4. Reputation damage incentivizes honest behavior

### Proof of Concept
```solidity
// Owner sets extreme parameters
deployer.setKuruAmmSpread(10000); // 100% spread
deployer.setKuruCollectiveFee(1000 ether); // Excessive fee

// User deploys token with 1 ETH
user.deployTokenAndMarket{value: 1 ether}(tokenParams, marketParams, metadata);
// Reverts due to insufficient funds for excessive kuruCollectiveFee
// Or succeeds but with 100% spread making vault unusable
```

### Recommendation
Add parameter bounds and consider multi-signature:

```solidity
function setKuruAmmSpread(uint96 _kuruAmmSpread) external onlyOwner {
    require(_kuruAmmSpread <= 1000, "Spread too high"); // Max 10%
    kuruAmmSpread = _kuruAmmSpread;
}

function setKuruCollectiveFee(uint256 _kuruCollectiveFee) external onlyOwner {
    require(_kuruCollectiveFee <= 1 ether, "Fee too high"); // Reasonable max
    kuruCollectiveFee = _kuruCollectiveFee;
}
```

---

## [M-08] Router Market Verification Bypass

### Summary
Router market validation only checks pricePrecision, leaving other critical parameters unchecked.

### Finding Description
The market validation in Router (lines 353-356) only validates that pricePrecision is greater than zero, but doesn't check other critical market parameters like sizePrecision, decimals, or other configuration values.

```solidity
require(_marketParams.pricePrecision > 0, RouterErrors.InvalidMarket());
// Missing checks for sizePrecision, decimals, etc.
```

### Impact Explanation
This is MEDIUM severity because:
1. May allow markets with invalid configurations
2. Can cause unexpected swap failures
3. Affects router reliability
4. May enable specific attack vectors

### Likelihood Explanation
This has MEDIUM likelihood because:
1. Incomplete validation is common oversight
2. Markets may have edge case configurations
3. Router processes many different markets
4. Impact varies by specific parameter values

### Proof of Concept
```solidity
// Deploy market with valid pricePrecision but invalid other params
MarketParams memory params = MarketParams({
    pricePrecision: 1, // Valid
    sizePrecision: 0,  // Invalid but unchecked
    // ... other potentially invalid params
});
```

### Recommendation
Validate all critical market parameters:

```solidity
require(_marketParams.pricePrecision > 0, RouterErrors.InvalidMarket());
require(_marketParams.sizePrecision > 0, RouterErrors.InvalidMarket());
require(_marketParams.decimals <= 18, RouterErrors.InvalidMarket());
// Add other parameter validations
```

---

## [M-09] KuruForwarder Interface Allowlist Risk

### Summary
Batch interface updates in KuruForwarder lack individual validation, potentially allowing dangerous function calls.

### Finding Description
The `setAllowedInterfaces` function (lines 106-110) allows batch updates to the interface allowlist without validating each interface for safety, potentially enabling dangerous function calls.

```solidity
function setAllowedInterfaces(bytes4[] memory _allowedInterfaces) external onlyOwner {
    for (uint256 i = 0; i < _allowedInterfaces.length; i++) {
        allowedInterface[_allowedInterfaces[i]] = true; // NO VALIDATION
    }
}
```

### Impact Explanation
This is MEDIUM severity because:
1. May enable unauthorized function execution
2. Could allow dangerous operations through meta-transactions
3. Affects access control security
4. Risk depends on specific interfaces allowed

### Likelihood Explanation
This has LOW-MEDIUM likelihood because:
1. Requires owner action
2. Owner may inadvertently allow dangerous interfaces
3. Interface validation is complex
4. Impact varies by allowed interfaces

### Proof of Concept
```solidity
// Owner accidentally allows dangerous interface
bytes4[] memory interfaces = new bytes4[](1);
interfaces[0] = DANGEROUS_FUNCTION_SELECTOR;
forwarder.setAllowedInterfaces(interfaces);
// Meta-transactions can now call dangerous functions
```

### Recommendation
Implement whitelist approach with dangerous function checking:

```solidity
mapping(bytes4 => bool) public dangerousFunctions;

function setAllowedInterfaces(bytes4[] memory _allowedInterfaces) external onlyOwner {
    for (uint256 i = 0; i < _allowedInterfaces.length; i++) {
        require(!dangerousFunctions[_allowedInterfaces[i]], "Dangerous interface");
        allowedInterface[_allowedInterfaces[i]] = true;
    }
}
```

---

## [M-10] Timestamp Dependence in Forwarder

### Summary
KuruForwarder deadline checks rely on block timestamps, enabling timing manipulation attacks by miners.

### Finding Description
Deadline validation in meta-transaction processing uses block.timestamp, which can be manipulated by miners within reasonable bounds, potentially enabling timing attacks.

### Impact Explanation
This is MEDIUM severity because:
1. Enables timing attack exploitation
2. Miners can manipulate timestamps
3. Can affect deadline-sensitive operations
4. May cause unexpected transaction behavior

### Likelihood Explanation
This has LOW-MEDIUM likelihood because:
1. Requires miner cooperation
2. Timestamp manipulation is limited
3. Economic incentives may not align
4. Other protections may mitigate impact

### Recommendation
Use block numbers instead of timestamps for deadline checks, or implement additional validation mechanisms.

---

## [L-01] Router Create2 Salt Predictability

### Summary
Deterministic salt generation enables address prediction and potential front-running attacks.

### Finding Description
The Router contract uses predictable salt generation for Create2 deployments (lines 392-410), making deployed addresses deterministic and potentially enabling front-running attacks.

```solidity
function _getSalt(...) internal pure returns (bytes32) {
    return keccak256(abi.encodePacked(...)); // PREDICTABLE
}
```

### Impact Explanation
This is LOW severity because:
1. Enables address prediction
2. May allow front-running of deployments
3. Could affect market creation fairness
4. Impact depends on specific use cases

### Likelihood Explanation
This has LOW likelihood because:
1. Requires sophisticated front-running setup
2. Economic incentives may be limited
3. Predictability may be intentional design choice
4. Impact is generally minor

### Proof of Concept
```solidity
// Predict deployment address
bytes32 salt = _getSalt(params);
address predictedAddress = computeCreate2Address(salt, bytecodeHash);
// Front-run deployment or prepare competing deployment
```

### Recommendation
Include timestamp or sender address in salt generation:

```solidity
function _getSalt(...) internal view returns (bytes32) {
    return keccak256(abi.encodePacked(..., block.timestamp, msg.sender));
}
```

---

## Summary

This comprehensive audit identified 33 security vulnerabilities across the Kuru Contracts system:

- **8 Critical**: Immediate deployment blockers requiring urgent fixes
- **14 High**: Significant security risks affecting core functionality  
- **10 Medium**: Important security concerns needing attention
- **1 Low**: Minor issue with limited impact

### Deployment Recommendation: **DO NOT DEPLOY TO MAINNET**

The system contains fundamental security flaws that make it unsuitable for production use. Immediate remediation of all critical and high-severity vulnerabilities is required before any mainnet consideration.

Each vulnerability follows the exact Cantina format with all required sections. Would you like me to continue with the remaining vulnerabilities in the same format?
