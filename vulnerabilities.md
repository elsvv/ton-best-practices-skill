# TON Smart Contract Vulnerabilities -- Full Catalog (Tolk Edition)

Based on 233 vulnerabilities from 34 audit reports (29 projects, 11 audit firms, 2023-2025).
All code examples use Tolk syntax (Tolk v1.2+).

## Severity Distribution
| Level | Count | % |
|-------|-------|---|
| Critical | 11 | 4.7% |
| Major | 35 | 15.0% |
| Medium | 53 | 22.7% |
| Low | 71 | 30.5% |
| Informational | 49 | 21.0% |

---

## Category 1: Contract Design (76 vulnerabilities)

### 1.1 Authorization Issues (25 cases -- most common design flaw)

Every handler must validate the sender. Tolk provides `in.senderAddress` directly. For Jetton operations, calculate expected wallet address and compare.

```tolk
// Tolk: validate internal message sender
fun onInternalMessage(in: InMessage) {
    assert(in.senderAddress == expectedAdmin, ERROR_UNAUTHORIZED);
}
```

```tolk
// Tolk: validate Jetton wallet authenticity
val expectedWallet = calcAddressOfJettonWallet(sender, jettonMaster, walletCode);
assert(in.senderAddress == expectedWallet, ERROR_FAKE_JETTON);
```

**Fake Jetton Attack**: Attacker deploys contract claiming to be a jetton wallet. Always compute expected wallet address from master contract's state init and compare to sender.

**False Deposit Attack** (exchanges): Check BOTH `in_msgs` and `out_msgs`. If `out_msgs` contains a refund, the deposit is fake (bounce-back).

### 1.2 Centralization Risks (19 cases)

Evaluate: Can admin drain all funds in one tx? Timelock? Multi-sig? Blast radius of compromised key?

```tolk
// Red flags:
// - createMessage({dest: attacker, value: 0}).send(SEND_MODE_CARRY_ALL_BALANCE) gated only by admin check
// - contract.setCodePostponed(newCode) without timelock
// - no emergency pause mechanism
// - single-owner upgradeable contract
```

### 1.3 Input Data Processing (15 cases)

```tolk
// Always validate all input fields
fun onInternalMessage(in: InMessage) {
    val msg = TransferMessage.fromSlice(in.body);
    assert(msg.amount > 0, ERROR_INVALID_AMOUNT);
    assert(msg.amount <= MAX_SUPPLY, ERROR_OVERFLOW);

    assert(msg.destination.getWorkchain() == BASECHAIN, ERROR_WRONG_WORKCHAIN);
}
```

### 1.4 Partial Transaction Execution (6 cases)

Contract modifies state in step 1, sends message for step 2. Step 2 fails. Step 1 is NOT reverted.

**Real case -- Onton Finance**: Pool zeroed user's ledger before confirming withdrawal. Downstream failure = permanent fund loss.

**Fix**: Design for "optimistic with recovery": mark as "pending" (not irreversibly zero), finalize on success, restore on bounce.

```tolk
// Correct pattern: bounce handler restores state
fun onBouncedMessage(in: InMessageBounced) {
    in.bouncedBody.skipBouncedPrefix();
    val msg = lazy BounceOpToHandle.fromSlice(in.bouncedBody);
    val restoreAmount = match (msg) {
        InternalTransferStep => msg.jettonAmount,
        BurnNotificationForMinter => msg.jettonAmount,
    };
    var storage = lazy WalletStorage.load();
    storage.jettonBalance += restoreAmount;
    storage.save();
}
```

### 1.5 Account Freezing/Deletion

Storage debt accumulates without incoming TON:
- Debt > 0.1 TON -> **Frozen** (code/data preserved as hashes, cannot execute)
- Debt > 1 TON -> **Deleted** (account removed entirely)

Ensure adequate TON reserves. Beware Jetton wallets with tiny balances.

---

## Category 2: Asynchronous Execution Vulnerabilities (6 cases -- high impact)

### 2.1 Message Ordering Non-Determinism

Messages to **same contract**: ordered by logical time (lt). Safe.
Messages to **different contracts**: **NO ordering guarantee**. Attackers exploit this.

```
Contract A sends msg to B AND msg to C
B and C both send to D
Order D receives them: UNPREDICTABLE
```

**Real case -- Storm Trade**: Two reward messages sent independently to same contract. One **overwrote** balance instead of accumulating. User lost 5 TON reward.

**Fix**: Accumulate (`+=` not assign). Use unique message IDs for idempotency.

### 2.2 Delayed State Updates

**Real case -- TONCO**: PositionNFT had stale `feeGrowth = 0` while pool had `feeGrowth = 110`. Result: `0 - 110 = -110` (negative rewards).

**Fix**: Embed state hash in cross-contract requests. Reject if state doesn't match.

### 2.3 Race Condition Pattern

```
Assume: While flow A->B->C processes, attacker launches parallel flow A'->B->C
State at B may have changed between flows
B must re-validate ALL conditions it depended on, not trust state from flow A's start
```

---

## Category 3: Common Errors (92 vulnerabilities -- largest category)

### 3.1 Logical Errors (70 cases -- dominant!)

**Division before multiplication** (precision loss):
```tolk
// WRONG: 40 / 100 * 20 = 0 (integer division loses remainder)
val result = x / z * y;

// CORRECT: 40 * 20 / 100 = 8
val result = x * y / z;

// BEST: use mulDivFloor for overflow-safe multiply-then-divide
val result = mulDivFloor(x, y, z);
```

**Asymmetric state updates** (ThunderFinance case):
```tolk
// lpSupply increased on deposit but NEVER decreased on withdrawal
// Over time: lpSupply = 1300, actual backing = 800 -> rewards diluted
```
Fix: All state changes must have symmetric counterparts.

**Signed/unsigned confusion**:
```tolk
// Tolk has explicit signed/unsigned types in structs
struct VoteMessage {
    votes: int64;    // signed -- can be negative!
    balance: uint64; // unsigned -- always >= 0
}

// votes + balance can produce unexpected results if votes is negative!
assert(msg.votes >= 0, ERROR_NEGATIVE_VOTES); // validate sign
```

### 3.2 Bounced Message Handling (3 cases)

Every bounceable message **must** have a corresponding bounce handler.

Bounce format: 32-bit prefix `0xFFFFFFFF` + first 256 bits of original body = only **224 bits of useful data** after stripping marker.

```tolk
// Tolk bounce handler pattern
type BounceOpToHandle = InternalTransferStep | BurnNotificationForMinter

fun onBouncedMessage(in: InMessageBounced) {
    in.bouncedBody.skipBouncedPrefix();
    val msg = lazy BounceOpToHandle.fromSlice(in.bouncedBody);
    val restoreAmount = match (msg) {
        InternalTransferStep => msg.jettonAmount,
        BurnNotificationForMinter => msg.jettonAmount,
    };
    // RESTORE state -- transfer never happened
    var storage = lazy WalletStorage.load();
    storage.jettonBalance += restoreAmount;
    storage.save();
}
```

Bounced messages CANNOT be re-bounced. If bounce handler fails, no further recovery.

In `BounceMode.Only256BitsOfBody`, only 256 bits are included. Place critical data (like `jettonAmount`) early in message structs.

### 3.3 Replay Attacks (3 cases)

```tolk
// Complete replay protection pattern (wallet v5 style)
fun onExternalMessage(inMsgBody: slice) {
    var signature = inMsgBody.getLastBits(SIZE_SIGNATURE);
    var signedSlice = inMsgBody.removeLastBits(SIZE_SIGNATURE);

    val storage = lazy Storage.load();
    assert(isSignatureValid(signedSlice.hash(), signature, storage.publicKey), ERROR_INVALID_SIGNATURE);

    val msg = SignedMessage.fromSlice(signedSlice);
    assert(msg.seqno == storage.seqno, ERROR_INVALID_SEQNO);            // seqno check
    assert(msg.walletId == storage.subwalletId, ERROR_INVALID_WALLET_ID); // wallet ID check
    assert(msg.validUntil > blockchain.now(), ERROR_EXPIRED);            // expiry check

    acceptExternalMessage(); // ONLY after all checks!

    // Increment seqno immediately and commit
    storage.seqno += 1;
    storage.save();
    commitContractDataAndActions(); // commit before processing actions

    // ... process actions ...
}
```

**Front-running via signature reuse**: Signatures must include recipient address and seqno; otherwise replayed for different recipients.

### 3.4 Data Parsing / Serialization (6 cases)

```tolk
// WRONG: load 64 bits but storage had 32 bits
val cs = contract.getData().beginParse();
val balance = cs.loadUint(64); // corrupts all subsequent reads!

// CORRECT: use structs for type-safe serialization
struct WalletStorage {
    jettonBalance: coins;  // type-checked at compile time
    ownerAddress: address;
    minterAddress: address;
}
var storage = lazy WalletStorage.load(); // safe deserialization
```

Prefer structs over manual `loadUint`/`storeUint` to eliminate parsing bugs.

### 3.5 Smart Contract Updates (3 cases)

```tolk
// setCodePostponed() and setData() overwrite c3/c4; effects after current execution succeeds
// Migration must handle old storage layout gracefully
fun handleUpgrade(in: InMessage, msg: UpgradeMessage) {
    assert(in.senderAddress == storage.adminAddress, ERROR_NOT_ADMIN);
    // Optionally verify code signature
    contract.setData(migrateData(contract.getData()));
    contract.setCodePostponed(msg.newCode);
}
```

### 3.6 Exit Codes -- Do Not Use Reserved Values

```
TVM reserved: 0-127
Tolk/Tact reserved: 128-255
Custom: use 256+
```

| Code | Meaning |
|------|---------|
| 0, 1 | Normal exit -- using throw(0) looks like success! |
| 4 | Integer overflow |
| 7 | Null dereference (force-unwrap `!` on null in Tolk) |
| 8 | Cell overflow (>1023 bits or >4 refs) |
| 9 | Cell underflow (reading past end) |
| 13 | Out of gas (cannot be caught) |
| 37 | Not enough Toncoin for action |

### 3.7 Loop Dangers / DoS

```tolk
// DANGEROUS: attacker controls loop count
fun handleBatch(in: InMessage) {
    val msg = BatchMessage.fromSlice(in.body);
    var r = msg.items.findFirst();
    while (r.isFound) {
        expensiveOperation(r.loadValue());
        r = msg.items.iterateNext(r);
    }
    // No bound! Attacker sends 10,000 items -> out of gas
}

// SAFE: bound iterations
fun handleBatch(in: InMessage) {
    val msg = BatchMessage.fromSlice(in.body);
    var counter = 0;
    var r = msg.items.findFirst();
    while (r.isFound) {
        assert(counter < 250, ERROR_BATCH_LIMIT_EXCEEDED); // action list limit
        expensiveOperation(r.loadValue());
        r = msg.items.iterateNext(r);
        counter += 1;
    }
}
```

---

## Category 4: Gas Control (18 vulnerabilities)

### 4.1 Insufficient Gas Reserve

```tolk
// Validate at entry point of each handler
fun onInternalMessage(in: InMessage) {
    val requiredGas = JETTON_WALLET_GAS_CONSUMPTION
        + MIN_TONS_FOR_STORAGE
        + msg.forwardTonAmount
        + forwardedMessagesCount * in.originalForwardFee;
    assert(in.valueCoins > requiredGas, ERROR_NOT_ENOUGH_TON);
}
```

### 4.2 Dangerous Send Modes

```tolk
// SEND_MODE_CARRY_ALL_REMAINING_MESSAGE_VALUE (64): forwards ALL remaining inbound value
// PROBLEM: if contract also pays storage fees or sends external msgs,
// those come from CONTRACT balance, slowly draining it to zero

// SEND_MODE_CARRY_ALL_BALANCE (128): sends ENTIRE contract balance
// Only safe for final contract closure, with auth gate

// SEND_MODE_CARRY_ALL_BALANCE + SEND_MODE_DESTROY (128+32): send all + DESTROY CONTRACT

// SAFE excess return pattern:
val excessesMsg = createMessage({
    bounce: BounceMode.NoBounce,
    dest: responseDestination,
    value: 0,
    body: ReturnExcessesBack {
        queryId: msg.queryId,
    }
});
excessesMsg.send(SEND_MODE_CARRY_ALL_REMAINING_MESSAGE_VALUE | SEND_MODE_IGNORE_ERRORS);
```

### 4.3 Third-Party Code Execution (COMMIT Attack)

```tolk
// OOG cannot be caught with try/catch
// Attacker code:
try {
    commitContractDataAndActions(); // persist malicious state changes
    // trigger OOG here
} catch {
    // only gas cost rolls back, COMMIT changes survive!
}
```

Never execute untrusted code. Verify with signature before running.

### 4.4 Storage Fee Drain

External message fees come from **contract balance** regardless of mode 64. Combined with storage rent, balance slowly drains.

**Fix**: Calculate rent accumulation, keep reserve, avoid external messages unless necessary.

```tolk
// Notcoin pattern: reserve before sending excesses
val toLeaveOnBalance = contract.getOriginalBalance() - in.valueCoins + contract.getStorageDuePayment();
reserveToncoinsOnBalance(max(toLeaveOnBalance, calculateMinStorageFee()), RESERVE_MODE_AT_MOST);

val excessesMsg = createMessage({ /* ... */ });
excessesMsg.send(SEND_MODE_CARRY_ALL_BALANCE | SEND_MODE_IGNORE_ERRORS);
```

---

## Category 5: Randomness Vulnerabilities (1 case -- but critical)

**Real case -- TRS 404 NFT**: `random()` without seed -> validators manipulated NFT level assignment.

### How Validators Manipulate Randomness

1. Block seed: `SHA256(block_seed || contract_address)` -- validator controls `block_seed`
2. `RANDU256`: `SHA512(current_seed)` -> new seed + output -- deterministic given seed
3. Validator can choose to skip creating blocks to get favorable seed
4. 1/250 network validator can influence 0.4% of blocks -> for high-value operations: enough

### Secure Patterns

```tolk
// Tolk: minimum viable (still manipulable for high value)
randomizeLt();
val n = random() % 100;

// Tolk: better entropy mix -- mix message body hash, time, and logical time
randomizeBySeed(in.body.hash() ^ blockchain.now() ^ getLogicalTime());
randomizeLt();
val n = random() % 100;
```

**For high-stakes**: Implement commit-reveal:
1. Participants submit `hash(secret || salt)` on-chain
2. After all commits: reveal `secret`
3. Contract combines all secrets for final randomness
4. Add slashing/collateral for no-reveal

---

## Category 6: Tolk-Specific Errors (replaces legacy FunC-specific errors)

FunC's `missing impure` and `wrong ~ vs . operator` are eliminated in Tolk. Tolk introduces its own pitfalls:

### 6.1 Lazy Loading Validation Bypass

**Severity**: Medium | **Eliminated FunC vuln**: "Missing impure"

`lazy` defers deserialization -- fields not parsed until accessed. Validation depending on field values is skipped if the field is never loaded.

```tolk
// VULNERABLE: lazy field not validated
struct (0x0f8a7ea5) UserMessage {
    queryId: uint64;
    op: uint32;
    @lazy payload: Cell<TransferPayload>;  // Not validated until loaded
}

fun onInternalMessage(in: InMessage) {
    val msg = lazy UserMessage.fromSlice(in.body);
    // Bug: never loading payload means validation never happens
    if (msg.op == OP_TRANSFER) {
        // WRONG: assume payload is valid without loading/validating
        doTransfer(/* uses defaults */);
    }
}

// CORRECT: always load and validate lazy fields you use
fun onInternalMessage(in: InMessage) {
    val msg = lazy UserMessage.fromSlice(in.body);
    if (msg.op == OP_TRANSFER) {
        val payload = msg.payload.load();  // This triggers deserialization + validation
        assert(payload.amount > 0, ERROR_INVALID_AMOUNT);
        assert(payload.recipient.getWorkchain() == BASECHAIN, ERROR_WRONG_WORKCHAIN);
        doTransfer(payload.recipient, payload.amount);
    }
}
```

**Detection**: Audit all `lazy` declarations. Trace whether fields are loaded before decisions depending on their validity.

### 6.2 Non-Exhaustive Union Type Dispatch

**Severity**: Medium | **Eliminated FunC vuln**: "Wrong ~ vs . operator"

`match` with `else` silently absorbs new union variants without compiler warnings.

```tolk
type AllowedMessage = Transfer | Burn | Mint

// VULNERABLE: else branch hides unhandled message types
fun onInternalMessage(in: InMessage) {
    val msg = lazy AllowedMessage.fromSlice(in.body);
    match (msg) {
        Transfer => handleTransfer(msg),
        Burn => handleBurn(msg),
        else => {}  // Silently ignores Mint -- dangerous!
    }
}

// CORRECT: handle all union members explicitly
fun onInternalMessage(in: InMessage) {
    val msg = lazy AllowedMessage.fromSlice(in.body);
    match (msg) {
        Transfer => handleTransfer(msg),
        Burn => handleBurn(msg),
        Mint => handleMint(msg),
        // If a new type is added to AllowedMessage, this match must be updated
        else => {
            assert(in.body.isEmpty(), 0xFFFF); // only accept empty bodies as fallback
        }
    }
}
```

**Detection**: Search for `else => {}` or `else => { return; }` in match blocks. Verify all union members have explicit arms.

### 6.3 Null Force-Unwrap on Nullable Admin

**Severity**: High | **New Tolk-specific vulnerability**

`!` force-unwraps nullable types, throwing error code 7 if null. Useful as a deliberate security feature (dropped admin = null blocks admin ops), but a footgun when the null check is unintentional.

```tolk
// Pattern: nullable admin used as a security feature
fun assertSenderIsAdmin(senderAddress: address, adminAddress: address?) {
    // If adminAddress is null (admin dropped), this throws error 7
    assert(senderAddress == adminAddress!, ERROR_NOT_OWNER);
}

// DANGEROUS: accidental null dereference in non-admin context
fun getRewardRate(config: PoolConfig): int {
    // If rewardConfig was never set, this throws error 7 -- unclear to users
    return config.rewardConfig!.ratePerSecond;
}

// CORRECT: explicit null handling with meaningful error
fun getRewardRate(config: PoolConfig): int {
    assert(config.rewardConfig != null, ERROR_REWARD_NOT_CONFIGURED);
    return config.rewardConfig!.ratePerSecond;
}
```

### 6.4 Struct Field Ordering and Bounce Safety

**Severity**: Medium | **New Tolk-specific vulnerability**

Struct field order determines serialization layout. With `BounceMode.Only256BitsOfBody`, bounced messages carry only ~256 bits. Critical fields placed late are truncated, preventing state restoration.

```tolk
// VULNERABLE: amount field placed after large fields -- truncated in bounce
struct (0xABCD1234) TransferPayload {
    queryId: uint64;           // 64 bits
    sender: address;           // 267 bits -- already past 256-bit bounce limit!
    amount: coins;             // TRUNCATED in bounced message
    recipient: address;
}

// CORRECT: critical fields (amount) placed early
struct (0xABCD1234) TransferPayload {
    queryId: uint64;           // 64 bits
    amount: coins;             // within 256-bit bounce limit
    sender: address;
    recipient: address;
}
```

**Detection**: Verify bounce-critical fields fit within first 256 bits (after 32-bit opcode).

---

## Category 7: Best Practices Violations (36 cases)

### Documentation (23 cases)
- All message opcodes documented
- Message flow diagrams maintained
- Storage layout documented (struct definitions with field types)
- Upgrade procedures documented

### Magic Numbers -> Named Constants
```tolk
// WRONG
if (op == 0x178d4519) { /* ... */ }
msg.send(160);

// CORRECT
const OP_BURN_NOTIFICATION = 0x178d4519;
const SEND_WHOLE_BALANCE_AND_DESTROY = SEND_MODE_CARRY_ALL_BALANCE + 32;

// BEST: Tolk struct opcodes define constants at the type level
struct (0x178d4519) BurnNotificationForMinter {
    queryId: uint64;
    jettonAmount: coins;
    burnInitiator: address;
    sendExcessesTo: address?;
}
```

### Standards Compliance
- Jetton: TEP-74, TEP-89
- NFT: TEP-62, TEP-66
- Follow standard message formats exactly
- Use typed union dispatch instead of raw `op` checks

---

## Real-World Case Studies

### Onton Finance -- Missing Rebound (Critical)
Pool zeros user ledger before confirming withdrawal. Downstream failure = permanent asset loss. Always implement `onBouncedMessage` with state restoration.

### TONCO -- Async State Desync (Major)
Stale feeGrowth in PositionNFT; rewards calculated negative. Embed state hashes in cross-contract requests.

### Storm Trade -- Race Condition Rewards (Major)
Concurrent reward messages overwrote each other. Use `+=` accumulation, never assignment.

### ThunderFinance -- lpSupply Never Decremented (Major)
Deposit increases lpSupply; withdrawal does NOT decrease. Audit all state mutations for symmetry.

### EVAA -- Wrong Collateral Factor (Major)
`calculateMaximumWithdrawAmount()` ignored per-asset risk weights. Protocol undercollateralized.

### TRS 404 NFT -- Predictable Random (Critical)
`random()` without seed -> validator manipulation of NFT attributes. Use commit-reveal for high-stakes randomness.

### EVAA -- Missing `impure` (Major) -- **Eliminated in Tolk**
FunC: compiler removed `ton::cell_fwd_fee()` call (no `impure`) -> gas calculation skipped. Tolk: all functions impure by default -- this vulnerability class is eliminated.

### ThunderFinance -- Gas + No Bounce (Major)
No gas calculation + no bounce handler = partial execution with inconsistent state. Always validate `in.valueCoins` against required gas and implement `onBouncedMessage`.
