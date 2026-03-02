---
name: ton-best-practices
description: Use when auditing, reviewing, writing, or testing TON smart contracts in Tolk. Security vulnerabilities, async model pitfalls, bounce message handling, gas management, access control, serialization. Triggers: Tolk, TVM, TVM 12, TON contract, jetton, NFT TON, TON audit, bounce message, smart contract security.
---

# TON Smart Contract Best Practices (Tolk)

## Overview

TON uses an **asynchronous actor model**: one transaction changes state of **one account** processing **one message**. A single Ethereum tx can span thousands of TON txs across hundreds of blocks. This creates unique vulnerability classes absent from Solidity.

**Language**: Tolk v1.2 -- compiles to TVM 12 bytecode. Modern syntax, explicit mutation, union types, lazy fields, built-in message construction APIs.

**Based on**: 233 vulnerabilities from 34 audits (29 projects, 11 firms). Top findings: logical errors (70), auth (25), centralization (19).

**Key reference files:**
- `vulnerabilities.md` — Full vulnerability catalog with code examples
- `audit-checklist.md` — Complete audit checklist
- `tolk-security.md` — Tolk-specific language pitfalls
- `tvm-async.md` — TVM internals, async model, bounce messages (Tolk 1.2 / TVM 12)
- `tolk-best-practices.md` — Tolk language best practices

---

## TON vs EVM: Critical Differences

| Aspect | TON | EVM |
|--------|-----|-----|
| Execution | **Async** message-passing | Synchronous, atomic |
| Cross-contract | **Async messages only** (no sync calls) | Synchronous calls |
| Reentrancy | Not possible (classical form) | Major attack class |
| Failure recovery | **Manual bounce handlers required** | Automatic revert |
| Token standard | **Jetton** (separate wallet per user) | ERC-20 (central mapping) |
| Gas OOG | **Cannot be caught** in try/catch | Reverts entire tx |
| Replay protection | **Must implement manually** (seqno) | Protocol nonces |
| Storage | **Manual cell serialization**, 65536 cell limit | 256-bit slots, unbounded |
| Account freezing | **Yes** (storage debt -> frozen -> deleted) | No |
| Randomness | **Validator-manipulable** (block seed) | Same issue |

---

## Top 10 Critical Vulnerabilities (Quick Reference)

### 1. Unauthorized Access / Missing Auth Checks -- CRITICAL
All state-mutating functions must verify sender identity.

```tolk
// WRONG -- anyone can call this
fun transferOwnership(newOwner: address) {
    owner = newOwner;
    saveData();
}

// CORRECT -- verify sender
fun transferOwnership(msg: InternalMessage, newOwner: address) {
    assert(msg.sender == owner, 401);
    owner = newOwner;
    saveData();
}
```

### 2. Integer Overflow/Underflow -- CRITICAL
Tolk `int` is 257-bit signed. Overflow is **silent at runtime** -- only caught during cell serialization (exit code 5) when the value exceeds the field's bit width. Sized types (`uint32`, `uint64`, etc.) overflow silently in arithmetic until stored.

```tolk
// DANGEROUS -- silent overflow in arithmetic
var balance: uint64 = maxUint64;
balance = balance + 1; // wraps silently, NO runtime error

// Only caught here when serializing to cell:
beginCell().storeUint(balance, 64); // exit code 5 if out of range

// CORRECT -- validate before arithmetic
assert(balance + amount >= balance, 400); // overflow check
assert(fromVotes >= amount, 998);         // underflow check
fromVotes = fromVotes - amount;
```

### 3. Reentrancy via Async Messages -- HIGH
While chain A->B->C processes, attacker launches parallel chain. State checked at start may be invalid later.

**Fix**: Carry-value pattern -- embed critical values in message payload, don't query state. Debit balance **immediately** before sending dependent messages.

### 4. Lazy Loading Validation Bypass -- HIGH
Tolk's `lazy` fields defer deserialization. Unloaded portions bypass schema validation.

```tolk
struct VaultData {
    owner: address,
    lazy config: VaultConfig, // NOT loaded until accessed
    lazy ledger: Ledger,      // NOT loaded until accessed
}

// DANGEROUS -- config and ledger are NOT validated on load
fun onInternalMessage(msg: InternalMessage) {
    var data = loadData<VaultData>();
    // If only 'owner' is checked, a malformed config/ledger
    // passes deserialization silently
    assert(msg.sender == data.owner, 401);
    // ... operates without ever touching lazy fields
    saveData(data); // re-serializes unvalidated lazy data as-is
}

// CORRECT -- explicitly load and validate lazy fields when their
// invariants matter for the operation's correctness
fun onInternalMessage(msg: InternalMessage) {
    var data = loadData<VaultData>();
    assert(msg.sender == data.owner, 401);
    var config = data.config; // force load -- triggers deserialization
    assert(config.minDeposit > 0, 402); // validate invariants
}
```

### 5. Non-Exhaustive Union Type Dispatch -- HIGH
A catch-all `else` branch in `match` silently swallows unknown message types, hiding bugs or allowing unexpected operations.

```tolk
union IncomingOp {
    Transfer,
    Burn,
    Mint,
    UpdateConfig,
}

// DANGEROUS -- else hides unhandled ops
fun dispatch(op: IncomingOp) {
    match op {
        Transfer => handleTransfer(op),
        Burn => handleBurn(op),
        else => { } // silently ignores Mint and UpdateConfig!
    }
}

// CORRECT -- exhaustive match, compiler enforces all arms
fun dispatch(op: IncomingOp) {
    match op {
        Transfer => handleTransfer(op),
        Burn => handleBurn(op),
        Mint => handleMint(op),
        UpdateConfig => handleUpdateConfig(op),
    }
}
```

### 6. Incorrect Message Mode Flags -- HIGH
- **Mode 64** after mode 64 in same tx = subsequent messages fail (balance already forwarded)
- **Mode 128 + 32** = send all + destroy account -- must be authorization-gated
- **Flag +2 (IgnoreErrors)** = silent failures, state changes persist with no rollback notification

```tolk
// Use Tolk's createMessage API with mode enums
createMessage(MessageFlags.NonBounce)
    .storeAddress(destination)
    .storeCoins(amount)
    .send(SendMode.RemainingValue | SendMode.IgnoreErrors); // 64 + 2

// DANGEROUS -- mode 128 + 32 without auth check
createMessage(MessageFlags.NonBounce)
    .storeAddress(attacker)
    .storeCoins(0)
    .send(SendMode.RemainingBalance | SendMode.DestroyOnZero); // drains + destroys
```

### 7. Storage Deserialization Vulnerability -- HIGH
Mismatched `load`/`store` calls or disabled `assertEndAfterReading` allows extra data injection.

```tolk
// DANGEROUS -- extra data in slice is silently ignored
fun loadConfig(s: slice): Config {
    var owner = s.loadAddress();
    var amount = s.loadCoins();
    // missing assertEndAfterReading -- attacker can append extra data
    return Config { owner, amount };
}

// CORRECT -- ensure entire slice is consumed
fun loadConfig(s: slice): Config {
    var owner = s.loadAddress();
    var amount = s.loadCoins();
    s.assertEndAfterReading(); // throws if leftover bits/refs
    return Config { owner, amount };
}
```

### 8. Unsafe Null Assertion (`!` Operator) -- HIGH
`!` force-unwrap on nullable types crashes at runtime (TVM exit code 7) if null.

```tolk
// DANGEROUS -- crashes if jettonWallet is null
fun forwardToWallet(data: ContractData) {
    var wallet = data.jettonWallet!; // TVM crash if null
    sendTransfer(wallet, amount);
}

// CORRECT -- check before unwrap
fun forwardToWallet(data: ContractData) {
    if (data.jettonWallet == null) {
        throw(404); // explicit, testable error
    }
    var wallet = data.jettonWallet!;
    sendTransfer(wallet, amount);
}

// ALSO CORRECT -- use pattern matching
fun forwardToWallet(data: ContractData) {
    match data.jettonWallet {
        null => throw(404),
        wallet => sendTransfer(wallet, amount),
    }
}
```

### 9. Bounce Message Handling Errors -- HIGH
Bounceable message fails -> bounce returns -> **no handler = permanent fund loss**.

`BounceMode` selection (Tolk 1.2 / TVM 12):
- `BounceMode.Only256BitsOfBody` (legacy) -- bounce returns only first 256 bits of original body after the `0xFFFFFFFF` prefix. Insufficient for complex recovery.
- `BounceMode.RichBounce` (TVM 12) -- bounce returns the **FULL original message body** with prefix `0xFFFFFFFE`. Enables complete state recovery from bounced messages.

```tolk
// Bounce handler in Tolk 1.2
fun onBounceMessage(msg: BouncedMessage) {
    if (msg.isRichBounce()) {
        // Full body available (prefix 0xFFFFFFFE)
        var body = msg.body;
        var op = body.loadUint(32);
        if (op == OP_INTERNAL_TRANSFER) {
            var jettonAmount = body.loadCoins();
            var fromAddress = body.loadAddress();
            // Full recovery -- restore total_supply
            totalSupply = totalSupply - jettonAmount;
            saveData();
        }
    } else {
        // Legacy bounce (prefix 0xFFFFFFFF, only 256 bits)
        var body = msg.body;
        body.skipBits(32); // skip op
        var jettonAmount = body.loadCoins();
        // Partial recovery with limited data
        totalSupply = totalSupply - jettonAmount;
        saveData();
    }
}
```

Send messages with `BounceMode.RichBounce` on TVM 12 to enable full error recovery.

### 10. Gas Exhaustion / TON Draining -- MEDIUM
Gas exhaustion mid-flow leaves state inconsistent. OOG **cannot be caught**.

```tolk
// Validate gas BEFORE expensive operations
assert(msg.value > getComputeFee(voteGasUsage, false), 400);
```

Design each handler to be atomic. Use bounce handlers to restore state on failure. No unbounded loops over user-controlled data.

---

## Transaction Phases (Security Impact)

```
Storage Phase -> Credit Phase -> Compute Phase -> Action Phase -> Bounce Phase
```

- **Storage phase** deducts rent BEFORE credit -- if accumulated debt > incoming value -> freeze
- **Compute phase** failure: state reverts, bounce triggers automatically
- **Action phase** failure: state changes **persist** but messages NOT sent; bounce only if flag +16 set
- **Bounce phase**: only fires if inbound message had bounce bit AND there was a failure

**Critical rule**: "We cannot allow fails in action phase since there will be no bounce. Check and throw in computation phase."

---

## Carry-Value Pattern

TON cannot query another contract's state synchronously. **Embed the value in the message itself.**

```
BAD:  A sends request to B asking "what's your balance?"
       B sends back balance
       A uses balance (may be stale by now)

GOOD: A embeds required_amount in message to B
       B processes with the embedded amount
       B responds with result embedded in bounce/response
```

---

## Gas Management Rules

1. **Pre-calculate** gas for each handler; validate `msg.value >= computeFee + forwardFee`
2. **Return excess** gas: send with `SendMode.RemainingValue | SendMode.IgnoreErrors` with op `0xd53276db`
3. **No unbounded loops** over user-controlled data structures
4. **No infinite storage growth** -- tokenize into separate contracts if needed
5. **Storage fees drain balance** independently of message value -- account for rent
6. **If contract can't afford bounce** -- silent failure, funds lost

---

## Quick Security Checklist (Tolk)

```
[] All state-mutating functions check `sender == owner` or equivalent
[] `lazy` fields: verify all required fields are loaded before validation
[] Union type `match`: exhaustive -- no hidden `else` branch
[] Nullable types: no unsafe `!` force-unwrap on untrusted data
[] Integer arithmetic: check overflow before/after operation (sized types)
[] Message modes: correct flags in `createMessage`, `BounceMode` appropriate
[] `assertEndAfterReading` not disabled (prevents extra data injection)
[] Bounce handler uses correct `BounceMode` (prefer `RichBounce` on TVM 12)
[] External messages: seqno + expiration + signature validation all present
[] Async flows: balance debited immediately before sending dependent messages
```

---

## Tools

| Tool | Purpose |
|------|---------|
| [Tolk Compiler](https://docs.ton.org/develop/tolk) | Tolk v1.2 (tolk-js@1.2.0), targets TVM version 12 |
| [Misti](https://github.com/nowarp/misti) | Static analyzer -- 42 detectors, CI/CD ready |
| [TSA](https://tonsec.dev/) | Symbolic execution analyzer (bytecode-level) |
| [@ton/sandbox](https://github.com/ton-org/sandbox) | Test harness with `printTransactionFees()` |
| [BugMagnifier](https://arxiv.org/abs/2509.24444) | Async race condition simulator |
| [verifier.ton.org](https://verifier.ton.org/) | Source code verification |

Run Misti as minimum; get professional audit for production.

---

## Audit Firms (TON-Specialized)
TonBit, Beosin, Quantstamp, Nowarp, Hacken, CertiK, SlowMist, Zellic, Positive Technologies, Cantina/Spearbit, Trail of Bits

## CTF / Practice
- [TON Hack Challenge #1](https://docs.ton.org/develop/smart-contracts/security/ton-hack-challenge-1) -- 8 vulnerable contracts
- [TonBit CTF 2024](https://ctf.tonbit.xyz/)
- [Hack The TON](https://www.hacktheton.com/)
- [PositiveCTF TON](https://github.com/PositiveSecurity/PositiveCTF-TON)
