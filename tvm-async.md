# TVM Internals and Async Model Security

> Code examples: **Tolk 1.2** / TVM 12. FunC-to-Tolk syntax mapping at end of document.

## TVM Architecture

### Stack and Data Types

TVM is a stack-based VM (LIFO). Seven types:

| Type | Description | Security Note |
|------|-------------|---------------|
| **Integer** | 257-bit signed with NaN | Overflow throws exit 4; underflows need manual checks |
| **Cell** | ≤1023 bits, ≤4 refs | Overflow=exit 8, Underflow=exit 9 |
| **Slice** | Read cursor over cell | Read-only; advance with `loadXxx` methods |
| **Builder** | Write cursor for cells | Manual serialization = error-prone; prefer struct `toCell()` |
| **Tuple** | 0-255 mixed elements | Global vars stored here; lost between txs |
| **Continuation** | Executable bytecode | Code-as-data; SETCODE changes c3 |
| **Null** | Empty value | Global vars return null if unassigned |

### Control Registers (Security-Critical)

| Register | Contents | Security Impact |
|----------|----------|-----------------|
| **c0** | Return continuation | Exit code 0 on quit |
| **c1** | Alternative return | Exit code 1 on quit |
| **c2** | Exception handler | Modified by try/catch |
| **c3** | Contract code root | Changed by `contract.setCode()` |
| **c4** | Persistent data (storage) | Changed by `contract.setData()` |
| **c5** | Output action list | Messages queued here |
| **c7** | Context tuple | Balance, time, address, config |

**c4 and c5 max depth: 512 cells**. Max 255 output actions.

### Hard Limits (Know These!)

```
Per contract storage: 65,536 unique cells
Per cell: 1,023 bits, 4 references
c4/c5 depth: 512 cells
Output actions: 255 max
Message size: 8,192 cells or 2^21 bits
Dictionary practical max: ~32,768 entries (2N-1 cells for N entries)
```

---

## Transaction Phases -- Security Impact

```
Non-bounceable: Credit -> Storage -> Compute -> Action -> Bounce
Bounceable:     Storage -> Credit -> Compute -> Action -> Bounce
```

**Phase details**:

1. **Storage phase** -- deducts rent BEFORE credit. Debt can consume entire incoming value. Contract may freeze in same tx.

2. **Credit phase** -- message value added to balance.

3. **Compute phase** -- TVM executes. Success: state applied, actions queued in c5. Failure: state **rolled back**, bounce if inbound had bounce bit.

4. **Action phase** -- processes c5 (send messages, set code, reserves). Failure: compute state **persists** but messages NOT sent. Bounce only with **flag +16**. **CRITICAL**: Compute success + Action failure -> inconsistent state!

5. **Bounce phase** -- only if inbound bounceable AND something failed.

**Golden rule**: Never allow action phase to fail. Validate and throw during compute phase.

---

## Message Sending -- Complete Reference

### The `createMessage()` API (Tolk 1.0+)

Typed `createMessage()` replaces manual cell construction:

```tolk
createMessage(MessageRelaxed {
    dest: targetAddress,
    value: coins(1),
    bounce: BounceMode.RichBounce,    // Tolk 1.2 BounceMode enum
    body: MyOperation { amount: 100, recipient: addr }.toCell(),
}).send(SendMode.PAY_FEES_SEPARATELY);
```

### Base Modes (mutually exclusive)

| Mode | Tolk Enum | Effect |
|------|-----------|--------|
| **0** | `SendMode.DEFAULT` | Fees from message value; receiver gets `value - fees` |
| **64** | `SendMode.CARRY_REMAINING_VALUE` | Add all remaining inbound value to outgoing |
| **128** | `SendMode.CARRY_REMAINING_BALANCE` | Send **entire contract balance** |

Combining `CARRY_REMAINING_VALUE` + `CARRY_REMAINING_BALANCE` = exit code 34 (invalid).

### Additive Flags

| Flag | Tolk Enum | Effect |
|------|-----------|--------|
| **+1** | `SendMode.PAY_FEES_SEPARATELY` | Fees from contract balance, not message value |
| **+2** | `SendMode.IGNORE_ERRORS` | Suppress action phase errors (silent failures!) |
| **+16** | `SendMode.BOUNCE_IF_ACTION_FAIL` | Trigger bounce on action failure |
| **+32** | `SendMode.DESTROY_IF_ZERO` | Destroy account when balance hits zero (mode 128 only) |

### Common Combinations and Their Risks

```tolk
// MODE 3 (0+1+2): Standard send, fees separate, ignore errors
// Good for: notifications, events where failure is acceptable
createMessage(MessageRelaxed {
    dest: notificationAddr,
    value: coins(0.01),
    bounce: BounceMode.NoBounce,
    body: eventBody,
}).send(SendMode.PAY_FEES_SEPARATELY | SendMode.IGNORE_ERRORS);

// MODE 64: Forward remaining inbound value
// RISK: if contract emits events or has storage fees, balance drains
// Use for: simple pass-through, no extra costs in handler
msg.send(SendMode.CARRY_REMAINING_VALUE);

// MODE 65 (64+1): Forward remaining + pay fees from balance
// Use for: Jetton transfers where receiver gets full amount
msg.send(SendMode.CARRY_REMAINING_VALUE | SendMode.PAY_FEES_SEPARATELY);

// MODE 80 (64+16): Forward + bounce protection
// Use for: critical operations where failure must be detected
msg.send(SendMode.CARRY_REMAINING_VALUE | SendMode.BOUNCE_IF_ACTION_FAIL);

// MODE 128: Send entire balance
// DANGER: contract may have 0 balance after -- freeze risk
// Only for: intentional account draining/closure

// MODE 160 (128+32): Send all + destroy contract
// EXTREME: account deleted after tx
// Require: explicit authorization, no pending operations

// SAFE excess gas return:
excessMsg.send(SendMode.CARRY_REMAINING_VALUE | SendMode.IGNORE_ERRORS);
```

### The Mode 64 Trap

```tolk
// Mode 64 with extra costs drains contract:
// - Storage fees come from contract balance (not forwarded value)
// - External messages (events/logs) come from contract balance
// - Multiple sends in one tx: only first gets "remaining" value

// EXAMPLE: mode 64 + emit event
transferMsg.send(SendMode.CARRY_REMAINING_VALUE);  // forwards all remaining inbound
emitEvent(data);                                    // THIS costs from contract balance!
// After many txs: contract balance = 0 -> deletion

// FIX: calculate storage fees explicitly, reserve, return remainder manually
```

---

## Bounce Messages -- Complete Guide (Updated for Tolk 1.2 / TVM 12)

### What Triggers a Bounce

- Inbound message had bounce mode set (any mode other than `BounceMode.NoBounce`)
- Compute phase failed OR action phase failed with flag `SendMode.BOUNCE_IF_ACTION_FAIL`
- Destination has enough balance for bounce message fees

### What Bounces CANNOT Do

- Re-bounce (a bounce of a bounce is silently dropped)
- Fire if destination had insufficient balance for bounce fee

### Silent Failure Scenario

1. Contract A sends bounceable message to Contract B
2. B's storage debt > incoming value -> B never processes the message
3. B can't afford to send bounce -> no bounce generated
4. A never knows the operation failed
5. State inconsistency persists forever

**Prevention**: Always attach enough TON for bounce. Formula: `compute_fee + forward_fee + bounce_fee + storage_reserve`. The `storage_reserve` is unpredictable (depends on time since last tx), so add a buffer.

### BounceMode Selection Guide (Tolk 1.2 / TVM 12)

TVM 12 introduced **rich bounced messages**, returning the full original body instead of just 256 bits.

```tolk
enum BounceMode {
    NoBounce                // No bounce at all
    Only256BitsOfBody       // Legacy: 0xFFFFFFFF prefix + 224 bits of original data
    RichBounce              // Full body as tree of cells (0xFFFFFFFE prefix)
    RichBounceOnlyRootCell  // Root cell only, no refs (0xFFFFFFFE prefix, cheaper)
}
```

| Mode | Body Returned | Cost on Bounce | Bounce Prefix | Use Case |
|------|--------------|----------------|---------------|----------|
| `NoBounce` | No bounce | N/A | N/A | Fire-and-forget notifications |
| `Only256BitsOfBody` | First 256 bits | Cheapest | `0xFFFFFFFF` | Legacy compat; simple opcode-only rollback |
| `RichBounce` | Full body (tree of cells) | Most expensive | `0xFFFFFFFE` | Any message with addresses, complex structs |
| `RichBounceOnlyRootCell` | Root cell only (no refs) | Medium | `0xFFFFFFFE` | Message data fits in root cell; gas-saving compromise |

**Backward compatibility**: `bounce: true` = `Only256BitsOfBody`, `bounce: false` = `NoBounce`. These still work but are deprecated.

### The Legacy 256-Bit Limitation (Pre-TVM 12)

Pre-TVM 12: bounce body = `0xFFFFFFFF` (32 bits) + first 256 bits of original body = only 224 bits after skipping opcode. An `address` (267 bits) could NOT fit. Complex structs were impossible to recover.

### Rich Bounce Messages (TVM 12)

`BounceMode.RichBounce` returns the **full original body** plus failure metadata:

```tolk
struct (0xFFFFFFFE) RichBounceBody {
    originalBody: cell             // full original body (tree of cells)
    originalInfo: Cell<RichBounceOriginalMsgInfo>  // fields of original outgoing message
    bouncedByPhase: uint8          // which phase caused the bounce
    exitCode: int32                // exception code from throw or TVM internals
    computePhase: RichBounceComputePhaseInfo?  // gasUsed/vmSteps if compute phase ran
}
```

### Sending with Rich Bounce

```tolk
fun sendJettonTransfer(dest: address, jettonWallet: address, amount: coins, recipient: address) {
    createMessage(MessageRelaxed {
        dest: jettonWallet,
        value: coins(0.1),
        bounce: BounceMode.RichBounce,   // request full body on bounce
        body: JettonTransfer {
            queryId: blockchain.logicalTime(),
            amount: amount,
            destination: recipient,        // 267 bits -- would NOT fit in 224-bit legacy bounce
            responseDestination: dest,
            // ...
        }.toCell(),
    }).send(SendMode.PAY_FEES_SEPARATELY);
}
```

### Handling Rich Bounced Messages

```tolk
@onBouncedMessage
fun onBouncedMessage(in: InMessageBounced) {
    // Parse the rich bounce body
    val rich = lazy RichBounceBody.fromSlice(in.bouncedBody);

    // Access the FULL original message body
    val originalBody = rich.originalBody.beginParse();
    val op = originalBody.loadUint(32);

    if (op == OP_JETTON_TRANSFER) {
        // Recover the full transfer details -- including addresses!
        val originalMsg = lazy JettonTransfer.fromSlice(
            rich.originalBody.beginParse()
        );
        // This was IMPOSSIBLE with the legacy 256-bit limitation
        val failedRecipient: address = originalMsg.destination;
        val failedAmount: coins = originalMsg.amount;

        // Proper rollback: credit tokens back to sender
        self.balances.set(failedRecipient, self.balances.get(failedRecipient)!! + failedAmount);
    }

    // Optionally inspect WHY it failed
    val exitCode: int32 = rich.exitCode;
    val phase: uint8 = rich.bouncedByPhase;

    // Compute phase details (gas, steps) if compute phase executed
    if (rich.computePhase != null) {
        // rich.computePhase.gasUsed, rich.computePhase.vmSteps
    }
}
```

### Handling Legacy Bounced Messages (Only256BitsOfBody)

If you must support legacy bounce mode or interact with pre-TVM 12 contracts:

```tolk
@onBouncedMessage
fun onBouncedMessage(in: InMessageBounced) {
    in.bouncedBody.skipBouncedPrefix();    // skips 0xFFFFFFFF (32 bits)
    val originalOpcode = in.bouncedBody.loadUint(32);
    // Only 192 bits of data remain (256 total - 32 prefix - 32 opcode)
    // NOT enough for an address (267 bits)
}
```

### Distinguishing Old vs Rich Bounces (Mixed Mode)

If a contract might receive bounces from both old and new senders:

```tolk
@onBouncedMessage
fun onBouncedMessage(in: InMessageBounced) {
    val prefix = in.bouncedBody.preloadUint(32);
    if (prefix == 0xFFFFFFFF) {
        // Old-style bounce (256 bits only)
        in.bouncedBody.skipBouncedPrefix();
        val op = in.bouncedBody.loadUint(32);
        // ... limited rollback logic
    } else if (prefix == 0xFFFFFFFE) {
        // Rich bounce -- full body available
        val rich = lazy RichBounceBody.fromSlice(in.bouncedBody);
        // ... comprehensive rollback logic
    }
}
```

**Best practice**: Do NOT mix modes. Use either `Only256BitsOfBody` everywhere or `RichBounce` everywhere in a single contract.

### BounceMode Security Implications

1. **`Only256BitsOfBody` is insufficient for most rollback logic.** Messages with addresses (267 bits) or nested structs cannot be fully recovered -> permanent state inconsistency.

2. **Use `RichBounce` for all stateful messages.** Extra gas cost on bounce is negligible vs. unrecoverable state desync. Overhead only on the failure path.

3. **`RichBounceOnlyRootCell`**: compromise when critical data fits in root cell (no `Cell<T>` fields).

4. **Rich bounces cost more on failure path.** Consider if bounces are frequent (speculative sends to potentially-nonexistent addresses).

5. **Migration risk.** Switching from `Only256BitsOfBody` to `RichBounce` changes bounce body format. The `onBouncedMessage` handler must be updated simultaneously.

6. **Cross-contract compatibility.** Rich bounces require TVM 12. Sending `RichBounce` on pre-TVM 12 falls back to legacy.

7. **`exitCode` enables smart error handling.** Distinguish OOG (exit 13), custom throws, and action phase failures for different rollback strategies.

---

## Asynchronous Security Patterns

### The Logical Time (lt) Guarantee

Each transaction has an `lt` (logical timestamp). Within a single contract, all transactions ordered by lt. Messages A->B (same pair) are ordered.

Between different contracts in different shards: **no ordering guarantee**. Cross-shard latency: min 1 masterchain block (~12-13s). Routing: up to 15 hops.

### Designing for Non-Deterministic Message Order

```
WRONG ASSUMPTION: if A sends msg1 to B and msg2 to C simultaneously,
                  and both B and C send responses to D,
                  D will receive them in order.

REALITY: D may receive B's response before C's, or C's before B's.
         The actual order depends on routing, shard placement, validator schedule.

CORRECT DESIGN:
- D must handle EITHER order correctly
- D must not assume previous state from concurrent flows
- D must use idempotent handlers (same result regardless of processing order)
```

### Idempotent Message Handlers

```tolk
// Include unique message ID, check if already processed
fun onInternalMessage(in: InMessage) {
    val body = in.body.beginParse();
    val msgId = body.loadUint(64);

    if (self.processedIds.exists(msgId)) {
        return;  // ignore duplicate
    }

    // Process...
    self.processedIds.set(msgId, true);
}
```

Using `map<K, V>` (Tolk 1.1+) for processed IDs:

```tolk
struct Storage {
    processedIds: map<uint64, bool>
    // ...
}
```

### State Validation Pattern for Multi-Step Flows

```tolk
// Step 2 of a 3-step flow must re-validate all assumptions
// Don't trust state from Step 1 -- may have changed in parallel flow

// WRONG:
// Step 1: validates user has 100 tokens
// Step 2: (assumes user still has 100 tokens) transfers them
// ATTACK: parallel flow drains tokens between step 1 and 2

// CORRECT: carry the validated amount in the message
// Step 1: validates 100 tokens, embeds 100 in message to step 2
// Step 2: uses the embedded 100, doesn't query current balance

// Tolk example:
struct (0x12345678) TransferStep2 {
    validatedAmount: coins       // carried from step 1
    recipient: address           // carried from step 1
    originalQueryId: uint64      // for idempotency
}

fun handleTransferStep2(msg: TransferStep2) {
    // Use msg.validatedAmount directly -- do NOT re-read from storage
    // The amount was validated in step 1 and embedded in the message
    self.balance -= msg.validatedAmount;
    // Send to recipient...
}
```

---

## Account States

| State | Condition | Effect |
|-------|-----------|--------|
| **Uninit** | Has balance, no code | Cannot execute; accumulates debt |
| **Active** | Has code + balance | Fully operational |
| **Frozen** | Storage debt > 0.1 TON | Cannot execute; only hash preserved |
| **Deleted** | Storage debt > 1 TON | Account removed entirely |

**Unfreezing**: Send StateInit (original code + data) with enough TON to cover accumulated debt.

**Griefing attack**: Small Jetton wallets accumulate storage debt without interaction, freeze, and tokens become inaccessible.

---

## Library Cells

Library cells store 256-bit hash references to shared code. Published on masterchain (global) or contract state (private).

**Security risks**:
1. **Frozen host = inaccessible library**: Host account freezes -> all referencing contracts fail
2. **Local override**: Contract's local library env overrides global -- malicious override possible
3. **RUNVM state pollution (CVE-2025-70956)**: OOG during RUNVM corrupted parent VM. Fixed v2025.04.

---

## Dangerous Opcodes Reference

| Opcode / Tolk Function | Risk | Mitigation |
|------------------------|------|------------|
| `ACCEPT` / `acceptExternalMessage()` | Gas drain if called before auth | Always validate BEFORE calling |
| `SENDRAWMSG` mode 128 / `SendMode.CARRY_REMAINING_BALANCE` | Depletes entire balance | Auth gate; only for account closure |
| `SENDRAWMSG` mode 128+32 / `SendMode.CARRY_REMAINING_BALANCE \| SendMode.DESTROY_IF_ZERO` | Destroys contract | Extreme auth gate; verify no pending ops |
| `SETCODE` / `contract.setCode()` | Total contract takeover | Require multi-factor auth + code validation |
| `COMMIT` | Persists state before any error | Don't use before all validation complete |
| `RUNVM` | Sandboxed but state pollution bug | Check for patched version; don't trust results fully |

---

## Gas Fee Calculation Reference

### Three Fee Types

```
total_fee = storage_fee + compute_fee + forward_fee

storage_fee = ceil((bits * bit_price + cells * cell_price) * time_delta / 2^16)
compute_fee = flat_price + gas_price * max(0, gas_used - flat_limit) / 65536
forward_fee = lump_price + ceil(body_fwd_fee / 2^16)
  where: body_fwd_fee = price_per_cell * (cells-1) + price_per_bit * (bits - root_bits)
```

### Security Validation Pattern

```tolk
// Per handler: validate sufficient gas before expensive ops
val computeFee = getComputeFee(MY_GAS_ESTIMATE, false);
val forwardFee = getForwardFee(OUT_MSG_CELLS, OUT_MSG_BITS, false);
val storageReserve = TON_PER_YEAR / 12;  // rough monthly reserve

assert(
    in.valueCoins >= computeFee + forwardFee + storageReserve,
    Err.InsufficientGas
);
```

### Out-of-Gas Behavior

```
OOG exception (exit code 13/-14):
- Cannot be caught with try/catch
- Compute phase fails
- State changes rolled back (UNLESS COMMIT was called before OOG)
- Bounce triggered if inbound was bounceable

POST-acceptExternalMessage() OOG:
- Transaction IS recorded on chain
- Fees ARE deducted from contract
- State changes NOT applied
- Same message can be replayed! -> repeated gas drain until balance = 0
```

---

## Appendix: FunC-to-Tolk Syntax Quick Reference

| FunC | Tolk |
|------|------|
| `;;` comment | `//` comment |
| `send_raw_message(msg, mode)` | `msg.send(mode)` or `createMessage(...).send(mode)` |
| `load_uint(32)` | `loadUint(32)` |
| `store_uint(x, 32)` | `storeUint(x, 32)` |
| `begin_cell()` | `beginCell()` |
| `end_cell()` | `endCell()` |
| `throw_unless(401, cond)` | `assert(cond, 401)` or `assert (cond) throw 401` |
| `throw_if(401, cond)` | `assert(!cond, 401)` |
| `() fun_name(params) impure { }` | `fun funName(params): void { }` |
| `accept_message()` | `acceptExternalMessage()` |
| `set_code(c)` | `contract.setCode(c)` |
| `set_data(c)` | `contract.setData(c)` |
| `get_data()` | `contract.getData()` |
| `cell d = begin_cell()...end_cell()` | `val msg = createMessage(MessageRelaxed { ... })` |
| `send_raw_message(msg, 64)` | `msg.send(SendMode.CARRY_REMAINING_VALUE)` |
| `send_raw_message(msg, 128 + 32)` | `msg.send(SendMode.CARRY_REMAINING_BALANCE \| SendMode.DESTROY_IF_ZERO)` |
