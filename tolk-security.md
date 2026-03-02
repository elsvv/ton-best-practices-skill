# Tolk Language Security Pitfalls

## Overview

Tolk replaces FunC (compiler no longer maintained as of v2025.07). Compiles to Fift assembler then TVM bitcode. Modern type system, auto-serialization, union types, nullable safety.

Tolk introduces its own security pitfalls from the gap between compile-time type safety and runtime TVM behavior: silent integer overflow, unsafe `as` casts, `lazy` validation bypass, nullable force-unwrap crashes.

**Scope**: Tolk v1.0 -- v1.2 (latest 2026-03).

---

## 1. Eliminated FunC Vulnerabilities

Tolk eliminates several FunC bug categories by design. Skip these when auditing Tolk:

### 1.1 `impure` Modifier Removal -- Silent Call Elimination (ELIMINATED)

FunC: omitting `impure` let the compiler silently remove unused function calls -- including security checks. Tolk: **all user function calls preserved by default**. Only `@pure`-marked functions eligible for removal.

### 1.2 `~` vs `.` Operator Confusion (ELIMINATED)

FunC: `.method()` (non-modifying) vs `~method()` (modifying) caused silent no-ops. Tolk: uniform dot notation with explicit `mutate` keyword, compiler-enforced:

```tolk
// Tolk: mutation is explicit and compiler-enforced
fun increment(mutate x: int) { x += 1; }
var n = 0;
increment(mutate n);  // must write "mutate" at call site
increment(n);         // COMPILE ERROR -- mutation intent unclear
```

### 1.3 Boolean `-1` vs `1` Confusion (ELIMINATED)

FunC: `true` was `-1`, not `1`, causing `if (flag == true)` to fail for `flag = 1`. Tolk: proper `bool` type.

### 1.4 Special Characters in Identifiers (ELIMINATED)

FunC allowed `+`, `-`, `~`, `?` in identifiers, enabling confusing names. Tolk: alphanumeric + underscores only.

### 1.5 Manual Storage Serialization Order (LARGELY ELIMINATED)

FunC: manual `load_data()`/`save_data()` with exact field ordering -- swapping fields corrupted storage silently. Tolk: struct-based auto-serialization ensures consistent ordering. Still possible with raw `builder`/`slice` operations.

### 1.6 Manual Message Construction Errors (LARGELY ELIMINATED)

FunC: bit-level message header construction (`store_uint(0x18, 6)`, etc.). Tolk: `createMessage()` API handles headers, bounce flags, state init automatically.

---

## 2. Type System Vulnerabilities

### 2.1 Silent Integer Overflow on Sized Types

**Severity: Critical**

Sized types (`uint32`, `int64`, `coins`) only affect **serialization** -- arithmetic produces `int` results with no bounds checking. Overflow detected only at serialization (exit code 5), far from the arithmetic.

**Vulnerable:**
```tolk
fun processDeposit(mutate storage: WalletStorage, amount: coins) {
    storage.jettonBalance += amount;
    // If jettonBalance exceeds 2^120-1 (coins max), no error here!
    // Error only when storage.save() serializes to cell (exit code 5)
    // By then, other state changes may have already occurred
    storage.save();
}
```

**Fixed:**
```tolk
const MAX_COINS: int = (1 << 120) - 1;

fun processDeposit(mutate storage: WalletStorage, amount: coins) {
    val newBalance = storage.jettonBalance + amount;
    assert (newBalance <= MAX_COINS) throw ERR_OVERFLOW;
    storage.jettonBalance = newBalance as coins;
    storage.save();
}
```

**Audit rule**: Any arithmetic on sized types (`uint32`, `int64`, `coins`) where the result is stored back to a sized field must have explicit range validation before assignment.

### 2.2 `coins` Arithmetic Loses Type Safety

**Severity: Medium**

`coins` preserves type only for `+` and `-`. All other operators degrade to `int`, silently losing type safety.

**Vulnerable:**
```tolk
fun calculateFee(totalAmount: coins, basisPoints: int): coins {
    val fee = totalAmount * basisPoints / 10000;
    // fee is `int`, not `coins` -- type safety lost!
    // If assigned to a coins field, silent truncation possible at serialization
    return fee;  // COMPILE WARNING or silent degradation
}
```

**Fixed:**
```tolk
fun calculateFee(totalAmount: coins, basisPoints: int): coins {
    val fee = mulDivFloor(totalAmount, basisPoints, 10000);
    // fee is `int` -- explicitly validate range before returning as coins
    assert (fee >= 0 && fee <= (1 << 120) - 1) throw ERR_FEE_OVERFLOW;
    return fee as coins;
}
```

### 2.3 Unsafe `as` Cast -- No Runtime Validation

**Severity: High**

`as` performs compile-time type reinterpretation with **zero runtime validation**. Casting untrusted input creates invalid typed values causing unpredictable failures.

**Vulnerable:**
```tolk
fun handleMessage(body: slice) {
    val op = body.loadUint(32) as MyOpcode;
    // If the loaded value is not a valid MyOpcode variant,
    // the enum is invalid -- equality checks fail, match throws exit code 5

    val addr = body.loadBits(267) as address;
    // If the 267 bits are not a valid MsgAddressInt, downstream sends fail
}
```

**Fixed:**
```tolk
fun handleMessage(body: slice) {
    // Let Tolk's auto-deserialization validate the opcode
    val msg = MyMessage.fromSlice(body);
    // Throws exit code 63 on opcode mismatch -- clean failure

    // For addresses, use the typed loadAddress
    val addr = body.loadAddress();
    // Validated as proper MsgAddressInt format
}
```

**Audit rule**: Every use of `as` on data from external sources (messages, storage reads, user input) is a potential vulnerability. Prefer typed deserialization (`fromSlice`, `fromCell`, `loadAddress`, `loadAny<T>`) over `as` casts.

### 2.4 Enum Cast from Invalid Integer

**Severity: High**

Casting arbitrary integer to enum via `as` does not validate the variant. Invalid enum values fail all equality checks; exhaustive `match` throws exit code 5.

**Vulnerable:**
```tolk
enum Status {
    Active = 0,
    Paused = 1,
    Closed = 2,
}

fun loadStatus(s: slice): Status {
    val raw = s.loadUint(8);
    return raw as Status;  // If raw = 99, creates invalid Status!
}
```

**Fixed:**
```tolk
enum Status {
    Active = 0,
    Paused = 1,
    Closed = 2,
}

fun loadStatus(s: slice): Status {
    val raw = s.loadUint(8);
    assert (raw >= 0 && raw <= 2) throw ERR_INVALID_STATUS;
    return raw as Status;
}

// Or better: use struct-based deserialization if Status is part of a message
```

### 2.5 Nullable Force-Unwrap (`!`) Crashes

**Severity: High**

`!` bypasses null safety and throws TVM error code 7 if null -- a raw TVM error, not a semantic application error.

**Vulnerable:**
```tolk
fun assertSenderIsAdmin(senderAddress: address, adminAddress: address?) {
    // If adminAddress is null, `!` throws error code 7 (not ERROR_NOT_OWNER)
    assert (senderAddress == adminAddress!) throw ERROR_NOT_OWNER;
}
```

**Fixed:**
```tolk
fun assertSenderIsAdmin(senderAddress: address, adminAddress: address?) {
    assert (adminAddress != null) throw ERROR_NO_ADMIN;
    // After null check, smart cast narrows adminAddress to `address`
    assert (senderAddress == adminAddress) throw ERROR_NOT_OWNER;
}
```

**Audit rule**: Every `!` operator is a potential runtime crash. Grep for all uses and verify the value is logically guaranteed non-null. Prefer `if (x != null)` smart casts.

---

## 3. `lazy` Loading Pitfalls

### 3.1 Validation Bypass with `lazy` Deserialization

**Severity: High**

`lazy` defers deserialization: fields load only when accessed. A `lazy`-loaded struct may contain **invalid data that eager `fromSlice()` would reject** -- the contract accepts it without error if invalid fields are never accessed.

**Vulnerable:**
```tolk
fun onInternalMessage(in: InMessage) {
    // lazy loading: only fields actually accessed are validated
    var storage = lazy Storage.load();

    // If storage contains a corrupted `metadata` field,
    // but we only access `balance`, no error is raised.
    // The corrupted data persists and can cause failures later.
    if (storage.balance > 0) {
        // process...
    }
    storage.save();  // Re-serializes including potentially corrupted fields
}
```

**Fixed:**
```tolk
fun onInternalMessage(in: InMessage) {
    // Use eager loading when full validation is required
    var storage = Storage.load();  // No `lazy` -- validates all fields

    if (storage.balance > 0) {
        // process...
    }
    storage.save();
}

// Reserve lazy loading for get methods and hot paths where gas matters
get fun get_balance(): coins {
    val storage = lazy Storage.load();  // OK: read-only, gas-sensitive
    return storage.balance;
}
```

**Audit rule**: Determine whether `lazy` loading is acceptable for each code path. Critical state-modifying operations should use eager loading. Get methods and read-only paths may safely use `lazy`.

### 3.2 `lazy` with Union Type Matching and `else` Branches

**Severity: Medium**

`lazy` union deserialization enables the `else` branch in `match` (eager requires exhaustive matching). An `else` branch silently accepts unexpected message types.

**Vulnerable:**
```tolk
type AllowedMessage = Transfer | Burn | Mint

fun onInternalMessage(in: InMessage) {
    val msg = lazy AllowedMessage.fromSlice(in.body);
    match (msg) {
        Transfer => { /* ... */ }
        Burn => { /* ... */ }
        // Missing: Mint handler!
        else => {
            // Silently accepts Mint AND any unknown opcode
            // This is a security gap if Mint should be handled
        }
    }
}
```

**Fixed:**
```tolk
type AllowedMessage = Transfer | Burn | Mint

fun onInternalMessage(in: InMessage) {
    val msg = lazy AllowedMessage.fromSlice(in.body);
    match (msg) {
        Transfer => { /* ... */ }
        Burn => { /* ... */ }
        Mint => { /* ... */ }
        else => {
            // Only reaches here for empty messages (top-ups) or unknown opcodes
            assert (in.body.isEmpty()) throw 0xFFFF;
        }
    }
}
```

---

## 4. Union Types and Pattern Matching

### 4.1 Non-Exhaustive Match with `else` Branches

**Severity: Medium**

With `lazy` union deserialization, `else` catches all unmatched types. New variants added to the union silently fall through to `else`. Without `lazy`, the compiler enforces exhaustive matching.

**Vulnerable:**
```tolk
// Developer adds NewAction to the union but forgets to add a match arm
type AdminAction = Upgrade | Pause | Resume | NewAction

fun handleAdmin(body: slice) {
    val msg = lazy AdminAction.fromSlice(body);
    match (msg) {
        Upgrade => { /* ... */ }
        Pause => { /* ... */ }
        Resume => { /* ... */ }
        else => { return; }  // NewAction silently ignored!
    }
}
```

**Fixed:**
```tolk
type AdminAction = Upgrade | Pause | Resume | NewAction

fun handleAdmin(body: slice) {
    // Option 1: Remove lazy to get compile-time exhaustiveness check
    val msg = AdminAction.fromSlice(body);
    match (msg) {
        Upgrade => { /* ... */ }
        Pause => { /* ... */ }
        Resume => { /* ... */ }
        NewAction => { /* ... */ }
        // No else -- compiler enforces all variants handled
    }
}
```

**Audit rule**: For security-critical dispatch (admin actions, token operations), prefer eager deserialization without `else` to get compile-time exhaustiveness guarantees.

### 4.2 `is` / `!is` Type Checks on Untrusted Data

**Severity: Low**

The `is` operator checks whether a union value matches a specific variant. When used with `lazy`-loaded data, the check reads only the opcode prefix, not the full struct. A message with a valid opcode but corrupted body fields will pass the `is` check.

```tolk
// The `is` check validates the opcode but not the full body
if (msg is Transfer) {
    // msg.amount could still be invalid if lazy-loaded
    processTransfer(msg);
}
```

---

## 5. Message Handling

### 5.1 Missing Bounce Handler

**Severity: Critical**

Without `onBouncedMessage`, bounced messages route to `onInternalMessage` with the bounce flag set. If unchecked, a bounced transfer gets processed as a new incoming transfer -- double-crediting.

**Vulnerable:**
```tolk
// No onBouncedMessage defined!
fun onInternalMessage(in: InMessage) {
    val msg = lazy AllowedMessage.fromSlice(in.body);
    match (msg) {
        InternalTransfer => {
            // This handles both real transfers AND bounced transfers!
            storage.jettonBalance += msg.jettonAmount;
            storage.save();
        }
    }
}
```

**Fixed:**
```tolk
fun onInternalMessage(in: InMessage) {
    val msg = lazy AllowedMessage.fromSlice(in.body);
    match (msg) {
        InternalTransfer => {
            storage.jettonBalance += msg.jettonAmount;
            storage.save();
        }
    }
}

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

### 5.2 BounceMode Selection Errors

**Severity: High**

`BounceMode.NoBounce` for financial messages means failures are silently lost -- tokens debited, destination never receives them, no bounce comes back.

**Vulnerable:**
```tolk
val transferMsg = createMessage({
    bounce: BounceMode.NoBounce,  // DANGEROUS for token transfers!
    dest: recipientWallet,
    value: 0,
    body: InternalTransferStep { /* ... */ }
});
transferMsg.send(SEND_MODE_CARRY_ALL_REMAINING_MESSAGE_VALUE);
```

**Fixed:**
```tolk
val transferMsg = createMessage({
    bounce: BounceMode.Only256BitsOfBody,  // Bounce on failure
    dest: recipientWallet,
    value: 0,
    body: InternalTransferStep { /* ... */ }
});
transferMsg.send(SEND_MODE_CARRY_ALL_REMAINING_MESSAGE_VALUE);
```

**Rule of thumb**:
- **Bounceable** (`Only256BitsOfBody` or `RichBounce`): transfers, burns, deploys -- messages where failure must restore state.
- **Non-bounceable** (`NoBounce`): excess returns, notifications, owner top-ups -- messages where failure is acceptable.

### 5.3 Send Mode Flag Misuse

**Severity: High**

Incorrect send mode flags can drain the contract balance or cause silent failures.

**Vulnerable:**
```tolk
// DANGEROUS: carries entire contract balance, not just remaining message value
excessMsg.send(SEND_MODE_CARRY_ALL_BALANCE);

// DANGEROUS: ignores errors on a critical burn notification
burnNotifyMsg.send(SEND_MODE_IGNORE_ERRORS);

// DANGEROUS: mode 128 + 64 is undefined behavior (both carry flags)
msg.send(SEND_MODE_CARRY_ALL_BALANCE | SEND_MODE_CARRY_ALL_REMAINING_MESSAGE_VALUE);
```

**Fixed:**
```tolk
// Return excesses: carry remaining message value, ignore errors (best-effort)
excessMsg.send(SEND_MODE_CARRY_ALL_REMAINING_MESSAGE_VALUE | SEND_MODE_IGNORE_ERRORS);

// Critical burn notification: must succeed or bounce
burnNotifyMsg.send(SEND_MODE_CARRY_ALL_REMAINING_MESSAGE_VALUE | SEND_MODE_BOUNCE_ON_ACTION_FAIL);

// Use CARRY_ALL_BALANCE only after reserving with reserveToncoinsOnBalance()
reserveToncoinsOnBalance(minBalance, RESERVE_MODE_AT_MOST);
excessMsg.send(SEND_MODE_CARRY_ALL_BALANCE | SEND_MODE_IGNORE_ERRORS);
```

### 5.4 Bounced Message Data Truncation

**Severity: Medium**

With `BounceMode.Only256BitsOfBody`, bounced messages contain only the first 256 bits of the original body (after the 32-bit bounce prefix `0xFFFFFFFF`). If critical data (like `jettonAmount`) is placed too deep in the struct, it will be truncated in the bounce.

**Vulnerable:**
```tolk
struct (0xABCDEF01) BadTransfer {
    queryId: uint64          // 64 bits
    senderAddress: address   // 267 bits -- pushes amount past 256-bit boundary!
    amount: coins            // TRUNCATED in bounce -- cannot restore balance
}
```

**Fixed:**
```tolk
struct (0xABCDEF01) GoodTransfer {
    queryId: uint64       // 64 bits
    amount: coins         // variable, typically <124 bits -- within 256-bit boundary
    senderAddress: address
    // amount is early enough to survive bounce truncation
}
```

**Audit rule**: For any bounceable message, verify that data needed for bounce recovery (typically `jettonAmount`) fits within the first 256 bits of the body after the opcode prefix.

### 5.5 Empty Message Handling

**Severity: Medium**

Contracts that do not handle empty messages (simple TON transfers / balance top-ups) will throw on opcode parsing, causing the message to bounce and the TON to be returned. This may be intentional for some contracts but is usually a bug.

**Vulnerable:**
```tolk
fun onInternalMessage(in: InMessage) {
    val msg = AllowedMessage.fromSlice(in.body);
    // Throws exit code 9 (cell underflow) on empty body!
    match (msg) { /* ... */ }
}
```

**Fixed:**
```tolk
fun onInternalMessage(in: InMessage) {
    val msg = lazy AllowedMessage.fromSlice(in.body);
    match (msg) {
        Transfer => { /* ... */ }
        Burn => { /* ... */ }
        else => {
            // Accept empty messages (balance top-ups) silently
            assert (in.body.isEmpty()) throw 0xFFFF;
        }
    }
}
```

---

## 6. Access Control in Tolk

### 6.1 Nullable Admin Pattern

**Severity: High**

Contracts use `address?` for admin to support "admin drop" (null = immutable). Force-unwrapping null admin with `!` throws TVM error 7 instead of the intended application error code.

**Vulnerable:**
```tolk
struct Storage {
    adminAddress: address?
    // ...
}

fun requireAdmin(sender: address, admin: address?) {
    // If admin is null: throws error code 7 (TVM null dereference)
    // NOT the intended ERROR_NOT_OWNER (e.g., 401)
    assert (sender == admin!) throw ERROR_NOT_OWNER;
}
```

**Fixed:**
```tolk
fun requireAdmin(sender: address, admin: address?) {
    // Explicit null check with proper error code
    assert (admin != null) throw ERROR_NO_ADMIN_SET;
    // Smart cast: admin is now `address` (not `address?`)
    assert (sender == admin) throw ERROR_NOT_OWNER;
}
```

### 6.2 Two-Step Admin Transfer

**Severity: Medium (if missing)**

Single-message admin transfer risks permanent loss of admin control if the new address is wrong.

**Vulnerable:**
```tolk
ChangeAdmin => {
    assert (in.senderAddress == storage.adminAddress) throw ERR_NOT_ADMIN;
    storage.adminAddress = msg.newAdmin;  // Immediate, irreversible
    storage.save();
}
```

**Fixed:**
```tolk
// Step 1: Current admin proposes
ChangeAdmin => {
    requireAdmin(in.senderAddress, storage.adminAddress);
    storage.nextAdminAddress = msg.newAdmin;
    storage.save();
}

// Step 2: New admin claims
ClaimAdmin => {
    assert (storage.nextAdminAddress != null) throw ERR_NO_PENDING_ADMIN;
    assert (in.senderAddress == storage.nextAdminAddress) throw ERR_NOT_PENDING_ADMIN;
    storage.adminAddress = storage.nextAdminAddress;
    storage.nextAdminAddress = null;
    storage.save();
}
```

### 6.3 Sender Address Validation Gaps

**Severity: Critical**

In TON, `in.senderAddress` is a trusted field provided by the TVM. However, contracts in multi-contract architectures (jettons, NFTs) must validate that the sender is the **expected contract** by recomputing the expected address from the state init.

**Vulnerable:**
```tolk
InternalTransferStep => {
    // Accepts transfer from ANY address claiming to be a jetton wallet!
    storage.jettonBalance += msg.jettonAmount;
    storage.save();
}
```

**Fixed:**
```tolk
InternalTransferStep => {
    // Verify sender is a legitimate jetton wallet
    if (in.senderAddress != storage.minterAddress) {
        val expectedWallet = calcAddressOfJettonWallet(
            msg.transferInitiator!, storage.minterAddress, contract.getCode()
        );
        assert (in.senderAddress == expectedWallet) throw ERR_INVALID_WALLET;
    }
    storage.jettonBalance += msg.jettonAmount;
    storage.save();
}
```

---

## 7. Storage and Serialization

### 7.1 `assertEndAfterReading` Bypass

**Severity: High**

`fromSlice()`/`fromCell()` assert all data consumed after deserialization. Disabling with `assertEndAfterReading: false` allows extra data to be silently ignored -- data injection vector.

**Vulnerable:**
```tolk
fun parseConfig(configCell: cell): Config {
    // DANGEROUS: extra data after Config fields is silently ignored
    return Config.fromCell(configCell, { assertEndAfterReading: false });
}
```

**Fixed:**
```tolk
fun parseConfig(configCell: cell): Config {
    // Default: assertEndAfterReading = true -- throws exit code 9 on extra data
    return Config.fromCell(configCell);
}

// Only disable when you explicitly handle the remaining data:
fun parseWithPayload(s: slice): (Config, slice) {
    val config = s.loadAny<Config>();  // Reads Config, advances slice
    // Remaining data is explicitly captured and processed
    return (config, s);
}
```

### 7.2 Cell Overflow (1023-bit Limit)

**Severity: Medium**

TVM cells: max 1023 bits, 4 refs. Tolk warns when a struct might exceed this. Suppressing with `@overflow1023_policy("suppress")` without analysis causes runtime serialization failures.

**Vulnerable:**
```tolk
@overflow1023_policy("suppress")  // Suppressed without analysis!
struct LargeStorage {
    owner: address           // 267 bits
    admin: address           // 267 bits
    balance1: coins          // 4-124 bits
    balance2: coins          // 4-124 bits
    balance3: coins          // 4-124 bits
    metadata: bits256        // 256 bits
    // Worst case: 267+267+124+124+124+256 = 1162 bits > 1023!
}
```

**Fixed:**
```tolk
struct LargeStorage {
    owner: address
    admin: address
    balance1: coins
    balance2: coins
    balance3: coins
    metadata: Cell<bits256>  // Moved to reference cell
    // Worst case without metadata: 267+267+124+124+124 = 906 bits -- fits
}
```

### 7.3 Global Variables Start as TVM NULL

**Severity: Medium**

Globals initialize to TVM `NULL`. Accessing before initialization causes an unhandled TVM exception. Globals cannot use smart casts for null safety.

**Vulnerable:**
```tolk
global cachedFee: int;

fun onInternalMessage(in: InMessage) {
    // If this is the first transaction ever, cachedFee is TVM NULL
    val total = in.valueCoins - cachedFee;  // CRASH: null arithmetic
}
```

**Fixed:**
```tolk
global cachedFee: int;

fun initGlobals() {
    cachedFee = calculateGasFee(BASECHAIN, GAS_LIMIT);
}

fun onInternalMessage(in: InMessage) {
    initGlobals();  // Always initialize before use
    val total = in.valueCoins - cachedFee;
}
```

**Audit rule**: Trace all global variables to verify they are initialized before first use in every possible entry point (`onInternalMessage`, `onExternalMessage`, `onBouncedMessage`, get methods).

### 7.4 Initialization Detection Fragility

**Severity: Medium**

Some contracts detect whether they are initialized by checking storage cell properties (e.g., number of references). This is fragile and breaks if the storage format changes.

**Vulnerable:**
```tolk
struct StorageLoader {
    itemIndex: uint64
    collectionAddress: address
    rest: RemainingBitsAndRefs
}

fun StorageLoader.isNotInitialized(self): bool {
    return self.rest.isEmpty();  // Relies on refs count!
    // Breaks if initialized storage format changes to have no refs
}
```

**Fixed:**
```tolk
struct Storage {
    isInitialized: bool      // Explicit flag
    itemIndex: uint64
    collectionAddress: address
    ownerAddress: address?   // null if not initialized
    content: Cell<SnakeString>?
}
```

---

## 8. Gas and Resource Management

### 8.1 Out-of-Gas Cannot Be Caught

**Severity: Critical**

`try-catch` in Tolk does NOT catch out-of-gas exceptions (TVM exit code 13). Gas exhaustion always terminates execution and reverts all state changes. This means any operation with unbounded gas consumption (map iteration, deep cell traversal) is a potential denial-of-service vector.

**Vulnerable:**
```tolk
fun processAllItems(items: map<uint64, Item>) {
    try {
        var r = items.findFirst();
        while (r.isFound) {
            val item = r.loadValue();
            processItem(item);  // If map is very large, runs out of gas
            r = items.iterateNext(r);
        }
    } catch (errCode) {
        // Will NOT catch out-of-gas! Transaction reverts completely.
    }
}
```

**Fixed:**
```tolk
const MAX_ITEMS_PER_TX = 50;

fun processItemsBatch(items: map<uint64, Item>, startKey: uint64): uint64? {
    var r = items.findFrom(startKey);
    var count = 0;
    while (r.isFound && count < MAX_ITEMS_PER_TX) {
        val item = r.loadValue();
        processItem(item);
        r = items.iterateNext(r);
        count += 1;
    }
    return r.isFound ? r.getKey() : null;  // Return continuation key
}
```

### 8.2 External Message Gas Drain

**Severity: Critical**

External messages have a small initial gas credit. Calling `acceptExternalMessage()` before validation allows attackers to drain the contract's TON balance by sending many invalid external messages (each consuming gas for processing before failing).

**Vulnerable:**
```tolk
fun onExternalMessage(inMsg: slice) {
    acceptExternalMessage();  // WRONG: accept before any validation
    val signature = inMsg.loadAny<bits512>();
    val storage = lazy Storage.load();
    assert (isSignatureValid(inMsg.hash(), signature, storage.publicKey))
        throw ERR_INVALID_SIG;
}
```

**Fixed:**
```tolk
fun onExternalMessage(inMsg: slice) {
    // 1. Validate BEFORE accepting (uses initial gas credit)
    val signature = inMsg.loadAny<bits512>();
    val msgHash = inMsg.hash();
    val storage = lazy Storage.load();
    assert (isSignatureValid(msgHash, signature, storage.publicKey))
        throw ERR_INVALID_SIG;
    assert (inMsg.loadAny<uint32>() == storage.seqno) throw ERR_INVALID_SEQNO;
    assert (inMsg.loadAny<uint32>() > blockchain.now()) throw ERR_EXPIRED;

    // 2. Only NOW accept the message (contract pays gas from here)
    acceptExternalMessage();

    // 3. Process and update state
    storage.seqno += 1;
    storage.save();
}
```

### 8.3 Insufficient TON for Gas and Fees

**Severity: High**

Multi-hop message flows (e.g., jetton transfers) require sufficient TON to cover gas at each hop plus forward fees. Failing to validate upfront leads to mid-flow failures and stuck state.

**Vulnerable:**
```tolk
AskToTransfer => {
    assert (storage.jettonBalance >= msg.jettonAmount) throw ERR_NOT_ENOUGH_BALANCE;
    storage.jettonBalance -= msg.jettonAmount;
    storage.save();
    // Sends transfer without checking if msg value covers gas + forward fees
    deployMsg.send(SEND_MODE_CARRY_ALL_REMAINING_MESSAGE_VALUE);
}
```

**Fixed:**
```tolk
AskToTransfer => {
    assert (storage.jettonBalance >= msg.jettonAmount) throw ERR_NOT_ENOUGH_BALANCE;

    val forwardedMessagesCount: int = msg.forwardTonAmount > 0 ? 2 : 1;
    assert (in.valueCoins >
        msg.forwardTonAmount +
        forwardedMessagesCount * in.originalForwardFee +
        (2 * JETTON_WALLET_GAS_CONSUMPTION + MIN_TONS_FOR_STORAGE)
    ) throw ERR_NOT_ENOUGH_TON;

    storage.jettonBalance -= msg.jettonAmount;
    storage.save();
    deployMsg.send(SEND_MODE_CARRY_ALL_REMAINING_MESSAGE_VALUE);
}
```

---

## 9. Async and Multi-Message Patterns

### 9.1 Balance-Before-Send (Race Condition Prevention)

**Severity: Critical**

TON's async model means messages are processed in separate transactions. If a contract checks a balance but debits it only after receiving a confirmation message, a second transaction can pass the same check before the first completes -- a classic double-spend.

**Vulnerable:**
```tolk
Transfer => {
    assert (storage.balance >= msg.amount) throw ERR_INSUFFICIENT;
    // Sends transfer message but does NOT debit balance yet
    // Plans to debit on confirmation message
    sendTransfer(msg);
    storage.save();  // balance unchanged!
    // RACE: second Transfer message can pass the same check
}
```

**Fixed:**
```tolk
Transfer => {
    assert (storage.balance >= msg.amount) throw ERR_INSUFFICIENT;
    storage.balance -= msg.amount;  // Debit BEFORE sending
    storage.save();
    sendTransfer(msg);
}

// Restore on bounce
fun onBouncedMessage(in: InMessageBounced) {
    in.bouncedBody.skipBouncedPrefix();
    val msg = lazy BouncedTransfer.fromSlice(in.bouncedBody);
    storage.balance += msg.amount;  // Restore on failure
    storage.save();
}
```

### 9.2 Missing Bounce Recovery

**Severity: Critical**

When a bounceable message fails, the contract must restore the debited state. Missing or incorrect bounce handlers lead to permanent loss of tokens or funds.

**Vulnerable:**
```tolk
AskToBurn => {
    assert (storage.jettonBalance >= msg.jettonAmount) throw ERR_NOT_ENOUGH_BALANCE;
    storage.jettonBalance -= msg.jettonAmount;
    storage.save();
    // Sends burn notification to minter (bounceable)
    burnMsg.send(SEND_MODE_CARRY_ALL_REMAINING_MESSAGE_VALUE);
}

// No onBouncedMessage handler!
// If minter rejects the burn, jettonBalance is permanently reduced
```

**Fixed:**
```tolk
AskToBurn => {
    assert (storage.jettonBalance >= msg.jettonAmount) throw ERR_NOT_ENOUGH_BALANCE;
    storage.jettonBalance -= msg.jettonAmount;
    storage.save();
    burnMsg.send(SEND_MODE_CARRY_ALL_REMAINING_MESSAGE_VALUE | SEND_MODE_BOUNCE_ON_ACTION_FAIL);
}

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

### 9.3 Workchain Validation

**Severity: Medium**

Sending messages to addresses in an unexpected workchain can fail silently or behave unpredictably. Contracts should validate the workchain of destination addresses.

```tolk
// Validate recipient workchain
assert (msg.transferRecipient.getWorkchain() == BASECHAIN) throw ERR_WRONG_WORKCHAIN;
```

---

## 10. Upgrade and Admin Patterns

### 10.1 Code Upgrade Without Timelock

**Severity: Critical**

Immediate code upgrade allows a compromised admin key to replace the entire contract logic in a single transaction, with no opportunity for users to exit or object.

**Vulnerable:**
```tolk
UpgradeCode => {
    requireAdmin(in.senderAddress, storage.adminAddress);
    contract.setData(msg.newData);
    contract.setCodePostponed(msg.newCode);  // Immediate effect!
}
```

**Fixed (timelock pattern):**
```tolk
struct PendingUpgrade {
    newCode: cell
    newData: cell
    executeAfter: uint32  // Timestamp
}

ProposeUpgrade => {
    requireAdmin(in.senderAddress, storage.adminAddress);
    storage.pendingUpgrade = PendingUpgrade {
        newCode: msg.newCode,
        newData: msg.newData,
        executeAfter: blockchain.now() + UPGRADE_DELAY,  // e.g., 48 hours
    }.toCell();
    storage.save();
}

ExecuteUpgrade => {
    requireAdmin(in.senderAddress, storage.adminAddress);
    assert (storage.pendingUpgrade != null) throw ERR_NO_PENDING_UPGRADE;
    val pending = storage.pendingUpgrade!.load();
    assert (blockchain.now() >= pending.executeAfter) throw ERR_UPGRADE_TOO_EARLY;
    contract.setData(pending.newData);
    contract.setCodePostponed(pending.newCode);
}

CancelUpgrade => {
    requireAdmin(in.senderAddress, storage.adminAddress);
    storage.pendingUpgrade = null;
    storage.save();
}
```

### 10.2 Admin Drop Irreversibility

**Severity: Medium**

Setting admin to `null` makes the contract permanently immutable. This is often intentional but must be a conscious, irreversible decision.

```tolk
DropAdmin => {
    requireAdmin(in.senderAddress, storage.adminAddress);
    // Irreversible! No one can ever admin this contract again.
    storage.adminAddress = null;
    storage.nextAdminAddress = null;
    storage.save();
}
```

**Audit rule**: Verify that admin drop is intentional and that all necessary configuration is finalized before dropping admin.

---

## 11. Common Code Patterns to Audit

### 11.1 Error Code Collisions

**Severity: Low**

Different error conditions sharing the same error code makes debugging and monitoring difficult. Common in contracts ported from FunC where error codes were reused.

**Vulnerable:**
```tolk
const ERR_INVALID_OP = 709
const ERR_NOT_ENOUGH_TON = 709  // Same code! Which error was it?
const ERR_NOT_ENOUGH_GAS = 707
const ERR_INVALID_WALLET = 707  // Same code!
```

**Fixed:**
```tolk
enum ErrCode {
    InvalidOp = 709,
    NotEnoughTon = 710,
    NotEnoughGas = 711,
    InvalidWallet = 712,
}
// Or use a dedicated errors.tolk file with unique constants
```

### 11.2 Bitwise `&` / `|` vs Logical `&&` / `||`

**Severity: Medium**

Tolk supports both bitwise (`&`, `|`) and logical (`&&`, `||`) operators. Bitwise operators do **not** short-circuit: both sides are always evaluated. Using `&` where `&&` is intended can cause null dereferences or unnecessary computation.

**Vulnerable:**
```tolk
// Bitwise AND: both sides always evaluated
if (flags & FLAG_ACTIVE != 0 & sender == owner) {
    // Wrong! `&` has lower precedence than `!=` and `==`
    // Parsed as: flags & (FLAG_ACTIVE != 0) & (sender == owner)
}

// No short-circuit: right side evaluated even when left is false
if (admin != null & sender == admin!) {
    // If admin is null, admin! still executes and crashes!
}
```

**Fixed:**
```tolk
// Logical AND: short-circuits, correct precedence
if ((flags & FLAG_ACTIVE) != 0 && sender == owner) {
    // Correct: checks flag first, then owner
}

// Short-circuit prevents null dereference
if (admin != null && sender == admin) {
    // admin is smart-cast to non-null by the time right side executes
}
```

**Audit rule**: Check every use of `&` and `|` in boolean contexts. If short-circuit behavior is needed (especially with nullable values), use `&&` and `||`.

### 11.3 `try-catch` with `commitContractDataAndActions()`

**Severity: Critical**

If `commitContractDataAndActions()` (formerly `COMMIT`) is called inside a `try` block, state changes are persisted even if the `try` block later throws. This can be exploited to persist malicious state.

**Vulnerable:**
```tolk
try {
    performRiskyOperation();
    commitContractDataAndActions();  // State persisted!
    // If code after this throws, catch runs but state is already committed
    anotherOperation();
} catch (errCode) {
    // State from commitContractDataAndActions is NOT rolled back
}
```

**Fixed:**
```tolk
// Move commit outside try-catch, or ensure all state changes are after commit
performRiskyOperation();
commitContractDataAndActions();

try {
    anotherOperation();
} catch (errCode) {
    // Only anotherOperation's changes are rolled back
}
```

### 11.4 Lambdas Are NOT Closures

**Severity: Low**

Tolk lambdas cannot capture variables from the enclosing scope. This is a compile-time error in Tolk (unlike JavaScript/TypeScript where closures are natural). While not a runtime vulnerability, developers coming from other languages may expect closure behavior and write incorrect code.

```tolk
val multiplier = 10;
val f = fun(x: int) { return x * multiplier; };
// COMPILE ERROR: cannot capture `multiplier` from outer scope

// Solution: pass as parameter
fun multiply(x: int, multiplier: int) { return x * multiplier; }
```

### 11.5 `AutoDeployAddress` Validation

**Severity: Medium**

When using `AutoDeployAddress` patterns to deploy child contracts, the derived address depends on the state init (code + data). If the code or initial data is wrong, the contract deploys to an unexpected address, and funds sent to the "expected" address are lost.

**Vulnerable:**
```tolk
fun calcWalletAddress(owner: address): AutoDeployAddress {
    return {
        stateInit: {
            code: walletCode,
            data: WalletStorage { balance: 0, owner }.toCell()
        }
    }
}

// If walletCode is from storage and was upgraded, the address changes!
// Existing wallets at old addresses become unreachable
```

**Fixed:**
```tolk
fun calcWalletAddress(owner: address, code: cell): AutoDeployAddress {
    // Always use the code from contract.getCode() or a consistent source
    return {
        stateInit: {
            code: code,
            data: WalletStorage { balance: 0, owner }.toCell()
        }
    }
}

// Verify the calculated address matches expectations
val expectedAddr = calcWalletAddress(owner, contract.getCode()).calculateAddress();
assert (in.senderAddress == expectedAddr) throw ERR_INVALID_WALLET;
```

### 11.6 Missing SnakeString / Cell Layout Validation

**Severity: Low**

Jetton metadata uses SnakeString encoding (linked list of cells). Contracts that accept arbitrary metadata cells without validating the encoding may store malformed data.

**Vulnerable:**
```tolk
fun SnakeString.unpackFromSlice(mutate s: slice) {
    // No validation of refs count or snake encoding format
    val snakeRemainder = s;
    s = createEmptySlice();
    return snakeRemainder;
}
```

**Fixed:**
```tolk
fun SnakeString.unpackFromSlice(mutate s: slice) {
    assert (s.remainingRefsCount() <= 1) throw ERR_INVALID_SNAKE_STRING;
    val snakeRemainder = s;
    s = createEmptySlice();
    return snakeRemainder;
}
```

### 11.7 Deprecated Fee Calculation

**Severity: Low**

Using deprecated fee calculation methods (e.g., raw `INMSG_FWDFEE` asm instruction) instead of the modern `in.originalForwardFee` field can give slightly incorrect results. This is common in contracts ported from FunC.

**Vulnerable:**
```tolk
@deprecated
fun calculateFwdFeeDeprecated(): coins
    asm "INMSG_FWDFEE"

fun getFee(): coins {
    return mulDivFloor(calculateFwdFeeDeprecated(), 3, 2);
}
```

**Fixed:**
```tolk
fun onInternalMessage(in: InMessage) {
    val fwdFee = in.originalForwardFee;  // Modern, accurate
    // Use fwdFee for fee calculations
}
```

### 11.8 Vesting External Message Silent Failure

**Severity: Medium**

The pattern where `try-catch` silently swallows errors while still incrementing seqno can cause user confusion: the transaction appears to succeed (seqno consumed, gas paid) but the intended action silently failed.

**Vulnerable:**
```tolk
fun onExternalMessage(extBody: slice) {
    // ... signature, seqno, expiry checks ...
    acceptExternalMessage();

    try {
        val attachedMsg = AttachedMessage.fromSlice(msg.rest);
        sendRawMessage(attachedMsg.msgCell, attachedMsg.sendMode);
    } catch {
        // Silently swallowed -- user thinks tx succeeded
    }

    storage.seqno += 1;
    storage.save();
}
```

**Fixed:**
```tolk
fun onExternalMessage(extBody: slice) {
    // ... signature, seqno, expiry checks ...
    acceptExternalMessage();

    try {
        val attachedMsg = AttachedMessage.fromSlice(msg.rest);
        sendRawMessage(attachedMsg.msgCell, attachedMsg.sendMode);
    } catch (errCode) {
        // Log the failure as an external message for monitoring
        val logMsg = createExternalLogMessage({
            dest: createAddressNone(),
            body: OperationFailed { seqno: storage.seqno, errCode: errCode as uint32 }
        });
        logMsg.send(SEND_MODE_IGNORE_ERRORS);
    }

    storage.seqno += 1;
    storage.save();
}
```

### 11.9 Auction / Config Validation Gaps

**Severity: Medium**

When accepting configuration structs from messages, every field must be validated for reasonable bounds. Missing validation can allow zero-price auctions, impossibly long durations, or other economically exploitable configurations.

```tolk
fun AuctionConfig.isInvalid(self): bool {
    return
        (self.minBid < MIN_TONS_FOR_STORAGE + MINTING_PRICE) |
        ((self.maxBid != 0) && (self.maxBid < self.minBid)) |
        (self.minBidStep <= 0) |
        (self.minExtendTime > 60 * 60 * 24 * 7) |  // max 7 days
        (self.duration > 60 * 60 * 24 * 365);        // max 1 year
}
```

---

## 12. Quick Reference: Severity Summary

| # | Vulnerability | Severity | Section |
|---|-------------|----------|---------|
| 1 | Silent integer overflow on sized types | Critical | 2.1 |
| 2 | `coins` arithmetic type degradation | Medium | 2.2 |
| 3 | Unsafe `as` cast (no runtime check) | High | 2.3 |
| 4 | Invalid enum from integer cast | High | 2.4 |
| 5 | Nullable force-unwrap (`!`) crash | High | 2.5 |
| 6 | `lazy` validation bypass | High | 3.1 |
| 7 | `lazy` union `else` branch catch-all | Medium | 3.2 |
| 8 | Non-exhaustive match with `else` | Medium | 4.1 |
| 9 | Missing bounce handler | Critical | 5.1 |
| 10 | Wrong BounceMode for financial messages | High | 5.2 |
| 11 | Send mode flag misuse | High | 5.3 |
| 12 | Bounce data truncation | Medium | 5.4 |
| 13 | Empty message not handled | Medium | 5.5 |
| 14 | Nullable admin force-unwrap | High | 6.1 |
| 15 | Single-step admin transfer | Medium | 6.2 |
| 16 | Missing sender address verification | Critical | 6.3 |
| 17 | `assertEndAfterReading` disabled | High | 7.1 |
| 18 | Cell overflow (1023-bit limit) | Medium | 7.2 |
| 19 | Uninitialized global variables | Medium | 7.3 |
| 20 | Fragile initialization detection | Medium | 7.4 |
| 21 | Out-of-gas uncatchable | Critical | 8.1 |
| 22 | External message gas drain | Critical | 8.2 |
| 23 | Insufficient TON for multi-hop | High | 8.3 |
| 24 | Balance debit after send (race condition) | Critical | 9.1 |
| 25 | Missing bounce recovery | Critical | 9.2 |
| 26 | Code upgrade without timelock | Critical | 10.1 |
| 27 | Error code collisions | Low | 11.1 |
| 28 | Bitwise vs logical AND/OR | Medium | 11.2 |
| 29 | COMMIT inside try-catch | Critical | 11.3 |
| 30 | `AutoDeployAddress` mismatch | Medium | 11.5 |
