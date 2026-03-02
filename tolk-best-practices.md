# Tolk Best Practices for Security Auditors and Developers

> Tolk v1.2 (tolk-js@1.2.0) / TVM 12 -- March 2026
> For auditing and writing secure TON smart contracts

## Table of Contents

1. [Project Structure and Compilation](#1-project-structure-and-compilation)
2. [Type System Best Practices](#2-type-system-best-practices)
3. [Struct and Union Patterns](#3-struct-and-union-patterns)
4. [Message Handling Patterns](#4-message-handling-patterns)
5. [Access Control Patterns](#5-access-control-patterns)
6. [Integer and Arithmetic Safety](#6-integer-and-arithmetic-safety)
7. [Storage Patterns](#7-storage-patterns)
8. [Gas Management](#8-gas-management)
9. [Upgrade Patterns](#9-upgrade-patterns)
10. [Map (Dictionary) Patterns](#10-map-dictionary-patterns)
11. [External Message Security](#11-external-message-security)
12. [Random Values](#12-random-values)
13. [Tolk Version-Specific Features](#13-tolk-version-specific-features)
14. [Common Anti-Patterns](#14-common-anti-patterns)
15. [Production Contract Patterns](#15-production-contract-patterns)
16. [Audit Checklist for Tolk Contracts](#16-audit-checklist-for-tolk-contracts)

---

## 1. Project Structure and Compilation

### Recommended File Organization

Production contracts follow a consistent structure. Every file has a clear responsibility:

```
my-jetton/
  errors.tolk          -- Error code constants (enums or named constants)
  storage.tolk         -- Storage structs, load/save methods
  messages.tolk        -- Message structs with opcodes, union types
  fees-management.tolk -- Gas/fee constants and calculation helpers
  jetton-wallet.tolk   -- Main contract logic: onInternalMessage, onBouncedMessage, get methods
  jetton-minter.tolk   -- Second contract (minter) with its own entrypoints
```

**Audit note**: Tolk uses a flat namespace. All top-level symbols across all imported files must have unique names. Name collisions between files produce compile errors, but collisions between error code *values* do not -- check manually.

### Imports

```tolk
import "errors"                // imports errors.tolk from project
import "storage"               // imports storage.tolk
import "@stdlib/gas-payments"  // imports stdlib module
```

- `@stdlib/common.tolk` is auto-imported (provides `beginCell`, `contract.*`, `blockchain.*`, etc.)
- No `export` keyword -- all declarations are public by default
- All symbols from an imported file become available in the importing file

### Compiler Settings

- Compile with `@ton/tolk-js@1.2.0` (requires TVM 12 on the network)
- The compiler auto-inlines small and single-call functions -- no need for manual `@inline` in most cases
- Use `@inline_ref` for large rarely-called functions (compiled as separate code cells, cheaper to call on cold paths)
- Use `@noinline` only if a function reference is taken or if compile time is problematic

### The `@lazy` Annotation on Struct Fields

Not to be confused with `lazy` keyword for loading -- `@lazy` on a struct field defers its serialization into a separate `Cell<T>`:

```tolk
struct ItemStorage {
    itemIndex: uint64
    collectionAddress: address
    @lazy content: Cell<SnakeString>   // stored as cell reference, loaded on demand
}
```

**Security note**: `@lazy` fields in structs that contain user-supplied data should be validated after loading. The lazy mechanism skips the field unless accessed, so a malicious payload may go unvalidated if the field is never read in a particular code path.

### Strict Mode Behaviors

The Tolk 1.2 compiler enforces several safety checks:

- **Borrow checker**: Concurrent mutation of the same variable is a compile error
- **Exhaustive match**: Union match without `else` must cover all variants
- **Nullable enforcement**: Cannot use `T?` value without null check (smart cast)
- **`assertEndAfterReading: true`** (default): Deserialization fails if extra data remains
- **1023-bit overflow warning**: Compiler warns if a struct may exceed a single cell

---

## 2. Type System Best Practices

### Use Sized Integer Types

```tolk
// GOOD -- explicit sizes document the contract's expectations
struct TransferMessage {
    queryId: uint64        // 64-bit unsigned
    amount: coins          // variable-length 0..2^120-1
    destination: address   // 267-bit internal address
}

// AVOID -- int is 257-bit, not serializable
var x: int = 100;         // cannot serialize directly
```

**Critical**: Arithmetic on sized types degrades to `int` at runtime. No overflow checking occurs during computation -- overflow is only caught at serialization time (exit code 5):

```tolk
var a: uint8 = 200;
var b: uint8 = 100;
var c = a + b;    // c is `int` (value 300), no error
// Storing c back to uint8 would throw exit code 5
```

### Prefer `address` Over `any_address` (Tolk 1.2+)

Since Tolk 1.2, the `address` type only accepts internal addresses, validated by TVM 12's `LDSTDADDR` instruction (throws excno 9 if not internal). This eliminates an entire class of vulnerabilities:

```tolk
// GOOD -- address is guaranteed internal, no manual isInternal() check needed
struct Storage {
    owner: address         // auto-validated on deserialization
}

// Use address? for optional addresses (null = addr_none)
struct Storage {
    admin: address?        // null means "no admin"
}

// Use any_address ONLY when you must accept external addresses
struct ExternalRegistry {
    target: any_address    // requires manual isInternal() checks!
}
```

**Audit note**: When reviewing Tolk 1.2 contracts, `address` fields do not need `isInternal()` validation. But `any_address` fields still require the old checks. Watch for incorrect usage of `any_address` where `address` would suffice.

### Nullable Address Patterns

```tolk
// GOOD -- use address? with null for "absent"
struct Storage {
    admin: address?        // null = no admin (addr_none in TL-B)
}

// BAD -- magic sentinel addresses
struct Storage {
    admin: address         // "zero address" used as sentinel -- fragile
}

// Safe null check pattern
fun requireAdmin(sender: address, admin: address?) {
    assert (admin != null) throw ERROR_NO_ADMIN;
    assert (sender == admin) throw ERROR_NOT_ADMIN;
}
```

### Use `Cell<T>` for Typed Cell References

```tolk
struct MinterStorage {
    walletCode: cell                    // untyped -- any cell
    vestingParams: Cell<VestingParams>  // typed -- compiler knows the content
}

// Loading a typed cell validates the content structure
val params = storage.vestingParams.load();

// With opcode validation
val msg = lazy storage.msgRef.load({
    throwIfOpcodeDoesNotMatch: ERROR_INVALID_OP
});
```

### Avoid `as` Casts From Raw Data

The `as` operator performs NO runtime validation:

```tolk
// DANGEROUS -- no validation whatsoever
val addr = someSlice as address;      // could be garbage
val color = userInput as Color;       // could be invalid enum value (UB!)

// SAFE -- use structured deserialization
val addr = someSlice.loadAddress();   // validated by TVM
val msg = MyStruct.fromSlice(s);      // validates structure + asserts end
```

### Enum Types (Tolk 1.1+)

Enums are validated on deserialization -- invalid values throw excno 5:

```tolk
enum Role: int8 {
    Admin       // 0
    User        // 1
    Guest       // 2
}

// Deserialization: loading value 50 from a slice throws excno 5
// This prevents invalid state transitions via crafted enum values

// DANGEROUS: `as` cast bypasses validation
val r = 50 as Role;   // UB! No error at cast time, fails on match/equality
```

**Audit note**: Verify that security-critical enums use auto-deserialization (not `as` casts). Also verify the serialization width: `enum Role: int8` uses 8 bits; auto-calculated widths use the minimum needed.

---

## 3. Struct and Union Patterns

### Define Opcodes as Struct Annotations

```tolk
struct (0x0f8a7ea5) AskToTransfer {
    queryId: uint64
    jettonAmount: coins
    transferRecipient: address
    sendExcessesTo: address?
    customPayload: cell?
    forwardTonAmount: coins
    forwardPayload: ForwardPayloadRemainder
}
```

The `(0x0f8a7ea5)` prefix is a 32-bit opcode automatically serialized/deserialized. This replaces FunC's manual `load_uint(32)` + if/else chains and prevents opcode mismatch bugs.

**Prefix size**: The prefix can be any power-of-two bit width -- `(0x12345678)` = 32 bits, `(0x000F)` = 16 bits, `(0b010)` = 3 bits.

### Use Union Types for Message Dispatch

```tolk
type AllowedMessageToWallet =
    | AskToTransfer
    | AskToBurn
    | InternalTransferStep

type BounceOpToHandle = InternalTransferStep | BurnNotificationForMinter
```

**Exhaustive matching on unions**:

```tolk
val msg = lazy AllowedMessageToWallet.fromSlice(in.body);

match (msg) {
    InternalTransferStep => handleTransfer(in, msg),
    AskToTransfer => handleAskTransfer(in, msg),
    AskToBurn => handleBurn(in, msg),
    // No else branch -- compiler ensures exhaustiveness
    // If a new message type is added to the union, this won't compile
    // until the new case is handled
}
```

**Security risk of `else` branches**:

```tolk
// RISKY -- hides new message types added to the union
match (msg) {
    AskToTransfer => { ... },
    else => {
        // This silently swallows any new message types
        // added to AllowedMessageToWallet
        assert (in.body.isEmpty()) throw 0xFFFF;
    }
}
```

Use `else` only when you intentionally want to accept unknown opcodes (e.g., for top-up messages with empty bodies). The standard pattern is:

```tolk
match (msg) {
    AskToTransfer => { ... },
    AskToBurn => { ... },
    InternalTransferStep => { ... },
    else => {
        // Accept empty messages (top-ups) only
        assert (in.body.isEmpty()) throw 0xFFFF;
    }
}
```

### Lazy Fields

Mark heavy payloads as `@lazy` to defer loading, but validate after loading when the field contains untrusted data:

```tolk
struct NftCollectionStorage {
    nextItemIndex: uint64
    ownerAddress: address
    @lazy content: Cell<CollectionContent>   // large, rarely needed
}

// When content IS needed, load and validate
fun getContent(): CollectionContent {
    val storage = lazy NftCollectionStorage.load();
    val content = storage.content.load();   // loaded on demand
    // Validation happens automatically via fromCell if assertEndAfterReading is true
    return content;
}
```

### Private and Readonly Fields (Tolk 1.1+)

```tolk
struct SecureStorage {
    private readonly secretKey: uint256   // not accessible or modifiable outside methods
    readonly ownerAddress: address        // readable but not modifiable after creation
    balance: coins                        // fully mutable
}

// Order matters: `private readonly` is correct; `readonly private` is a syntax error

fun SecureStorage.getPublicKey(self): uint256 {
    return self.secretKey;   // accessible from methods on SecureStorage
}
```

### Generic Structs

```tolk
struct (0x05138d91) NotificationOwnershipAssigned<TPayload> {
    queryId: uint64
    oldOwnerAddress: address?
    payload: TPayload
}

struct ForwardPayloadInlineWrapper<T> {
    eitherBitIsRef: bool = false
    contents: T
}
```

### Default Field Values

```tolk
struct NftDataReply {
    isInitialized: bool
    itemIndex: int
    collectionAddress: address
    ownerAddress: address? = null      // default value
    content: Cell<SnakeString>? = null // default value
}
```

---

## 4. Message Handling Patterns

### Entry Points

Tolk uses named entry points:

```tolk
fun onInternalMessage(in: InMessage) { ... }         // internal messages
fun onBouncedMessage(in: InMessageBounced) { ... }   // bounced messages
fun onExternalMessage(inMsgBody: slice) { ... }      // external messages
get fun seqno(): int { ... }                          // getter (read-only)
```

If `onBouncedMessage` is not declared, bounced messages are automatically filtered out and never reach `onInternalMessage`. This is the safe default.

### Receiving Internal Messages

```tolk
type AllowedMessage = Transfer | Burn | Mint

fun onInternalMessage(in: InMessage) {
    val msg = lazy AllowedMessage.fromSlice(in.body);

    match (msg) {
        Transfer => handleTransfer(in, msg),
        Burn => handleBurn(in, msg),
        Mint => handleMint(in, msg),
        else => {
            assert (in.body.isEmpty()) throw 0xFFFF;
        }
    }
}
```

**InMessage fields**:
- `in.senderAddress` -- sender address (already parsed, type `address`)
- `in.valueCoins` -- message value in nanotons (type `coins`)
- `in.body` -- message body as `slice`
- `in.originalForwardFee` -- forward fee from the message

### Bounce Handling (Old Style -- Only256BitsOfBody)

```tolk
type BounceOpToHandle = InternalTransferStep | BurnNotificationForMinter

fun onBouncedMessage(in: InMessageBounced) {
    in.bouncedBody.skipBouncedPrefix();  // skip 0xFFFFFFFF (32 bits)

    // Only 224 bits of original body available (256 - 32 prefix)
    val msg = lazy BounceOpToHandle.fromSlice(in.bouncedBody);
    val restoreAmount = match (msg) {
        InternalTransferStep => msg.jettonAmount,
        BurnNotificationForMinter => msg.jettonAmount,
    };

    var storage = lazy WalletStorage.load();
    storage.jettonBalance += restoreAmount;  // restore balance on bounce
    storage.save();
}
```

**Critical**: With `Only256BitsOfBody`, only the first 256 bits of the original body are returned. Place critical recovery data (opcode, queryId, amount) early in message structs. An `address` field (267 bits) will NOT fit.

### Bounce Handling (Rich Bounce -- Tolk 1.2 / TVM 12)

```tolk
fun onBouncedMessage(in: InMessageBounced) {
    val rich = lazy RichBounceBody.fromSlice(in.bouncedBody);

    // Full original body available (prefix 0xFFFFFFFE)
    val originalBody: cell = rich.originalBody;
    val exitCode: int32 = rich.exitCode;

    // Parse the FULL original body -- including addresses!
    val originalMsg = lazy JettonTransfer.fromSlice(
        rich.originalBody.beginParse()
    );
    // originalMsg.destination, originalMsg.amount all accessible
    // This was IMPOSSIBLE with the old 256-bit limitation
}
```

**RichBounceBody fields**:
- `originalBody: cell` -- full original message body (tree of cells)
- `exitCode: int32` -- exception code from throw or TVM
- `bouncedByPhase: uint8` -- which phase caused the bounce
- `computePhase: RichBounceComputePhaseInfo?` -- gasUsed, vmSteps

**Best practice**: Do NOT mix bounce modes in a single contract. Either use `Only256BitsOfBody` everywhere or `RichBounce` everywhere. The prefix bytes differ (`0xFFFFFFFF` vs `0xFFFFFFFE`) and mixing requires manual prefix detection.

If mixing is unavoidable:

```tolk
fun onBouncedMessage(in: InMessageBounced) {
    val prefix = in.bouncedBody.preloadUint(32);
    if (prefix == 0xFFFFFFFF) {
        // Old-style bounce
        in.bouncedBody.skipBouncedPrefix();
        // ... handle with 224-bit limitation
    } else if (prefix == 0xFFFFFFFE) {
        // Rich bounce
        val rich = lazy RichBounceBody.fromSlice(in.bouncedBody);
        // ... full body available
    }
}
```

### Sending Messages

```tolk
// Declarative message creation
val deployMsg = createMessage({
    bounce: BounceMode.Only256BitsOfBody,
    dest: calcDeployedJettonWallet(recipient, minterAddr, walletCode),
    value: 0,
    body: InternalTransferStep {
        queryId: msg.queryId,
        jettonAmount: msg.jettonAmount,
        transferInitiator: storage.ownerAddress,
        sendExcessesTo: msg.sendExcessesTo,
        forwardTonAmount: msg.forwardTonAmount,
        forwardPayload: msg.forwardPayload,
    }
});
deployMsg.send(SEND_MODE_CARRY_ALL_REMAINING_MESSAGE_VALUE);
```

**BounceMode choices**:

| Mode | When to Use |
|------|-------------|
| `NoBounce` | Excess returns, owner notifications, top-ups |
| `Only256BitsOfBody` | Transfers, burns, deploys (recovery data < 224 bits) |
| `RichBounce` | Complex messages where full body recovery is needed |
| `RichBounceOnlyRootCell` | Cheaper middle ground -- root cell without refs |

**Send mode choices**:

| Constant | Value | When to Use |
|----------|-------|-------------|
| `SEND_MODE_PAY_FEES_SEPARATELY` | 1 | Standard sends, deploy messages |
| `SEND_MODE_IGNORE_ERRORS` | 2 | Excess returns (failure is acceptable) |
| `SEND_MODE_CARRY_ALL_REMAINING_MESSAGE_VALUE` | 64 | Forward all remaining value (transfers) |
| `SEND_MODE_CARRY_ALL_BALANCE` | 128 | Send entire balance (after reserve) |
| `SEND_MODE_BOUNCE_ON_ACTION_FAIL` | 16 | Critical messages that must succeed |

### AutoDeployAddress for Deployments

```tolk
fun calcDeployedJettonWallet(
    ownerAddress: address,
    minterAddress: address,
    jettonWalletCode: cell
): AutoDeployAddress {
    val emptyWalletStorage: WalletStorage = {
        jettonBalance: 0,
        ownerAddress,
        minterAddress,
    };
    return {
        stateInit: {
            code: jettonWalletCode,
            data: emptyWalletStorage.toCell()
        }
    }
}

// Use as message destination (auto-deploys if needed)
val msg = createMessage({
    dest: calcDeployedJettonWallet(recipient, minter, code),
    // ...
});

// Or compute the address
val walletAddr = calcDeployedJettonWallet(recipient, minter, code).calculateAddress();
```

**With shard targeting** (Tolk 1.2):

```tolk
return {
    workchain: BASECHAIN,
    stateInit: { code: walletCode, data: walletData.toCell() },
    toShard: {
        fixedPrefixLength: 8,    // shard prefix length
        closeTo: ownerAddress    // place wallet near owner's shard
    }
}
```

### Manual Bounce Policy

```tolk
@on_bounced_policy("manual")
fun onInternalMessage(in: InMessage) {
    // Bounced messages are NOT filtered -- they arrive here too
    // Use this when you want to silently accept/ignore bounced messages
    // (e.g., wallet contracts that should always accept funds)
    match (msg) {
        Transfer => { ... },
        else => {
            // Silently ignores unknown opcodes AND bounced messages
        }
    }
}
```

**Audit note**: When `@on_bounced_policy("manual")` is used, verify that bounced messages cannot be misinterpreted as valid commands. The bounce flag is not automatically checked.

---

## 5. Access Control Patterns

### Basic Owner Check

```tolk
// SIMPLE: direct address comparison
assert (in.senderAddress == storage.ownerAddress) throw ERR_NOT_FROM_OWNER;
```

### Nullable Admin Pattern

```tolk
// SAFE: explicit null check before comparison
fun requireAdmin(sender: address, admin: address?) {
    assert (admin != null) throw ERROR_NO_ADMIN;
    assert (sender == admin) throw ERROR_NOT_ADMIN;
}

// RISKY: force-unwrap throws error code 7, not your custom error
fun assertSenderIsAdmin(senderAddress: address, adminAddress: address?) {
    assert (senderAddress == adminAddress!) throw ERROR_NOT_OWNER;
    // If adminAddress is null, TVM throws error code 7 (null dereference)
    // NOT ERROR_NOT_OWNER -- confusing for debugging
}
```

### Two-Step Admin Transfer (Notcoin Pattern)

Prevents accidental ownership transfer:

```tolk
ChangeMinterAdmin => {
    assertSenderIsAdmin(in.senderAddress, storage.adminAddress);
    storage.nextAdminAddress = msg.newAdminAddress;
    storage.save();
}

ClaimMinterAdmin => {
    assertSenderIsAdmin(in.senderAddress, storage.nextAdminAddress);
    storage.adminAddress = storage.nextAdminAddress;
    storage.nextAdminAddress = null;
    storage.save();
}
```

### Irrevocable Admin Drop

```tolk
DropMinterAdmin => {
    assertSenderIsAdmin(in.senderAddress, storage.adminAddress);
    storage.adminAddress = null;
    storage.nextAdminAddress = null;
    storage.save();
    // After this, no admin functions can ever be called again
}
```

### Workchain Validation

```tolk
// Ensure sender is on basechain (workchain 0)
assert (in.senderAddress.getWorkchain() == BASECHAIN) throw ERR_WRONG_WORKCHAIN;
```

### Wallet Address Verification (Jetton Pattern)

Prevents unauthorized internal transfers by verifying the sender's contract code matches the expected wallet code:

```tolk
if (in.senderAddress != storage.minterAddress) {
    // Verify sender is a legitimate jetton wallet
    val expectedAddr = calcAddressOfJettonWallet(
        msg.transferInitiator!,
        storage.minterAddress,
        contract.getCode()
    );
    assert (in.senderAddress == expectedAddr) throw ERR_INVALID_WALLET;
}
```

### Extension-Based Authentication (Wallet V5)

```tolk
// Auth by address, not signature -- for on-chain plugins
var (senderWorkchain, senderAddrHash) = in.senderAddress.getWorkchainAndHash();
var myWorkchain = contract.getAddress().getWorkchain();
if (myWorkchain != senderWorkchain) { return; }

val storage = lazy Storage.load();
if (!storage.extensions.exists(senderAddrHash)) { return; }
// Extension is authenticated
```

---

## 6. Integer and Arithmetic Safety

### Integer Types at Runtime

ALL arithmetic in Tolk uses TVM's native 257-bit signed integer. Sized types are only enforced during serialization:

```tolk
var a: uint8 = 200;
var b: uint8 = 100;
var c = a + b;           // c is type `int`, value 300 -- no error
var d: uint8 = a + b;    // ALSO no error at computation time
// But serializing d to a cell throws exit code 5 (300 > 255)
```

### `coins` Type Behavior

The `coins` type (0 to 2^120-1, variable 4-124 bits serialization) preserves its type only for `+` and `-`:

```tolk
val a: coins = ton("1");
val b: coins = ton("2");
val c = a + b;            // type: coins
val d = a - b;            // type: coins
val e = a * 3;            // type: int (NOT coins)
val f = a / 100;          // type: int (NOT coins)
val g = mulDivFloor(a, 3, 100);  // type: int
```

**Security implication**: After non-additive arithmetic, the result is `int` and loses the `coins` serialization constraints. Either cast back with `as coins` or store in an `int` field and validate manually.

### Safe Arithmetic Patterns

```tolk
// Balance check before deduction (prevents underflow)
assert (storage.jettonBalance >= msg.jettonAmount) throw ERR_NOT_ENOUGH_BALANCE;
storage.jettonBalance -= msg.jettonAmount;

// Sufficient TON for gas (prevents stuck messages)
assert (in.valueCoins >
    msg.forwardTonAmount +
    forwardedMessagesCount * in.originalForwardFee +
    (2 * JETTON_WALLET_GAS_CONSUMPTION + MIN_TONS_FOR_STORAGE)
) throw ERR_NOT_ENOUGH_TON;

// Safe division (use mulDivFloor to avoid intermediate overflow)
val royaltyValue = mulDivFloor(bidAmount, royaltyFactor, royaltyBase);

// Cap values to prevent overflow on serialization
val toSend = min(myBalance - MIN_TONS_FOR_STORAGE, refundAmount);
```

### Bitwise vs Logical Operators

Tolk has BOTH bitwise (`&`, `|`) and logical short-circuit (`&&`, `||`) operators. This differs from FunC which only had bitwise:

```tolk
// Bitwise AND -- both sides ALWAYS evaluated (like FunC)
if ((a > 0) & (b > 0)) { ... }

// Logical AND -- short-circuit (safe for null checks)
if (addr != null && addr.getWorkchain() == 0) { ... }

// DANGER: using & with null check -- right side evaluated even if left is false
if (addr != null & addr!.getWorkchain() == 0) { ... }  // CRASH if addr is null
```

**Audit note**: Many production contracts (migrated from FunC) use `&` and `|` for boolean conditions. This is valid but does not short-circuit. Verify there are no side effects or null dereferences on the right side when the left side would short-circuit in other languages.

---

## 7. Storage Patterns

### Standard Storage Pattern

```tolk
struct WalletStorage {
    jettonBalance: coins = 0
    ownerAddress: address
    minterAddress: address
}

fun WalletStorage.load() {
    return WalletStorage.fromCell(contract.getData());
}

fun WalletStorage.save(self) {
    contract.setData(self.toCell());
}
```

### Lazy Loading for Efficiency

```tolk
fun onInternalMessage(in: InMessage) {
    var storage = lazy WalletStorage.load();
    // Only accessed fields are loaded from the cell
    // Modifications are tracked; save() re-serializes only what changed
    storage.jettonBalance += msg.jettonAmount;
    storage.save();
}
```

**Security trade-off**: `lazy` does NOT call `assertEnd()`. It picks only requested fields and ignores extra/missing data. This is fine for contract storage (you control the format) but risky for untrusted message parsing. For storage, you always control the data, so `lazy` is safe and efficient.

### Two-Phase Storage (Uninitialized vs Initialized)

Used by NFT items that start uninitialized:

```tolk
struct NftItemStorageMaybeNotInitialized {
    contractData: slice
}

fun NftItemStorageMaybeNotInitialized.isInitialized(self) {
    return self.contractData.remainingRefsCount();
}

fun onInternalMessage(in: InMessage) {
    val rawStorage = NftItemStorageMaybeNotInitialized.fromCell(contract.getData());

    if (!rawStorage.isInitialized()) {
        // Only collection contract can initialize
        assert (in.senderAddress == uninitedSt.collectionAddress) throw ERROR_NOT_FROM_COLLECTION;
        // Initialize...
        return;
    }

    // Normal operation with fully typed storage
    var storage = lazy NftItemStorage.load();
    // ...
}
```

### Multi-Contract Storage

When a project has multiple contracts (minter + wallet, collection + item), define all storage structs in a shared `storage.tolk` but have separate `onInternalMessage` functions in each contract file:

```tolk
// storage.tolk (shared)
struct MinterStorage { totalSupply: coins; adminAddress: address?; ... }
struct WalletStorage { jettonBalance: coins; ownerAddress: address; ... }

fun MinterStorage.load() { return MinterStorage.fromCell(contract.getData()); }
fun WalletStorage.load() { return WalletStorage.fromCell(contract.getData()); }

// jetton-minter.tolk
import "storage"
fun onInternalMessage(in: InMessage) {
    var st = lazy MinterStorage.load();
    // ...
}

// jetton-wallet.tolk
import "storage"
fun onInternalMessage(in: InMessage) {
    var st = lazy WalletStorage.load();
    // ...
}
```

### commitContractDataAndActions()

For replay protection in wallet contracts, commit state changes BEFORE processing actions:

```tolk
storage.seqno += 1;
storage.save();
commitContractDataAndActions();  // commit c4 and c5 registers
// Now process potentially dangerous actions
// If actions fail, seqno is already incremented (prevents replay)
```

---

## 8. Gas Management

### Gas Constants and Fee Estimation

```tolk
import "@stdlib/gas-payments"

const MIN_TONS_FOR_STORAGE = ton("0.01")
const JETTON_WALLET_GAS_CONSUMPTION = ton("0.015")

// Static storage fee estimation
const STORAGE_SIZE_MaxWallet_bits = 1033
const STORAGE_SIZE_MaxWallet_cells = 3
const MIN_STORAGE_DURATION = 5 * 365 * 24 * 3600  // 5 years

fun calculateJettonWalletMinStorageFee() {
    return calculateStorageFee(
        BASECHAIN,
        MIN_STORAGE_DURATION,
        STORAGE_SIZE_MaxWallet_bits,
        STORAGE_SIZE_MaxWallet_cells
    );
}
```

### Precompiled Gas (Production Contracts)

Precompiled contracts have known gas consumption:

```tolk
fun getPrecompiledGasConsumption(): int?
    asm "GETPRECOMPILEDGAS"

var gasConsumption = getPrecompiledGasConsumption();
var sendTransferGas = (gasConsumption == null)
    ? GAS_CONSUMPTION_JettonTransfer
    : gasConsumption;
```

### Sufficient TON Checks

Before sending messages, verify the incoming value covers all costs:

```tolk
fun checkAmountIsEnoughToTransfer(msgValue: int, forwardTonAmount: int, fwdFee: int) {
    var fwdCount = forwardTonAmount ? 2 : 1;
    assert (msgValue >
        forwardTonAmount +
        fwdCount * fwdFee +
        forwardInitStateOverhead() +
        calculateGasFee(BASECHAIN, sendTransferGasConsumption) +
        calculateGasFee(BASECHAIN, receiveTransferGasConsumption) +
        calculateJettonWalletMinStorageFee()
    ) throw ERROR_NOT_ENOUGH_GAS;
}
```

### Balance Reservation Pattern

The reserve + carry-all pattern ensures the contract retains exactly what it needs:

```tolk
// Reserve minimum storage balance, then send everything else
reserveToncoinsOnBalance(ton("0.01"), RESERVE_MODE_EXACT_AMOUNT);
excessesMsg.send(SEND_MODE_CARRY_ALL_BALANCE | SEND_MODE_IGNORE_ERRORS);

// More precise: reserve what was there before this message
var toLeaveOnBalance = contract.getOriginalBalance()
    - in.valueCoins
    + contract.getStorageDuePayment();
reserveToncoinsOnBalance(
    max(toLeaveOnBalance, calculateJettonWalletMinStorageFee()),
    RESERVE_MODE_AT_MOST
);
```

**Audit note**: `SEND_MODE_CARRY_ALL_BALANCE` (128) after `reserveToncoinsOnBalance` sends everything except the reserved amount. Incorrect reservation could drain the contract below minimum storage balance, leading to freezing and eventual deletion.

### External Message Gas

External messages have limited gas before acceptance. Validate cheaply BEFORE calling `acceptExternalMessage()`:

```tolk
fun onExternalMessage(inMsgBody: slice) {
    // These operations use minimal gas:
    val signature = inMsgBody.loadAny<bits512>();
    val msgHash = inMsgBody.hash();
    val storage = lazy Storage.load();

    // Validate BEFORE accepting
    assert (isSignatureValid(msgHash, signature, storage.publicKey)) throw ERR_INVALID_SIG;
    assert (storage.seqno == inMsgBody.loadAny<uint32>()) throw ERR_INVALID_SEQNO;

    // ONLY NOW accept (and pay gas from contract balance)
    acceptExternalMessage();
    // ... process
}
```

### Gas Monitoring

```tolk
val gasUsed = getGasConsumedAtTheMoment();
// Use to decide whether to continue processing or stop early
```

---

## 9. Upgrade Patterns

### Basic Code Upgrade

```tolk
UpgradeCode => {
    assertSenderIsAdmin(in.senderAddress, storage.adminAddress);
    contract.setData(msg.newData);
    contract.setCodePostponed(msg.newCode);
    // WARNING: setCodePostponed takes effect in the NEXT transaction
    // The current transaction continues with the OLD code
}
```

**Critical security notes**:

1. `contract.setCodePostponed()` changes code for the NEXT transaction, not the current one
2. `contract.setData()` changes data IMMEDIATELY in the current transaction
3. No timelock or multisig -- a compromised admin key allows instant full control
4. After code upgrade, the storage format may change -- verify data migration

### Recommended Upgrade Pattern

```tolk
struct (0x1234) UpgradeCode {
    newCode: cell
    newData: cell
    migratePayload: cell?   // optional migration data
}

UpgradeCode => {
    // 1. Verify admin authority
    assertSenderIsAdmin(in.senderAddress, storage.adminAddress);

    // 2. Optionally require timelock
    // assert (blockchain.now() >= storage.upgradeUnlockTime) throw ERROR_TIMELOCK;

    // 3. Update code and data
    contract.setData(msg.newData);
    contract.setCodePostponed(msg.newCode);

    // 4. Do NOT access state or call functions that depend on new code
    // The new code takes effect in the next transaction
}
```

**Audit checklist for upgrades**:
- Is upgrade protected by multisig, timelock, or governance?
- Can the admin upgrade to malicious code that drains all funds?
- Is there a mechanism to renounce upgrade capability?
- Is data migration handled correctly between old and new storage formats?

---

## 10. Map (Dictionary) Patterns

### Basic Map Usage (Tolk 1.1+)

```tolk
var balances: map<address, coins> = createEmptyMap();

balances.set(userAddr, ton("100"));
balances.addIfNotExists(userAddr, ton("0"));  // only if not present

val exists = balances.exists(userAddr);   // true/false
val empty = balances.isEmpty();           // true if no entries

balances.delete(userAddr);
```

### Safe Lookup Pattern

`map.get()` returns `MapLookupResult`, NOT an optional. This is a deliberate design for zero-overhead distinction between "key not found" and "value is null":

```tolk
// CORRECT pattern
var r = balances.get(userAddr);
if (r.isFound) {
    val balance = r.loadValue();
    // use balance
}

// WRONG -- does NOT work
var v = balances.get(userAddr);
if (v != null) { ... }  // Compile error or wrong behavior

// With default value
val balance = balances.get(userAddr).isFound
    ? balances.mustGet(userAddr)
    : 0;

// Or use mustGet with custom error code
val balance = balances.mustGet(userAddr, ERROR_USER_NOT_FOUND);
```

### Map Iteration

```tolk
var r = balances.findFirst();
while (r.isFound) {
    val key = r.getKey();
    val value = r.loadValue();
    // process...
    r = balances.iterateNext(r);
}
```

**Gas warning**: Map iteration is O(n) with significant per-entry gas cost. For large maps, iteration can exceed gas limits. Consider batch processing patterns or off-chain computation.

### Map Key and Value Constraints

| Valid Keys | Invalid Keys | Valid Values | Invalid Values |
|------------|-------------|-------------|----------------|
| `int8`, `int32`, `uint64` | `int` (unbounded) | `int32`, `coins` | `int` (unbounded) |
| `address`, `bits256` | `coins` (variable width) | Any struct | `builder` |
| Simple fixed-width structs | `cell`, `slice` | `Cell<T>` | |

### Emptiness Check

```tolk
// CORRECT
balances.isEmpty()

// WRONG -- compiler warning
balances == null
```

### Practical Map Patterns

**Extension registry (Wallet V5)**:
```tolk
type ExtensionsDict = map<uint256, bool>

storage.extensions.addIfNotExists(extensionAddrHash, true);
storage.extensions.delete(extensionAddrHash);
storage.extensions.exists(senderAddrHash);
storage.extensions.isEmpty();
```

**Whitelist (Vesting)**:
```tolk
type WhitelistDict = map<address, ()>

fun WhitelistDict.isWhitelisted(self, addr: address) {
    return self.exists(addr);
}
fun WhitelistDict.addWhitelisted(mutate self, addr: address) {
    self.set(addr, ());
}
```

---

## 11. External Message Security

External messages are sent from outside the blockchain (e.g., from a user's device). They are the primary attack surface for wallet contracts.

### Complete External Message Pattern

```tolk
fun onExternalMessage(inMsgBody: slice) {
    // Load signature (last 512 bits of message body)
    var signature = inMsgBody.getLastBits(SIZE_SIGNATURE);
    var signedSlice = inMsgBody.removeLastBits(SIZE_SIGNATURE);

    // Load storage (lazy for minimal gas before acceptance)
    val storage = lazy Storage.load();

    // 1. Signature verification (FIRST -- cheapest rejection)
    assert (isSignatureValid(signedSlice.hash(), signature, storage.publicKey))
        throw ERROR_INVALID_SIGNATURE;

    // 2. Parse signed fields
    val msg = SignedBody.fromSlice(signedSlice);

    // 3. Wallet ID check (prevents cross-wallet replay)
    assert (msg.walletId == storage.subwalletId) throw ERROR_INVALID_WALLET_ID;

    // 4. Expiration check (prevents replay after window closes)
    assert (msg.validUntil > blockchain.now()) throw ERROR_EXPIRED;

    // 5. Seqno check (prevents replay within window)
    assert (msg.seqno == storage.seqno) throw ERROR_INVALID_SEQNO;

    // 6. ACCEPT -- pay gas from contract balance
    acceptExternalMessage();

    // 7. Increment seqno and commit IMMEDIATELY
    storage.seqno += 1;
    storage.save();
    commitContractDataAndActions();

    // 8. Process actions (after commit -- seqno already incremented)
    processActions(msg.actions);
}
```

### Validation Order Rationale

1. **Signature first**: Cheapest rejection. Invalid signatures are the most common attack (random spam). Reject before any complex logic.
2. **Wallet ID**: Prevents replaying transactions intended for a different wallet with the same key.
3. **Expiration**: Prevents replay of old transactions after the intended time window.
4. **Seqno**: Final replay protection. Must match exactly.
5. **Accept ONLY after all checks pass**: Before acceptance, gas is limited. After acceptance, the contract pays.
6. **Commit immediately**: Even if subsequent action processing fails, the seqno is incremented and replay is prevented.

### Try-Catch Pattern for Actions (Vesting)

```tolk
acceptExternalMessage();

try {
    val attachedMsg = AttachedMessage.fromSlice(msg.rest);
    attachedMsg.validate(whitelist, lockedAmount);
    sendRawMessage(attachedMsg.msgCell, attachedMsg.sendMode);
} catch {
    // Silently ignore -- seqno still increments
}

storage.seqno += 1;
storage.save();
```

**Security note**: The empty `catch` block means a failed action is silently consumed. The seqno increments regardless, preventing replay, but the user gets no on-chain indication of failure.

### One-Time External Initialization (Telemint)

```tolk
fun onExternalMessage(inMsg: slice) {
    var storage = lazy CollectionStorage.load();
    assert (!storage.isCollectionInitialized) throw ERR_FORBIDDEN_TOUCH;
    acceptExternalMessage();
    storage.isCollectionInitialized = true;
    storage.save();
}
```

### Signature-Based Authorization (Telemint)

```tolk
AskToDeployItem => {
    val storage = lazy CollectionStorage.load();
    val hash = msg.signedData.hash();
    assert (isSignatureValid(hash, msg.signature as slice, storage.publicKey))
        throw ERR_INVALID_SIGNATURE;

    val input = lazy SignedDataAtDeploy.fromSlice(msg.signedData);
    assert (storage.subwalletId == input.subwalletId) throw ERR_WRONG_SUBWALLET_ID;
    assert (input.validSince < blockchain.now()) throw ERR_NOT_YET_VALID_SIGNATURE;
    assert (blockchain.now() < input.validTill) throw ERR_EXPIRED_SIGNATURE;
}
```

---

## 12. Random Values

Random values in TON are **deterministic and predictable by validators**. The seed is derived from the block seed, which validators can manipulate.

### Never Use For

- Token distribution lotteries
- Winner selection in games
- Generating secret values or keys
- Any outcome where economic value depends on randomness

### If You Must Use Randomness

```tolk
// INSECURE -- predictable by validators
random.initialize();                // seed with current time (predictable)
val r = random.range(100);          // 0..99

// SLIGHTLY BETTER -- mix with user input
random.initializeBy(userSeed);      // mix user value into seed
val r = random.range(100);
// Still manipulable by colluding validators
```

### Commit-Reveal Pattern

The only secure pattern for on-chain randomness:

```tolk
// Phase 1: User commits hash(secret + choice)
struct Commit {
    commitHash: uint256
    timestamp: uint32
}

// Phase 2: User reveals secret + choice, contract verifies
struct Reveal {
    secret: uint256
    choice: uint8
}

// In handler:
Reveal => {
    val expectedHash = beginCell()
        .storeUint(msg.secret, 256)
        .storeUint(msg.choice, 8)
        .endCell().hash();
    assert (expectedHash == storage.commitHash) throw ERROR_INVALID_REVEAL;
    assert (blockchain.now() <= storage.commitTimestamp + REVEAL_WINDOW) throw ERROR_EXPIRED;
    // Use choice...
}
```

---

## 13. Tolk Version-Specific Features

### Tolk 1.0 (TVM 11, July 2025)

| Feature | Security Impact |
|---------|----------------|
| `lazy` keyword | Efficient but skips full validation. Safe for storage, careful with messages. |
| `onInternalMessage(in: InMessage)` | Replaces FunC's 4-parameter `recv_internal`. Structured, harder to misparse. |
| `onBouncedMessage(in: InMessageBounced)` | Separate handler. If absent, bounces are filtered out (safe default). |
| Auto-serialization (`toCell`, `fromSlice`) | Eliminates manual bit-level serialization bugs. |
| Compiler auto-inlining | No `impure` keyword needed. Function calls are never silently dropped. |
| Custom `packToBuilder`/`unpackFromSlice` | For non-standard serialization (e.g., variable-length strings). |

### Tolk 1.1 (TVM 11, September 2025)

| Feature | Security Impact |
|---------|----------------|
| `map<K, V>` | Type-safe dictionaries. `MapLookupResult` prevents null confusion. |
| `enum` types | Validated on deserialization (invalid values throw excno 5). |
| `private`/`readonly` fields | Encapsulation at compile time. |
| Stricter type aliases | `UserId` and `OwnerId` are no longer interchangeable. |
| Partial specialization | More correct overload resolution. |

### Tolk 1.2 (TVM 12, December 2025)

| Feature | Security Impact |
|---------|----------------|
| `address` = internal only | Eliminates missing `isInternal()` check vulnerabilities. |
| `address?` for nullable | Standard null pattern for optional addresses. |
| `any_address` for old behavior | Still requires manual `isInternal()` checks. |
| `BounceMode.RichBounce` | Full bounce body recovery -- enables proper error handling. |
| Anonymous functions (lambdas) | Not closures -- cannot capture outer scope. No new attack surface. |
| Borrow checker | Prevents concurrent mutation UB (`x += (x = 0)` is now a compile error). |
| `builder.toSlice()` via BTOS | 500 gas savings on builder-to-slice (no intermediate cell). |
| Enum match safety | Hidden `else { throw 5 }` prevents wrong branch on corrupted stack. |

### Version Compatibility Matrix

| Feature | 1.0 | 1.1 | 1.2 |
|---------|-----|-----|-----|
| TVM Required | 11 | 11 | 12 |
| `lazy` keyword | Yes | Yes | Yes |
| `map<K,V>` | No | Yes | Yes |
| `enum` | No | Yes | Yes |
| `private`/`readonly` | No | Yes | Yes |
| Rich bounces | No | No | Yes |
| `address` = internal only | No | No | Yes |
| Anonymous functions | No | No | Yes |
| Borrow checker | No | No | Yes |

---

## 14. Common Anti-Patterns

### Anti-Pattern Reference Table

| Anti-Pattern | Problem | Fix |
|---|---|---|
| `admin!` on nullable | Throws error code 7 (TVM null deref), not your error | Check null first, then compare |
| `val x = data as MyEnum` | No validation, UB on invalid values | Use auto-deserialization via `fromSlice` |
| `assertEndAfterReading: false` | Attacker can append unvalidated data | Keep default `true` |
| Magic number error codes | Hard to debug, codes may collide | Use `const` or `enum` with unique values |
| State change after `send` | Async model -- state already committed | Always update state BEFORE sending |
| `body.remainingBits() == 0` check | Fragile, breaks with format changes | Use structured deserialization |
| `else` in union match | Hides new message types silently | Exhaustive match without `else` |
| Unchecked `lazy` field | Validation skipped for unaccessed fields | Load and validate explicitly |
| `acceptExternalMessage()` before checks | Gas drain attack | Always validate first |
| `&` instead of `&&` for null guard | No short-circuit -- right side always evaluated | Use `&&` for null-guarded expressions |
| Mixing bounce modes | Ambiguous bounce body format | Use one mode consistently |
| Error code collisions | Same code for different errors | Verify unique error codes across contract |
| `@overflow1023_policy("suppress")` | Suppresses real overflow warnings | Split struct into Cell references |
| Using `global` where `val` suffices | Uninitialized globals throw at runtime | Prefer local `val`/`var` |

### Detailed Anti-Patterns

**Force-unwrap on nullable admin**:
```tolk
// BAD
assert (sender == admin!) throw 401;
// If admin is null, throws 7 (not 401)

// GOOD
assert (admin != null) throw 401;
assert (sender == admin) throw 401;
```

**Error code collisions** (found in production jetton code):
```tolk
// BAD -- same error code for different errors
const ERR_INVALID_OP = 709
const ERR_NOT_ENOUGH_TON = 709  // collision!
const ERR_NOT_ENOUGH_GAS = 707
const ERR_INVALID_WALLET = 707  // collision!

// GOOD -- unique codes, use enum
enum Err {
    InvalidOp = 709
    NotEnoughTon = 710
    NotEnoughGas = 711
    InvalidWallet = 712
}
```

**State change after send** (TON-specific):
```tolk
// BAD -- state change lost if transaction continues after send
msg.send(SEND_MODE_CARRY_ALL_REMAINING_MESSAGE_VALUE);
storage.balance -= amount;  // may not be persisted correctly
storage.save();

// GOOD -- state change first
storage.balance -= amount;
storage.save();
msg.send(SEND_MODE_CARRY_ALL_REMAINING_MESSAGE_VALUE);
```

**NFT initialization detection by refs count** (fragile):
```tolk
// FRAGILE -- breaks if storage format changes
fun isInitialized(self) {
    return self.contractData.remainingRefsCount();
}

// BETTER -- explicit initialization flag
struct NftItemStorage {
    isInitialized: bool
    // ...
}
```

---

## 15. Production Contract Patterns

### Standard Jetton Wallet Pattern

```tolk
import "errors"
import "storage"
import "messages"
import "fees-management"

type AllowedMessageToWallet =
    | AskToTransfer
    | AskToBurn
    | InternalTransferStep

type BounceOpToHandle = InternalTransferStep | BurnNotificationForMinter

fun onInternalMessage(in: InMessage) {
    val msg = lazy AllowedMessageToWallet.fromSlice(in.body);

    match (msg) {
        InternalTransferStep => {
            // Verify sender is minter or valid wallet
            var storage = lazy WalletStorage.load();
            if (in.senderAddress != storage.minterAddress) {
                assert (in.senderAddress == calcAddressOfJettonWallet(
                    msg.transferInitiator!,
                    storage.minterAddress,
                    contract.getCode()
                )) throw ERR_INVALID_WALLET;
            }
            storage.jettonBalance += msg.jettonAmount;
            storage.save();
            // Send notifications...
        }

        AskToTransfer => {
            var storage = lazy WalletStorage.load();
            assert (in.senderAddress == storage.ownerAddress) throw ERR_NOT_FROM_OWNER;
            assert (storage.jettonBalance >= msg.jettonAmount) throw ERR_NOT_ENOUGH_BALANCE;
            assert (msg.transferRecipient.getWorkchain() == BASECHAIN) throw ERR_WRONG_WORKCHAIN;

            storage.jettonBalance -= msg.jettonAmount;
            storage.save();
            // Send deploy + transfer message...
        }

        AskToBurn => {
            var storage = lazy WalletStorage.load();
            assert (in.senderAddress == storage.ownerAddress) throw ERR_NOT_FROM_OWNER;
            assert (storage.jettonBalance >= msg.jettonAmount) throw ERR_NOT_ENOUGH_BALANCE;

            storage.jettonBalance -= msg.jettonAmount;
            storage.save();
            // Send burn notification to minter...
        }

        else => {
            assert (in.body.isEmpty()) throw 0xFFFF;
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

get fun get_wallet_data(): JettonWalletDataReply {
    val storage = lazy WalletStorage.load();
    return {
        jettonBalance: storage.jettonBalance,
        ownerAddress: storage.ownerAddress,
        minterAddress: storage.minterAddress,
        jettonWalletCode: contract.getCode(),
    }
}
```

### Vesting Wallet Message Validation

```tolk
@inline_ref
fun VestingParameters.getLockedAmount(self, nowTime: int): coins {
    if (nowTime > self.startTime + self.totalDuration) { return 0; }
    if (nowTime < self.startTime + self.cliffDuration) { return self.totalAmount; }
    return self.totalAmount -
        mulDivFloor(
            self.totalAmount,
            (nowTime - self.startTime) / self.unlockPeriod,
            self.totalDuration / self.unlockPeriod
        );
}

@inline_ref
fun AttachedMessage.validateIfLockedAmount(
    self,
    whitelist: WhitelistDict,
    lockedAmount: coins,
    vestingSenderAddress: address
) {
    // Only allow specific send mode
    assert (self.sendMode == SEND_MODE_IGNORE_ERRORS + SEND_MODE_PAY_FEES_SEPARATELY)
        throw ERROR_SEND_MODE_NOT_ALLOWED;

    val destinationAddress = cellHeader.destinationAddress;

    // Can send any message to vesting sender (return funds)
    if (destinationAddress == vestingSenderAddress) { return; }

    // Must be whitelisted for other destinations
    if (!whitelist.isWhitelisted(destinationAddress)) {
        // Not whitelisted -- reserve locked amount instead of throwing
        reserveToncoinsOnBalance(lockedAmount, RESERVE_MODE_AT_MOST);
        return;
    }

    // Must be bounceable (for whitelisted)
    assert (cellHeader.isBounceable()) throw ERROR_NON_BOUNCEABLE_NOT_ALLOWED;

    // No StateInit allowed (prevents deploying arbitrary contracts)
    assert (!restOfCell.hasStateInit()) throw ERROR_STATE_INIT_NOT_ALLOWED;
}
```

### Custom Type Serialization

For non-standard binary formats, define custom pack/unpack:

```tolk
type TelegramString = slice

fun TelegramString.packToBuilder(self, mutate b: builder) {
    val bytes = self.remainingBitsCount() / 8;
    b.storeUint(bytes, 8);
    b.storeSlice(self);
}

fun TelegramString.unpackFromSlice(mutate s: slice) {
    val bytes = s.loadUint(8);
    return s.loadBits(bytes * 8);
}
```

### UnsafeBodyNoRef Optimization

When you know the message body will fit inline (< 1023 bits), bypass the compiler's automatic ref creation:

```tolk
body: UnsafeBodyNoRef {
    forceInline: ResponseStaticData {
        queryId: msg.queryId,
        itemIndex: storage.itemIndex as uint256,
        collectionAddress: storage.collectionAddress,
    }
}
```

**Audit note**: If the body actually exceeds the cell limit, serialization will fail at runtime. Only use when the exact bit count is known and guaranteed to fit.

### TLB Either Validation

```tolk
fun ForwardPayloadRemainder.checkIsCorrectTLBEither(self) {
    var mutableCopy = self;
    if (mutableCopy.loadMaybeRef() != null) {
        mutableCopy.assertEnd();
    }
}
```

### C5 Register Validation (Wallet V5)

Prevents malicious action injection via external messages:

```tolk
fun OutActionsCell.verifyC5Actions(self, isExternal: bool): self {
    var cs = self.beginParseAllowExotic();
    do {
        var (nBits, nRefs) = cs.remainingBitsAndRefsCount();
        assert (nRefs == 2) throw ERROR_INVALID_C5;
        assert (nBits == 32 + 8) throw ERROR_INVALID_C5;

        val outAction = lazy OutActionWithSendMessageOnly.fromSlice(cs, {
            throwIfOpcodeDoesNotMatch: ERROR_INVALID_C5
        });

        if (isExternal) {
            assert (outAction.sendMode & SEND_MODE_IGNORE_ERRORS)
                throw ERROR_EXTERNAL_SEND_MESSAGE_MUST_HAVE_IGNORE_ERRORS_SEND_MODE;
        }
        cs = outAction.prev.beginParseAllowExotic();
    } while (!cs.isEmpty());
    return self;
}
```

---

## 16. Audit Checklist for Tolk Contracts

### Authentication and Authorization

- [ ] All state-mutating messages verify `in.senderAddress` against expected sender
- [ ] Admin/owner checks use explicit null validation (not `!` force-unwrap)
- [ ] Workchain is validated where applicable (`getWorkchain() == BASECHAIN`)
- [ ] Wallet address verification uses `calcAddressOfJettonWallet` pattern for cross-contract auth
- [ ] Code upgrade is protected by governance (multisig, timelock, or admin drop)
- [ ] Two-step admin transfer implemented for admin changes

### Message Handling

- [ ] Union types list ALL expected message types (no hidden `else` swallowing new types)
- [ ] `else` branch only accepts empty bodies (`assert (in.body.isEmpty()) throw 0xFFFF`)
- [ ] Bounce handler restores state (balance, supply) on failure
- [ ] `BounceMode` choices are consistent (not mixing old and rich within one contract)
- [ ] Critical recovery data is placed early in message structs (for 256-bit bounce)
- [ ] `@on_bounced_policy("manual")` is used intentionally and bounced messages handled
- [ ] Send modes are correct for each message type (carry value, pay separately, ignore errors)

### Serialization and Types

- [ ] `assertEndAfterReading: true` (default) is not overridden without good reason
- [ ] No `as` casts from raw/untrusted data (use `fromSlice`, `fromCell` instead)
- [ ] Enum values come from deserialization, not `as` casts
- [ ] `@overflow1023_policy("suppress")` verified to be safe (struct fits in practice)
- [ ] `lazy` loading is appropriate (storage: yes; untrusted messages: careful)
- [ ] Custom `packToBuilder`/`unpackFromSlice` validated for correctness

### Integer Safety

- [ ] Balance checks performed BEFORE deduction (`assert (balance >= amount)`)
- [ ] `coins` type arithmetic does not rely on non-additive ops preserving the type
- [ ] Error codes are unique across the contract (no collisions)
- [ ] Sufficient TON checks account for all outgoing messages, gas, and storage fees
- [ ] `mulDivFloor` used for safe multiplication-then-division (no intermediate overflow)

### Gas and Balance

- [ ] `acceptExternalMessage()` called ONLY after all validation passes
- [ ] Balance reservation leaves enough for storage (`MIN_TONS_FOR_STORAGE`)
- [ ] Gas estimation accounts for precompiled gas when available
- [ ] `SEND_MODE_CARRY_ALL_BALANCE` is only used after `reserveToncoinsOnBalance`
- [ ] Forward fee calculations use `in.originalForwardFee` (not deprecated methods)

### External Messages

- [ ] Signature validated before `acceptExternalMessage()`
- [ ] Seqno checked for replay protection
- [ ] Expiration time checked (`validUntil > blockchain.now()`)
- [ ] Wallet ID checked (prevents cross-wallet replay)
- [ ] `commitContractDataAndActions()` called after seqno increment
- [ ] Try-catch blocks do not silently hide critical failures

### Map Safety

- [ ] `MapLookupResult.isFound` pattern used (not null checks)
- [ ] `mustGet()` has appropriate error codes
- [ ] `isEmpty()` used for emptiness checks (not `== null`)
- [ ] Map iteration has gas bounds (batch size limits)
- [ ] Key types are fixed-width (not `int` or `coins`)

### Tolk 1.2-Specific

- [ ] `address` type used for internal-only fields (not `any_address`)
- [ ] `any_address` fields have `isInternal()` validation
- [ ] `address?` null checks performed before use
- [ ] Rich bounce handling is correct (if `BounceMode.RichBounce` used)
- [ ] No concurrent mutation warnings (borrow checker clean)
- [ ] Deprecated methods replaced (`buildSameAddressInAnotherShard` -> `calculateSameAddressInAnotherShard`)

---

## Key Stdlib Reference

### Contract State

| Function | Purpose |
|----------|---------|
| `contract.getData()` | Read persistent storage cell |
| `contract.setData(cell)` | Write persistent storage cell |
| `contract.getCode()` | Get current contract code |
| `contract.setCodePostponed(cell)` | Set new code (next transaction) |
| `contract.getAddress()` | Get this contract's address |
| `contract.getOriginalBalance()` | Balance before this message |
| `contract.getStorageDuePayment()` | Storage fee debt |

### Blockchain

| Function | Purpose |
|----------|---------|
| `blockchain.now()` | Current Unix timestamp |
| `blockchain.logicalTime()` | Logical time of current transaction |
| `blockchain.configParam(id)` | Global config parameter |

### Messages

| Function | Purpose |
|----------|---------|
| `createMessage({...})` | Create typed message |
| `msg.send(mode)` | Send with mode flags |
| `sendRawMessage(cell, mode)` | Low-level send |
| `acceptExternalMessage()` | Accept external message |
| `commitContractDataAndActions()` | Commit c4 and c5 registers |
| `reserveToncoinsOnBalance(amount, mode)` | Reserve balance |

### Crypto

| Function | Purpose |
|----------|---------|
| `isSignatureValid(hash, sig, pubkey)` | Ed25519 verification |
| `cell.hash()` | SHA-256 representation hash |
| `slice.hash()` | SHA-256 of slice |
| `builder.hash()` | SHA-256 of builder |

### Gas (requires `import "@stdlib/gas-payments"`)

| Function | Purpose |
|----------|---------|
| `getGasConsumedAtTheMoment()` | Current gas usage |
| `calculateGasFee(wc, gas)` | Estimate gas fee |
| `calculateStorageFee(wc, sec, bits, cells)` | Estimate storage fee |
| `calculateForwardFee(wc, bits, cells)` | Estimate forward fee |
