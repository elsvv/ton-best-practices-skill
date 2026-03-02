# FunC and Tact Language-Specific Security

## FunC Security Pitfalls

### 1. The `impure` Modifier — Most Insidious Bug

Without `impure`, FunC compiler treats a function as pure and may **silently remove the call** if the return value is unused.

```func
;; WRONG — compiler may optimize away this ENTIRE call
() authorize(slice sender) inline {
    throw_unless(401, equal_slices(sender, admin_address));
}

;; If caller does:
authorize(sender); ;; return value unused → compiler deletes it → anyone bypasses auth!

;; CORRECT — impure prevents removal
() authorize(slice sender) impure inline {
    throw_unless(401, equal_slices(sender, admin_address));
}
```

**Rule**: Every function that sends messages, modifies storage, or has security-critical side effects MUST be `impure`.

```func
;; All of these need impure:
() save_data(...) impure inline { ... }
() send_money(slice addr, int amount) impure inline { ... }
() check_and_update_state() impure inline { ... }
() require_admin(slice sender) impure inline { ... }
```

### 2. Modifying (`~`) vs Non-Modifying (`.`) Method Calls

This is one of the most common FunC bugs — **silent no-op** on dictionary operations.

```func
;; WRONG — dict is NOT modified, returns new value that's discarded
accounts.udict_delete_get?(256, sender);  ;; . operator

;; WRONG — deletes from copy, original unchanged
(cell new_dict, slice val, int found) = accounts.udict_delete_get?(256, sender);
;; accounts is still the same!

;; CORRECT — ~ modifies in-place
(slice val, int found) = accounts~udict_delete_get?(256, sender);
;; accounts is now updated

;; Other common mistakes:
dict.dict_set(key, value);    ;; WRONG — use dict~dict_set(...)
slice.load_uint(32);          ;; WRONG — use slice~load_uint(32) or slice.preload_uint(32)
```

**Rule**: Use `~` when you want to modify the variable. Use `.` when you want to peek (preload).

### 3. Storage Variable Ordering

FunC storage is manual serialization/deserialization. Variable order in `load_data()` and `save_data()` MUST match exactly.

```func
;; STORAGE LAYOUT MUST BE CONSISTENT:
(int total_supply, slice admin_addr, cell jetton_wallet_code) = load_data();
;; Later save must use SAME order:
save_data(total_supply, admin_addr, jetton_wallet_code);

;; WRONG — swapped order corrupts storage
save_data(admin_addr, total_supply, jetton_wallet_code); ;; admin_addr stored in total_supply field!

;; BEST PRACTICE: use a dedicated function pair
() save_data(int total_supply, slice admin_addr, cell code) impure {
    set_data(begin_cell()
        .store_coins(total_supply)
        .store_slice(admin_addr)
        .store_ref(code)
        .end_cell());
}

(int, slice, cell) load_data() inline {
    slice ds = get_data().begin_parse();
    return (ds~load_coins(), ds~load_msg_addr(), ds~load_ref());
}
```

### 4. Variable Shadowing / Name Collisions

FunC allows special characters in identifiers and allows redeclaration:

```func
;; DANGER: same-name redeclaration
int balance = data~load_uint(64);
;; ... later ...
int balance = 0; ;; redeclares! Now we have two 'balance' in scope
;; save_data uses local 'balance = 0' not the loaded one!

;; DANGER: FunC identifiers can include +, -, ~, etc.
;; Name collisions with built-ins: avoid 'balance', 'now', 'min', 'max'
int balance = msg_value;  ;; shadows built-in balance variable

;; FIX: use descriptive unique names
int user_token_balance = data~load_uint(64);
int contract_ton_balance = my_balance;
```

### 5. Global Variables Do NOT Persist

```func
;; Global variables: stored in c7 register (tuple)
;; RESET on every TVM invocation!

global int g_total_processed; ;; always 0 at start of every tx

;; WRONG: assuming globals survive between transactions
() recv_internal(...) impure {
    g_total_processed += 1; ;; lost after this transaction!
}

;; CORRECT: use c4 (set_data/get_data) for persistence
() recv_internal(...) impure {
    int total = get_data()~load_uint(64);
    total += 1;
    set_data(begin_cell().store_uint(total, 64).end_cell());
}
```

### 6. try-catch Behavior (FunC v0.4.0+)

```func
try {
    ;; If exception here:
    ;; - state changes in try block are ROLLED BACK
    ;; - gas consumed is NOT rolled back
    ;; - gas limit changes persist
    ;; OOG (exit code 13) CANNOT be caught here!
    risky_operation();
} catch(e, n) {
    ;; e = exception value, n = exit code
    ;; safe to handle recoverable errors
}

;; ATTACK VECTOR: third-party code with COMMIT
try {
    COMMIT; ;; attacker persists malicious state!
    ;; then triggers OOG or other exit
} catch(_, _) { }
;; COMMIT survives even if compute phase exits with error
;; (but action phase failure would still revert)
```

### 7. Boolean Values

```func
;; FunC has no boolean type
;; false = 0, true = -1 (not 1!)

;; PITFALL:
int flag = 1; ;; truthy in conditionals but NOT equal to true constant
if (flag) { ... }         ;; executes (any nonzero is truthy)
if (flag == true) { ... } ;; NEVER executes! (1 != -1)

;; SAFE: compare to 0 directly
if (flag != 0) { ... }
if (is_valid?) { ... }  ;; use ? suffix convention for booleans
```

### 8. `end_parse()` — Always

```func
;; Always call end_parse() after reading from slices
slice ds = get_data().begin_parse();
int seqno = ds~load_uint(32);
ds.end_parse(); ;; throws exit code 9 if extra data present

;; WHY: detects storage format changes, serialization bugs, extra junk
;; Without it: silently ignores unread data — bugs hide for months
```

### 9. Message Body Construction

```func
;; Standard internal message header
var msg = begin_cell()
    .store_uint(0x18, 6)        ;; flags: bounceable=1, ihr_disabled=1
    .store_slice(to_address)    ;; destination
    .store_coins(amount)        ;; value in nanotons
    .store_uint(0, 1 + 4 + 4 + 64 + 32 + 1 + 1)  ;; default fields
    ;; ↑ ihr_disabled(1) + bounce(4) + bounced(4) + src(64) + lt(32) + init_flag(1) + body_flag(1)
    .store_uint(op::transfer, 32)  ;; op code
    .store_uint(query_id, 64)
    ;; ... payload ...
    .end_cell();

;; For large bodies — use reference cell:
var msg = begin_cell()
    .store_uint(0x18, 6)
    .store_slice(to_address)
    .store_coins(amount)
    .store_uint(1, 1 + 4 + 4 + 64 + 32 + 1 + 1)  ;; last bit = 1 (body as ref)
    .store_ref(body_cell)        ;; body in separate cell
    .end_cell();
```

### 10. Dictionary Return Value Checking

```func
;; ALL dict operations return success flags — ALWAYS check them!

;; WRONG — silent failure if key not found
slice value = dict~udict_get?(256, key);

;; CORRECT
(slice value, int found) = dict.udict_get?(256, key);
throw_unless(error::not_found, found);

;; For delete:
(dict, slice old_value, int found) = dict~udict_delete_get?(256, key);
throw_unless(error::not_found, found);
```

---

## Tact Security Pitfalls

### 1. Pass-by-Value Arguments

```tact
// Tact passes ALL arguments by VALUE
// Mutations inside functions DON'T affect callers

fun processMessage(msg: TokenTransfer): Int {
    msg.amount = 0; // changes LOCAL copy only!
    return msg.amount; // returns 0
}

// Caller still has original amount
let transfer: TokenTransfer = TokenTransfer{ amount: 100 };
let result = processMessage(transfer);
// transfer.amount is STILL 100!
```

**Implication**: If you expect to modify a message and use the modified version, you must return it.

### 2. Reserved Exit Codes

```tact
// TON TVM: 0-127 reserved
// Tact: 128-255 reserved

// Built-in Tact exit codes:
// 128: Null reference (!! on null value)
// 129: Invalid serialization prefix
// 130: Invalid incoming message (no receiver)
// 132: Access denied (requireOwner() from Ownable trait)
// 133: Contract stopped (Stoppable trait)
// 134: Invalid argument
// 135: Contract code not found
// 136: Invalid standard address (not 267-bit)
// 138: Not a basechain address

// CORRECT: use 256+ for custom errors
const ERROR_INSUFFICIENT_FUNDS: Int = 1000;
const ERROR_NOT_AUTHORIZED: Int = 1001;
require(balance >= amount, "INSUFFICIENT_FUNDS"); // uses exit code based on message
throw(ERROR_INSUFFICIENT_FUNDS); // use explicit code
```

### 3. Variable Initialization — init() vs Declaration

```tact
contract MyContract {
    totalSupply: Int = 1000; // initialized at declaration
    owner: Address;

    init(owner: Address) {
        self.owner = owner;
        self.totalSupply = 0; // init() value WINS — totalSupply starts at 0, NOT 1000!
    }
}

// Recommendation: initialize ONLY in init(), not at declaration
contract MyContract {
    totalSupply: Int; // no declaration value
    owner: Address;

    init(owner: Address) {
        self.owner = owner;
        self.totalSupply = 0; // clear and unambiguous
    }
}
```

### 4. Randomness in Tact

```tact
// WRONG — doesn't prepare seed
let n: Int = randomInt();  // deprecated, doesn't call nativePrepareRandom()
let m: Int = random(1, 100); // same issue

// CORRECT
nativePrepareRandom(); // seed TVM PRNG from block randomness
let n: Int = nativeRandom();           // full 256-bit random
let m: Int = nativeRandomInterval(1, 100); // bounded random
```

### 5. Trait Variable Modification

```tact
// Traits define variables with specific update rules
// Direct modification may violate invariants

trait Ownable {
    owner: Address;

    fun requireOwner() {
        require(sender() == self.owner, "Access denied");
    }
}

contract MyContract with Ownable {
    // WRONG: directly modifying trait variable
    receive("changeOwner") {
        self.owner = sender(); // bypasses any validation in trait!
    }

    // CORRECT: use trait's provided method if it exists
    // Or add proper validation:
    receive(msg: ChangeOwner) {
        self.requireOwner(); // current owner validates
        self.owner = msg.newOwner;
        // emit event
    }
}
```

### 6. Implicit Integer Serialization

```tact
// Tact's Int serializes as 257-bit signed by default
// Receivers expecting uint256 will FAIL to deserialize

// WRONG: mismatched serialization
message TokenTransfer {
    amount: Int; // 257-bit signed by default
}

// If FunC contract expects:
// amount = slice~load_coins() // variable-length, different format!

// CORRECT: use explicit annotations
message TokenTransfer {
    amount: Int as coins; // matches load_coins() / store_coins()
    // or:
    amount: Int as uint256; // matches load_uint(256)
}
```

### 7. TVM Assembly in Tact

```tact
// Assembly blocks are dangerous — review carefully
// No type safety, direct TVM manipulation

asm fun dangerousOp(x: Int): Int {
    // arbitrary TVM opcodes here
    COMMIT // THIS IS DANGEROUS — persists state before any error handling!
}

// Review: does assembly preserve invariants?
// Does it interact with c4 (storage)?
// Could it be exploited to persist malicious state?
```

### 8. onBounce Handler

```tact
// Tact equivalent of FunC bounce handling
bounced(msg: bounced<TokenTransfer>) {
    // MUST restore state — transfer never completed
    self.totalSupply -= msg.amount;
    // emit event for monitoring
}

// bounced<T> gives you the first 224 bits of original message body
// Enough for amount/op fields, may not have full payload
```

### 9. Upgrade Patterns in Tact

```tact
// Tact has no native upgrade support
// Use Ton-Dynasty's Upgradable trait or manual approach

// CRITICAL: validate upgrade authorization
receive(msg: Upgrade) {
    self.requireOwner(); // must be authorized
    // Consider: timelock, multi-sig, governance vote

    // Code change — takes effect AFTER this tx completes
    setCode(msg.newCode);

    // Data migration — run BEFORE setCode if needed
    // Old: (seqno: Int, balance: Int)
    // New: (seqno: Int, balance: Int, config: Cell)
    // Must handle both layouts in new code's init!
}
```

---

## Solidity → TON Migration Pitfalls

| Solidity Pattern | TON Equivalent | Security Concern |
|-----------------|----------------|-----------------|
| `transfer(amount)` | Send message with value | Message can fail/bounce — handle it |
| `balances[addr]` | Separate Jetton wallet contract | Must verify wallet authenticity |
| `require(condition)` | `throw_unless(code, condition)` | Use 256+ for error codes |
| `event Transfer(...)` | External message / log | Costs gas from contract balance |
| `msg.sender` | Parse from `in_msg_full` | Must extract and validate |
| `address(this).balance` | `my_balance` | Includes in-flight messages |
| Reentrancy guard | Not needed (no sync calls) | Use race condition guards instead |
| `delegatecall` | Library cells | Different security model |
| Atomic multi-contract | NOT possible | Design for partial execution |
| Pull payments | Push with bounce handling | Handle bounce = undo debit |
