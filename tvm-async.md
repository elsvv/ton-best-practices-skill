# TVM Internals and Async Model Security

## TVM Architecture

### Stack and Data Types

TVM is a stack-based VM (LIFO). Seven types:

| Type | Description | Security Note |
|------|-------------|---------------|
| **Integer** | 257-bit signed with NaN | Overflow throws exit 4; underflows need manual checks |
| **Cell** | ≤1023 bits, ≤4 refs | Overflow=exit 8, Underflow=exit 9 |
| **Slice** | Read cursor over cell | Read-only; use ~ methods to advance |
| **Builder** | Write cursor for cells | Manual serialization = error-prone |
| **Tuple** | 0-255 mixed elements | Global vars stored here; lost between txs |
| **Continuation** | Executable bytecode | Code-as-data; SETCODE changes c3 |
| **Null** | Empty value | Global vars return null if unassigned |

### Control Registers (Security-Critical)

| Register | Contents | Security Impact |
|----------|----------|-----------------|
| **c0** | Return continuation | Exit code 0 on quit |
| **c1** | Alternative return | Exit code 1 on quit |
| **c2** | Exception handler | Modified by try/catch |
| **c3** | Contract code root | Changed by `set_code()` |
| **c4** | Persistent data (storage) | Changed by `set_data()` |
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

## Transaction Phases — Security Impact

```
Non-bounceable: Credit → Storage → Compute → Action → Bounce
Bounceable:     Storage → Credit → Compute → Action → Bounce
```

**Phase details**:

1. **Storage phase** — deducts rent BEFORE credit. Accumulated debt can consume entire incoming value, leaving 0 for computation. Contract may freeze in same tx that receives a message.

2. **Credit phase** — message value added to balance.

3. **Compute phase** — TVM executes code.
   - Success: state changes applied, actions queued in c5
   - Failure: state changes **rolled back**, bounce triggered IF inbound had bounce bit

4. **Action phase** — processes c5 action list (send messages, set code, reserves).
   - Failure: state changes from compute phase **persist** but messages NOT sent
   - Bounce only if failed action had **flag +16** explicitly set
   - **CRITICAL**: Compute can succeed while Action fails → inconsistent state!

5. **Bounce phase** — only if inbound was bounceable AND something failed.

**The golden rule**: "Never allow action phase to fail. Validate in compute phase. Throw during compute if anything might fail in action phase."

---

## Message Sending Modes — Complete Reference

### Base Modes (mutually exclusive)

| Mode | Name | Effect |
|------|------|--------|
| **0** | Standard | Fees from message value; receiver gets `value - fees` |
| **64** | SendRemainingValue | Add all remaining inbound value to outgoing |
| **128** | SendRemainingBalance | Send **entire contract balance** |

Modes 64+128 = exit code 34 (invalid).

### Additive Flags

| Flag | Name | Effect |
|------|------|--------|
| **+1** | PayFwdFeesSeparately | Fees from contract balance, not message value |
| **+2** | IgnoreErrors | Suppress action phase errors (silent failures!) |
| **+16** | BounceIfActionFail | Trigger bounce on action failure |
| **+32** | DestroyIfZero | Destroy account when balance hits zero (mode 128 only) |

### Common Combinations and Their Risks

```func
;; MODE 3 (0+1+2): Standard send, fees separate, ignore errors
;; Good for: notifications, events where failure is acceptable
send_raw_message(msg, 3);

;; MODE 64: Forward remaining inbound value
;; RISK: if contract emits events or has storage fees, balance drains
;; Use for: simple pass-through, no extra costs in handler
send_raw_message(msg, 64);

;; MODE 65 (64+1): Forward remaining + pay fees from balance
;; Use for: Jetton transfers where receiver gets full amount
send_raw_message(msg, 65);

;; MODE 80 (64+16): Forward + bounce protection
;; Use for: critical operations where failure must be detected

;; MODE 128: Send entire balance
;; DANGER: contract may have 0 balance after — freeze risk
;; Only for: intentional account draining/closure

;; MODE 160 (128+32): Send all + destroy contract
;; EXTREME: account deleted after tx
;; Require: explicit authorization, no pending operations

;; SAFE excess gas return:
send_raw_message(excesses_msg, 64 | 2); ;; forward remaining, ignore errors
```

### The Mode 64 Trap

```func
;; Mode 64 with extra costs drains contract:
;; - Storage fees come from contract balance (not forwarded value)
;; - External messages (events/logs) come from contract balance
;; - Multiple sends in one tx: only first gets "remaining" value

;; EXAMPLE: mode 64 + emit event
send_raw_message(transfer_msg, 64);  ;; forwards all remaining inbound
emit_event(data);                     ;; THIS costs from contract balance!
;; After many txs: contract balance = 0 → deletion

;; FIX: calculate storage fees explicitly, reserve, return remainder manually
```

---

## Bounce Messages — Technical Details

**What triggers a bounce**:
- Inbound message had bounce bit set (`0x18` flag)
- Compute phase failed OR action phase failed with flag +16
- Destination has enough balance for bounce message fees

**What a bounce looks like**:
```
Bounce body = 0xFFFFFFFF (32 bits) + first 256 bits of original body
= 32 + 256 = 288 bits total
= 288 - 32 = 256 bits of useful original data
```

**What bounces CANNOT do**:
- Re-bounce (a bounce of a bounce is silently dropped)
- Carry more than 256 bits of original payload
- Fire if destination had insufficient balance for bounce fee

**Silent failure scenario**:
1. Contract A sends bounceable message to Contract B
2. B's storage debt > incoming value → B never processes the message
3. B can't afford to send bounce → no bounce generated
4. A never knows the operation failed
5. State inconsistency persists forever

**Prevention**:
```func
;; Always attach enough TON for bounce
;; Formula: attach at least (compute_fee + forward_fee + bounce_fee + storage_reserve)
;; storage_reserve: unpredictable (depends on time since last tx), add buffer
```

---

## Asynchronous Security Patterns

### The Logical Time (lt) Guarantee

Each transaction has an `lt` (logical timestamp). Within a single contract:
- All transactions are ordered by lt
- Messages from contract A to B (and only A→B) are ordered

Between different contracts in different shards:
- **No ordering guarantee whatsoever**
- Cross-shard latency: minimum 1 masterchain block (~12-13 seconds)
- Routing: up to 15 hops through hypercube mesh

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

```func
;; Include unique message ID, check if already processed
int msg_id = in_msg_body~load_uint(64);
(_, int already_processed) = processed_ids.udict_get?(64, msg_id);
if (already_processed) { return (); } ;; ignore duplicate

;; Process...
processed_ids~udict_set(64, msg_id, empty_slice);
```

### State Validation Pattern for Multi-Step Flows

```func
;; Step 2 of a 3-step flow must re-validate all assumptions
;; Don't trust state from Step 1 - may have changed in parallel flow

;; WRONG:
;; Step 1: validates user has 100 tokens
;; Step 2: (assumes user still has 100 tokens) transfers them
;; ATTACK: parallel flow drains tokens between step 1 and 2

;; CORRECT: carry the validated amount in the message
;; Step 1: validates 100 tokens, embeds 100 in message to step 2
;; Step 2: uses the embedded 100, doesn't query current balance
```

---

## Account States

| State | Condition | Effect |
|-------|-----------|--------|
| **Uninit** | Has balance, no code | Cannot execute; accumulates debt |
| **Active** | Has code + balance | Fully operational |
| **Frozen** | Storage debt > 0.1 TON | Cannot execute; only hash preserved |
| **Deleted** | Storage debt > 1 TON | Account removed entirely |

**Unfreezing**: Send StateInit (original code + data) with enough TON to cover all accumulated debt.

**Griefing attack**: An attacker can cause small Jetton wallets to freeze by simply not interacting with them. The Jetton wallet accumulates storage debt, freezes, and tokens become inaccessible.

---

## Library Cells

Libraries allow shared code across contracts. A library cell stores a 256-bit hash reference to a cell hosted elsewhere.

**Publication**: On masterchain (expensive, globally accessible) or on contract's own state (private).

**Security risks**:
1. **Frozen host = inaccessible library**: If the account hosting a public library freezes, all contracts referencing it fail to execute
2. **Local override**: A contract's local library env overrides global — malicious contract could override expected library
3. **RUNVM state pollution (CVE-2025-70956)**: OOG during RUNVM resource transfer corrupted parent VM with emptied libraries. Fixed in v2025.04.

---

## Dangerous Opcodes Reference

| Opcode | Risk | Mitigation |
|--------|------|------------|
| `ACCEPT` / `accept_message()` | Gas drain if called before auth | Always validate BEFORE calling |
| `SENDRAWMSG` mode 128 | Depletes entire balance | Auth gate; only for account closure |
| `SENDRAWMSG` mode 128+32 | Destroys contract | Extreme auth gate; verify no pending ops |
| `SETCODE` / `set_code()` | Total contract takeover | Require multi-factor auth + code validation |
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

```func
;; Per handler: validate sufficient gas before expensive ops
int compute_fee = getComputeFee(MY_GAS_ESTIMATE, false);
int forward_fee = getForwardFee(OUT_MSG_CELLS, OUT_MSG_BITS, false);
int storage_reserve = TON_PER_YEAR / 12; ;; rough monthly reserve

throw_unless(error::insufficient_gas,
    context().value >= compute_fee + forward_fee + storage_reserve);
```

### Out-of-Gas Behavior

```
OOG exception (exit code 13/-14):
- Cannot be caught with try/catch
- Compute phase fails
- State changes rolled back (UNLESS COMMIT was called before OOG)
- Bounce triggered if inbound was bounceable

POST-accept_message() OOG:
- Transaction IS recorded on chain
- Fees ARE deducted from contract
- State changes NOT applied
- Same message can be replayed! → repeated gas drain until balance = 0
```
