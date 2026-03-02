# TON Smart Contract Audit Checklist

Complete checklist based on 34 professional audit reports, PositiveSecurity guide, and TON official security documentation.

## Phase 1: Architecture Review

### Message Flow Mapping
- [ ] Draw complete message flow diagram for all operations
- [ ] Identify all entry points (recv_internal opcodes, recv_external, get methods)
- [ ] Map all inter-contract calls and their possible failure modes
- [ ] Identify all state-changing operations across the entire flow

### Contract Design
- [ ] No unnecessary admin centralization (single key can drain funds?)
- [ ] Partial transaction execution handled (what if step N fails?)
- [ ] All operations can complete independently (each handler is atomic)
- [ ] Account freezing prevention (adequate TON reserve maintained?)
- [ ] Upgrade/migration path documented and secure

---

## Phase 2: Authorization & Access Control

### Internal Message Auth
- [ ] All handlers extract and validate sender address from `in_msg_full`
- [ ] Jetton operations verify wallet authenticity via master contract
- [ ] Admin operations check sender against stored admin address
- [ ] Workchain validated with `force_chain()` where applicable

### External Message Auth (recv_external)
- [ ] Signature verification BEFORE `accept_message()`
- [ ] Sequence number (seqno) checked and incremented
- [ ] Valid-until timestamp checked (`throw_if(35, valid_until <= now())`)
- [ ] Subwallet ID validated (prevents cross-wallet replay)
- [ ] Signed data includes: recipient, amount, seqno, op (no partial signing)

### Code Update Protection
- [ ] `set_code()` requires multi-factor authorization
- [ ] New code validated before applying
- [ ] Storage migration handled for format changes
- [ ] Upgrade effects only take place after current execution completes

---

## Phase 3: Asynchronous Safety

### Multi-Step Flows
- [ ] Each handler re-validates conditions (doesn't trust earlier step's state)
- [ ] Parallel message flows don't corrupt shared state
- [ ] No global state assumptions between async steps
- [ ] Carry-value pattern used (not cross-contract state queries)

### Bounced Message Handling
- [ ] Every `send_raw_message()` with bounceable mode has corresponding bounce handler
- [ ] Bounce handlers restore original state (undo state changes from failed step)
- [ ] Bounce flag checked FIRST: `if (msg_flags & 1)`
- [ ] Bounce body parsed correctly: skip 32-bit `0xFFFFFFFF` marker
- [ ] Handlers designed knowing bounce = only 256 bits of original payload

### Race Condition Analysis
- [ ] "What if attacker runs parallel flow during this operation?" for each multi-step op
- [ ] State not overwritten by concurrent messages (accumulate, don't assign)
- [ ] Reward/balance updates are idempotent or have unique message IDs
- [ ] DeFi protocols: LP supply updates symmetric for deposits AND withdrawals

---

## Phase 4: Gas Management

### Per-Handler Validation
- [ ] Each handler validates: `msg_value ≥ compute_fee + forward_fee + buffer`
- [ ] Gas calculated for most expensive execution path
- [ ] Deployment flows include new contract storage fee reserve
- [ ] Cross-shard messages account for additional routing cost

### Gas Return
- [ ] Excess gas returned to sender via excesses message (op `0xd53276db`)
- [ ] Mode 64 + 2 used for excess return (not just mode 64 alone)

### Data Structure Safety
- [ ] No unbounded storage growth (dictionaries, lists)
- [ ] Loops have explicit bounds (`MAX_ITERATIONS`)
- [ ] Dictionary traversal is bounded

### Mode 64 Trap Check
- [ ] Contract doesn't emit external messages in same handler as mode 64 send
- [ ] Contract doesn't accumulate storage fees while using mode 64
- [ ] Multiple sends in one tx don't use mode 64 (only first gets "remaining")

---

## Phase 5: Common Vulnerability Patterns

### Integer Arithmetic
- [ ] No division before multiplication (causes precision loss)
- [ ] All subtraction checked for underflow (`throw_unless(cond, a >= b)`)
- [ ] No signed/unsigned mixing (`load_int` vs `load_uint`)
- [ ] No overflow in intermediate calculations (use `muldiv` for big numbers)

### Data Handling
- [ ] `end_parse()` called after reading all storage/message slices
- [ ] Store/load types consistent (same bit width, same sign)
- [ ] No sensitive data stored on-chain (passwords, keys, secrets)
- [ ] Cell limits respected: ≤1023 bits, ≤4 refs per cell

### Loop Safety
- [ ] No infinite loops possible
- [ ] User-controlled loop bounds have hard caps
- [ ] Loops over dictionaries have maximum iteration limits
- [ ] No sending messages inside loops without bound

### Exit Codes
- [ ] No `throw(0)` or `throw(1)` (reserved for normal exit!)
- [ ] Custom error codes ≥256 (0-127 TVM, 128-255 Tact reserved)
- [ ] All error codes documented with meanings

### Replay Protection
- [ ] External messages use seqno
- [ ] External messages use valid_until timestamp
- [ ] Seqno incremented AFTER successful processing

---

## Phase 6: FunC-Specific Checks

- [ ] ALL state-changing functions have `impure` modifier
- [ ] `~` used for in-place modifications (NOT `.` on dict/slice)
- [ ] Variable order in `load_data()` matches `save_data()` exactly
- [ ] No variable name shadowing (local name same as storage field)
- [ ] No variable redeclaration in same scope
- [ ] `end_parse()` after reading storage
- [ ] No third-party code execution without signature verification
- [ ] `COMMIT` not called before all validation complete
- [ ] Global variables not used for persistence (use c4)
- [ ] Boolean comparisons use `!= 0` not `== true` (true = -1, not 1)
- [ ] Method IDs don't conflict with built-ins (recv_internal=0, recv_external=-1)

---

## Phase 7: Tact-Specific Checks

- [ ] Function arguments are pass-by-value (mutations don't propagate)
- [ ] `nativeRandom()` / `nativeRandomInterval()` used (not `randomInt()` / `random()`)
- [ ] Custom exit codes ≥256 (not 128-255 reserved by Tact)
- [ ] Variables initialized ONLY in `init()`, not at declaration
- [ ] Trait variables modified only through trait methods
- [ ] Explicit Int annotations for messages (`as coins`, `as uint256`, etc.)
- [ ] TVM assembly blocks reviewed for safety
- [ ] `bounced<T>` handlers implemented for all critical sent messages
- [ ] Optional variables actually used as optional (or type removed)
- [ ] No double initialization (declaration AND init() both set same var)

---

## Phase 8: Randomness

- [ ] No `random()` without `randomize_lt()` first (FunC)
- [ ] No randomness in external message receivers
- [ ] High-value randomness uses commit-reveal with collateral
- [ ] Validator manipulation considered (1/250 validator = 0.4% block influence)

---

## Phase 9: Jetton / NFT Specific

### Jetton Security
- [ ] Jetton wallet authenticity verified (calculate and compare address)
- [ ] Minter bounce handler decrements `total_supply` on failed mint
- [ ] Transfer failure (bounce) restores sender balance
- [ ] `op::transfer_notification` validated for authenticity
- [ ] TEP-74 message format followed exactly
- [ ] Non-bounceable flag (`0x10`) NOT used for transfers (use `0x18`)

### NFT Security
- [ ] Ownership transfer validated with authorization
- [ ] Minting uses secure randomness for attributes (commit-reveal)
- [ ] Metadata immutability considered (on-chain vs off-chain)
- [ ] TEP-62 compliance checked

### Exchange / DEX Specific
- [ ] Check both `in_msgs` AND `out_msgs` (false deposit detection)
- [ ] Slippage protection in all code paths (including edge cases)
- [ ] Fee collection happens in ALL paths (not skipped on slippage trigger)
- [ ] Liquidity math symmetric for add AND remove operations

---

## Phase 10: Testing & Documentation

- [ ] All handlers covered by unit tests
- [ ] Multi-contract interaction integration tests
- [ ] Gas consumption benchmarked for each handler
- [ ] Bounce scenarios tested explicitly
- [ ] Race condition scenarios simulated
- [ ] All magic numbers replaced with named constants
- [ ] Storage layout documented
- [ ] Message format documented
- [ ] Error codes documented

---

## Red Flags (Automatic Review Required)

Any of these require immediate deep investigation:

- `accept_message()` appears before any validation
- Function missing `impure` but modifying state or sending messages
- `.` used on dictionary operations instead of `~`
- Loop with no bound check
- `set_code()` or `set_data()` without strict auth
- `send_raw_message(msg, 128)` without auth gate
- Missing `bounce handler` for any send to another contract
- `random()` without `randomize_lt()`
- Arithmetic subtraction without underflow check
- Cross-contract "query" pattern (should be carry-value instead)
- `COMMIT` instruction before validation complete
- Global variables used for persistent state

---

## Severity Classification Guide

| Severity | Criteria |
|----------|----------|
| **Critical** | Direct fund loss, contract takeover, protocol shutdown |
| **Major** | Financial loss via specific attack, significant operational disruption |
| **Medium** | Potential financial loss with specific conditions, significant logic error |
| **Low** | Minor financial impact, deviation from best practices |
| **Informational** | Style, documentation, non-exploitable inefficiency |

From real audits: 70% of reports had logical errors or access control issues.
Most common findings by frequency: logical errors (70), auth (25), centralization (19), documentation (23).
