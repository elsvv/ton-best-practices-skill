# TON Smart Contract Audit Checklist (Tolk)

Based on 34 audit reports, PositiveSecurity guide, TON official docs, and tolk-bench analysis.

## Phase 0: Tolk Language Configuration

### Compiler & Runtime
- [ ] Tolk compiler version identified (target: 1.2.x / `@ton/tolk-js` v1.2.0)
- [ ] TVM version confirmed (TVM 12 for Tolk 1.2 features)
- [ ] All imports reviewed (no unexpected stdlib overrides)
- [ ] Compiler flags and settings checked for security implications
- [ ] `@overflow1023_policy("suppress")` annotations justified (struct fits in practice)

### Struct & Storage Layout
- [ ] Storage struct defined clearly (not raw cell parsing)
- [ ] All `@lazy` fields documented and loading verified in handlers
- [ ] Union types exhaustively matched (no hidden `else` branches accepting unknown opcodes)
- [ ] All `@opcode` annotations unique across the contract and across union types

### Type Safety
- [ ] `address` vs `address?` vs `any_address` usage reviewed
- [ ] No unsafe `as` casts from untrusted data (slices, cells)
- [ ] No unsafe `!` force-unwrap on nullable values (throws exit code 7 on null)
- [ ] Global variables initialized before first use

### Message Configuration
- [ ] `BounceMode` explicitly selected per message: `RichBounce` for stateful sends (Tolk 1.2)
- [ ] `@onBouncedMessage` handler covers all sent message types
- [ ] `assertEndAfterReading` not disabled (default: true)
- [ ] Enum values validated during deserialization (auto-validated by Tolk)

---

## Phase 1: Architecture Review

### Message Flow Mapping
- [ ] Draw complete message flow diagram for all operations
- [ ] Identify all entry points (`@onInternalMessage` handlers, `@onExternalMessage`, `@onTickTock`, get methods)
- [ ] Map all inter-contract calls and their possible failure modes
- [ ] Identify all state-changing operations across the entire flow
- [ ] Union type message dispatch reviewed for completeness (all opcodes handled)

### Contract Design
- [ ] No unnecessary admin centralization (single key can drain funds?)
- [ ] Partial transaction execution handled (what if step N fails?)
- [ ] All operations can complete independently (each handler is atomic)
- [ ] Account freezing prevention (adequate TON reserve maintained?)
- [ ] Upgrade/migration path documented and secure
- [ ] `contract.setCodePostponed()` requires multi-factor authorization or timelock

---

## Phase 2: Authorization & Access Control

### Internal Message Auth
- [ ] All handlers extract and validate sender address via `in.senderAddress`
- [ ] `address` type used (not `any_address`) to validate internal address format
- [ ] Jetton operations verify wallet authenticity via master contract
- [ ] Admin operations check sender against stored admin address
- [ ] Nullable admin pattern: no `!` force-unwrap on optional admin without null check
- [ ] Workchain validated where applicable: `in.senderAddress.getWorkchain() == 0`

### External Message Auth (`@onExternalMessage`)
- [ ] Signature verification BEFORE `acceptExternalMessage()`
- [ ] Sequence number (seqno) checked and incremented
- [ ] Valid-until timestamp checked: `assert (validUntil > blockchain.now()) throw ERR_EXPIRED`
- [ ] Time check performed BEFORE `acceptExternalMessage()`
- [ ] Subwallet ID validated (prevents cross-wallet replay)
- [ ] Signed data includes: recipient, amount, seqno, op (no partial signing)
- [ ] Signature validation covers all body fields

### Code Update Protection
- [ ] `contract.setCodePostponed()` requires strict authorization
- [ ] New code validated before applying
- [ ] Storage migration handled for format changes
- [ ] Upgrade effects take place after current execution (postponed by default in Tolk)

---

## Phase 3: Asynchronous Safety

### Multi-Step Flows
- [ ] Each handler re-validates conditions (doesn't trust earlier step's state)
- [ ] Parallel message flows don't corrupt shared state
- [ ] No global state assumptions between async steps
- [ ] Carry-value pattern used (not cross-contract state queries)

### Bounced Message Handling
- [ ] Every outgoing bounceable message has a corresponding `@onBouncedMessage` handler
- [ ] `BounceMode` explicitly set: `RichBounce` for full body recovery (Tolk 1.2), `Only256BitsOfBody` otherwise
- [ ] Bounce handlers restore original state (undo state changes from failed step)
- [ ] Bounce body parsed correctly via `InMessageBounced` type and `.skipBouncedPrefix()`
- [ ] `@on_bounced_policy("manual")` reviewed: contract handles or intentionally ignores bounces

### Race Condition Analysis
- [ ] "What if attacker runs parallel flow during this operation?" for each multi-step op
- [ ] State not overwritten by concurrent messages (accumulate, don't assign)
- [ ] Reward/balance updates are idempotent or have unique message IDs
- [ ] DeFi protocols: LP supply updates symmetric for deposits AND withdrawals

---

## Phase 4: Gas Management

### Per-Handler Validation
- [ ] Each handler validates: `msg_value >= compute_fee + forward_fee + buffer`
- [ ] Gas calculated for most expensive execution path
- [ ] Deployment flows include new contract storage fee reserve
- [ ] Cross-shard messages account for additional routing cost
- [ ] Gas constants recalibrated for Tolk (20-56% savings vs FunC may change thresholds)

### Gas Return
- [ ] Excess gas returned to sender via excesses message (op `0xd53276db`)
- [ ] `SEND_MODE_PAY_FEES_SEPARATELY | SEND_MODE_BOUNCE_ON_ACTION_FAIL` used for excess return

### Data Structure Safety
- [ ] No unbounded storage growth (maps, lists)
- [ ] Loops have explicit bounds (`MAX_ITERATIONS`)
- [ ] Map traversal is bounded (`.findFirst()` / `.iterateNext()` loops have limits)

### Reserve + Send Mode Safety
- [ ] `reserveToncoinsOnBalance` + `SEND_MODE_CARRY_ALL_BALANCE` (128) combination reviewed
- [ ] Incorrect reservation cannot drain contract
- [ ] Multiple sends in one tx don't use `SEND_MODE_CARRY_ALL_REMAINING_BALANCE` (only first gets "remaining")
- [ ] Contract doesn't emit external messages in same handler as carry-remaining send

---

## Phase 5: Common Vulnerability Patterns

### Integer Arithmetic
- [ ] No division before multiplication (causes precision loss)
- [ ] Use `mulDivFloor(a, b, c)` for safe big-number arithmetic
- [ ] All subtraction checked for underflow: `assert (a >= b) throw ERR_UNDERFLOW`
- [ ] Sized integer types (`uint32`, `uint64`, etc.) reviewed for silent arithmetic overflow
- [ ] `coins` arithmetic: only `+` and `-` preserve `coins` type, other operators degrade to `int`
- [ ] Overflow at serialization: values exceeding type width cause exit code 5

### Data Handling
- [ ] `assertEndAfterReading` not set to false (ensures slices fully consumed)
- [ ] `@lazy` fields validated after loading (security-relevant fields actually read)
- [ ] No raw `as` casts from untrusted slice data
- [ ] `Cell<T>` types used correctly (typed cell wrappers)
- [ ] No sensitive data stored on-chain (passwords, keys, secrets)
- [ ] Cell limits respected: <=1023 bits, <=4 refs per cell

### Loop Safety
- [ ] No infinite loops possible
- [ ] User-controlled loop bounds have hard caps
- [ ] Loops over maps have maximum iteration limits
- [ ] No sending messages inside loops without bound

### Exit Codes
- [ ] No `assert ... throw 0` or `throw 1` (reserved for normal exit)
- [ ] Custom error codes >= 256 (0-127 TVM reserved, 128-255 Tact reserved)
- [ ] Force-unwrap `!` on null produces exit code 7 -- verify this is acceptable
- [ ] All error codes documented with meanings

### Replay Protection
- [ ] External messages use seqno
- [ ] External messages use valid_until timestamp
- [ ] Seqno incremented AFTER successful processing
- [ ] `commitContractDataAndActions()` used to commit seqno before action processing

---

## Phase 6: Tolk-Specific Checks

### Type System Safety
- [ ] `address` type used for all sender/recipient fields (validates MsgAddressInt format)
- [ ] `any_address` only used where `addr_none` is intentionally accepted
- [ ] Nullable types (`address?`, `cell?`, `int?`) checked before use, not force-unwrapped
- [ ] Sized integers (`uint32`, `uint64`, `coins`) match TL-B schema exactly
- [ ] `RemainingBitsAndRefs` used correctly for pass-through payloads

### Struct & Serialization
- [ ] Storage struct layout matches on-chain data format
- [ ] `@lazy` fields: security-relevant fields actually loaded before checks
- [ ] `@lazy` fields: not accidentally skipped by compiler optimization
- [ ] Union type `else =>` branches throw or are intentionally permissive
- [ ] `@opcode` values unique within each union type
- [ ] Generic structs (`Cell<T>`, `map<K,V>`) properly typed

### Message Construction
- [ ] `createMessage()` API used (not raw cell building) for type safety
- [ ] `BounceMode` explicitly set for all stateful outgoing messages
- [ ] `BounceMode.RichBounce` used for full body recovery (Tolk 1.2)
- [ ] `BounceMode.NoBounce` only where delivery failure is acceptable
- [ ] `AutoDeployAddress`: `stateInit` data matches deployed contract expectations
- [ ] `sendRawMessage` calls: send mode validated (used for proxied messages)

### Bounce Handling
- [ ] `@onBouncedMessage` handler exists if contract sends bounceable messages
- [ ] Union type message dispatch in bounce handler is exhaustive
- [ ] `@on_bounced_policy("manual")` justified and fully implemented

### State Management
- [ ] `contract.setData()` / `contract.getData()` used correctly
- [ ] `commitContractDataAndActions()` placement reviewed (replay protection)
- [ ] Global variables not used for persistent state (use storage structs)
- [ ] `contract.setCodePostponed()` has governance controls

---

## Phase 7: External Message Security

### Validation Order (Critical)
```
1. Parse message body
2. Check valid_until > blockchain.now()
3. Check seqno matches stored seqno
4. Verify signature with isSignatureValid(hash, signature, publicKey)
5. acceptExternalMessage()       <-- gas payment starts here
6. Increment seqno
7. commitContractDataAndActions() <-- commit seqno for replay protection
8. Process actions
```

### Tolk-Specific External Message Checks
- [ ] `acceptExternalMessage()` called (not the FunC `accept_message()`)
- [ ] Seqno + validUntil + signature all checked BEFORE `acceptExternalMessage()`
- [ ] Signature validation covers all body fields (no partial signing)
- [ ] `commitContractDataAndActions()` used to commit seqno before action processing
- [ ] Empty `catch` blocks reviewed: failed actions must not silently consume seqno
- [ ] `try/catch` around action execution reviewed for seqno increment correctness

---

## Phase 8: Randomness

- [ ] No `random()` without `randomizeBySeedAndLogicalTime()` first
- [ ] No randomness in external message receivers
- [ ] High-value randomness uses commit-reveal with collateral
- [ ] Validator manipulation considered (1/250 validator = 0.4% block influence)

---

## Phase 9: Jetton / NFT Specific

### Jetton Security
- [ ] Jetton wallet authenticity verified (calculate and compare address)
- [ ] Minter bounce handler decrements `totalSupply` on failed mint
- [ ] Transfer failure (bounce) restores sender balance
- [ ] Transfer notification validated for authenticity
- [ ] TEP-74 message format followed exactly
- [ ] Non-bounceable flag NOT used for transfers (use bounceable mode)
- [ ] `coins` type used for all token amounts

### NFT Security
- [ ] Ownership transfer validated with authorization
- [ ] Minting uses secure randomness for attributes (commit-reveal)
- [ ] Metadata immutability considered (on-chain vs off-chain)
- [ ] TEP-62 compliance checked
- [ ] Initialization detection logic is robust (not fragile ref-counting)

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
- [ ] `@deprecated` functions reviewed for continued use

---

## Red Flags (Automatic Review Required)

Any of these require immediate investigation:

- `acceptExternalMessage()` appears before any validation
- `!` force-unwrap on nullable from untrusted input
- `as` cast from untrusted slice/cell data
- `else =>` in union match that silently accepts unknown opcodes
- Loop with no bound check
- `contract.setCodePostponed()` or `contract.setData()` without strict auth
- `SEND_MODE_CARRY_ALL_BALANCE` (128) without auth gate
- Missing `@onBouncedMessage` handler for any bounceable send
- `random()` without `randomizeBySeedAndLogicalTime()`
- Arithmetic subtraction without underflow check
- Cross-contract "query" pattern (should be carry-value instead)
- `commitContractDataAndActions()` before validation complete
- Global variables used for persistent state
- `@on_bounced_policy("manual")` without explicit bounce handling
- `sendRawMessage` with unvalidated send mode
- `assertEndAfterReading` set to false without justification
- `@overflow1023_policy("suppress")` without size analysis

---

## Tolk Version Compatibility

Verify target Tolk version -- security features differ:

### Tolk 1.0
- `@lazy` loading (deferred deserialization for gas savings)
- Auto-serialization via struct definitions
- New entrypoints: `@onInternalMessage`, `@onExternalMessage`, `@onTickTock`
- `createMessage()` API for typed message construction
- `acceptExternalMessage()` replaces FunC `accept_message()`
- `contract.setData()` / `contract.getData()` replace `set_data()` / `get_data()`
- `assert ... throw` replaces `throw_unless` / `throw_if`
- Method syntax `.method()` replaces FunC `~method()` tilde calls

### Tolk 1.1
- `map<K,V>` typed dictionaries with `.set()`, `.exists()`, `.delete()`
- Enum validation during deserialization (automatic)
- `private` / `readonly` field modifiers
- Stricter type aliases (sized integers enforced)
- `@deprecated` annotation for migration warnings

### Tolk 1.2
- `BounceMode.RichBounce` for full message body recovery in bounce handlers
- `address` type validates MsgAddressInt format (rejects addr_none)
- Borrow checker for `mutate` parameters (prevents aliasing bugs)
- Anonymous functions (closures)
- TVM 12 instruction support

**Audit note**: Tolk 1.2 requires TVM 12. Verify deployment environment matches contract's target version.

---

## Severity Classification Guide

| Severity | Criteria |
|----------|----------|
| **Critical** | Direct fund loss, contract takeover, protocol shutdown |
| **Major** | Financial loss via specific attack, significant operational disruption |
| **Medium** | Potential financial loss with specific conditions, significant logic error |
| **Low** | Minor financial impact, deviation from best practices |
| **Informational** | Style, documentation, non-exploitable inefficiency |

From 34 audits: logical errors (70), auth (25), documentation (23), centralization (19). 70% of reports had logic or access control issues.
