---
name: ton-smart-contract-security
description: Use when developing, auditing, or reviewing TON blockchain smart contracts in FunC, Tact, or Tolk. Covers vulnerabilities, attack patterns, secure coding practices, and audit methodology specific to TON's async actor model. Triggers on: FunC, Tact, Tolk, TVM, TON contract, jetton, NFT on TON, smart contract audit TON.
---

# TON Smart Contract Security

## Overview

TON (The Open Network) uses an **asynchronous actor model** fundamentally different from EVM. A transaction on TON changes state of **one account** processing **one message** — what's one Ethereum tx can span thousands of TON txs across hundreds of blocks. This paradigm shift creates unique vulnerability classes absent from Solidity.

**Based on**: Analysis of 233 vulnerabilities from 34 professional audits (29 projects, 11 audit firms). Top findings: logical errors (70), auth issues (25), centralization (19).

**Key reference files:**
- `vulnerabilities.md` — Full vulnerability catalog with code examples
- `audit-checklist.md` — Complete audit checklist
- `func-tact-security.md` — Language-specific pitfalls (FunC, Tact)
- `tvm-async.md` — TVM internals and async model

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
| Account freezing | **Yes** (storage debt → frozen → deleted) | No |
| Randomness | **Validator-manipulable** (block seed) | Same issue |

---

## Top 10 Critical Vulnerabilities (Quick Reference)

### 1. Missing Bounce Handler ⚡ CRITICAL
Tokens sent via bounceable message fail → bounce returns → **no handler = permanent fund loss**.

```func
;; MUST CHECK bounce flag first in recv_internal
if (msg_flags & 1) { ;; is bounced
    in_msg_body~skip_bits(32); ;; skip 0xFFFFFFFF marker
    int op = in_msg_body~load_uint(32);
    if (op == op::internal_transfer) {
        int jetton_amount = in_msg_body~load_coins();
        ;; restore total_supply — tokens never arrived
        save_data(total_supply - jetton_amount, ...);
    }
    return ();
}
```

### 2. Unconditional accept_message() ⚡ CRITICAL
External messages cost the **contract's own balance**. Accepting before auth = gas drain attack.

```func
;; WRONG — drains contract balance
() recv_external(slice in_msg) impure {
    accept_message(); ;; ← NEVER before validation!
    ...
}

;; CORRECT — validate ALL before accepting
() recv_external(slice in_msg) impure {
    var signature = in_msg~load_bits(512);
    var (subwallet_id, valid_until, msg_seqno) = ...;
    throw_if(35, valid_until <= now());
    throw_unless(33, msg_seqno == stored_seqno);
    throw_unless(35, check_signature(slice_hash(in_msg), signature, public_key));
    accept_message(); ;; ← ONLY after all checks pass
}
```

### 3. Race Conditions in Multi-Contract Flows ⚡ HIGH
While message chain A→B→C processes over blocks, attacker initiates parallel chain. State checked at start may be invalid later.

**Pattern**: Never rely on state from a previous message step. Re-validate at each handler.
**Fix**: Carry-value pattern — embed critical values in message payload, don't query state.

### 4. Missing `impure` Modifier ⚡ HIGH (FunC)
Without `impure`, FunC compiler **silently removes** calls to the function if return value unused.

```func
;; WRONG — compiler may delete this call entirely!
() authorize(slice sender) inline {
    throw_unless(401, equal_slices(sender, admin));
}

;; CORRECT
() authorize(slice sender) impure inline {
    throw_unless(401, equal_slices(sender, admin));
}
```

### 5. Wrong Method Operator `~` vs `.` ⚡ HIGH (FunC)
`.` returns a new value, `~` modifies in-place. Using `.` on dict = **silent no-op**.

```func
;; WRONG — dict is NOT modified
accounts.udict_delete_get?(256, sender);

;; CORRECT — dict IS modified
accounts~udict_delete_get?(256, sender);
```

### 6. Insecure Randomness ⚡ HIGH
`random()` without seed = **validator-predictable**. Validators control block seeds.

```func
;; WRONG
int n = rand(100);

;; BETTER (still manipulable by colluding validators)
randomize_lt();
int n = rand(100);

;; CORRECT for high-value: commit-reveal off-chain scheme
```
Tact: use `nativeRandom()` NOT `randomInt()`.

### 7. Replay Attack — Missing Seqno ⚡ HIGH
External messages without sequence numbers can be replayed forever.

```func
throw_unless(33, msg_seqno == stored_seqno);
throw_if(35, valid_until <= now()); ;; also add expiry
accept_message();
stored_seqno += 1; ;; increment AFTER accept
```

### 8. Partial Transaction Execution ⚡ HIGH
Gas exhaustion mid-flow leaves state inconsistent. OOG **cannot be caught**.

```func
;; Validate gas BEFORE expensive operations
require(context().value > getComputeFee(voteGasUsage, false));
```

**Key**: Design each handler to be atomic independently. Use bounce handlers to restore state on failure.

### 9. Dangerous Message Modes ⚡ MEDIUM
- **Mode 64** after mode 64 in same tx = subsequent messages fail (balance already forwarded)
- **Mode 128 + 32** = send all + destroy account — must be authorization-gated
- **Flag +2 (IgnoreErrors)** = silent failures, state changes persist with no rollback notification

```func
;; SAFE: return excess gas
send_raw_message(excesses_msg, SendRemainingValue | SendIgnoreErrors); ;; 64 + 2
```

### 10. Signed/Unsigned Integer Confusion ⚡ MEDIUM
Mixing signed/unsigned allows negative values — addition becomes subtraction.

```func
;; ALWAYS validate before arithmetic
throw_unless(998, from_votes >= amount);
from_votes -= amount;
```

---

## Transaction Phases (Security Impact)

```
Storage Phase → Credit Phase → Compute Phase → Action Phase → Bounce Phase
```

- **Storage phase** deducts rent BEFORE credit — if accumulated debt > incoming value → freeze
- **Compute phase** failure: state reverts, bounce triggers automatically
- **Action phase** failure: state changes **persist** but messages NOT sent; bounce only if flag +16 set
- **Bounce phase**: only fires if inbound message had bounce bit AND there was a failure

**Critical rule**: "We cannot allow fails in action phase since there will be no bounce. Check and throw in computation phase."

---

## Carry-Value Pattern (Fundamental TON Pattern)

TON cannot query another contract's state synchronously. State changes between messages. **Always embed the value in the message itself.**

```
✗ WRONG:  A sends request to B asking "what's your balance?"
           B sends back balance
           A uses balance (may be stale by now)

✓ CORRECT: A embeds required_amount in message to B
            B processes with the embedded amount
            B responds with result embedded in bounce/response
```

---

## Gas Management Rules

1. **Pre-calculate** gas for each handler; validate `msg_value ≥ compute_fee + forward_fee`
2. **Return excess** gas: `send_raw_message(excesses_msg, 64 | 2)` with op `0xd53276db`
3. **No unbounded loops** over user-controlled data structures
4. **No infinite storage growth** — tokenize into separate contracts if needed
5. **Storage fees drain from balance** independently of message value — account for rent
6. **If contract can't afford bounce** — silent failure, no notification, funds lost

---

## Quick Security Checklist

**Design**
- [ ] All message flows diagrammed
- [ ] Bounce handlers for all bounceable messages
- [ ] Each handler independent/atomic (no multi-step state assumptions)
- [ ] No unnecessary centralization / admin powers

**Auth & Access**
- [ ] All functions check sender address
- [ ] External messages: signature + seqno + expiry BEFORE accept_message()
- [ ] Code updates require multi-check authorization
- [ ] Workchain validated: `force_chain(to_address)`

**Async Safety**
- [ ] No state queried cross-contract (carry-value instead)
- [ ] Parallel message flows don't corrupt state
- [ ] Re-validate conditions at each message step

**Gas**
- [ ] Gas sufficient for each handler (pre-calculated)
- [ ] Excess returned to sender
- [ ] No unbounded data structures
- [ ] Partial execution handled gracefully

**Language (FunC)**
- [ ] All state-changing fns have `impure`
- [ ] `~` used for modifying dict/slice operations
- [ ] Variables ordered correctly in load_data/save_data
- [ ] `end_parse()` used after reading
- [ ] No variable name collisions/shadowing

**Language (Tact)**
- [ ] Args are pass-by-value — mutations don't propagate
- [ ] `nativeRandom()` not `randomInt()`
- [ ] Custom exit codes ≥ 256 (128-255 reserved by Tact)
- [ ] Variables initialized in `init()` not at declaration

**Randomness**
- [ ] `randomize_lt()` before `rand()` in FunC
- [ ] Commit-reveal for high-value randomness
- [ ] No randomness in external message receivers

**Serialization**
- [ ] Types consistent: store_uint/load_uint match
- [ ] Cell limits respected (1023 bits, 4 refs)
- [ ] Dictionary return values checked (success flag)
- [ ] No reserved exit codes used (0-127 TVM, 128-255 Tact)

---

## Tools

| Tool | Purpose |
|------|---------|
| [Misti](https://github.com/nowarp/misti) | Static analyzer for Tact — 42 detectors, CI/CD ready |
| [TSA](https://tonsec.dev/) | Symbolic execution analyzer (bytecode-level) |
| [@ton/sandbox](https://github.com/ton-org/sandbox) | Test harness with `printTransactionFees()` |
| [BugMagnifier](https://arxiv.org/abs/2509.24444) | Async race condition simulator |
| [verifier.ton.org](https://verifier.ton.org/) | Source code verification |

**Static analysis cannot replace manual audit.** Run Misti as minimum, get professional audit for production.

---

## Audit Firms (TON-Specialized)
TonBit, Beosin, Quantstamp, Nowarp, Hacken, CertiK, SlowMist, Zellic, Positive Technologies, Cantina/Spearbit, Trail of Bits

## CTF / Practice
- [TON Hack Challenge #1](https://docs.ton.org/develop/smart-contracts/security/ton-hack-challenge-1) — 8 vulnerable contracts
- [TonBit CTF 2024](https://ctf.tonbit.xyz/)
- [Hack The TON](https://www.hacktheton.com/)
- [PositiveCTF TON](https://github.com/PositiveSecurity/PositiveCTF-TON)
