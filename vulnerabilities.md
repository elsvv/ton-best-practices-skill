# TON Smart Contract Vulnerabilities — Full Catalog

Based on 233 vulnerabilities from 34 audit reports (29 projects, 11 audit firms, 2023-2025).

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

### 1.1 Authorization Issues (25 cases — most common design flaw)

Every function and message handler must validate the sender. For internal messages, extract and check `in_msg_full` sender. For Jetton operations, calculate expected wallet address.

```func
;; FunC: validate internal message sender
slice cs = in_msg_full.begin_parse();
int flags = cs~load_uint(4);
slice sender = cs~load_msg_addr();
throw_unless(error::unauthorized, equal_slices(sender, expected_admin));
```

```func
;; FunC: validate Jetton wallet authenticity
slice expected_wallet = calculate_user_jetton_wallet_address(sender, jetton_master, wallet_code);
throw_unless(error::fake_jetton, equal_slices(msg_sender, expected_wallet));
```

**Fake Jetton Attack**: Attacker deploys contract claiming to be a jetton wallet with inflated balance. Always verify by calling `get_wallet_address()` on master and checking the result matches sender.

**False Deposit Attack** (exchanges): Check BOTH inbound and outbound messages. If `out_msgs` contains a refund message, the deposit is fake (bounce-back).

### 1.2 Centralization Risks (19 cases)

Evaluate: Can admin drain all funds in one tx? Is there a timelock? Multi-sig? If one key is compromised, what's the blast radius?

```func
;; Red flags:
;; - send_raw_message(msg, 128) gated only by admin check
;; - set_code() without timelock
;; - no emergency pause mechanism
;; - single-owner upgradeable contract
```

### 1.3 Input Data Processing (15 cases)

```func
;; Always validate all input fields
int amount = in_msg_body~load_coins();
throw_unless(error::invalid_amount, amount > 0);
throw_unless(error::overflow, amount <= max_supply);

slice destination = in_msg_body~load_msg_addr();
force_chain(destination); ;; ensure valid workchain
```

### 1.4 Partial Transaction Execution (6 cases)

**Pattern**: Contract modifies state in step 1, sends message for step 2. Step 2 fails. Step 1 is NOT reverted.

**Real case — Onton Finance**: Pool zeroed user's ledger before confirming withdrawal. If downstream operation failed, user lost funds permanently.

**Fix**: Design for "optimistic with recovery":
1. Mark as "pending" (not irreversibly zero)
2. On success: finalize
3. On bounce: restore original state

### 1.5 Account Freezing/Deletion

Contracts with storage but no incoming TON accumulate storage debt:
- Debt > 0.1 TON → **Frozen** (code/data preserved as hashes, cannot execute)
- Debt > 1 TON → **Deleted** (account removed entirely)

**Prevent**: Ensure contracts always have adequate TON reserves. Beware of Jetton wallets with tiny balances.

---

## Category 2: Asynchronous Execution Vulnerabilities (6 cases — high impact)

### 2.1 Message Ordering Non-Determinism

Messages to **same contract**: ordered by logical time (lt). Safe.
Messages to **different contracts**: **NO ordering guarantee**. Attackers exploit this.

```
Contract A sends msg to B AND msg to C
B and C both send to D
Order D receives them: UNPREDICTABLE
```

**Real case — Storm Trade**: Two reward messages sent independently to same Referral Item contract. Message B processed first, then Message A **overwrote** balance instead of accumulating. User lost 5 TON reward.

**Fix**: Make reward handlers accumulate (+= not assign). Use unique message IDs for idempotency.

### 2.2 Delayed State Updates

**Real case — TONCO**: PositionNFT had stale `fee_growth = 0` while PoolContract had `fee_growth = 110`. Reward calculation: `0 - 110 = -110` (negative rewards).

**Fix**: Embed pool state hash in withdrawal requests. Reject if PositionNFT state doesn't match current pool state.

### 2.3 Race Condition Pattern

```
Assume: While flow A→B→C processes, attacker launches parallel flow A'→B→C
State at B may have changed between flows
B must re-validate ALL conditions it depended on, not trust state from flow A's start
```

---

## Category 3: Common Errors (92 vulnerabilities — largest category)

### 3.1 Logical Errors (70 cases — dominant!)

**Division before multiplication** (precision loss):
```func
;; WRONG: 40 / 100 * 20 = 0 (integer division loses remainder)
let result = x / z * y;

;; CORRECT: 40 * 20 / 100 = 8
let result = x * y / z;
```

**Asymmetric state updates** (ThunderFinance case):
```func
;; lpSupply increased on deposit but NEVER decreased on withdrawal
;; Over time: lpSupply = 1300, actual backing = 800 → rewards diluted
```
Fix: All state changes must have symmetric counterparts.

**Signed/unsigned confusion**:
```func
int votes = msg~load_int(64);   ;; signed
uint balance = storage~load_uint(64); ;; unsigned

;; votes + balance can be votes - balance if votes is negative!
throw_unless(998, votes >= 0); ;; validate sign
```

### 3.2 Bounced Message Handling (3 cases)

Every bounceable message sent to another contract **must** have a corresponding bounce handler.

Bounce message format:
- 32-bit prefix: `0xFFFFFFFF`
- Then first 256 bits of original message body
- Only **224 bits of useful data** after stripping marker

```func
;; FunC bounce handler pattern
if (msg_flags & 1) { ;; bounced flag
    slice body = in_msg_body;
    body~skip_bits(32); ;; skip 0xFFFFFFFF
    int op = body~load_uint(32);

    if (op == op::internal_transfer) {
        int amount = body~load_coins();
        ;; RESTORE state — transfer never happened
        total_supply -= amount; ;; if minting
        ;; OR restore sender balance if transferring
    }
    return ();
}
```

```tact
// Tact bounce handler
bounced(msg: bounced<TokenTransfer>) {
    // restore state
    self.totalSupply -= msg.amount;
}
```

**Important**: Bounced messages CANNOT be re-bounced. If bounce handler fails, no further recovery.

### 3.3 Replay Attacks (3 cases)

```func
;; Complete replay protection pattern (from wallet3)
() recv_external(slice in_msg) impure {
    var signature = in_msg~load_bits(512);
    var cs = in_msg;
    var (subwallet_id, valid_until, msg_seqno) = (
        cs~load_uint(32), cs~load_uint(32), cs~load_uint(32)
    );
    throw_if(35, valid_until <= now());      ;; expiry check
    var ds = get_data().begin_parse();
    var (stored_seqno, stored_subwallet, public_key) = (
        ds~load_uint(32), ds~load_uint(32), ds~load_uint(256)
    );
    throw_unless(33, msg_seqno == stored_seqno);          ;; seqno check
    throw_unless(34, subwallet_id == stored_subwallet);   ;; wallet ID check
    throw_unless(35, check_signature(slice_hash(in_msg), signature, public_key));
    accept_message(); ;; ONLY after all checks!
    ;; ... process ...
    set_data(begin_cell()
        .store_uint(stored_seqno + 1, 32) ;; increment seqno
        ...
    .end_cell());
}
```

**Front-running via signature reuse**: Signatures must include recipient address and seqno, otherwise valid signatures can be replayed for different recipients.

### 3.4 Data Parsing / Serialization (6 cases)

```func
;; WRONG: load 64 bits but storage had 32 bits
int balance = ds~load_uint(64); ;; corrupts all subsequent reads!

;; CORRECT: match exact types from store operations
;; store_uint(x, 32) → load_uint(32)
;; store_coins(x) → load_coins()
;; store_int(x, 257) → load_int(257)

;; ALWAYS end with:
ds.end_parse(); ;; throws if unconsumed data exists — catches bugs!
```

### 3.5 Smart Contract Updates (3 cases)

```func
;; set_code and set_data completely overwrite c3 and c4
;; Effects take place ONLY after current execution succeeds

;; MUST verify storage compatibility before upgrade
;; Old storage layout: (int seqno, int balance, slice owner)
;; New storage layout: (int seqno, int balance, slice owner, cell config) ← ADDED
;; Migration script must handle old layout gracefully

;; MUST authorize:
throw_unless(error::not_admin, equal_slices(sender, admin));
throw_unless(error::invalid_code, verify_code_signature(new_code));
set_code(new_code);
set_data(migrate_data(get_data())); ;; transform old layout to new
```

### 3.6 Exit Codes — Do Not Use Reserved Values

```
TVM reserved: 0-127
Tact reserved: 128-255
Custom: use 256+
```

| Code | Meaning |
|------|---------|
| 0, 1 | Normal exit — using throw(0) looks like success! |
| 4 | Integer overflow |
| 8 | Cell overflow (>1023 bits or >4 refs) |
| 9 | Cell underflow (reading past end) |
| 13 | Out of gas (cannot be caught) |
| 37 | Not enough Toncoin for action |

### 3.7 Loop Dangers / DoS

```func
;; DANGEROUS: attacker controls loop count
int count = msg~load_uint(32);
repeat(count) {
    expensive_operation();
}

;; SAFE: bound loops
int MAX_ITERATIONS = 100;
throw_unless(error::too_many, count <= MAX_ITERATIONS);
repeat(count) { ... }
```

---

## Category 4: Gas Control (18 vulnerabilities)

### 4.1 Insufficient Gas Reserve

```func
;; Validate at entry point of each handler
int required_gas = getComputeFee(MY_HANDLER_GAS, false)
    + getForwardFee(MY_MSG_CELLS, MY_MSG_BITS, false);
throw_unless(error::insufficient_gas, context().value >= required_gas);
```

### 4.2 Dangerous Send Modes

```func
;; Mode 64 (SendRemainingValue): forwards ALL remaining inbound value
;; PROBLEM: if contract also pays storage fees or sends external msgs,
;; those come from CONTRACT balance, slowly draining it to zero

;; Mode 128 (SendRemainingBalance): sends ENTIRE contract balance
;; Only safe for final contract closure, with auth gate

;; Mode 128 + 32: send all + DESTROY CONTRACT — extreme caution!

;; SAFE excess return:
var msg = begin_cell()
    .store_uint(0x10, 6)
    .store_slice(response_destination)
    .store_coins(0)
    .store_uint(0, 1 + 4 + 4 + 64 + 32 + 1 + 1)
    .store_uint(op::excesses, 32) ;; 0xd53276db
    .store_uint(query_id, 64)
    .end_cell();
send_raw_message(msg, SendRemainingValue | SendIgnoreErrors); ;; 64 | 2
```

### 4.3 Third-Party Code Execution (COMMIT Attack)

```func
;; OOG cannot be caught with try/catch
;; Attacker code:
try {
    COMMIT; ;; persist malicious state changes
    ;; trigger OOG here
} catch(_, _) {
    ;; only gas cost rolls back, COMMIT changes survive!
}
```

**Never execute untrusted code**. Always verify code with signature before running.

### 4.4 Storage Fee Drain

If contract sends external messages (events/logs), those fees come from **contract balance** regardless of mode 64. Combined with storage rent, balance slowly drains.

**Fix**: Calculate storage rent accumulation. Keep reserve. Avoid external messages unless necessary.

---

## Category 5: Randomness Vulnerabilities (1 case — but critical)

**Real case — TRS 404 NFT**: Used `random()` without seed → validators manipulated NFT level assignment. Attackers waited for preferred validator to get desired attributes.

### How Validators Manipulate Randomness

1. Block seed: `SHA256(block_seed || contract_address)` — validator controls `block_seed`
2. `RANDU256`: `SHA512(current_seed)` → new seed + output — deterministic given seed
3. Validator can choose to skip creating blocks to get favorable seed
4. 1/250 network validator can influence 0.4% of blocks → for high-value operations: enough

### Secure Patterns

```func
;; FunC: minimum viable (still manipulable for high value)
randomize_lt();
int n = rand(100);

;; FunC: better entropy mix
randomize(slice_hash(in_msg_body) ^ now() ^ cur_lt());
randomize_lt();
int n = rand(100);
```

```tact
// Tact: use native functions
let n: Int = nativeRandom();         // 256-bit random
let m: Int = nativeRandomInterval(1, 100); // bounded
// NOT randomInt() or random() — these don't prepare seed
```

**For high-stakes**: Implement commit-reveal:
1. Participants submit `hash(secret || salt)` on-chain
2. After all commits: reveal `secret`
3. Contract combines all secrets for final randomness
4. Add slashing/collateral for no-reveal

---

## Category 6: Language-Specific Errors (4 FunC cases)

See `func-tact-security.md` for complete language-specific details.

---

## Category 7: Best Practices Violations (36 cases)

### Documentation (23 cases)
- All message opcodes documented
- Message flow diagrams maintained
- Storage layout documented (field types, sizes, order)
- Upgrade procedures documented

### Magic Numbers → Named Constants
```func
;; WRONG
if (op == 0x178d4519) { ... }
send_raw_message(msg, 160);

;; CORRECT
const int op::burn_notification = 0x178d4519;
const int SEND_WHOLE_BALANCE_AND_DESTROY = 128 + 32;
```

### Standards Compliance
- Jetton: TEP-74, TEP-89
- NFT: TEP-62, TEP-66
- Follow standard message formats exactly
- Check `op` field before routing to handler

---

## Real-World Case Studies

### Onton Finance — Missing Rebound (Critical)
Pool zeros user ledger before confirming withdrawal. Downstream failure = permanent asset loss.

### TONCO — Async State Desync (Major)
PositionNFT had stale fee_growth; rewards calculated as negative number.

### Storm Trade — Race Condition Rewards (Major)
Concurrent reward messages overwrote each other. Balance: 5 instead of expected 10 TON.

### ThunderFinance — lpSupply Never Decremented (Major)
Deposit increases lpSupply; withdrawal does NOT decrease it. Reward dilution grows over time.

### EVAA — Wrong Collateral Factor (Major)
`calculate_maximum_withdraw_amount()` ignored per-asset risk weights. Protocol became undercollateralized.

### TRS 404 NFT — Predictable Random (Critical)
`deployNftItem()` used `random()` → validator manipulation of NFT attributes.

### EVAA — Missing `impure` (Major)
`ton::cell_fwd_fee()` lacked `impure` → compiler removed the call → gas calculation skipped.

### ThunderFinance — Gas + No Bounce (Major)
Deposit without gas calculation + no bounce handler = partial execution leaves inconsistent state.
