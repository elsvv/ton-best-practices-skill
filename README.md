# ton-best-practices

A Claude Code skill for TON blockchain smart contract security auditing, development, and best practices.

**Language**: Tolk v1.2 / TVM 12
**Based on**: 233 vulnerabilities from 34 professional audits + full Tolk documentation + 42 production contracts from tolk-bench

## Installation

```bash
npx skills add elsvv/ton-best-practices-skill
```

## What's inside

| File | Contents |
|------|----------|
| `SKILL.md` | Entry point — Top 10 vulnerabilities, quick checklist, TON vs EVM comparison |
| `tolk-security.md` | 30 Tolk-specific security pitfalls with vulnerable/correct code examples |
| `tolk-best-practices.md` | 16-section Tolk language best practices from production contracts |
| `vulnerabilities.md` | Full 233-vulnerability catalog with Tolk code examples |
| `tvm-async.md` | TVM internals, async model, BounceMode guide (Tolk 1.2 / TVM 12) |
| `audit-checklist.md` | 11-phase professional audit checklist (Phase 0 = Tolk config) |

## Key topics

- **Top 10 vulnerabilities**: auth checks, integer overflow, async reentrancy, lazy loading bypass, union type dispatch, message modes, deserialization, null assertions, bounce handling, gas exhaustion
- **Tolk 1.2 features**: `BounceMode.RichBounce` (full bounce body recovery), `address` internal-only validation, borrow checker
- **Async model**: carry-value pattern, bounce handlers, multi-message race conditions
- **Access control**: nullable admin patterns, two-step ownership transfer, workchain validation
- **Gas management**: fee estimation, reserve patterns, out-of-gas handling

## Trigger keywords

`Tolk`, `TVM`, `TVM 12`, `TON contract`, `jetton`, `NFT TON`, `TON audit`, `bounce message`, `smart contract security`, `TON blockchain`

## Sources

- [PositiveSecurity/ton-audit-guide](https://github.com/PositiveSecurity/ton-audit-guide)
- [arXiv:2509.10823](https://arxiv.org/abs/2509.10823) — "From Paradigm Shift to Audit Rift" (233 vulns, 34 audits)
- [docs.ton.org Tolk docs](https://docs.ton.org/languages/tolk/overview) — full Tolk documentation
- [tolk-bench](https://github.com/ton-blockchain/ton) — 42 production Tolk contracts
- GitHub PRs [#1741](https://github.com/ton-blockchain/ton/pull/1741), [#1795](https://github.com/ton-blockchain/ton/pull/1795), [#1886](https://github.com/ton-blockchain/ton/pull/1886) — Tolk 1.0 / 1.1 / 1.2 changelogs
