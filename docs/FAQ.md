# Frequently Asked Questions

## General

### What is Mobi?

A deterministic algorithm that converts a 32-byte public key into a 21-digit phone-number-like identifier.

```
Public Key: 17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917
Mobi:     879-044-656-584 (display) or 879044656584686196443 (full)
```

### Why "21"?

1. **Bitcoin's number** — 21 million coins, a cultural touchstone
2. **Mathematical necessity** — 10²¹ values = 44.7 billion users before 50% collision probability
3. **Hierarchical harmony** — 21 = 12 + 9, allowing 12-digit display with 9 digits of resolution

### Why not just use the first 12 characters of the hex pubkey?

Hex is hostile to humans:
- Confusable characters (0/O, 1/l, 8/B)
- No natural grouping
- Can't speak it over the phone without spelling

Decimal digits with phone-number grouping are universally understood.

## Technical

### Is this cryptographically secure?

For its purpose, yes. Mobi is an **identifier**, not an authenticator.

- **Preimage resistance**: Finding a pubkey for a given mobi requires ~5×10²⁰ operations
- **Uniform distribution**: Rejection sampling eliminates bias
- **Deterministic**: Same pubkey always produces same mobi

For **authentication**, always verify the underlying public key.

### What about collisions?

| Users | Collision Probability |
|-------|----------------------|
| 100,000 | 0.0005% |
| 1,000,000 | 0.05% |
| 10,000,000 | 5% |
| 44,700,000 | 50% (extended form) |
| 44,700,000,000 | 50% (full form) |

At 12 digits, collisions become likely around 1.4 million users. When collisions occur, show more digits (15, 18, or 21).

### Why rejection sampling instead of modulo?

Modulo introduces bias. With 9 bytes (2^72) mapped to 10^21 values:

```
2^72 mod 10^21 = 722,366,482,869,645,213,696

Values 0 to 722... appear 5 times in the input space
Values 722... to 999... appear 4 times

Bias: ~25% more likely for lower values
```

Rejection sampling eliminates this entirely. Every output is equally likely.

### How many rounds does rejection sampling take?

- Acceptance rate: ~21.2%
- Expected rounds: ~4.7
- 99% of derivations complete in < 20 rounds
- Worst case (256 rounds): probability < 10^-25

### What happens if 256 rounds aren't enough?

It won't happen. The probability is less than 10^-25—far less likely than hardware failure, cosmic ray bit flips, or SHA256 breaking.

The implementation returns an error rather than falling back to a biased result, but this code path will never execute in practice.

### Why append round counter to pubkey instead of hashing the hash?

Two reasons:

1. **Traceability** — Every hash includes the original pubkey, maintaining the identity connection
2. **Independence** — Each round is cryptographically independent, not a chain that could accumulate bias

### Can I derive the public key from a mobi?

No. SHA256 is a one-way function. Given a mobi, you cannot compute the original public key.

You could brute-force search, but with ~10²¹ possible outputs and 5×10²⁰ average attempts needed, this is computationally infeasible.

## Usage

### When should I show 12 digits vs 21?

**12 digits (display)**: Default for UI, conversation, short-form references
**15 digits (extended)**: When two users' 12-digit forms collide
**18 digits (long)**: Rare, for large-scale systems with many collisions
**21 digits (full)**: Database storage, API responses, machine processing

### How do I handle user input?

Normalize first, then validate:

```c
char normalized[22];
int len = mobi_normalize(input, normalized, sizeof(normalized));

if (len == 12 || len == 15 || len == 18 || len == 21) {
    // Valid mobi
} else {
    // Invalid input
}
```

Normalization strips hyphens, spaces, parentheses, and dots.

### Should I store 12 digits or 21?

**Always store 21 digits** (the full form).

- Enables collision detection
- Allows progressive disclosure
- Future-proofs against user base growth

Display can always be derived from storage, but you can't recover full from display.

### How do I format for display?

Groups of 3 digits, separated by hyphens:

| Digits | Format |
|--------|--------|
| 12 | `XXX-XXX-XXX-XXX` |
| 15 | `XXX-XXX-XXX-XXX-XXX` |
| 18 | `XXX-XXX-XXX-XXX-XXX-XXX` |
| 21 | `XXX-XXX-XXX-XXX-XXX-XXX-XXX` |

### Can I use mobi for URLs?

Yes, but normalize first:

```
https://example.com/user/587135537154         (12 digits)
https://example.com/user/587135537154686717107 (21 digits)
```

Hyphens in URLs can work but may cause issues with some parsers. Prefer digits-only for URLs.

## Implementation

### What languages have implementations?

| Language | Location | Status |
|----------|----------|--------|
| C | `src/mobi.c` | Reference implementation |
| Rust | `megab/src/mobi.rs` | Production |
| Go | `beebase/crypto/mobi.go` | Production |
| Python | (docs example) | Reference |
| JavaScript | (docs example) | Reference |

### How do I verify my implementation?

Run against the canonical test vectors:

| Input | Full Output |
|-------|-------------|
| `0000...0000` (64 zeros) | `587135537154686717107` |
| `17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917` | `879044656584686196443` |

If your output doesn't match exactly, your implementation has a bug.

### What's the minimum buffer size?

- Full mobi: 22 bytes (21 digits + null terminator)
- Formatted full: 28 bytes (21 digits + 6 hyphens + null)
- Display: 13 bytes (12 digits + null)
- Formatted display: 16 bytes (12 digits + 3 hyphens + null)

### Does this work with compressed/uncompressed public keys?

Mobi is designed for **x-only (32-byte) public keys** as used by:
- Nostr (npub)
- Bitcoin Taproot
- Schnorr signatures

For compressed (33-byte) or uncompressed (65-byte) keys, extract the x-coordinate first.

## Compatibility

### Is this compatible with BIP-XXX?

Mobi is not a BIP. It's an independent specification that operates on secp256k1 public keys, which are used by Bitcoin and Nostr.

### Can I use this with Ethereum addresses?

Ethereum uses the same secp256k1 curve, but Ethereum addresses are already derived from the public key via Keccak-256. You could derive mobi from the underlying public key, but this would create a parallel identity system.

### Is this standardized?

The specification is in PROTOCOL.md (version 2.1). All reference implementations produce identical output for the test vectors.

For formal standardization (RFC, BIP), community adoption would need to reach critical mass first.
