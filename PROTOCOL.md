# MobiNumber Protocol v1.0

## Abstract

This document specifies the MobiNumber protocol for deriving human-readable 12-digit identifiers from secp256k1 public keys with uniform distribution.

## Motivation

Cryptographic public keys are difficult for humans to remember, read aloud, or type manually. Phone numbers, by contrast, are universally understood and easily memorized. MobiNumber bridges this gap by deterministically mapping public keys to phone-like 12-digit numbers.

## Specification

### Input

A 32-byte secp256k1 x-only public key, represented as a 64-character hexadecimal string (lowercase).

### Output

A 12-character decimal string, zero-padded, representing a value in the range [0, 10^12 - 1].

### Algorithm

```
function derive_mobinumber(pubkey_hex: string) -> string:

    # Step 1: Decode hex to bytes
    pubkey_bytes = hex_decode(pubkey_hex)
    assert len(pubkey_bytes) == 32

    # Step 2: Initial hash
    hash = SHA256(pubkey_bytes)

    # Step 3: Rejection sampling loop
    for iteration in 0..256:

        # Extract first 5 bytes as big-endian u64
        value = 0
        for i in 0..5:
            value = (value << 8) | hash[i]

        # Check if value is in valid range
        if value < 1_000_000_000_000:
            return format(value, width=12, pad='0')

        # Rehash with iteration counter
        hash = SHA256(hash || byte(iteration))

    # Unreachable: probability < 10^-255
    panic("exceeded maximum iterations")
```

### Rationale

#### Why SHA256?

SHA256 provides:
- Uniform output distribution (each bit equally likely to be 0 or 1)
- Avalanche effect (small input change → ~50% output bits change)
- Widely available in all programming languages
- Cryptographic security (preimage resistance)

#### Why 5 bytes (40 bits)?

- 40 bits = 1,099,511,627,775 possible values
- 12 digits = 1,000,000,000,000 possible values
- 40 bits is the minimum that covers the 12-digit space
- Excess (~10%) handled by rejection sampling

#### Why rejection sampling?

Using modulo introduces bias:
```
2^40 mod 10^12 = 99,511,627,776
```
Values 0 to 99,511,627,775 would be ~9.95% more likely than others.

Rejection sampling eliminates this bias entirely by discarding out-of-range values and rehashing.

#### Why 256 max iterations?

Probability of needing N iterations:
- P(1) ≈ 91%
- P(2) ≈ 8.2%
- P(3) ≈ 0.7%
- P(256) ≈ 10^-255 (never happens)

Expected iterations: ~1.1

### Display Format

For human readability, mobinumbers SHOULD be displayed with hyphen separators in groups of 3:

```
Storage:  650073047435
Display:  650-073-047-435
```

Implementations MUST accept both formats as input.

### Normalization

Before comparison or storage, mobinumbers MUST be normalized:
1. Remove all non-digit characters
2. Verify exactly 12 digits remain
3. Store as 12-digit string with leading zeros preserved

### Collision Properties

| Users | Collision Probability |
|-------|----------------------|
| 1,000 | 0.00005% |
| 10,000 | 0.005% |
| 100,000 | 0.5% |
| 1,000,000 | 39% |
| 1,414,214 | 50% |

Applications requiring more than ~100,000 unique identifiers should implement collision detection at registration time.

## Test Vectors

### Vector 1: All zeros

```
Input:  0000000000000000000000000000000000000000000000000000000000000000
Output: 374708832682
```

### Vector 2: All ones

```
Input:  ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
Output: 521101723786
```

### Vector 3: Nostr test key

```
Input:  7f3b1a2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a
Output: 892451037629
```

## Security Considerations

1. **Not reversible**: Mobinumber cannot be used to recover the public key
2. **Collision handling**: Applications should reject registration on collision
3. **Not a secret**: Mobinumber is derived from public key and is public information

## References

- [SHA-256](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf) - NIST FIPS 180-4
- [secp256k1](https://www.secg.org/sec2-v2.pdf) - SEC 2 v2.0
- [Rejection Sampling](https://en.wikipedia.org/wiki/Rejection_sampling)

## Version History

- v1.0 (2024-12-29): Initial specification
