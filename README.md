# Mobi Protocol v21.0.0

A deterministic algorithm for deriving human-readable 21-digit identifiers from cryptographic public keys with **uniform distribution** (zero bias).

## Overview

Mobi maps any secp256k1 public key to a unique 21-digit decimal number. Display 12 digits to users (like phone numbers). Store full 21 digits. Resolve collisions with extended forms.

```
Public Key: 17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917
     ↓
Full:    879-044-656-584-686-196-443  (21 digits, stored)
Display: 879-044-656-584              (12 digits, shown to users)
```

## Why 21?

21 is Bitcoin's number. And 10²¹ = 1 sextillion possible values.

| Digits | 50% Collision At |
|--------|------------------|
| 12 | 1.4 million |
| 15 | 44.7 million |
| 18 | 1.4 billion |
| **21** | **44.7 billion** |

## Properties

- **Deterministic**: Same pubkey always produces same mobi
- **Uniform**: Rejection sampling ensures zero bias (every output equally likely)
- **Hierarchical**: Display (12) → Extended (15) → Long (18) → Full (21)
- **Collision-resistant**: Birthday collision at ~44.7 billion for full form
- **Memorable**: Phone number format, easy to read aloud
- **Verifiable**: Anyone can derive mobi from pubkey

## Quick Start

### C (Reference Implementation)

```c
#include "mobi.h"

mobi_t m;
mobi_derive("17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917", &m);

printf("Display: %s\n", m.display);    // "879044656584"
printf("Full:    %s\n", m.full);       // "879044656584686196443"

char formatted[28];
mobi_format_display(&m, formatted);
printf("Formatted: %s\n", formatted);   // "879-044-656-584"
```

### Rust

```rust
use megab::mobi::derive_from_hex;

let mobi = derive_from_hex("17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917").unwrap();
println!("Display: {}", mobi.display);           // "879044656584"
println!("Full:    {}", mobi.full);              // "879044656584686196443"
println!("Formatted: {}", mobi.display_formatted()); // "879-044-656-584"
```

### Go

```go
import "github.com/obiverse/beebase/crypto"

mobi, _ := crypto.DeriveMobiFromHex("17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917")
fmt.Println("Display:", mobi.Display)          // "879044656584"
fmt.Println("Full:", mobi.Full)                // "879044656584686196443"
fmt.Println("Formatted:", mobi.DisplayFormatted()) // "879-044-656-584"
```

## Algorithm

```
FOR round = 0 TO 255:
  hash = SHA256(pubkey) if round == 0 else SHA256(pubkey || round)
  value = first 9 bytes as 72-bit big-endian integer
  IF value < 10^21:
    RETURN zero_pad(value, 21)
```

Rejection sampling ensures uniform distribution. Expected rounds: ~4.7.

See [PROTOCOL.md](PROTOCOL.md) for the complete specification.

## Canonical Test Vectors

| Input | Display | Full |
|-------|---------|------|
| `0000...0000` | `587135537154` | `587135537154686717107` |
| `17162c...d917` | `879044656584` | `879044656584686196443` |

## Implementations

| Language | Location | Status |
|----------|----------|--------|
| C | `src/mobi.c` | Reference (zero dependencies) |
| Rust | `megab/src/mobi.rs` | Production |
| Go | `beebase/crypto/mobi.go` | Production |

## Use Cases

- **Lightning Addresses**: `879044656584@beewallet.net`
- **Voice calls**: "Send to 879-044-656-584"
- **Identity routing**: Route messages by mobinumber
- **Collision resolution**: Show 15/18/21 digits when needed

## Build

```bash
make        # Build library
make test   # Run tests (22/22 pass)
make clean  # Clean build
```

## License

MIT OR Apache-2.0

Copyright (c) 2024-2025 OBIVERSE LLC
