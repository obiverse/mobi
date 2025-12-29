# Mobi Documentation

## Quick Start

```c
#include "mobi.h"

mobi_t m;
mobi_derive("17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917", &m);

printf("%s\n", m.display);  // 879044656584
```

## Documents

| Document | Purpose |
|----------|---------|
| [PROTOCOL.md](../PROTOCOL.md) | **Specification** — The complete, normative protocol definition |
| [ALGORITHM.md](ALGORITHM.md) | **Deep Dive** — Step-by-step algorithm explanation with math |
| [INTEGRATION.md](INTEGRATION.md) | **How-To** — Use cases, patterns, and language examples |
| [PHILOSOPHY.md](PHILOSOPHY.md) | **Why** — Design principles and the thinking behind decisions |
| [FAQ.md](FAQ.md) | **Questions** — Common questions and quick answers |

## Reading Order

**For implementers:**
1. PROTOCOL.md — Understand the spec
2. ALGORITHM.md — Understand the math
3. Test your implementation against canonical vectors

**For integrators:**
1. INTEGRATION.md — See use cases and patterns
2. FAQ.md — Resolve specific questions
3. PROTOCOL.md — Reference as needed

**For the curious:**
1. PHILOSOPHY.md — Understand the "why"
2. ALGORITHM.md — Appreciate the "how"

## Canonical Test Vectors

Every implementation MUST produce these exact outputs:

```
Input:  0000000000000000000000000000000000000000000000000000000000000000
Output: 587135537154686717107

Input:  17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917
Output: 879044656584686196443
```

## Core Concepts

### The Transform

```
pubkey (32 bytes) → SHA256 → rejection sampling → 21 digits
```

### The Forms

| Form | Digits | Use |
|------|--------|-----|
| display | 12 | Show to users |
| extended | 15 | Collision resolution |
| long | 18 | Rare collisions |
| full | 21 | Storage |

### The Invariants

1. **Deterministic** — Same input always yields same output
2. **Uniform** — Every output equally likely (no bias)
3. **Hierarchical** — Display is a prefix of full
4. **Reversible formatting** — format(normalize(x)) = x

## API Reference

### Core Functions

```c
// Derive from hex string
mobi_error_t mobi_derive(const char *pubkey_hex, mobi_t *out);

// Derive from raw bytes
mobi_error_t mobi_derive_bytes(const uint8_t *pubkey, mobi_t *out);
```

### Formatting Functions

```c
// Format with hyphens
mobi_error_t mobi_format_display(const mobi_t *m, char *out);
mobi_error_t mobi_format_extended(const mobi_t *m, char *out);
mobi_error_t mobi_format_full(const mobi_t *m, char *out);
```

### Parsing Functions

```c
// Strip formatting, validate
int mobi_normalize(const char *input, char *out, size_t len);

// Check validity
int mobi_validate(const char *mobi);
```

### Comparison Functions

```c
// Compare display forms (first 12 digits)
int mobi_display_matches(const char *a, const char *b);

// Compare full forms (all 21 digits)
int mobi_full_matches(const mobi_t *a, const mobi_t *b);
```

### Error Handling

```c
const char* mobi_strerror(mobi_error_t err);
```

| Error | Meaning |
|-------|---------|
| MOBI_OK | Success |
| MOBI_ERR_NULL | Null pointer argument |
| MOBI_ERR_INVALID_HEX | Invalid hex character |
| MOBI_ERR_INVALID_LEN | Wrong input length |
| MOBI_ERR_INVALID_CHAR | Invalid character in mobi |

## Building

```bash
make        # Build libmobi.a
make test   # Run test suite
make clean  # Clean build artifacts
```

## License

MIT OR Apache-2.0

Copyright (c) 2024-2025 OBIVERSE LLC
