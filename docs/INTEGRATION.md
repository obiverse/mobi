# Integration Guide

## Quick Reference

```
pubkey (32 bytes) → SHA256 → rejection sampling → 21 digits
```

Display 12. Store 21. Reveal more on collision.

## Use Cases

### 1. Lightning Addresses

Traditional: `user@wallet.com` (requires DNS, centralized)

With Mobi:
```
587135537154@beewallet.net
```

The identifier IS the user. No username registration. No collision management at the service level. Derive from pubkey, done.

```c
mobi_t m;
mobi_derive(user_pubkey_hex, &m);
sprintf(lightning_address, "%s@beewallet.net", m.display);
```

### 2. Voice Communication

**Before:**
> "Send to npub1zuvhc43xhvtj63cyt0gax... wait, let me spell that..."

**After:**
> "Send to 587-135-537-154"

Four groups of three. Like a phone number. Humans handle this effortlessly.

### 3. QR Code Fallback

QR codes fail in low light, at angles, on damaged surfaces. Mobi provides a human-readable fallback:

```
┌────────────────────┐
│  ▄▄▄▄▄ ▄▄▄▄ ▄▄▄▄▄  │
│  █ ▄▄▄ █▄▄▄█ ▄▄▄ █ │
│  █ ███ █ ▄▄ █ ███ │ │
│  █▄▄▄▄▄█ ▄▀█▄▄▄▄▄█ │
│  ▄▄▄▄ ▄ ▄▄▄▄▄▄ ▄▄  │
│  █▄▄▄▄▄▄▄▄▄▄▄▄▄▄█  │
│                    │
│  587-135-537-154   │  ← Human fallback
└────────────────────┘
```

### 4. Identity Verification

Phone support scenario:

```
Agent: "Can you verify your identity?"
User:  "587-135-537-154"
Agent: [Types into system, sees matching pubkey]
Agent: "Verified. How can I help?"
```

The mobi is public information (derived from public key), but knowing it proves the user has access to their identity.

### 5. Collision Resolution

Two users have the same 12-digit display:

```
User A: 587135537154686717107
User B: 587135537154892341256
        ^^^^^^^^^^^^
        Same 12-digit display
```

Resolution:
1. Show 15 digits: `587-135-537-154-686` vs `587-135-537-154-892`
2. Users can now distinguish

In practice, with 10¹² display values, collisions appear at ~1.4 million users. Most applications will never need extended forms.

## Implementation Patterns

### Pattern 1: Derive Once, Store Both

```c
// On identity creation
mobi_t m;
mobi_derive(pubkey_hex, &m);

// Store in database
db_insert(pubkey_hex, m.full);  // Full 21 digits for collision detection
```

### Pattern 2: Display Formatting

```c
// For UI display
char formatted[16];
mobi_format_display(&m, formatted);
printf("Your ID: %s\n", formatted);  // "587-135-537-154"
```

### Pattern 3: Input Normalization

```c
// User typed "587 135 537 154" or "(587) 135-537-154"
char normalized[22];
int len = mobi_normalize(user_input, normalized, sizeof(normalized));

if (len == 12 || len == 15 || len == 18 || len == 21) {
    // Valid mobi
}
```

### Pattern 4: Lookup with Collision Handling

```c
// Find user by mobi input
char normalized[22];
mobi_normalize(input, normalized, sizeof(normalized));

// Query by prefix
results = db_query("SELECT * FROM users WHERE mobi LIKE ?%", normalized);

if (count(results) == 1) {
    return results[0];  // Unique match
} else if (count(results) > 1) {
    return "Please provide more digits";  // Request extended form
} else {
    return "Not found";
}
```

## Language-Specific Examples

### C

```c
#include "mobi.h"

int main() {
    const char *pubkey = "17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917";
    mobi_t m;

    if (mobi_derive(pubkey, &m) != MOBI_OK) {
        fprintf(stderr, "Derivation failed\n");
        return 1;
    }

    printf("Display: %s\n", m.display);   // 879044656584
    printf("Full:    %s\n", m.full);      // 879044656584686196443

    char formatted[16];
    mobi_format_display(&m, formatted);
    printf("Formatted: %s\n", formatted); // 879-044-656-584

    return 0;
}
```

### Python (Reference)

```python
import hashlib

def derive_mobi(pubkey_hex: str) -> dict:
    pubkey = bytes.fromhex(pubkey_hex)
    assert len(pubkey) == 32

    for round in range(256):
        if round == 0:
            h = hashlib.sha256(pubkey).digest()
        else:
            h = hashlib.sha256(pubkey + bytes([round])).digest()

        value = int.from_bytes(h[:9], 'big')

        if value < 10**21:
            full = str(value).zfill(21)
            return {
                'full': full,
                'display': full[:12],
                'extended': full[:15],
                'lng': full[:18],
            }

    raise RuntimeError("Exceeded 256 rounds")

# Usage
result = derive_mobi("17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917")
print(result['display'])  # 879044656584
```

### JavaScript/TypeScript

```typescript
import { createHash } from 'crypto';

function deriveMobi(pubkeyHex: string): { full: string; display: string } {
  const pubkey = Buffer.from(pubkeyHex, 'hex');
  if (pubkey.length !== 32) throw new Error('Invalid pubkey length');

  for (let round = 0; round < 256; round++) {
    const input = round === 0
      ? pubkey
      : Buffer.concat([pubkey, Buffer.from([round])]);

    const hash = createHash('sha256').update(input).digest();
    const value = hash.readBigUInt64BE(0) * 256n + BigInt(hash[8]);

    if (value < 10n ** 21n) {
      const full = value.toString().padStart(21, '0');
      return {
        full,
        display: full.slice(0, 12),
      };
    }
  }

  throw new Error('Exceeded 256 rounds');
}
```

### Rust

```rust
use sha2::{Sha256, Digest};

pub struct Mobi {
    pub full: String,
    pub display: String,
}

pub fn derive(pubkey: &[u8; 32]) -> Result<Mobi, &'static str> {
    for round in 0u8..=255 {
        let hash = if round == 0 {
            Sha256::digest(pubkey)
        } else {
            let mut input = pubkey.to_vec();
            input.push(round);
            Sha256::digest(&input)
        };

        // First 9 bytes as u128 (we only use 72 bits)
        let mut bytes = [0u8; 16];
        bytes[7..16].copy_from_slice(&hash[0..9]);
        let value = u128::from_be_bytes(bytes);

        if value < 1_000_000_000_000_000_000_000u128 {
            let full = format!("{:021}", value);
            let display = full[..12].to_string();
            return Ok(Mobi { full, display });
        }
    }

    Err("Exceeded 256 rounds")
}
```

## Testing Your Implementation

Your implementation MUST produce these exact outputs:

| Input (hex) | Display | Full |
|-------------|---------|------|
| `0000...0000` (64 zeros) | `587135537154` | `587135537154686717107` |
| `17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917` | `879044656584` | `879044656584686196443` |

If your implementation produces different values, it is not compatible.
