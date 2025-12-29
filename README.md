# MobiNumber Protocol

A deterministic algorithm for deriving human-readable 12-digit identifiers from cryptographic public keys.

## Overview

MobiNumber maps any secp256k1 public key to a unique 12-digit decimal number, formatted like a phone number for easy memorization and verbal communication.

```
Public Key: 7f3b...a9c1 (32 bytes)
     ↓
MobiNumber: 650-073-047-435
```

## Properties

- **Deterministic**: Same pubkey always produces same mobinumber
- **Uniform**: All 10^12 outputs equally likely (zero bias)
- **Collision-resistant**: Birthday collision at ~1.4M users
- **Memorable**: Phone number format, easy to read aloud
- **Verifiable**: Anyone can derive mobinumber from pubkey

## Quick Start

```rust
// Rust
use mobi::derive_mobinumber;
let mobi = derive_mobinumber("7f3b...a9c1");
// "650073047435"
```

```go
// Go
import "github.com/anthropics/mobi-go"
mobi := mobi.Derive("7f3b...a9c1")
// "650073047435"
```

```dart
// Dart
import 'package:mobi/mobi.dart';
final mobi = deriveMobinumber("7f3b...a9c1");
// "650073047435"
```

## Specification

See [PROTOCOL.md](PROTOCOL.md) for the complete specification.

## Implementations

| Language | Package | Status |
|----------|---------|--------|
| Rust | `mobi` | Reference |
| Go | `mobi-go` | Official |
| Dart | `mobi` | Official |
| TypeScript | `@mobi/core` | Planned |

## Use Cases

- **Lightning Addresses**: `650073047435@wallet.example`
- **Voice calls**: "Call me at 650-073-047-435"
- **Identity routing**: Route messages by mobinumber
- **Process IDs**: Assign memorable IDs to services

## License

MIT OR Apache-2.0
