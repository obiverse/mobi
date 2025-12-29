# The Philosophy of Mobi

*"Programs must be written for people to read, and only incidentally for machines to execute."*
— Structure and Interpretation of Computer Programs

## The Problem

Cryptographic identities are hostile to humans:

```
npub1zuvhc43xhvtj63cyt0gaxqgapf7xlc24thq7lcex4xes7j4h5c3s0qgxhq
bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq
```

These are precise. They are verifiable. They are also impossible to remember, painful to dictate over the phone, and guaranteed to be mistyped.

Phone numbers, by contrast, are memorable:
```
650-073-047-435
```

Mobi bridges the gap.

## The Synthesis

**Thesis**: Cryptographic keys provide security and verifiability.
**Antithesis**: Human memory and communication require simplicity.
**Synthesis**: Derive a human-readable identifier deterministically from the key.

The key insight: we don't need to choose. The mobi is not a replacement for the public key—it's a *projection* of it into human-accessible space.

## Design Principles

### 1. Solve et Coagula (Dissolve and Coagulate)

The alchemical principle: first dissolve the impure, then crystallize the pure.

**Dissolve**: We take 32 bytes of cryptographic entropy and hash it—destroying the structure, creating uniform randomness.

**Coagulate**: From that chaos, we extract exactly what we need—21 decimal digits—and no more.

The SHA256 hash is the dissolution. The rejection sampling is the purification. The decimal conversion is the crystallization.

### 2. Use ≠ Representation (SICP)

Data abstraction separates *how something is used* from *how it is stored*.

```
Storage:    587135537154686717107  (21 digits, full precision)
Display:    587-135-537-154        (12 digits, human-friendly)
```

The same identity. Different representations for different purposes. The user sees 12 digits. The database stores 21. The public key remains the source of truth.

### 3. Progressive Disclosure (Git's Wisdom)

Git shows `a3f2b1c` but stores `a3f2b1c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0`.

When two commits collide on 7 characters, Git shows more. Simple default, complexity on demand.

Mobi follows the same pattern:
- Show 12 digits (handles 1.4 million identities)
- If collision: show 15 (handles 44.7 million)
- If still colliding: show 18 (handles 1.4 billion)
- Ultimate: show 21 (handles 44.7 billion)

### 4. Uniform Distribution (Bitcoin's Lesson)

In Bitcoin, the slightest bias is a security hole. Attackers will find it and exploit it.

Mobi uses rejection sampling—not because identifiers need cryptographic uniformity, but because **correctness is easier to verify than "good enough."**

The modulo operation would work. It would be faster. But we'd forever be explaining why "~25% more likely for some values" doesn't matter.

Rejection sampling eliminates the question entirely.

### 5. The Categorical Imperative (Kant)

*"Act only according to that maxim whereby you can at the same time will that it should become a universal law."*

Every design decision in Mobi asks: **if every identity system followed this pattern, would coherence emerge?**

- 21 digits? Bitcoin's number. A sextillion values. Beyond humanity.
- Phone number format? Universal human understanding.
- SHA256? Available in every language, verified correct, trusted by billions in value.
- Rejection sampling? Mathematical purity, no asterisks.

## The Three Stages

### Nigredo (Blackening)

The hash function destroys the structure of the public key. All patterns are annihilated. What remains is uniform chaos—32 bytes of apparent randomness.

This is necessary. The public key's structure (a point on secp256k1) is meaningless to humans. We must first destroy before we can create.

### Albedo (Whitening)

Rejection sampling purifies. We discard everything that doesn't fit our target space. Only values less than 10²¹ survive.

This is the filter. The crucible. What passes through is pure—uniformly distributed across exactly the space we need.

### Rubedo (Reddening)

The final form emerges: 21 decimal digits, formatted for human consumption. The rubedo—the philosopher's stone—is achieved.

```
587-135-537-154
```

A public key, transmuted into speech.

## Why This Matters

Identity is the foundation of trust. A cryptographic key provides *machine* trust—verifiable, unforgeable, precise.

But humans don't think in hex. We think in names, in numbers, in patterns we can hold in memory.

Mobi doesn't replace cryptographic identity. It makes it *accessible*. You can say your identity over the phone. You can remember it. You can write it on a napkin.

The math remains rigorous. The implementation remains secure. But the interface becomes human.

That is the synthesis.

---

*"The purpose of abstraction is not to be vague, but to create a new semantic level in which one can be absolutely precise."*
— Edsger Dijkstra
