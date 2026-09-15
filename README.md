# KpqC

KpqC provides safe, synchronous Swift APIs for AIMer, HAETAE, NTRU+, and
SMAUG-T.

## Runtime support

- Swift 5.8 or newer
- iOS 13, macOS 10.15, tvOS 13, or watchOS 6 and newer
- CocoaPods

## Install

```ruby
pod 'KpqC', '~> 0.1'
```

Then run `pod install` and import the module:

```swift
import KpqC
```

## Available schemes

| Algorithm | Type | Exports |
| --- | --- | --- |
| **AIMer** | Signature | `aimer128f`, `aimer128s`, `aimer192f`, `aimer192s`, `aimer256f`, `aimer256s` |
| **HAETAE** | Signature | `haetae2`, `haetae3`, `haetae5` |
| **NTRU+** | Key encapsulation | `ntruplus768`, `ntruplus864`, `ntruplus1152` |
| **SMAUG&#8209;T** | Key encapsulation | `smaugt128`, `smaugt192`, `smaugt256`, `timer` |

```swift
import Foundation
import KpqC

let payload = Data("release-manifest:v3".utf8)
let keys = try aimer128f.generateKeyPair()
defer { keys.dispose() }

let proof = try aimer128f.sign(payload, secretKey: keys.secretKey)
guard try aimer128f.verify(
    payload,
    signature: proof,
    publicKey: keys.publicKey
) else {
    fatalError("Signature verification failed")
}
```

### Signature contexts

AIMer and HAETAE accept an optional context. A context separates signatures
created for different application purposes and may contain up to 255 bytes.

```swift
let payload = Data("account=42".utf8)
let context = Data("audit-record".utf8)
let keys = try haetae3.generateKeyPair()
defer { keys.dispose() }

let signature = try haetae3.sign(
    payload,
    secretKey: keys.secretKey,
    context: context
)
let valid = try haetae3.verify(
    payload,
    signature: signature,
    publicKey: keys.publicKey,
    context: context
)
```

Verification fails when the supplied context does not match the one used for
signing.

### Key encapsulation

A KEM creates a shared secret for a sender and a recipient. The public key may
be distributed; the secret key and resulting shared secret must remain private.

```swift
let recipient = try smaugt192.generateKeyPair()
defer { recipient.dispose() }

let outbound = try smaugt192.encapsulate(recipient.publicKey)
defer { outbound.dispose() }

// Send outbound.ciphertext to the recipient.
var inboundSecret = try smaugt192.decapsulate(
    outbound.ciphertext,
    secretKey: recipient.secretKey
)
defer { inboundSecret.resetBytes(in: 0..<inboundSecret.count) }

precondition(inboundSecret == outbound.sharedSecret)
```

## Data and failures

Inputs and outputs use `Data`. Each algorithm exposes an `id` and a `sizes`
value. Incorrect key or ciphertext lengths and native failures throw
`KpqCError`. Signature verification returns `false` for an invalid signature.

### Parameter sizes

All sizes are in bytes.

#### Signatures

| Algorithm | Public key | Secret key | Signature |
| --- | ---: | ---: | ---: |
| `aimer128f` | 32 | 48 | 5,888 |
| `aimer128s` | 32 | 48 | 4,160 |
| `aimer192f` | 48 | 72 | 13,056 |
| `aimer192s` | 48 | 72 | 9,120 |
| `aimer256f` | 64 | 96 | 25,120 |
| `aimer256s` | 64 | 96 | 17,056 |
| `haetae2` | 992 | 1,408 | 1,474 |
| `haetae3` | 1,472 | 2,112 | 2,349 |
| `haetae5` | 2,080 | 2,752 | 2,948 |

#### Key encapsulation

| Algorithm | Public key | Secret key | Ciphertext | Shared secret |
| --- | ---: | ---: | ---: | ---: |
| `ntruplus768` | 1,152 | 2,336 | 1,152 | 32 |
| `ntruplus864` | 1,296 | 2,624 | 1,296 | 32 |
| `ntruplus1152` | 1,728 | 3,488 | 1,728 | 32 |
| `smaugt128` | 672 | 832 | 672 | 32 |
| `smaugt192` | 1,088 | 1,312 | 992 | 32 |
| `smaugt256` | 1,440 | 1,728 | 1,376 | 32 |
| `timer` | 672 | 832 | 608 | 32 |

Methods reject values of the wrong size. NTRU+ rejects an invalid ciphertext.
SMAUG-T performs implicit rejection and returns a replacement secret instead;
that value will not equal the sender's shared secret.

## Distribution

The pod includes the bundled native sources. Each parameter set is compiled
with its upstream configuration macros and isolated C symbols.

`KeyPair.dispose()` and `EncapsulatedSecret.dispose()` overwrite their secret
data on a best-effort basis. The caller is responsible for clearing the value
returned directly by `decapsulate`.

## Security

The native cores are compiled from the upstream algorithm implementations. This
package has not received an independent security audit and does not provide a
constant-time execution guarantee. Assess those constraints before using it
with sensitive production keys.

Third-party licenses and attributions are listed in
[THIRD_PARTY_NOTICES.md](./THIRD_PARTY_NOTICES.md).
