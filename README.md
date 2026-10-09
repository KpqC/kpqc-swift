# KpqC

KpqC provides safe, synchronous Swift APIs for the AIMer and HAETAE signature
schemes and the NTRU+ and SMAUG-T key encapsulation mechanisms (KEMs).

## Runtime support

- Swift 5.8 or newer
- iOS 15, macOS 12, tvOS 15, or watchOS 9 and newer
- CocoaPods or Swift Package Manager

## Install

### Swift Package Manager

Add `https://github.com/KpqC/kpqc-swift` as a package dependency and select
the `KpqC` product, or add it to `Package.swift`:

```swift
.package(url: "https://github.com/KpqC/kpqc-swift.git", from: "0.2.0")
```

### CocoaPods

```ruby
pod 'KpqC', '~> 0.2'
```

Then run `pod install` and import the module:

```swift
import KpqC
```

KpqC 0.2.0 uses AIM3. AIMer keys and signatures from the 0.1.x AIM2 release
are not compatible with this version.

## Available schemes

| Algorithm | Type | Exports |
| --- | --- | --- |
| **AIMer** | Signature | `aimer128f`, `aimer128s`, `aimer192f`, `aimer192s`, `aimer256f`, `aimer256s` |
| **HAETAE** | Signature | `haetae2`, `haetae3`, `haetae5` |
| **NTRU+** | KEM | `ntruplus768`, `ntruplus864`, `ntruplus1152` |
| **SMAUG&#8209;T** | KEM | `smaugt128`, `smaugt192`, `smaugt256`, `timer` |

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

### KEM

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
| `aimer128f` | 32 | 48 | 6,944 |
| `aimer128s` | 32 | 48 | 4,704 |
| `aimer192f` | 48 | 72 | 15,408 |
| `aimer192s` | 48 | 72 | 10,320 |
| `aimer256f` | 64 | 96 | 31,360 |
| `aimer256s` | 64 | 96 | 20,224 |
| `haetae2` | 992 | 1,408 | 1,474 |
| `haetae3` | 1,472 | 2,112 | 2,349 |
| `haetae5` | 2,080 | 2,752 | 2,948 |

#### KEM

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

## Known-answer tests

The implementation is tested against all 1,600 KAT records in
[KpqC/kpqc-test-vectors at commit d75490bf824f](https://github.com/KpqC/kpqc-test-vectors/tree/d75490bf824faa4b148cd0b901a2eb13198fe0da).
With `kpqc-test-vectors` checked out beside `kpqc-swift`, run:

```sh
KPQC_TEST_VECTORS=../kpqc-test-vectors ./scripts/test.sh
```

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
