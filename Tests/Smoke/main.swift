import Foundation

let signatures = [
    aimer128f, aimer128s, aimer192f, aimer192s, aimer256f, aimer256s,
    haetae2, haetae3, haetae5
]
let kems = [
    ntruplus768, ntruplus864, ntruplus1152,
    smaugt128, smaugt192, smaugt256, timer
]
let message = Data([0x4b, 0x70, 0x71, 0x43, 0x00, 0xff])
let context = Data("test-suite".utf8)

func expectFailure(_ label: String, _ operation: () throws -> Void) {
    do {
        try operation()
        fatalError("\(label) did not fail")
    } catch {
        // Expected.
    }
}

do {
    for algorithm in signatures {
        let keys = try algorithm.generateKeyPair()
        defer { keys.dispose() }
        let signature = try algorithm.sign(
            message,
            secretKey: keys.secretKey,
            context: context
        )
        guard try algorithm.verify(
            message,
            signature: signature,
            publicKey: keys.publicKey,
            context: context
        ) else {
            fatalError("\(algorithm.id) signature round trip failed")
        }

        var altered = signature
        altered[altered.startIndex] ^= 0x80
        guard try !algorithm.verify(
            message,
            signature: altered,
            publicKey: keys.publicKey,
            context: context
        ) else {
            fatalError("\(algorithm.id) accepted an altered signature")
        }
        guard try !algorithm.verify(
            message,
            signature: signature,
            publicKey: keys.publicKey,
            context: Data("other".utf8)
        ) else {
            fatalError("\(algorithm.id) accepted a different context")
        }
        guard try !algorithm.verify(
            message,
            signature: signature.dropFirst(),
            publicKey: keys.publicKey,
            context: context
        ) else {
            fatalError("\(algorithm.id) accepted a short signature")
        }
        expectFailure("\(algorithm.id) short secret key") {
            _ = try algorithm.sign(
                Data(),
                secretKey: Data(count: algorithm.sizes.secretKey - 1)
            )
        }
        expectFailure("\(algorithm.id) long context") {
            _ = try algorithm.sign(
                Data(),
                secretKey: keys.secretKey,
                context: Data(count: 256)
            )
        }
        expectFailure("\(algorithm.id) short public key") {
            _ = try algorithm.verify(
                Data(),
                signature: signature,
                publicKey: Data(count: algorithm.sizes.publicKey - 1)
            )
        }
        expectFailure("\(algorithm.id) long verification context") {
            _ = try algorithm.verify(
                Data(),
                signature: signature,
                publicKey: keys.publicKey,
                context: Data(count: 256)
            )
        }
    }

    for algorithm in kems {
        let keys = try algorithm.generateKeyPair()
        defer { keys.dispose() }
        let outbound = try algorithm.encapsulate(keys.publicKey)
        defer { outbound.dispose() }
        var recovered = try algorithm.decapsulate(
            outbound.ciphertext,
            secretKey: keys.secretKey
        )
        defer { recovered.resetBytes(in: 0..<recovered.count) }
        guard recovered == outbound.sharedSecret else {
            fatalError("\(algorithm.id) KEM round trip failed")
        }

        var altered = outbound.ciphertext
        altered[altered.startIndex] ^= 0x80
        if algorithm.id.hasPrefix("NTRU+") {
            expectFailure("\(algorithm.id) altered ciphertext") {
                _ = try algorithm.decapsulate(altered, secretKey: keys.secretKey)
            }
        } else {
            var replacement = try algorithm.decapsulate(
                altered,
                secretKey: keys.secretKey
            )
            guard replacement != outbound.sharedSecret else {
                fatalError("\(algorithm.id) did not implicitly reject")
            }
            replacement.resetBytes(in: 0..<replacement.count)
        }
        expectFailure("\(algorithm.id) short public key") {
            _ = try algorithm.encapsulate(Data(count: algorithm.sizes.publicKey - 1))
        }
        expectFailure("\(algorithm.id) short ciphertext") {
            _ = try algorithm.decapsulate(
                Data(count: algorithm.sizes.ciphertext - 1),
                secretKey: keys.secretKey
            )
        }
        expectFailure("\(algorithm.id) short secret key") {
            _ = try algorithm.decapsulate(
                outbound.ciphertext,
                secretKey: Data(count: algorithm.sizes.secretKey - 1)
            )
        }
    }

    let disposableKeys = try ntruplus768.generateKeyPair()
    disposableKeys.dispose()
    disposableKeys.dispose()
    guard disposableKeys.secretKey.allSatisfy({ $0 == 0 }) else {
        fatalError("secret key was not cleared")
    }

    let freshKeys = try ntruplus768.generateKeyPair()
    defer { freshKeys.dispose() }
    let disposableSecret = try ntruplus768.encapsulate(freshKeys.publicKey)
    disposableSecret.dispose()
    disposableSecret.dispose()
    guard disposableSecret.sharedSecret.allSatisfy({ $0 == 0 }) else {
        fatalError("shared secret was not cleared")
    }
} catch {
    fatalError("KpqC smoke test failed: \(error)")
}

print("Swift API tests passed for all 16 parameter sets")
