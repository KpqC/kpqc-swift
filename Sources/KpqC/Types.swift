import Foundation
#if SWIFT_PACKAGE
import KpqCCore
#endif

/// A generated public and secret key pair.
public final class KeyPair {
    /// Public key bytes suitable for distribution.
    public let publicKey: Data

    /// Secret key bytes. Call `dispose()` after use to overwrite this value on
    /// a best-effort basis.
    public private(set) var secretKey: Data

    internal init(publicKey: Data, secretKey: Data) {
        self.publicKey = publicKey
        self.secretKey = secretKey
    }

    deinit {
        dispose()
    }

    /// Overwrites the secret-key storage on a best-effort basis.
    public func dispose() {
        wipe(&secretKey)
    }
}

/// The result of a key-encapsulation operation.
public final class EncapsulatedSecret {
    /// Ciphertext to send to the holder of the secret key.
    public let ciphertext: Data

    /// Shared secret bytes. Call `dispose()` after use to overwrite this value
    /// on a best-effort basis.
    public private(set) var sharedSecret: Data

    internal init(ciphertext: Data, sharedSecret: Data) {
        self.ciphertext = ciphertext
        self.sharedSecret = sharedSecret
    }

    deinit {
        dispose()
    }

    /// Overwrites the shared-secret storage on a best-effort basis.
    public func dispose() {
        wipe(&sharedSecret)
    }
}

/// Byte sizes for a signature parameter set.
public struct SignatureSizes: Equatable {
    public let publicKey: Int
    public let secretKey: Int
    public let signature: Int

    public init(publicKey: Int, secretKey: Int, signature: Int) {
        self.publicKey = publicKey
        self.secretKey = secretKey
        self.signature = signature
    }
}

/// Byte sizes for a key-encapsulation parameter set.
public struct KemSizes: Equatable {
    public let publicKey: Int
    public let secretKey: Int
    public let ciphertext: Int
    public let sharedSecret: Int

    public init(publicKey: Int, secretKey: Int, ciphertext: Int, sharedSecret: Int) {
        self.publicKey = publicKey
        self.secretKey = secretKey
        self.ciphertext = ciphertext
        self.sharedSecret = sharedSecret
    }
}

internal typealias NativeKeyPair = (
    UnsafeMutablePointer<UInt8>, UnsafeMutablePointer<UInt8>
) -> Int32

internal typealias NativeSign = (
    UnsafeMutablePointer<UInt8>, UnsafeMutablePointer<Int>,
    UnsafePointer<UInt8>, Int, UnsafePointer<UInt8>, Int,
    UnsafePointer<UInt8>
) -> Int32

internal typealias NativeVerify = (
    UnsafePointer<UInt8>, Int, UnsafePointer<UInt8>, Int,
    UnsafePointer<UInt8>, Int, UnsafePointer<UInt8>
) -> Int32

internal typealias NativeEncapsulate = (
    UnsafeMutablePointer<UInt8>, UnsafeMutablePointer<UInt8>,
    UnsafePointer<UInt8>
) -> Int32

internal typealias NativeDecapsulate = (
    UnsafeMutablePointer<UInt8>, UnsafePointer<UInt8>,
    UnsafePointer<UInt8>
) -> Int32

/// A signature algorithm and parameter set.
public final class SignatureAlgorithm: CustomStringConvertible {
    public let id: String
    public let sizes: SignatureSizes

    private let keyPair: NativeKeyPair
    private let signer: NativeSign
    private let verifier: NativeVerify

    internal init(
        id: String,
        sizes: SignatureSizes,
        keyPair: @escaping NativeKeyPair,
        sign: @escaping NativeSign,
        verify: @escaping NativeVerify
    ) {
        self.id = id
        self.sizes = sizes
        self.keyPair = keyPair
        signer = sign
        verifier = verify
    }

    /// Generates a new public and secret key pair using operating-system entropy.
    public func generateKeyPair() throws -> KeyPair {
        var publicKey = [UInt8](repeating: 0, count: sizes.publicKey)
        var secretKey = [UInt8](repeating: 0, count: sizes.secretKey)
        let status = publicKey.withUnsafeMutableBufferPointer { publicBuffer in
            secretKey.withUnsafeMutableBufferPointer { secretBuffer in
                keyPair(publicBuffer.baseAddress!, secretBuffer.baseAddress!)
            }
        }
        guard status == 0 else {
            wipe(&publicKey)
            wipe(&secretKey)
            throw KpqCError.coreFailure(operation: "key generation", status: status)
        }
        let result = KeyPair(publicKey: Data(publicKey), secretKey: Data(secretKey))
        wipe(&secretKey)
        return result
    }

    /// Creates a detached signature.
    public func sign(
        _ message: Data,
        secretKey: Data,
        context: Data = Data()
    ) throws -> Data {
        try requireLength("secretKey", actual: secretKey.count, expected: sizes.secretKey)
        try requireContext(context)

        var signature = [UInt8](repeating: 0, count: sizes.signature)
        var secretBytes = [UInt8](secretKey)
        defer { wipe(&secretBytes) }
        var signatureLength = 0
        let status = signature.withUnsafeMutableBufferPointer { signatureBuffer in
            secretBytes.withUnsafeBufferPointer { secretBuffer in
                withInput(message) { messagePointer in
                    withInput(context) { contextPointer in
                        signer(
                            signatureBuffer.baseAddress!, &signatureLength,
                            messagePointer, message.count,
                            contextPointer, context.count,
                            secretBuffer.baseAddress!
                        )
                    }
                }
            }
        }
        guard status == 0 else {
            wipe(&signature)
            throw KpqCError.coreFailure(operation: "signing", status: status)
        }
        guard signatureLength == sizes.signature else {
            wipe(&signature)
            throw KpqCError.invalidOutputLength(
                output: "signature",
                expected: sizes.signature,
                actual: signatureLength
            )
        }
        return Data(signature)
    }

    /// Verifies a detached signature. Invalid signatures return `false`.
    public func verify(
        _ message: Data,
        signature: Data,
        publicKey: Data,
        context: Data = Data()
    ) throws -> Bool {
        try requireLength("publicKey", actual: publicKey.count, expected: sizes.publicKey)
        try requireContext(context)
        guard signature.count == sizes.signature else { return false }

        return try withInput(signature) { signaturePointer in
            try withInput(message) { messagePointer in
                try withInput(context) { contextPointer in
                    try withInput(publicKey) { publicKeyPointer in
                        let status = verifier(
                            signaturePointer, signature.count,
                            messagePointer, message.count,
                            contextPointer, context.count,
                            publicKeyPointer
                        )
                        if status == -2 {
                            throw KpqCError.coreFailure(
                                operation: "verification",
                                status: status
                            )
                        }
                        return status == 0
                    }
                }
            }
        }
    }

    public var description: String { id }
}

/// A key-encapsulation algorithm and parameter set.
public final class KeyEncapsulationAlgorithm: CustomStringConvertible {
    public let id: String
    public let sizes: KemSizes

    private let keyPair: NativeKeyPair
    private let encapsulator: NativeEncapsulate
    private let decapsulator: NativeDecapsulate

    internal init(
        id: String,
        sizes: KemSizes,
        keyPair: @escaping NativeKeyPair,
        encapsulate: @escaping NativeEncapsulate,
        decapsulate: @escaping NativeDecapsulate
    ) {
        self.id = id
        self.sizes = sizes
        self.keyPair = keyPair
        encapsulator = encapsulate
        decapsulator = decapsulate
    }

    /// Generates a new public and secret key pair using operating-system entropy.
    public func generateKeyPair() throws -> KeyPair {
        var publicKey = [UInt8](repeating: 0, count: sizes.publicKey)
        var secretKey = [UInt8](repeating: 0, count: sizes.secretKey)
        let status = publicKey.withUnsafeMutableBufferPointer { publicBuffer in
            secretKey.withUnsafeMutableBufferPointer { secretBuffer in
                keyPair(publicBuffer.baseAddress!, secretBuffer.baseAddress!)
            }
        }
        guard status == 0 else {
            wipe(&publicKey)
            wipe(&secretKey)
            throw KpqCError.coreFailure(operation: "key generation", status: status)
        }
        let result = KeyPair(publicKey: Data(publicKey), secretKey: Data(secretKey))
        wipe(&secretKey)
        return result
    }

    /// Encapsulates a fresh shared secret for a recipient public key.
    public func encapsulate(_ publicKey: Data) throws -> EncapsulatedSecret {
        try requireLength("publicKey", actual: publicKey.count, expected: sizes.publicKey)
        var ciphertext = [UInt8](repeating: 0, count: sizes.ciphertext)
        var sharedSecret = [UInt8](repeating: 0, count: sizes.sharedSecret)
        let status = ciphertext.withUnsafeMutableBufferPointer { ciphertextBuffer in
            sharedSecret.withUnsafeMutableBufferPointer { secretBuffer in
                withInput(publicKey) { publicKeyPointer in
                    encapsulator(
                        ciphertextBuffer.baseAddress!, secretBuffer.baseAddress!,
                        publicKeyPointer
                    )
                }
            }
        }
        guard status == 0 else {
            wipe(&ciphertext)
            wipe(&sharedSecret)
            throw KpqCError.coreFailure(operation: "encapsulation", status: status)
        }
        let result = EncapsulatedSecret(
            ciphertext: Data(ciphertext),
            sharedSecret: Data(sharedSecret)
        )
        wipe(&sharedSecret)
        return result
    }

    /// Recovers a shared secret from a ciphertext and recipient secret key.
    public func decapsulate(_ ciphertext: Data, secretKey: Data) throws -> Data {
        try requireLength("ciphertext", actual: ciphertext.count, expected: sizes.ciphertext)
        try requireLength("secretKey", actual: secretKey.count, expected: sizes.secretKey)
        var sharedSecret = [UInt8](repeating: 0, count: sizes.sharedSecret)
        var secretBytes = [UInt8](secretKey)
        defer { wipe(&secretBytes) }
        let status = sharedSecret.withUnsafeMutableBufferPointer { sharedSecretBuffer in
            secretBytes.withUnsafeBufferPointer { secretKeyBuffer in
                withInput(ciphertext) { ciphertextPointer in
                    decapsulator(
                        sharedSecretBuffer.baseAddress!, ciphertextPointer,
                        secretKeyBuffer.baseAddress!
                    )
                }
            }
        }
        guard status == 0 else {
            wipe(&sharedSecret)
            throw KpqCError.coreFailure(operation: "decapsulation", status: status)
        }
        let result = Data(sharedSecret)
        wipe(&sharedSecret)
        return result
    }

    public var description: String { id }
}

private func requireLength(_ input: String, actual: Int, expected: Int) throws {
    guard actual == expected else {
        throw KpqCError.invalidLength(input: input, expected: expected, actual: actual)
    }
}

private func requireContext(_ context: Data) throws {
    guard context.count <= 255 else {
        throw KpqCError.contextTooLong(actual: context.count)
    }
}

private func withInput<Result>(
    _ data: Data,
    _ body: (UnsafePointer<UInt8>) throws -> Result
) rethrows -> Result {
    if data.isEmpty {
        var empty: UInt8 = 0
        return try withUnsafePointer(to: &empty, body)
    }
    return try data.withUnsafeBytes { bytes in
        try body(bytes.bindMemory(to: UInt8.self).baseAddress!)
    }
}

private func wipe(_ data: inout Data) {
    data.withUnsafeMutableBytes { bytes in
        guard let baseAddress = bytes.bindMemory(to: UInt8.self).baseAddress else { return }
        __kpqc_secure_zero(baseAddress, bytes.count)
    }
}

private func wipe(_ bytes: inout [UInt8]) {
    bytes.withUnsafeMutableBufferPointer { buffer in
        guard let baseAddress = buffer.baseAddress else { return }
        __kpqc_secure_zero(baseAddress, buffer.count)
    }
}
