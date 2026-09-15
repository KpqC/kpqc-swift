import Foundation
import XCTest
@testable import KpqC

final class KpqCTests: XCTestCase {
    private let signatures = [
        aimer128f, aimer128s, aimer192f, aimer192s, aimer256f, aimer256s,
        haetae2, haetae3, haetae5
    ]

    private let kems = [
        ntruplus768, ntruplus864, ntruplus1152,
        smaugt128, smaugt192, smaugt256, timer
    ]

    func testSignatureRoundTrips() throws {
        let message = Data([0x4b, 0x70, 0x71, 0x43, 0x00, 0xff])
        let context = Data("test-suite".utf8)

        for algorithm in signatures {
            let keys = try algorithm.generateKeyPair()
            defer { keys.dispose() }
            let signature = try algorithm.sign(
                message,
                secretKey: keys.secretKey,
                context: context
            )

            XCTAssertEqual(keys.publicKey.count, algorithm.sizes.publicKey)
            XCTAssertEqual(keys.secretKey.count, algorithm.sizes.secretKey)
            XCTAssertEqual(signature.count, algorithm.sizes.signature)
            XCTAssertTrue(try algorithm.verify(
                message,
                signature: signature,
                publicKey: keys.publicKey,
                context: context
            ))

            var altered = signature
            altered[altered.startIndex] ^= 0x80
            XCTAssertFalse(try algorithm.verify(
                message,
                signature: altered,
                publicKey: keys.publicKey,
                context: context
            ))
            XCTAssertFalse(try algorithm.verify(
                Data("changed".utf8),
                signature: signature,
                publicKey: keys.publicKey,
                context: context
            ))
            XCTAssertFalse(try algorithm.verify(
                message,
                signature: signature,
                publicKey: keys.publicKey,
                context: Data("other".utf8)
            ))
        }
    }

    func testKemRoundTrips() throws {
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

            XCTAssertEqual(recovered, outbound.sharedSecret)
            XCTAssertEqual(outbound.ciphertext.count, algorithm.sizes.ciphertext)
            XCTAssertEqual(outbound.sharedSecret.count, algorithm.sizes.sharedSecret)

            var altered = outbound.ciphertext
            altered[altered.startIndex] ^= 0x80
            if algorithm.id.hasPrefix("NTRU+") {
                XCTAssertThrowsError(try algorithm.decapsulate(
                    altered,
                    secretKey: keys.secretKey
                ))
            } else {
                var replacement = try algorithm.decapsulate(
                    altered,
                    secretKey: keys.secretKey
                )
                XCTAssertNotEqual(replacement, outbound.sharedSecret)
                replacement.resetBytes(in: 0..<replacement.count)
            }
        }
    }

    func testInvalidLengthsAndContext() throws {
        XCTAssertThrowsError(try aimer128f.sign(Data(), secretKey: Data(count: 47)))
        XCTAssertThrowsError(try aimer128f.sign(
            Data(),
            secretKey: Data(count: 48),
            context: Data(count: 256)
        ))
        XCTAssertFalse(try aimer128f.verify(
            Data(),
            signature: Data(),
            publicKey: Data(count: 32)
        ))
        XCTAssertThrowsError(try ntruplus768.encapsulate(Data(count: 1_151)))
    }

    func testSecretResultObjectsCanBeDisposed() throws {
        let keys = try ntruplus768.generateKeyPair()
        XCTAssertFalse(keys.secretKey.allSatisfy { $0 == 0 })
        keys.dispose()
        keys.dispose()
        XCTAssertTrue(keys.secretKey.allSatisfy { $0 == 0 })

        let freshKeys = try ntruplus768.generateKeyPair()
        defer { freshKeys.dispose() }
        let outbound = try ntruplus768.encapsulate(freshKeys.publicKey)
        XCTAssertFalse(outbound.sharedSecret.allSatisfy { $0 == 0 })
        outbound.dispose()
        outbound.dispose()
        XCTAssertTrue(outbound.sharedSecret.allSatisfy { $0 == 0 })
    }
}
