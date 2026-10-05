#if SWIFT_PACKAGE
import KpqCCore
#endif

/// The HAETAE2 signature parameter set.
public let haetae2 = SignatureAlgorithm(
    id: "haetae-mode2",
    sizes: SignatureSizes(publicKey: 992, secretKey: 1_408, signature: 1_474),
    keyPair: __kpqc_haetae2_keypair,
    sign: __kpqc_haetae2_sign,
    verify: __kpqc_haetae2_verify
)

/// The HAETAE3 signature parameter set.
public let haetae3 = SignatureAlgorithm(
    id: "haetae-mode3",
    sizes: SignatureSizes(publicKey: 1_472, secretKey: 2_112, signature: 2_349),
    keyPair: __kpqc_haetae3_keypair,
    sign: __kpqc_haetae3_sign,
    verify: __kpqc_haetae3_verify
)

/// The HAETAE5 signature parameter set.
public let haetae5 = SignatureAlgorithm(
    id: "haetae-mode5",
    sizes: SignatureSizes(publicKey: 2_080, secretKey: 2_752, signature: 2_948),
    keyPair: __kpqc_haetae5_keypair,
    sign: __kpqc_haetae5_sign,
    verify: __kpqc_haetae5_verify
)
