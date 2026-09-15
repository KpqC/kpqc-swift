/// The AIMer128f signature parameter set.
public let aimer128f = SignatureAlgorithm(
    id: "aimer-128f",
    sizes: SignatureSizes(publicKey: 32, secretKey: 48, signature: 5_888),
    keyPair: __kpqc_aimer128f_keypair,
    sign: __kpqc_aimer128f_sign,
    verify: __kpqc_aimer128f_verify
)

/// The AIMer128s signature parameter set.
public let aimer128s = SignatureAlgorithm(
    id: "aimer-128s",
    sizes: SignatureSizes(publicKey: 32, secretKey: 48, signature: 4_160),
    keyPair: __kpqc_aimer128s_keypair,
    sign: __kpqc_aimer128s_sign,
    verify: __kpqc_aimer128s_verify
)

/// The AIMer192f signature parameter set.
public let aimer192f = SignatureAlgorithm(
    id: "aimer-192f",
    sizes: SignatureSizes(publicKey: 48, secretKey: 72, signature: 13_056),
    keyPair: __kpqc_aimer192f_keypair,
    sign: __kpqc_aimer192f_sign,
    verify: __kpqc_aimer192f_verify
)

/// The AIMer192s signature parameter set.
public let aimer192s = SignatureAlgorithm(
    id: "aimer-192s",
    sizes: SignatureSizes(publicKey: 48, secretKey: 72, signature: 9_120),
    keyPair: __kpqc_aimer192s_keypair,
    sign: __kpqc_aimer192s_sign,
    verify: __kpqc_aimer192s_verify
)

/// The AIMer256f signature parameter set.
public let aimer256f = SignatureAlgorithm(
    id: "aimer-256f",
    sizes: SignatureSizes(publicKey: 64, secretKey: 96, signature: 25_120),
    keyPair: __kpqc_aimer256f_keypair,
    sign: __kpqc_aimer256f_sign,
    verify: __kpqc_aimer256f_verify
)

/// The AIMer256s signature parameter set.
public let aimer256s = SignatureAlgorithm(
    id: "aimer-256s",
    sizes: SignatureSizes(publicKey: 64, secretKey: 96, signature: 17_056),
    keyPair: __kpqc_aimer256s_keypair,
    sign: __kpqc_aimer256s_sign,
    verify: __kpqc_aimer256s_verify
)
