#if SWIFT_PACKAGE
import KpqCCore
#endif

/// The SMAUG-T128 KEM parameter set.
public let smaugt128 = KeyEncapsulationAlgorithm(
    id: "SMAUG-T128",
    sizes: KemSizes(publicKey: 672, secretKey: 832, ciphertext: 672, sharedSecret: 32),
    keyPair: __kpqc_smaugt128_keypair,
    encapsulate: __kpqc_smaugt128_encapsulate,
    decapsulate: __kpqc_smaugt128_decapsulate
)

/// The SMAUG-T192 KEM parameter set.
public let smaugt192 = KeyEncapsulationAlgorithm(
    id: "SMAUG-T192",
    sizes: KemSizes(publicKey: 1_088, secretKey: 1_312, ciphertext: 992, sharedSecret: 32),
    keyPair: __kpqc_smaugt192_keypair,
    encapsulate: __kpqc_smaugt192_encapsulate,
    decapsulate: __kpqc_smaugt192_decapsulate
)

/// The SMAUG-T256 KEM parameter set.
public let smaugt256 = KeyEncapsulationAlgorithm(
    id: "SMAUG-T256",
    sizes: KemSizes(publicKey: 1_440, secretKey: 1_728, ciphertext: 1_376, sharedSecret: 32),
    keyPair: __kpqc_smaugt256_keypair,
    encapsulate: __kpqc_smaugt256_encapsulate,
    decapsulate: __kpqc_smaugt256_decapsulate
)

/// The TiMER KEM parameter set.
public let timer = KeyEncapsulationAlgorithm(
    id: "TiMER",
    sizes: KemSizes(publicKey: 672, secretKey: 832, ciphertext: 608, sharedSecret: 32),
    keyPair: __kpqc_timer_keypair,
    encapsulate: __kpqc_timer_encapsulate,
    decapsulate: __kpqc_timer_decapsulate
)
