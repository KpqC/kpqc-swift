#if SWIFT_PACKAGE
import KpqCCore
#endif

/// The NTRU+768 KEM parameter set.
public let ntruplus768 = KeyEncapsulationAlgorithm(
    id: "NTRU+768",
    sizes: KemSizes(publicKey: 1_152, secretKey: 2_336, ciphertext: 1_152, sharedSecret: 32),
    keyPair: __kpqc_ntruplus768_keypair,
    encapsulate: __kpqc_ntruplus768_encapsulate,
    decapsulate: __kpqc_ntruplus768_decapsulate
)

/// The NTRU+864 KEM parameter set.
public let ntruplus864 = KeyEncapsulationAlgorithm(
    id: "NTRU+864",
    sizes: KemSizes(publicKey: 1_296, secretKey: 2_624, ciphertext: 1_296, sharedSecret: 32),
    keyPair: __kpqc_ntruplus864_keypair,
    encapsulate: __kpqc_ntruplus864_encapsulate,
    decapsulate: __kpqc_ntruplus864_decapsulate
)

/// The NTRU+1152 KEM parameter set.
public let ntruplus1152 = KeyEncapsulationAlgorithm(
    id: "NTRU+1152",
    sizes: KemSizes(publicKey: 1_728, secretKey: 3_488, ciphertext: 1_728, sharedSecret: 32),
    keyPair: __kpqc_ntruplus1152_keypair,
    encapsulate: __kpqc_ntruplus1152_encapsulate,
    decapsulate: __kpqc_ntruplus1152_decapsulate
)
