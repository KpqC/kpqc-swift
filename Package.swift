// swift-tools-version: 5.8

import PackageDescription

let package = Package(
    name: "KpqC",
    platforms: [
        .iOS(.v15),
        .macOS(.v12),
        .tvOS(.v15),
        .watchOS(.v9),
    ],
    products: [
        .library(name: "KpqC", targets: ["KpqC"]),
    ],
    targets: [
        .target(
            name: "KpqCCore",
            path: ".",
            exclude: [
                ".github",
                "Tests",
                "Sources/KpqC",
                "scripts",
                "vendor",
                "CHANGELOG.md",
                "KpqC.podspec",
                "LICENSE",
                "README.md",
                "THIRD_PARTY_NOTICES.md",
                "native/csrc/kem_wrapper.c",
                "native/csrc/randombytes.c",
                "native/csrc/randombytes_test.c",
                "native/csrc/signature.c",
            ],
            sources: [
                "Sources/KpqCCore/Generated",
                "native/csrc/secure_zero.c",
            ],
            publicHeadersPath: "Sources/KpqCCore/include",
            cSettings: [
                .headerSearchPath("."),
            ]
        ),
        .target(
            name: "KpqC",
            dependencies: ["KpqCCore"],
            path: "Sources/KpqC"
        ),
        .testTarget(
            name: "KpqCTests",
            dependencies: ["KpqC"],
            path: "Tests/KpqCTests",
            exclude: [
                "kat",
                "__pycache__",
                "kat_drbg.py",
                "test_kat.py",
            ]
        ),
    ],
    cLanguageStandard: .c11
)
