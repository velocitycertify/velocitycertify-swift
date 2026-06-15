// swift-tools-version: 5.9
// VelocityCertify — standalone trust layer for Mac Silicon game certification.
//
// This package is INDEPENDENT of any application, including Velocity.
// Any developer can add VelocityCertify as a dependency to show certification
// status in their own app:
//
//   .package(url: "https://github.com/velocitycertify/velocitycertify-swift", from: "1.0.0")
//
// The only trust anchor is the Ed25519 public key bundled in Sources/VelocityCertify/.
// The manifest is fetched from velocitycertify.com and verified against that key.
// Nothing about this package is controlled by any app — including Velocity.

import PackageDescription

let package = Package(
    name: "VelocityCertify",
    platforms: [
        .macOS(.v14)   // Sonoma: required for GPTK 2.0 + Metal 3 + CryptoKit Ed25519
    ],
    products: [
        .library(
            name: "VelocityCertify",
            targets: ["VelocityCertify"]
        ),
    ],
    dependencies: [],
    targets: [
        .target(
            name: "VelocityCertify",
            dependencies: [],
            path: "Sources/VelocityCertify",
            resources: [
                // The Ed25519 public key is the trust anchor.
                // It is bundled here — in VelocityCertify — not in any consuming app.
                // Apps cannot substitute or override this key.
                .copy("velocitycertify-pubkey.pem")
            ]
        ),
        .testTarget(
            name: "VelocityCertifyTests",
            dependencies: ["VelocityCertify"],
            path: "Tests/VelocityCertifyTests",
            resources: [
                .copy("Support/GameProcessStub")
            ]
        ),
    ]
)
