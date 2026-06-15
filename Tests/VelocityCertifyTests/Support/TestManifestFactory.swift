import Foundation
import CryptoKit
@testable import VelocityCertify

// MARK: - TestManifestFactory
//
// Produces signed VelocityCertifyManifest JSON for injection into
// ManifestCache and CertificationService tests.
//
// Each TestManifestFactory generates a UNIQUE Ed25519 keypair per instance.
// This means:
//   — Signatures produced by factory A cannot be verified with factory B's pubkey.
//   — Tests that verify "wrong key → rejected" can create a second factory
//     and use its pubkey while signing with the first factory's private key.
//
// The manifest JSON is minimal by default. Use the builder methods to add
// titles, revocations, and a schema version.
//
// Example:
//
//   let factory = TestManifestFactory()
//
//   let slug = "hades-2"
//   let binaryHash = "abc123..."
//   let gptkHash   = "def456..."
//
//   let manifestJSON = factory.buildManifest(
//       titles: [factory.makeTitle(slug: slug,
//                                  binarySHA256: binaryHash,
//                                  gptkSHA256: gptkHash,
//                                  status: "certified")],
//       revokedSlugs: []
//   )
//   let sigData = factory.sign(manifestJSON)
//
//   MockURLProtocol.stub(url: ManifestCache.manifestURL, data: manifestJSON)
//   MockURLProtocol.stub(url: ManifestCache.sigURL, data: sigData)
//
//   let cache = ManifestCache(session: MockURLProtocol.makeSession(),
//                              pubkeyPEM: factory.pubkeyPEM)

public final class TestManifestFactory {

    // MARK: - Key material

    private let privateKey: Curve25519.Signing.PrivateKey
    public  let publicKey:  Curve25519.Signing.PublicKey

    /// PKCS#8 SubjectPublicKeyInfo PEM — inject this into ManifestCache(pubkeyPEM:).
    public let pubkeyPEM: String

    public init() {
        let key   = Curve25519.Signing.PrivateKey()
        self.privateKey = key
        self.publicKey  = key.publicKey
        self.pubkeyPEM  = Self.encodePEM(publicKey: key.publicKey)
    }

    // MARK: - Signing

    /// Returns a detached Ed25519 signature over `data`, in the same format
    /// the vcertify-sign tool produces (raw 64-byte signature, no encoding).
    public func sign(_ data: Data) -> Data {
        // CryptoKit returns a 64-byte raw signature.
        // ManifestCache.verifyEd25519 expects raw bytes (it passes sigData directly
        // to Curve25519.Signing.PublicKey.isValidSignature(_:for:)).
        (try? privateKey.signature(for: data)) ?? Data()
    }

    // MARK: - Manifest construction

    /// Build a minimal valid manifest JSON. The `schema` defaults to "1.0".
    /// Pass a higher major (e.g. "2.0") to trigger the schema rejection path.
    public func buildManifest(
        titles:       [ManifestTitleSpec] = [],
        revokedSlugs: [RevokedSpec] = [],
        schema:       String = "1.0"
    ) -> Data {
        var json: [String: Any] = [
            "schema":    schema,
            "generated": ISO8601DateFormatter().string(from: Date()),
            "environment": [
                "velocity_version": "1.0.0-test",
                "gptk_version":     "2.0-test",
                "hardware_id":      "test-machine",
                "hardware_label":   "Test Mac (14-inch, 2023)",
                "macos_version":    "14.0"
            ] as [String: Any],
            "titles": titles.map { t -> [String: Any] in
                var entry: [String: Any] = [
                    "slug":   t.slug,
                    "name":   t.name,
                    "status": t.status,
                    "identity": [
                        "binary_sha256":     t.binarySHA256,
                        "gptk_dylib_sha256": t.gptkSHA256
                    ] as [String: Any]
                ]
                if let fps = t.avgFPS {
                    entry["performance"] = [
                        "fps_target": fps,
                        "cold": ["avg_fps": Double(fps), "p99_frametime_ms": 16.7]
                    ] as [String: Any]
                }
                return entry
            }
        ]

        if !revokedSlugs.isEmpty {
            json["revoked_titles"] = revokedSlugs.map { r -> [String: Any] in
                ["slug": r.slug, "revoked_at": "2024-01-01T00:00:00Z", "reason": r.reason]
            }
        }

        return (try? JSONSerialization.data(withJSONObject: json, options: .sortedKeys)) ?? Data()
    }

    /// Convenience: build manifest + sign in one call.
    /// Returns (manifestData, signatureData).
    public func buildAndSign(
        titles:       [ManifestTitleSpec] = [],
        revokedSlugs: [RevokedSpec] = [],
        schema:       String = "1.0"
    ) -> (manifest: Data, signature: Data) {
        let manifest  = buildManifest(titles: titles, revokedSlugs: revokedSlugs, schema: schema)
        let signature = sign(manifest)
        return (manifest, signature)
    }

    /// Stub both manifest and sig URLs in MockURLProtocol in one call.
    public func stubURLs(titles: [ManifestTitleSpec] = [],
                         revokedSlugs: [RevokedSpec] = [],
                         schema: String = "1.0") {
        let (manifest, sig) = buildAndSign(
            titles: titles, revokedSlugs: revokedSlugs, schema: schema)
        MockURLProtocol.stub(url: ManifestCache.manifestURL, data: manifest)
        MockURLProtocol.stub(url: ManifestCache.sigURL,      data: sig)
    }

    // MARK: - Builder helpers

    public struct ManifestTitleSpec {
        public let slug:         String
        public let name:         String
        public let binarySHA256: String
        public let gptkSHA256:   String
        public let status:       String
        public let avgFPS:       Int?

        public init(slug: String, name: String? = nil,
                    binarySHA256: String, gptkSHA256: String,
                    status: String = "certified", avgFPS: Int? = 60) {
            self.slug         = slug
            self.name         = name ?? slug
            self.binarySHA256 = binarySHA256
            self.gptkSHA256   = gptkSHA256
            self.status       = status
            self.avgFPS       = avgFPS
        }
    }

    public struct RevokedSpec {
        public let slug:   String
        public let reason: String
        public init(slug: String, reason: String = "Security vulnerability") {
            self.slug   = slug
            self.reason = reason
        }
    }

    // MARK: - PEM encoding

    /// Encode an Ed25519 public key as PKCS#8 SubjectPublicKeyInfo PEM.
    /// The DER header for Ed25519 SPKI is the 12-byte prefix:
    ///   30 2a 30 05 06 03 2b 65 70 03 21 00
    private static func encodePEM(publicKey: Curve25519.Signing.PublicKey) -> String {
        let spkiHeader = Data([
            0x30, 0x2a,              // SEQUENCE (42 bytes)
            0x30, 0x05,              // SEQUENCE (5 bytes)
            0x06, 0x03, 0x2b, 0x65, 0x70,  // OID 1.3.101.112 (Ed25519)
            0x03, 0x21, 0x00         // BIT STRING (33 bytes, 0 unused)
        ])
        let der    = spkiHeader + publicKey.rawRepresentation
        let base64 = der.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
        return "-----BEGIN PUBLIC KEY-----\n\(base64)\n-----END PUBLIC KEY-----\n"
    }
}

// manifestURL and sigURL are accessed directly from ManifestCache via
// @testable import VelocityCertify (both are internal, not private).
