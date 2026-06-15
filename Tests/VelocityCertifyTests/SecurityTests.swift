import XCTest
import CryptoKit
@testable import VelocityCertify

// MARK: - SecurityTests
//
// Adversarial test suite for VelocityCertify's trust model.
// Every test here models a specific attack vector that must be defeated.
//
// Attack vectors covered:
//
//   1. WRONG KEY — adversary generates their own Ed25519 keypair and signs
//      a forged manifest. The bundled pubkey must reject it.
//
//   2. BIT FLIP — valid manifest, valid signature, but one byte of the
//      signature is flipped. Must be detected.
//
//   3. JSON TAMPERING — valid signature over the original JSON, but the
//      JSON bytes are modified before verification. Must be detected.
//
//   4. STATUS UPGRADE — tamper the "status" field from "not_certified" to
//      "certified" in the JSON. Signature check must catch this.
//
//   5. HASH SUBSTITUTION — tamper binary_sha256 in the JSON to match the
//      attacker's binary. Signature check must catch this.
//
//   6. REVOCATION BYPASS — a revoked title has matching hashes. The
//      revocation gate must fire before the hash match. .revoked, not .certified.
//
//   7. SCHEMA DOWNGRADE ATTACK — adversary replaces schema "2.0" with "1.0"
//      in the JSON to bypass the schema gate. Signature check must catch this.
//
//   8. NULL REVOCATION LIST — manifest has revokedTitles: null vs [].
//      Neither must incorrectly gate a certified title.
//
//   9. GPTK SENTINEL INJECTION — sending "gptk-dylib-not-found" as the
//      gptkDylibSHA256 in the identity. Must never match a real manifest
//      entry and must not crash.
//
//  10. PUBKEY SUBSTITUTION — adversary provides a different PEM pubkey to
//      attempt verification with their own key. The injected pubkey only
//      works if the manifest was also signed with the matching private key.
//      (Tested by having factory A sign, factory B pubkey verify → reject.)
//
//  11. EMPTY SIGNATURE — zero-byte signature. Must be rejected.
//
//  12. TRUNCATED SIGNATURE — 63 bytes instead of 64. Must be rejected.
//
//  13. OVERSIZED SIGNATURE — 65 bytes. Must be rejected.
//
//  14. REPLAY ATTACK — same signature reused on a different manifest.
//      Must be rejected (signature is data-bound).

final class SecurityTests: XCTestCase {

    private var factory: TestManifestFactory!

    private let testSlug   = "hades-2"
    private let binaryHash = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
    private let gptkHash   = "f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5"

    override func setUp() {
        super.setUp()
        factory = TestManifestFactory()
        MockURLProtocol.reset()
    }

    override func tearDown() {
        MockURLProtocol.reset()
        super.tearDown()
    }

    // MARK: - Helpers

    private func makeCache(pubkeyPEM: String? = nil) -> ManifestCache {
        ManifestCache(session: MockURLProtocol.makeSession(),
                      pubkeyPEM: pubkeyPEM ?? factory.pubkeyPEM)
    }

    private func makeService(pubkeyPEM: String? = nil) -> CertificationService {
        CertificationService(cache: makeCache(pubkeyPEM: pubkeyPEM))
    }

    private func makeIdentity() -> CertificationIdentity {
        CertificationIdentity(gameSlug: testSlug, binarySHA256: binaryHash,
                              gptkDylibSHA256: gptkHash,
                              velocityVersion: "1.0", gptkVersion: "2.0")
    }

    private func stubManifestAndSig(manifest: Data, sig: Data) {
        MockURLProtocol.stub(url: ManifestCache.manifestURL, data: manifest)
        MockURLProtocol.stub(url: ManifestCache.sigURL,      data: sig)
    }

    // MARK: - 1. Wrong key

    func testAttack_wrongKey_manifestRejected() async {
        // Adversary has their own keypair (factory2)
        let factory2       = TestManifestFactory()
        let manifestData   = factory2.buildManifest()
        let adversarySig   = factory2.sign(manifestData)   // signed with factory2's key

        // Cache configured with factory1's pubkey
        MockURLProtocol.stub(url: ManifestCache.manifestURL, data: manifestData)
        MockURLProtocol.stub(url: ManifestCache.sigURL,      data: adversarySig)

        let cache = ManifestCache(session: MockURLProtocol.makeSession(),
                                  pubkeyPEM: factory.pubkeyPEM)   // factory1 pubkey
        let manifest = await cache.currentManifest()
        XCTAssertNil(manifest,
            "ATTACK: manifest signed with wrong key must be rejected")
    }

    // MARK: - 2. Bit flip in signature

    func testAttack_singleBitFlipInSignature_rejected() async {
        let manifestData = factory.buildManifest()
        var sig          = factory.sign(manifestData)
        sig[0] ^= 0x01   // flip one bit

        stubManifestAndSig(manifest: manifestData, sig: sig)
        let cache    = makeCache()
        let manifest = await cache.currentManifest()
        XCTAssertNil(manifest,
            "ATTACK: single-bit-flipped signature must be rejected")
    }

    func testAttack_lastByteFlipInSignature_rejected() async {
        let manifestData = factory.buildManifest()
        var sig          = factory.sign(manifestData)
        sig[sig.count - 1] ^= 0xFF   // flip last byte

        stubManifestAndSig(manifest: manifestData, sig: sig)
        let manifest = await makeCache().currentManifest()
        XCTAssertNil(manifest,
            "ATTACK: flip in last signature byte must be rejected")
    }

    // MARK: - 3. JSON tampering (signature was over original)

    func testAttack_jsonTampering_statusUpgrade_rejected() async {
        // Build and sign "not_certified" manifest
        let spec     = TestManifestFactory.ManifestTitleSpec(
            slug: testSlug, binarySHA256: binaryHash,
            gptkSHA256: gptkHash, status: "not_certified")
        let original = factory.buildManifest(titles: [spec])
        let sig      = factory.sign(original)

        // Tamper: change "not_certified" → "certified" in raw JSON bytes
        var tampered = original
        if let r = tampered.range(of: Data("not_certified".utf8)) {
            tampered.replaceSubrange(r, with: Data("    certified".utf8))
        }

        stubManifestAndSig(manifest: tampered, sig: sig)
        let manifest = await makeCache().currentManifest()
        XCTAssertNil(manifest,
            "ATTACK: status upgrade via JSON tampering must be caught by signature check")
    }

    func testAttack_jsonTampering_hashSubstitution_rejected() async {
        // Sign a manifest with binaryHash, then swap it for a different hash
        let spec     = TestManifestFactory.ManifestTitleSpec(
            slug: testSlug, binarySHA256: binaryHash,
            gptkSHA256: gptkHash, status: "certified")
        let original = factory.buildManifest(titles: [spec])
        let sig      = factory.sign(original)

        // Substitute the first 8 chars of binaryHash with "deadbeef"
        let fakeHash   = "deadbeef" + String(binaryHash.dropFirst(8))
        var tampered   = original
        if let r = tampered.range(of: Data(binaryHash.utf8)) {
            tampered.replaceSubrange(r, with: Data(fakeHash.utf8))
        }

        stubManifestAndSig(manifest: tampered, sig: sig)
        let manifest = await makeCache().currentManifest()
        XCTAssertNil(manifest,
            "ATTACK: hash substitution in JSON must be caught by signature check")
    }

    // MARK: - 4. Revocation bypass (hashes match, but title is revoked)

    func testAttack_revocationBypass_hashMatchDoesNotOverrideRevocation() async {
        // Revocation gate must fire BEFORE hash comparison.
        // Adversary tries: matching hashes, hoping to get .certified despite revocation.
        let spec = TestManifestFactory.ManifestTitleSpec(
            slug: testSlug, binarySHA256: binaryHash,
            gptkSHA256: gptkHash, status: "certified")
        factory.stubURLs(
            titles: [spec],
            revokedSlugs: [.init(slug: testSlug, reason: "Known exploit")])

        let service = CertificationService(cache: ManifestCache(
            session: MockURLProtocol.makeSession(), pubkeyPEM: factory.pubkeyPEM))
        let result  = await service.check(identity: makeIdentity())

        XCTAssertEqual(result.status, .revoked,
            "ATTACK: matching hashes must not bypass revocation — " +
            "revocation fires first regardless of hash state")
        XCTAssertNotEqual(result.status, .certified)
    }

    // MARK: - 5. Schema downgrade attack

    func testAttack_schemaDowngrade_rejected() async {
        // Build a schema "2.0" manifest (adversary's format), sign it,
        // then tamper the schema to "1.0" to bypass the schema gate.
        let original = factory.buildManifest(schema: "2.0")
        let sig      = factory.sign(original)

        var tampered = original
        if let r = tampered.range(of: Data("\"2.0\"".utf8)) {
            tampered.replaceSubrange(r, with: Data("\"1.0\"".utf8))
        }

        stubManifestAndSig(manifest: tampered, sig: sig)
        let manifest = await makeCache().currentManifest()
        XCTAssertNil(manifest,
            "ATTACK: schema downgrade (2.0 → 1.0 via tampering) must be caught by signature")
    }

    // MARK: - 6. GPTK sentinel injection

    func testAttack_GPTKSentinelInjection_neverReachesCertified() async {
        // Adversary sends the sentinel string hoping it matches some manifest entry
        let identity = CertificationIdentity(
            gameSlug:        testSlug,
            binarySHA256:    binaryHash,
            gptkDylibSHA256: "gptk-dylib-not-found",
            velocityVersion: "1.0",
            gptkVersion:     "2.0")

        let spec = TestManifestFactory.ManifestTitleSpec(
            slug: testSlug, binarySHA256: binaryHash,
            gptkSHA256: "gptk-dylib-not-found",   // adversary tried to pre-register sentinel
            status: "certified")
        factory.stubURLs(titles: [spec])

        let service = CertificationService(cache: ManifestCache(
            session: MockURLProtocol.makeSession(), pubkeyPEM: factory.pubkeyPEM))
        let result  = await service.check(identity: identity)

        // SKYFIRE must never certify a title where GPTK dylib wasn't found
        XCTAssertNotEqual(result.status, .certified,
            "ATTACK: GPTK sentinel in manifest entry must never produce .certified")
    }

    // MARK: - 7. Null / empty revocation list (no false positive)

    func testNullRevocationList_doesNotBlockCertifiedTitle() async {
        // revokedTitles absent → certified title must still certify
        let spec = TestManifestFactory.ManifestTitleSpec(
            slug: testSlug, binarySHA256: binaryHash,
            gptkSHA256: gptkHash, status: "certified")
        factory.stubURLs(titles: [spec], revokedSlugs: [])   // empty list

        let service = makeService()
        let result  = await service.check(identity: makeIdentity())
        XCTAssertEqual(result.status, .certified,
            "Empty revocation list must not block a certified title")
    }

    // MARK: - 8. Signature size attacks

    func testAttack_emptySignature_rejected() async {
        let manifestData = factory.buildManifest()
        stubManifestAndSig(manifest: manifestData, sig: Data())
        let manifest = await makeCache().currentManifest()
        XCTAssertNil(manifest,
            "ATTACK: empty (zero-byte) signature must be rejected")
    }

    func testAttack_truncatedSignature_63bytes_rejected() async {
        let manifestData = factory.buildManifest()
        let sig          = factory.sign(manifestData)
        XCTAssertEqual(sig.count, 64, "Ed25519 signature must be 64 bytes")
        stubManifestAndSig(manifest: manifestData, sig: sig.dropLast(1))
        let manifest = await makeCache().currentManifest()
        XCTAssertNil(manifest,
            "ATTACK: 63-byte truncated signature must be rejected")
    }

    func testAttack_oversizedSignature_65bytes_rejected() async {
        let manifestData = factory.buildManifest()
        var sig          = factory.sign(manifestData)
        sig.append(0x00)   // pad to 65 bytes
        XCTAssertEqual(sig.count, 65)
        stubManifestAndSig(manifest: manifestData, sig: sig)
        let manifest = await makeCache().currentManifest()
        XCTAssertNil(manifest,
            "ATTACK: oversized (65-byte) signature must be rejected")
    }

    func testAttack_allZeroSignature_rejected() async {
        let manifestData = factory.buildManifest()
        stubManifestAndSig(manifest: manifestData, sig: Data(repeating: 0x00, count: 64))
        let manifest = await makeCache().currentManifest()
        XCTAssertNil(manifest,
            "ATTACK: all-zero 64-byte signature must be rejected")
    }

    // MARK: - 9. Replay attack

    func testAttack_signatureReusedOnDifferentManifest_rejected() async {
        // Sign manifest A, then try to use that signature on manifest B
        let manifestA = factory.buildManifest(schema: "1.0")
        let sigA      = factory.sign(manifestA)

        let manifestB = factory.buildManifest(schema: "1.1")   // different content
        // Use sigA on manifestB — must fail
        stubManifestAndSig(manifest: manifestB, sig: sigA)

        let manifest = await makeCache().currentManifest()
        XCTAssertNil(manifest,
            "ATTACK: signature from manifest A must not verify against manifest B (replay)")
    }

    // MARK: - 10. Pubkey substitution

    func testAttack_pubkeySubstitution_adversaryKeyDoesNotVerifyOtherSignature() async {
        // Factory A signs the manifest; adversary provides factory B's pubkey.
        // CryptoKit must reject: sig from A cannot verify with B's pubkey.
        let factoryA = TestManifestFactory()
        let factoryB = TestManifestFactory()   // adversary's keypair

        let manifestData = factoryA.buildManifest()
        let sigA         = factoryA.sign(manifestData)

        MockURLProtocol.stub(url: ManifestCache.manifestURL, data: manifestData)
        MockURLProtocol.stub(url: ManifestCache.sigURL,      data: sigA)

        // Inject factoryB's pubkey — B's key cannot verify A's signature
        let cache    = ManifestCache(session: MockURLProtocol.makeSession(),
                                     pubkeyPEM: factoryB.pubkeyPEM)
        let manifest = await cache.currentManifest()
        XCTAssertNil(manifest,
            "ATTACK: signature from key A cannot be verified with key B's pubkey")
    }

    // MARK: - Positive controls (ensure security tests don't produce false negatives)

    func testPositiveControl_validSignatureAccepted() async {
        factory.stubURLs()
        let cache    = makeCache()
        let manifest = await cache.currentManifest()
        XCTAssertNotNil(manifest,
            "CONTROL: valid manifest + correct signature must be accepted by all security tests")
    }

    func testPositiveControl_certifiedTitleNotAffectedByOtherRevocations() async {
        let spec = TestManifestFactory.ManifestTitleSpec(
            slug: testSlug, binarySHA256: binaryHash,
            gptkSHA256: gptkHash, status: "certified")
        factory.stubURLs(
            titles: [spec],
            revokedSlugs: [.init(slug: "completely-different-game")])

        let service = makeService()
        let result  = await service.check(identity: makeIdentity())
        XCTAssertEqual(result.status, .certified,
            "CONTROL: revocation of an unrelated game must not affect certified title")
    }
}
