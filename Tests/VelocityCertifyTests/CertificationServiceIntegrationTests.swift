import XCTest
import CryptoKit
@testable import VelocityCertify

// MARK: - CertificationServiceIntegrationTests
//
// Tests the REAL CertificationService.check() actor — not a reimplemented free
// function. Each test injects a ManifestCache backed by MockURLProtocol, so
// the full call chain is exercised:
//
//   check(identity:)
//     → ManifestCache.currentManifest()
//         → MockURLProtocol (network layer)
//         → Ed25519 signature verification (real CryptoKit)
//         → JSON decoding
//     → revocation gate (slug lookup)
//     → title lookup by slug
//     → hash comparison (binarySHA256 + gptkDylibSHA256)
//     → status mapping
//     → CertificationResult construction
//
// Every test uses a fresh TestManifestFactory (unique Ed25519 keypair) and
// fresh ManifestCache + CertificationService to avoid cross-test state.
//
// Configuration matrix:
//
//   Known-good identity (slug + hashes match manifest entry, status "certified")
//     → .certified
//
//   Status "certified_degraded" in manifest
//     → .certifiedDegraded
//
//   Status "not_certified" in manifest
//     → .notCertified
//
//   Slug in manifest but binarySHA256 mismatch
//     → .unverified (binary changed since certification)
//
//   Slug in manifest but gptkDylibSHA256 mismatch
//     → .unverified (GPTK updated since certification)
//
//   Both hashes mismatched
//     → .unverified
//
//   Slug NOT in manifest (game not tested)
//     → .unverified
//
//   Slug in revoked_titles AND in titles with matching hashes
//     → .revoked (revocation fires BEFORE hash check — security invariant)
//
//   Slug in revoked_titles only (not in titles)
//     → .revoked
//
//   Manifest unavailable (network failure)
//     → .manifestUnavailable
//
//   Manifest with schema 2.0 (rejected by ManifestCache)
//     → .manifestUnavailable (cache returns nil → unavailable path)
//
//   Performance fields populated in manifest
//     → result.avgFPS and p1FPS non-nil and match manifest values
//
//   GPTK sentinel hash ("gptk-dylib-not-found") in identity
//     → .unverified even if slug exists (sentinel never matches a real hash)

final class CertificationServiceIntegrationTests: XCTestCase {

    private var factory: TestManifestFactory!

    // Canonical test values
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

    private func makeService() -> CertificationService {
        let cache = ManifestCache(session: MockURLProtocol.makeSession(),
                                  pubkeyPEM: factory.pubkeyPEM)
        return CertificationService(cache: cache)
    }

    private func makeIdentity(slug: String? = nil,
                               binary: String? = nil,
                               gptk: String? = nil) -> CertificationIdentity {
        CertificationIdentity(
            gameSlug:        slug   ?? testSlug,
            binarySHA256:    binary ?? binaryHash,
            gptkDylibSHA256: gptk   ?? gptkHash,
            velocityVersion: "1.0.0-test",
            gptkVersion:     "2.0-test"
        )
    }

    private func stubTitle(slug: String? = nil,
                            binary: String? = nil,
                            gptk: String? = nil,
                            status: String = "certified",
                            revokedSlugs: [TestManifestFactory.RevokedSpec] = []) {
        let spec = TestManifestFactory.ManifestTitleSpec(
            slug:         slug   ?? testSlug,
            binarySHA256: binary ?? binaryHash,
            gptkSHA256:   gptk   ?? gptkHash,
            status:       status
        )
        factory.stubURLs(titles: [spec], revokedSlugs: revokedSlugs)
    }

    // MARK: - Core status outcomes

    func testCertifiedTitle_matchingHashes_returnsCertified() async {
        stubTitle(status: "certified")
        let service = makeService()
        let result  = await service.check(identity: makeIdentity())
        XCTAssertEqual(result.status, .certified,
            "Matching hashes + status 'certified' must return .certified")
    }

    func testCertifiedDegraded_returnsCertifiedDegraded() async {
        stubTitle(status: "certified_degraded")
        let service = makeService()
        let result  = await service.check(identity: makeIdentity())
        XCTAssertEqual(result.status, .certifiedDegraded)
    }

    func testNotCertified_returnsNotCertified() async {
        stubTitle(status: "not_certified")
        let service = makeService()
        let result  = await service.check(identity: makeIdentity())
        XCTAssertEqual(result.status, .notCertified)
    }

    // MARK: - Hash mismatch → .unverified

    func testBinaryHashMismatch_returnsUnverified() async {
        stubTitle()
        let identity = makeIdentity(binary: "deadbeef00000000" + String(repeating: "0", count: 48))
        let service  = makeService()
        let result   = await service.check(identity: identity)
        XCTAssertEqual(result.status, .unverified,
            "Binary hash mismatch must return .unverified — binary changed since cert")
    }

    func testGPTKHashMismatch_returnsUnverified() async {
        stubTitle()
        let identity = makeIdentity(gptk: "cafebabe00000000" + String(repeating: "0", count: 48))
        let service  = makeService()
        let result   = await service.check(identity: identity)
        XCTAssertEqual(result.status, .unverified,
            "GPTK hash mismatch must return .unverified — GPTK updated since cert")
    }

    func testBothHashesMismatched_returnsUnverified() async {
        stubTitle()
        let identity = makeIdentity(
            binary: String(repeating: "aa", count: 32),
            gptk:   String(repeating: "bb", count: 32)
        )
        let service = makeService()
        let result  = await service.check(identity: identity)
        XCTAssertEqual(result.status, .unverified)
    }

    // MARK: - Slug not in manifest

    func testSlugNotInManifest_returnsUnverified() async {
        stubTitle(slug: "different-game")    // title is "different-game", not testSlug
        let service = makeService()
        let result  = await service.check(identity: makeIdentity())  // identity has testSlug
        XCTAssertEqual(result.status, .unverified,
            "Slug not in manifest must return .unverified")
    }

    func testEmptyManifest_returnsUnverified() async {
        factory.stubURLs(titles: [])     // no titles at all
        let service = makeService()
        let result  = await service.check(identity: makeIdentity())
        XCTAssertEqual(result.status, .unverified,
            "Empty manifest must return .unverified (slug not found)")
    }

    // MARK: - Revocation (SECURITY INVARIANT: fires before hash check)

    func testRevokedSlug_withMatchingHashes_returnsRevoked() async {
        // This is the critical security test:
        // Slug is in BOTH revoked_titles AND titles with matching hashes.
        // Revocation MUST fire before hash comparison → result must be .revoked, not .certified.
        stubTitle(status: "certified",
                  revokedSlugs: [.init(slug: testSlug, reason: "Security exploit")])
        let service = makeService()
        let result  = await service.check(identity: makeIdentity())
        XCTAssertEqual(result.status, .revoked,
            "SECURITY: revoked slug must return .revoked even when hashes match — " +
            "revocation gate must fire BEFORE hash comparison")
        XCTAssertNotEqual(result.status, .certified,
            "A revoked title must NEVER return .certified")
    }

    func testRevokedSlug_notInTitles_returnsRevoked() async {
        // Slug is in revoked_titles but not in titles at all
        factory.stubURLs(
            titles: [],
            revokedSlugs: [.init(slug: testSlug)])
        let service = makeService()
        let result  = await service.check(identity: makeIdentity())
        XCTAssertEqual(result.status, .revoked)
    }

    func testRevocation_onlyAffectsMatchingSlug() async {
        // Revoke "other-game", not testSlug
        let spec = TestManifestFactory.ManifestTitleSpec(
            slug: testSlug, binarySHA256: binaryHash,
            gptkSHA256: gptkHash, status: "certified")
        factory.stubURLs(
            titles: [spec],
            revokedSlugs: [.init(slug: "other-game")])
        let service = makeService()
        let result  = await service.check(identity: makeIdentity())
        XCTAssertEqual(result.status, .certified,
            "Revocation of 'other-game' must not affect testSlug")
    }

    func testMultipleRevokedSlugs_onlyMatchingOneRevokes() async {
        let spec = TestManifestFactory.ManifestTitleSpec(
            slug: testSlug, binarySHA256: binaryHash,
            gptkSHA256: gptkHash, status: "certified")
        factory.stubURLs(
            titles: [spec],
            revokedSlugs: [
                .init(slug: "game-a"),
                .init(slug: testSlug),
                .init(slug: "game-b")
            ])
        let service = makeService()
        let result  = await service.check(identity: makeIdentity())
        XCTAssertEqual(result.status, .revoked,
            "testSlug appears in revoked list → must be .revoked")
    }

    // MARK: - Manifest unavailable

    func testManifestNetworkFailure_returnsManifesetUnavailable() async {
        MockURLProtocol.stub(url: ManifestCache.manifestURL,
                             error: URLError(.notConnectedToInternet))
        let service = makeService()
        let result  = await service.check(identity: makeIdentity())
        XCTAssertEqual(result.status, .manifestUnavailable,
            "Network failure must return .manifestUnavailable")
    }

    func testSchema2Manifest_returnsManifesetUnavailable() async {
        // Schema 2 → ManifestCache returns nil → unavailable
        factory.stubURLs(schema: "2.0")
        let service = makeService()
        let result  = await service.check(identity: makeIdentity())
        XCTAssertEqual(result.status, .manifestUnavailable,
            "Unsupported schema → cache returns nil → .manifestUnavailable")
    }

    // MARK: - Result fields populated from manifest

    func testCertifiedResult_identityPreserved() async {
        stubTitle(status: "certified")
        let service  = makeService()
        let identity = makeIdentity()
        let result   = await service.check(identity: identity)
        XCTAssertEqual(result.identity.gameSlug,        identity.gameSlug)
        XCTAssertEqual(result.identity.binarySHA256,    identity.binarySHA256)
        XCTAssertEqual(result.identity.gptkDylibSHA256, identity.gptkDylibSHA256)
    }

    func testCertifiedResult_avgFPS_fromManifest() async {
        let spec = TestManifestFactory.ManifestTitleSpec(
            slug: testSlug, binarySHA256: binaryHash,
            gptkSHA256: gptkHash, status: "certified", avgFPS: 60)
        factory.stubURLs(titles: [spec])
        let service = makeService()
        let result  = await service.check(identity: makeIdentity())
        XCTAssertEqual(result.avgFPS, 60,
            "avgFPS should be populated from manifest performance.fps_target")
    }

    // MARK: - GPTK sentinel

    func testGPTKSentinel_neverMatchesCertified() async {
        // If the identity carries the "not found" sentinel, hashes can never
        // match a real manifest entry → must return .unverified
        let identity = CertificationIdentity(
            gameSlug:        testSlug,
            binarySHA256:    binaryHash,
            gptkDylibSHA256: "gptk-dylib-not-found",
            velocityVersion: "1.0",
            gptkVersion:     "2.0"
        )
        stubTitle(status: "certified")   // manifest has real gptkHash, not the sentinel
        let service = makeService()
        let result  = await service.check(identity: identity)
        XCTAssertNotEqual(result.status, .certified,
            "GPTK sentinel must never match a certified entry — GPTK not installed")
        XCTAssertEqual(result.status, .unverified,
            "Missing GPTK dylib → .unverified (not .certified, not .manifestUnavailable)")
    }

    // MARK: - Unavailable result factories

    func testUnavailableResult_hasCorrectIdentity() async {
        MockURLProtocol.stub(url: ManifestCache.manifestURL,
                             error: URLError(.cannotConnectToHost))
        let identity = makeIdentity()
        let service  = makeService()
        let result   = await service.check(identity: identity)
        XCTAssertEqual(result.identity.gameSlug, identity.gameSlug,
            "Even unavailable results must carry the identity for display purposes")
    }

    func testRevoked_emptyPerformanceFields() async {
        stubTitle(status: "certified",
                  revokedSlugs: [.init(slug: testSlug)])
        let service = makeService()
        let result  = await service.check(identity: makeIdentity())
        // Revoked results use the empty() factory — no performance data
        XCTAssertNil(result.avgFPS)
        XCTAssertNil(result.p1FPS)
        XCTAssertTrue(result.knownIssues.isEmpty)
    }
}
