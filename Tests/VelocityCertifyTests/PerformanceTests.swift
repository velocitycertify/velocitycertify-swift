import XCTest
@testable import VelocityCertify

// MARK: - VelocityCertify Performance Baselines
//
// XCTMetric baselines for the VelocityCertify trust layer running on Apple Silicon.
// These tests establish what "fast enough" means for the certification path —
// independent of any application that consumes VelocityCertify.
//
// If any of these baselines regress, the certification check has become too slow
// to be embedded in a game launcher's startup path without blocking the UI.
//
// All tests run on Apple Silicon (arm64). Results on Intel are informational only.
//
// What's NOT baselined here:
//   — Network latency to velocitycertify.com (network is mocked in NetworkTests)
//   — UI rendering time (that belongs to the consuming app's test suite)
//   — Game process launch time (belongs to Velocity's WineProcessIntegrationTests)

final class VelocityCertifyPerformanceTests: XCTestCase {

    private var factory: TestManifestFactory!

    override func setUp() async throws {
        try await super.setUp()
        factory = TestManifestFactory()
        let (manifest, sig) = factory.buildAndSign(
            titles: (0..<100).map { .init(slug: "game-\($0)", status: "certified") },
            revokedSlugs: [])
        MockURLProtocol.stub(url: ManifestCache.manifestURL, data: manifest, statusCode: 200)
        MockURLProtocol.stub(url: ManifestCache.sigURL,      data: sig,      statusCode: 200)
    }

    override func tearDown() async throws {
        MockURLProtocol.reset()
        factory = nil
        try await super.tearDown()
    }

    // MARK: - Manifest verification

    func testPerf_ed25519Verify_50iterations() throws {
        // Ed25519 signature verification is the innermost trust operation.
        // On M1: ~0.3ms per verify. Regression threshold: 5ms.
        let (manifest, sig) = factory.buildAndSign(
            titles: [.init(slug: "hades-2", status: "certified")],
            revokedSlugs: [])

        let options = XCTMeasureOptions()
        options.iterationCount = 50

        measure(metrics: [XCTClockMetric()], options: options) {
            // Verify the signature synchronously (mirrors ManifestCache.verifyEd25519 path)
            let pubkeyPEM = factory.pubkeyPEM
            let keyLines  = pubkeyPEM
                .components(separatedBy: "\n")
                .filter { !$0.hasPrefix("-----") && !$0.isEmpty }
            let derData   = Data(base64Encoded: keyLines.joined()) ?? Data()
            let rawKey    = derData.dropFirst(12)
            guard let pubkey = try? Curve25519.Signing.PublicKey(rawRepresentation: rawKey) else {
                XCTFail("Could not reconstruct public key"); return
            }
            let valid = pubkey.isValidSignature(sig, for: manifest)
            XCTAssertTrue(valid)
        }
    }

    func testPerf_sha256_4KB() {
        // SHA-256 of a 4 KB buffer — typical game .exe chunk size during hashing.
        let data = Data(repeating: 0xAB, count: 4096)
        let options = XCTMeasureOptions()
        options.iterationCount = 100

        measure(metrics: [XCTClockMetric()], options: options) {
            _ = SHA256.hash(data: data)
        }
    }

    func testPerf_sha256_512MB() throws {
        // SHA-256 of a 512 MB buffer — hashing a large game binary.
        // On M1: ~400ms. Regression threshold: 2s.
        let data = Data(repeating: 0xFF, count: 512 * 1024 * 1024)
        let options = XCTMeasureOptions()
        options.iterationCount = 3

        measure(metrics: [XCTClockMetric(), XCTMemoryMetric()], options: options) {
            _ = SHA256.hash(data: data)
        }
    }

    // MARK: - ManifestCache warm-path

    func testPerf_check_warmCache_10iterations() throws {
        // check() against a warm (already-fetched) cache.
        // This is the hot path on every game launch.
        // On M1: ~0.1ms. Regression threshold: 5ms.
        let cache   = ManifestCache(session: MockURLProtocol.makeSession(),
                                    pubkeyPEM: factory.pubkeyPEM, ttl: 3600)
        let service = CertificationService(cache: cache)
        let identity = CertificationIdentity(
            slug:         "game-42",
            gpuFamily:    "apple7",
            gpuHash:      String(repeating: "a", count: 64),
            gptkHash:     String(repeating: "b", count: 64),
            wineHash:     String(repeating: "c", count: 64),
            macOSVersion: "14.0")

        // Warm the cache first
        let warmExp = expectation(description: "warm")
        Task {
            _ = await service.check(identity: identity)
            warmExp.fulfill()
        }
        wait(for: [warmExp], timeout: 10)

        let options = XCTMeasureOptions()
        options.iterationCount = 10

        measure(metrics: [XCTClockMetric()], options: options) {
            let exp = expectation(description: "check")
            Task {
                _ = await service.check(identity: identity)
                exp.fulfill()
            }
            wait(for: [exp], timeout: 5)
        }
    }

    // MARK: - JSON decode

    func testPerf_jsonDecode_100titles() throws {
        // Decode a manifest with 100 title entries — typical manifest size at launch.
        let (manifest, _) = factory.buildAndSign(
            titles: (0..<100).map { .init(slug: "game-\($0)", status: "certified") },
            revokedSlugs: [])

        let options = XCTMeasureOptions()
        options.iterationCount = 20

        measure(metrics: [XCTClockMetric()], options: options) {
            _ = try? JSONDecoder().decode(VelocityCertifyManifest.self, from: manifest)
        }
    }
}
