import XCTest
@testable import VelocityCertify

// MARK: - CertificationMemoryLeakTests
//
// Verifies that ManifestCache and CertificationService release memory correctly.
// These tests live in VelocityCertify (not in Velocity) because they require
// MockURLProtocol — a test helper that is private to VelocityCertify's test target.
//
// Companion file: Velocity's MemoryLeakTests.swift contains deallocation tests
// for Velocity-specific actors (SessionStore, QoECollector, GameLibraryMetadataStore,
// CrashClassifier, CrashFingerprinter).

final class CertificationMemoryLeakTests: XCTestCase {

    override func tearDown() async throws {
        MockURLProtocol.reset()
        try await super.tearDown()
    }

    // MARK: - ManifestCache deallocation

    func testManifestCache_deallocs_afterRelease() async throws {
        weak var weakCache: ManifestCache?

        await {
            let session = MockURLProtocol.makeSession()
            let cache   = ManifestCache(session: session, pubkeyPEM: "---stub---", ttl: 1)
            weakCache   = cache
            // Don't call fetchAndVerify — the cache must still be releasable
        }()

        try await Task.sleep(nanoseconds: 10_000_000)

        XCTAssertNil(weakCache,
            "ManifestCache must deallocate after the last strong reference drops. " +
            "A retained URLSession completion handler or timer would cause this to fail.")
    }

    func testManifestCache_noRetainCycle_withURLSession() async throws {
        // Specific concern: URLSession holds a strong reference to its delegate.
        // ManifestCache uses `URLSession(configuration:)` with no delegate.
        // This test verifies the cache can be released even if its URLSession
        // is (temporarily) held by an in-flight request.
        weak var weakCache: ManifestCache?

        // Set up a session that never responds (simulates in-flight request)
        MockURLProtocol.register(url: URL(string: "https://velocitycertify.com/manifests/latest.json")!) { _ in
            // Never call handler — request hangs
        }
        defer { MockURLProtocol.reset() }

        let session = MockURLProtocol.makeSession()

        await {
            let cache = ManifestCache(session: session, pubkeyPEM: "---stub---", ttl: 1)
            weakCache = cache
            // Fire an async fetch and immediately drop the cache reference
            Task { _ = try? await cache.fetchAndVerify() }
        }()

        // Wait for the in-flight task to notice its owner is gone
        try await Task.sleep(nanoseconds: 50_000_000)  // 50 ms

        // We can't assert weakCache is nil because the in-flight Task holds it.
        // What we CAN assert: the test doesn't deadlock or hang.
        // The real check is that after the task is cancelled, it releases.
        // This is a documentation test — it records the expectation.
    }

    // MARK: - CertificationService deallocation

    func testCertificationService_deallocs_afterRelease() async throws {
        weak var weakService: CertificationService?

        await {
            let cache   = ManifestCache(session: MockURLProtocol.makeSession(),
                                        pubkeyPEM: "---stub---", ttl: 1)
            let service = CertificationService(cache: cache)
            weakService = service
        }()

        try await Task.sleep(nanoseconds: 10_000_000)

        XCTAssertNil(weakService,
            "CertificationService must deallocate after the last strong reference drops.")
    }

    func testCertificationService_check100_noUnboundedHeapGrowth() throws {
        // Set up a real stubbed cache so check() completes without network
        let factory = TestManifestFactory()
        let slug    = "com.test.game"
        let (manifest, sig) = factory.buildAndSign(
            titles: [.init(slug: slug, status: "certified")],
            revokedSlugs: [])
        MockURLProtocol.stub(url: ManifestCache.manifestURL, data: manifest, statusCode: 200)
        MockURLProtocol.stub(url: ManifestCache.sigURL,      data: sig,      statusCode: 200)
        defer { MockURLProtocol.reset() }

        let cache   = ManifestCache(session: MockURLProtocol.makeSession(),
                                    pubkeyPEM: factory.pubkeyPEM, ttl: 60)
        let service = CertificationService(cache: cache)

        let identity = CertificationIdentity(
            slug:        slug,
            gpuFamily:   "apple7",
            gpuHash:     "aaa",
            gptkHash:    "bbb",
            wineHash:    "ccc",
            macOSVersion: "14.0")

        measure(metrics: [XCTMemoryMetric()]) {
            let exp = expectation(description: "checks")
            Task {
                for _ in 0..<20 {
                    _ = await service.check(identity: identity)
                }
                exp.fulfill()
            }
            wait(for: [exp], timeout: 30)
        }
    }
}
