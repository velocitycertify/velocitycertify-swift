import XCTest
@testable import VelocityCertify

// MARK: - CertificationConcurrencyTests
//
// Concurrency stress tests for VelocityCertify's actor-isolated types.
// These tests live in VelocityCertify (not in Velocity) because they require
// MockURLProtocol — a test helper that is private to VelocityCertify's test target.
//
// Companion file: Velocity's ConcurrencyStressTests.swift contains stress tests
// for Velocity-specific actors (SessionStore, QoECollector, GameLibraryMetadataStore).

final class CertificationConcurrencyTests: XCTestCase {

    override func setUp() async throws {
        try await super.setUp()
        MockURLProtocol.reset()
    }

    override func tearDown() async throws {
        MockURLProtocol.reset()
        try await super.tearDown()
    }

    // MARK: - ManifestCache: 20 concurrent reads on fresh cache

    func testManifestCache_20ConcurrentReads_allReturnNonNil() async {
        let factory = TestManifestFactory()
        var fetchCount = 0
        let manifestData = factory.buildManifest()
        let sig          = factory.sign(manifestData)

        MockURLProtocol.register(url: ManifestCache.manifestURL) { _ in
            fetchCount += 1
            return .success(data: manifestData)
        }
        MockURLProtocol.stub(url: ManifestCache.sigURL, data: sig)

        let cache = ManifestCache(session: MockURLProtocol.makeSession(),
                                  pubkeyPEM: factory.pubkeyPEM)

        let results: [VelocityCertifyManifest?] = await withTaskGroup(
            of: VelocityCertifyManifest?.self,
            returning: [VelocityCertifyManifest?].self
        ) { group in
            for _ in 0..<20 {
                group.addTask { await cache.currentManifest() }
            }
            var out = [VelocityCertifyManifest?]()
            for await r in group { out.append(r) }
            return out
        }

        XCTAssertEqual(results.count, 20, "All 20 concurrent reads must complete")
        XCTAssertTrue(results.allSatisfy { $0 != nil },
            "All 20 concurrent reads must return a non-nil manifest")

        // Actor serializes access — the first waiter fetches, rest return cached value.
        // fetchCount should be 1 (or at most a small number due to actor scheduling).
        // We allow up to 3 to account for the actor not having cached before all tasks start.
        XCTAssertLessThanOrEqual(fetchCount, 3,
            "Concurrent reads must not each trigger a separate network fetch (actor coalesces)")
    }

    // MARK: - CertificationService: 20 concurrent check() for same identity

    func testCertificationService_20ConcurrentChecks_allReturnCertified() async {
        let factory  = TestManifestFactory()
        let slug     = "hades-2"
        let binHash  = String(repeating: "a1", count: 32)
        let gptkH    = String(repeating: "b2", count: 32)

        let spec = TestManifestFactory.ManifestTitleSpec(
            slug: slug, binarySHA256: binHash,
            gptkSHA256: gptkH, status: "certified")
        factory.stubURLs(titles: [spec])

        let cache   = ManifestCache(session: MockURLProtocol.makeSession(),
                                    pubkeyPEM: factory.pubkeyPEM)
        let service = CertificationService(cache: cache)
        let identity = CertificationIdentity(
            gameSlug: slug, binarySHA256: binHash,
            gptkDylibSHA256: gptkH, velocityVersion: "1.0", gptkVersion: "2.0")

        let results: [CertificationStatus] = await withTaskGroup(
            of: CertificationStatus.self,
            returning: [CertificationStatus].self
        ) { group in
            for _ in 0..<20 {
                group.addTask { await service.check(identity: identity).status }
            }
            var out = [CertificationStatus]()
            for await r in group { out.append(r) }
            return out
        }

        XCTAssertEqual(results.count, 20)
        XCTAssertTrue(results.allSatisfy { $0 == .certified },
            "20 concurrent check() calls must all return .certified — no interleaving bug")
    }
}
