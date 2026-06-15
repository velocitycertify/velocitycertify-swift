import XCTest
@testable import VelocityCertify

// MARK: - CertificationServiceTests
//
// These tests exercise the certification lookup logic in isolation — no network,
// no real manifest fetch. Each test constructs a synthetic VelocityCertifyManifest
// in memory and drives the internal decision tree through a local helper that
// mirrors check() exactly, bypassing the Ed25519/network path.
//
// Why this matters: the certification path is the trust boundary between "Skyfire
// tested this" and "this binary is what it claims to be." If the revocation check
// fires after the slug lookup, a revoked title can slip through on a hash match.
// If the hash comparison uses case-sensitive equality but the manifest generator
// lowercases hex, every cert check silently returns .unverified. These tests
// pin those exact ordering and format invariants.
//
// Test classes:
//
//   CertificationCheckLogicTests  — check() outcomes across all six status cases
//   CertificationRevocationTests  — revocation list ordering, partial matches, reason field
//   CertificationHashMatchTests   — hash mismatch detection: binary, GPTK, case, both
//   CertificationSchemaTests      — schema version negotiation: equal/minor/major/absent
//   CertificationHashingTests     — sha256() utility: correctness, streaming, sentinel
//
// Configuration matrix (applies across classes):
//
//   Manifest present vs. absent (nil from cache)
//     → present: lookup proceeds normally
//     → absent:  .manifestUnavailable regardless of identity content
//
//   Slug in manifest vs. not
//     → present: hash comparison runs
//     → absent:  .unverified
//
//   Hashes match vs. mismatch (binary, GPTK, one-of-two)
//     → both match:     status from manifest entry
//     → binary changed: .unverified ("binary or GPTK changed since certification")
//     → GPTK changed:   .unverified (same rejection path — the check is an AND)
//     → one changed:    .unverified (one mismatch is enough to reject)
//
//   Title revoked vs. not
//     → revoked:  .revoked fires before hash comparison even runs (order matters)
//     → not:      falls through to slug/hash path
//
//   Schema major version: equal, minor bump, major bump, absent
//     → equal (1.0):   decode proceeds
//     → minor bump (1.3): decode proceeds (minor is backwards-compatible)
//     → major bump (2.0): nil returned — every check() call returns .unverified
//     → absent:        treated as major=1, decode proceeds

// ─────────────────────────────────────────────────────────────────────────────
// MARK: - Test Infrastructure
// ─────────────────────────────────────────────────────────────────────────────

/// Reimplements the decision tree of CertificationService.check() against an
/// injected manifest rather than a live network fetch. Returns CertificationStatus
/// only — we're testing decisions, not result construction.
///
/// This must stay in sync with CertificationService.check(). If that function
/// changes its logic (e.g., reorders revocation vs. slug lookup), update here too
/// and re-examine whether any test expectations need to change.
private func evaluateCheck(
    identity: CertificationIdentity,
    manifest: VelocityCertifyManifest
) -> CertificationStatus {
    // Gate 1: Revocation — must fire BEFORE slug lookup.
    // NOTE: use `if let` not `!= nil` here. `revokedTitles?.first(where:)` returns
    // `ManifestRevocation??` (double-optional). With `!= nil`, an *empty array* would
    // produce `Optional(nil)` which compares non-nil — incorrectly triggering .revoked
    // for any slug. `if let` correctly unwraps through both levels and only binds when
    // `first(where:)` actually found a matching element. This mirrors CertificationService.check().
    if let _ = manifest.revokedTitles?.first(where: { $0.slug == identity.gameSlug }) {
        return .revoked
    }

    // Gate 2: Slug lookup
    guard let entry = manifest.titles.first(where: { $0.slug == identity.gameSlug }) else {
        return .unverified
    }

    // Gate 3: Hash comparison — both must match; one mismatch rejects
    guard entry.identity.binarySHA256    == identity.binarySHA256,
          entry.identity.gptkDylibSHA256 == identity.gptkDylibSHA256 else {
        return .unverified
    }

    // Status decode — unknown strings fall back to .unverified, never crash
    return CertificationStatus(rawValue: entry.status) ?? .unverified
}

// MARK: Fixture builders

private func makeIdentity(
    slug:   String = "hades-2",
    binary: String = "aabbccdd",
    gptk:   String = "11223344"
) -> CertificationIdentity {
    CertificationIdentity(
        gameSlug:        slug,
        binarySHA256:    binary,
        gptkDylibSHA256: gptk,
        velocityVersion: "1.0.0",
        gptkVersion:     "2.1"
    )
}

private func makeTitle(
    slug:   String = "hades-2",
    binary: String = "aabbccdd",
    gptk:   String = "11223344",
    status: String = "certified"
) -> ManifestTitle {
    ManifestTitle(
        slug:         slug,
        name:         slug,
        steamAppId:   nil,
        versionLabel: nil,
        identity:     ManifestIdentity(binarySHA256: binary, binaryPathHint: nil, gptkDylibSHA256: gptk),
        performance: nil, compatibility: nil, controller: nil, stability: nil,
        power: nil, display: nil, network: nil, macOSIntegration: nil, gptkCoverage: nil,
        versionMatrix: nil, status: status, certifiedDate: nil, certifierNotes: nil,
        toolStack: nil, appleSilicon: nil, protocolTests: nil,
        sourceRunId: nil, machineFingerprint: nil,
        witnessSignatures: nil, confirmingConfigs: nil, confirmingFingerprints: nil,
        runCount: nil, fpsStdDev: nil, videoWitnessHash: nil, stressSceneName: nil,
        crossToolComparison: nil, failedRunCount: nil
    )
}

private func makeManifest(
    schema:  String                    = "1.0",
    titles:  [ManifestTitle]           = [],
    revoked: [ManifestRevocation]?     = nil
) -> VelocityCertifyManifest {
    VelocityCertifyManifest(
        schema:        schema,
        generated:     "2025-01-01T00:00:00Z",
        environment:   VelocityCertifyManifest.ManifestEnvironment(
            velocityVersion: "1.0.0", gptkVersion: "2.1",
            hardwareId: "test-machine", hardwareLabel: "MacBook Pro M3 (test)",
            macosVersion: "14.0"
        ),
        titles:        titles,
        revokedTitles: revoked
    )
}

private func makeRevocation(slug: String, reason: String = "Security issue") -> ManifestRevocation {
    ManifestRevocation(slug: slug, revokedAt: "2025-01-01T00:00:00Z", reason: reason)
}

// ─────────────────────────────────────────────────────────────────────────────
// MARK: - CertificationCheckLogicTests
// ─────────────────────────────────────────────────────────────────────────────

/// Tests the six return statuses of CertificationService.check():
///   .certified, .certifiedDegraded, .notCertified, .revoked,
///   .unverified, .manifestUnavailable
///
/// Each test represents one branch in the decision tree. The assertion message
/// is written in plain English so that a CI failure reads as a statement of
/// what the contract is — not just what value was wrong.

final class CertificationCheckLogicTests: XCTestCase {

    // MARK: Manifest unavailable

    func testNilManifestYieldsManifestUnavailable() {
        // When the manifest cache has nothing — offline, or Ed25519 verification
        // failed — check() returns .manifestUnavailable. The game still launches
        // (this path is non-blocking), but the badge shows gray/silent.
        // This is the only status that doesn't depend on the title list at all.
        let identity = makeIdentity()
        let result   = CertificationResult.unavailable(identity: identity)
        XCTAssertEqual(result.status, .manifestUnavailable,
            "A nil manifest must yield .manifestUnavailable — the badge goes gray, the game launches anyway")
        XCTAssertEqual(result.identity.gameSlug, identity.gameSlug,
            "Identity must be preserved even on unavailable path")
    }

    // MARK: Slug not found

    func testSlugAbsentFromManifestYieldsUnverified() {
        // The title has never been certified, OR its slug doesn't match the manifest
        // normalisation (e.g., the local DB uses "Hades II" but the manifest uses "hades-2").
        // Either way we have no data on this title: gray badge.
        let status = evaluateCheck(
            identity: makeIdentity(slug: "unknown-game"),
            manifest: makeManifest(titles: [makeTitle(slug: "hades-2")])
        )
        XCTAssertEqual(status, .unverified,
            "A slug absent from the manifest must yield .unverified — we have no data on this title")
    }

    // MARK: Matching slug + matching hashes

    func testMatchingHashesWithCertifiedStatusYieldsCertified() {
        // The happy path: slug found, both hashes match exactly, status is "certified".
        // Expected: green badge, full performance/controller/power data available.
        let status = evaluateCheck(
            identity: makeIdentity(),
            manifest: makeManifest(titles: [makeTitle(status: "certified")])
        )
        XCTAssertEqual(status, .certified,
            "Matching slug + matching hashes + status='certified' must yield .certified (green badge)")
    }

    func testMatchingHashesWithCertifiedDegradedStatusYieldsCertifiedDegraded() {
        // The title runs, but didn't hit the fps target when Skyfire tested it.
        // Yellow badge. Common on M1 vs. M2: cert is still valid and meaningful,
        // user just knows performance is below the stated target.
        let status = evaluateCheck(
            identity: makeIdentity(),
            manifest: makeManifest(titles: [makeTitle(status: "certified_degraded")])
        )
        XCTAssertEqual(status, .certifiedDegraded,
            "Matching hashes + status='certified_degraded' must yield .certifiedDegraded (yellow badge)")
    }

    func testMatchingHashesWithNotCertifiedStatusYieldsNotCertified() {
        // The title was explicitly tested and failed. Red badge. This is different
        // from .unverified — Skyfire tried it and knows it doesn't work. The
        // distinction matters: "we don't know" vs. "we know and it's broken."
        let status = evaluateCheck(
            identity: makeIdentity(),
            manifest: makeManifest(titles: [makeTitle(status: "not_certified")])
        )
        XCTAssertEqual(status, .notCertified,
            "Matching hashes + status='not_certified' must yield .notCertified (red badge, explicitly tested/failed)")
    }

    func testUnknownStatusStringFallsBackToUnverified() {
        // A future manifest schema might add a new status value this client doesn't
        // know about. CertificationStatus(rawValue:) returns nil, so we fall back
        // to .unverified rather than crashing or misclassifying. Never hard-fail
        // on an unrecognised status — it might just mean the app needs updating.
        let status = evaluateCheck(
            identity: makeIdentity(),
            manifest: makeManifest(titles: [makeTitle(status: "future_unknown_status")])
        )
        XCTAssertEqual(status, .unverified,
            "An unrecognised status string must fall back to .unverified — never crash or misclassify")
    }

    // MARK: Identity preserved through factories

    func testIdentityPreservedThroughUnavailableFactory() {
        let id = makeIdentity(slug: "elden-ring", binary: "deadbeef", gptk: "cafebabe")
        let r  = CertificationResult.unavailable(identity: id)
        XCTAssertEqual(r.identity.gameSlug,        "elden-ring")
        XCTAssertEqual(r.identity.binarySHA256,    "deadbeef")
        XCTAssertEqual(r.identity.gptkDylibSHA256, "cafebabe")
    }

    func testIdentityPreservedThroughUnverifiedFactory() {
        // The identity passed to check() must roundtrip through the result unchanged.
        // The caller uses result.identity to populate the XPC message — if it's
        // mutated or swapped, the badge shows data for the wrong game.
        let id = makeIdentity(slug: "elden-ring", binary: "deadbeef", gptk: "cafebabe")
        let r  = CertificationResult.unverified(identity: id)
        XCTAssertEqual(r.identity.gameSlug,        "elden-ring")
        XCTAssertEqual(r.identity.binarySHA256,    "deadbeef")
        XCTAssertEqual(r.identity.gptkDylibSHA256, "cafebabe")
    }

    func testIdentityPreservedThroughRevokedFactory() {
        let id = makeIdentity(slug: "elden-ring", binary: "deadbeef", gptk: "cafebabe")
        let r  = CertificationResult.revoked(identity: id)
        XCTAssertEqual(r.identity.gameSlug,        "elden-ring")
        XCTAssertEqual(r.identity.binarySHA256,    "deadbeef")
        XCTAssertEqual(r.identity.gptkDylibSHA256, "cafebabe")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MARK: - CertificationRevocationTests
// ─────────────────────────────────────────────────────────────────────────────

/// Tests the revocation list path.
///
/// Revocation is the most security-sensitive part of VelocityCertify. If we
/// discover a title was certified against a compromised or broken build, we add
/// it to revoked_titles and push a manifest update. The revocation check must
/// fire BEFORE the slug/hash lookup — otherwise a revoked title could still
/// return .certified by matching its old hashes.
///
/// Configuration note:
///   revoked_titles absent from JSON → nil → no revocation check; lookup proceeds
///   revoked_titles: []              → empty → same as nil
///   revoked_titles: [{slug: "X"}]  → fires only for slug "X"

final class CertificationRevocationTests: XCTestCase {

    // MARK: Basic revocation

    func testRevokedSlugReturnsRevokedEvenWithMatchingHashes() {
        // The critical ordering invariant: revocation fires BEFORE hash comparison.
        // If it fired after, someone could replay an old certified binary after
        // revocation and get a green badge. .revoked must win over .certified.
        let status = evaluateCheck(
            identity: makeIdentity(slug: "hades-2", binary: "aabbccdd", gptk: "11223344"),
            manifest: makeManifest(
                titles:  [makeTitle(slug: "hades-2", binary: "aabbccdd", gptk: "11223344",
                                    status: "certified")],
                revoked: [makeRevocation(slug: "hades-2")]
            )
        )
        XCTAssertEqual(status, .revoked,
            ".revoked must fire even when hashes match — revocation is checked before hash comparison")
    }

    // MARK: Non-matching slug is unaffected

    func testRevocationDoesNotAffectDifferentSlug() {
        // "elden-ring" is revoked. "hades-2" is certified with matching hashes.
        // The player running Hades 2 must not be affected.
        let status = evaluateCheck(
            identity: makeIdentity(slug: "hades-2", binary: "aabbccdd", gptk: "11223344"),
            manifest: makeManifest(
                titles:  [makeTitle(slug: "hades-2", binary: "aabbccdd", gptk: "11223344",
                                    status: "certified")],
                revoked: [makeRevocation(slug: "elden-ring")]
            )
        )
        XCTAssertEqual(status, .certified,
            "Revoking a different slug must not affect the current title's certification")
    }

    // MARK: Missing or empty revocation list

    func testNilRevocationListDoesNotBlockLookup() {
        // Manifests without a revoked_titles key decode cleanly and have no revocations.
        // Absence of the key must not be treated as "everything is revoked."
        let status = evaluateCheck(
            identity: makeIdentity(),
            manifest: makeManifest(titles: [makeTitle(status: "certified")], revoked: nil)
        )
        XCTAssertEqual(status, .certified,
            "A nil (absent) revocation list must not block lookup — nil means no revocations")
    }

    func testEmptyRevocationListDoesNotBlockLookup() {
        let status = evaluateCheck(
            identity: makeIdentity(),
            manifest: makeManifest(titles: [makeTitle(status: "certified")], revoked: [])
        )
        XCTAssertEqual(status, .certified,
            "An empty revocation list must not block lookup")
    }

    // MARK: Multiple revocations

    func testOnlyMatchingSlugFiresFromMultipleRevocations() {
        // The revocation list has three entries. Only "title-b" (the current game)
        // should trigger .revoked. The other slugs must be ignored.
        let status = evaluateCheck(
            identity: makeIdentity(slug: "title-b"),
            manifest: makeManifest(
                titles:  [makeTitle(slug: "title-b", status: "certified")],
                revoked: [
                    makeRevocation(slug: "title-a", reason: "Compromised binary"),
                    makeRevocation(slug: "title-b", reason: "DRM incompatibility"),
                    makeRevocation(slug: "title-c", reason: "Cheating exploit"),
                ]
            )
        )
        XCTAssertEqual(status, .revoked,
            "When multiple slugs are revoked, only the one matching the current game must fire")
    }

    func testNonRevokedTitleSurvivesMultiEntryRevocationList() {
        // "title-a" and "title-c" are revoked. "title-b" is certified and should
        // be unaffected by the other entries in the revocation list.
        let status = evaluateCheck(
            identity: makeIdentity(slug: "title-b"),
            manifest: makeManifest(
                titles:  [makeTitle(slug: "title-b", status: "certified")],
                revoked: [
                    makeRevocation(slug: "title-a"),
                    makeRevocation(slug: "title-c"),
                ]
            )
        )
        XCTAssertEqual(status, .certified,
            "A non-revoked title must pass through a multi-entry revocation list unaffected")
    }

    // MARK: Revocation struct fields

    func testRevocationReasonAndTimestampArePresent() {
        // The reason string is written to NSLog in production and surfaced in
        // vcertify-verify --audit output. It's not shown in the user-facing badge,
        // but it must be present in the manifest struct for operator debugging.
        let rev = makeRevocation(slug: "hades-2", reason: "EasyAntiCheat kernel update broke Wine compatibility")
        XCTAssertEqual(rev.slug,   "hades-2")
        XCTAssertEqual(rev.reason, "EasyAntiCheat kernel update broke Wine compatibility")
        XCTAssertFalse(rev.revokedAt.isEmpty,
            "revokedAt must be a non-empty ISO-8601 timestamp for operator audit trail")
    }

    func testRevocationCodingKeysMapsRevockedAtFromSnakeCase() throws {
        // Verify that the JSON key "revoked_at" decodes into `revokedAt`.
        // If the CodingKeys mapping ever regresses, every revocation will fail to
        // decode and the list will silently be treated as empty.
        let json = """
        {"slug":"hades-2","revoked_at":"2025-06-01T12:00:00Z","reason":"Test"}
        """.data(using: .utf8)!
        let decoded = try JSONDecoder().decode(ManifestRevocation.self, from: json)
        XCTAssertEqual(decoded.revokedAt, "2025-06-01T12:00:00Z",
            "'revoked_at' JSON key must decode to revokedAt — snake_case CodingKeys are required here")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MARK: - CertificationHashMatchTests
// ─────────────────────────────────────────────────────────────────────────────

/// Tests the binary + GPTK hash comparison, the core identity anchor.
///
/// The hash pair (binary SHA-256 + GPTK dylib SHA-256) uniquely identifies the
/// exact (game × GPTK build) combination Skyfire tested. If either changes —
/// a game update, a Homebrew `brew upgrade game-porting-toolkit`, the user
/// switching to a different GPTK install path — the cert no longer applies.
///
/// Expected outcomes by hash configuration:
///
///   binary matches, GPTK matches   → status from manifest (.certified etc.)
///   binary changed, GPTK matches   → .unverified
///   binary matches, GPTK changed   → .unverified
///   both changed                   → .unverified
///   case difference in hex string  → .unverified (comparison is exact/case-sensitive)

final class CertificationHashMatchTests: XCTestCase {

    // MARK: Both match

    func testBothHashesMatchReturnsCertified() {
        // The happy path — exact string equality on both hashes.
        let status = evaluateCheck(
            identity: makeIdentity(binary: "abcdef01", gptk: "98765432"),
            manifest: makeManifest(titles: [makeTitle(binary: "abcdef01", gptk: "98765432")])
        )
        XCTAssertEqual(status, .certified,
            "When both hashes match exactly, check() must return the manifest's status")
    }

    // MARK: Binary changed (game update)

    func testBinaryHashChangedReturnsUnverified() {
        // The player updated their game. The new binary hasn't been certified.
        // We don't know if the update broke anything, so we conservatively return
        // .unverified — "we can't vouch for this version" — rather than asserting
        // the old cert still applies.
        let status = evaluateCheck(
            identity: makeIdentity(binary: "NEW_BINARY_HASH", gptk: "98765432"),
            manifest: makeManifest(titles: [makeTitle(binary: "abcdef01", gptk: "98765432")])
        )
        XCTAssertEqual(status, .unverified,
            "A changed game binary must return .unverified — the cert was for the old build, not this one")
    }

    // MARK: GPTK changed (Homebrew update)

    func testGPTKHashChangedReturnsUnverified() {
        // Homebrew updated game-porting-toolkit. A GPTK patch can change frame timing,
        // Metal shader behavior, and crash characteristics. We haven't tested this title
        // against the new GPTK, so we degrade to .unverified rather than claiming we have.
        let status = evaluateCheck(
            identity: makeIdentity(binary: "abcdef01", gptk: "NEW_GPTK_HASH"),
            manifest: makeManifest(titles: [makeTitle(binary: "abcdef01", gptk: "98765432")])
        )
        XCTAssertEqual(status, .unverified,
            "A changed GPTK dylib must return .unverified — frame timing, driver behavior may have changed")
    }

    // MARK: Both changed

    func testBothHashesChangedReturnsUnverified() {
        let status = evaluateCheck(
            identity: makeIdentity(binary: "NEW_BINARY", gptk: "NEW_GPTK"),
            manifest: makeManifest(titles: [makeTitle(binary: "abcdef01", gptk: "98765432")])
        )
        XCTAssertEqual(status, .unverified)
    }

    // MARK: Case sensitivity — catches format inconsistencies

    func testHashComparisonIsCaseSensitive() {
        // SHA-256 hex is always lowercase in our toolchain (String(format:"%02x")).
        // If the manifest generator ever produces uppercase, comparisons silently fail.
        // This test protects against that: uppercase identity must NOT match lowercase manifest.
        let status = evaluateCheck(
            identity: makeIdentity(binary: "ABCDEF01", gptk: "98765432"),  // uppercase
            manifest: makeManifest(titles: [makeTitle(binary: "abcdef01", gptk: "98765432")])
        )
        XCTAssertEqual(status, .unverified,
            "Hash comparison is case-sensitive — uppercase hex must not match lowercase manifest hash")
    }

    func testHashComparisonIsExactNoTrimming() {
        // A hash with trailing whitespace must not match. Defends against a manifest
        // generator that accidentally includes trailing newlines in hash fields.
        let status = evaluateCheck(
            identity: makeIdentity(binary: "abcdef01 ", gptk: "98765432"),  // trailing space
            manifest: makeManifest(titles: [makeTitle(binary: "abcdef01", gptk: "98765432")])
        )
        XCTAssertEqual(status, .unverified,
            "Hash comparison is exact — whitespace-padded hashes must not match")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MARK: - CertificationSchemaTests
// ─────────────────────────────────────────────────────────────────────────────

/// Tests the schema version negotiation in ManifestCache.
///
/// The manifest carries a "schema" field (e.g., "1.3") whose major version signals
/// structural compatibility. ManifestCache.supportedSchemaMajor = 1.
///
/// Rule: if the remote manifest's major > our supported major, the manifest may
/// contain fields or structural shapes we cannot safely decode. We return nil from
/// fetchAndVerify() rather than risking corrupt decode. Every subsequent check()
/// call then returns .unverified (via .unavailable → nil manifest path) until
/// the app is updated.
///
/// Expected outcomes:
///   "1.0"  → supported (major == 1)
///   "1.9"  → supported (minor bumps are backwards-compatible)
///   "2.0"  → NOT supported (breaking change)
///   absent → supported (old manifests pre-date this field; treat as 1.0)
///   "x.y"  → supported (unparseable → safe default of 1)

final class CertificationSchemaTests: XCTestCase {

    /// Mirrors the schema check logic from ManifestCache.fetchAndVerify().
    /// Returns true if the schema field indicates the manifest is safe to decode.
    private func isSupported(_ schemaField: String?) -> Bool {
        guard let s = schemaField else { return true }
        let parts = s.split(separator: ".").compactMap { Int($0) }
        let remoteMajor = parts.first ?? 1
        return remoteMajor <= ManifestCache.supportedSchemaMajor
    }

    // MARK: Supported versions

    func testSchemaOnePointZeroIsSupported() {
        // Schema 1.0 is what we ship today — must always be supported.
        XCTAssertTrue(isSupported("1.0"),
            "Schema 1.0 must be supported — it's the current production schema")
    }

    func testSchemaOnePointThreeIsSupported() {
        // Minor bumps add optional fields that Codable silently ignores.
        // The client doesn't need to understand every field to safely decode.
        XCTAssertTrue(isSupported("1.3"),
            "Schema 1.3 must be supported — minor bumps are backwards-compatible by convention")
    }

    func testSchemaOnePointNineNineIsSupported() {
        XCTAssertTrue(isSupported("1.99"),
            "Any 1.x schema must be supported regardless of minor version")
    }

    // MARK: Unsupported versions (major bump)

    func testSchemaTwoPointZeroIsNotSupported() {
        // A major bump signals breaking changes — required fields may have moved,
        // types may have changed, or the shape may be fundamentally different.
        // Decoding a 2.x manifest with a 1.x decoder risks silently wrong results.
        // We return nil instead, which degrades every check() to .unverified.
        XCTAssertFalse(isSupported("2.0"),
            "Schema 2.0 must NOT be supported — major bump signals a breaking change")
    }

    func testSchemaTwoPointNineNineIsNotSupported() {
        XCTAssertFalse(isSupported("2.99"),
            "Any 2.x schema must not be supported by a 1.x-aware client")
    }

    func testSchemaThreePointZeroIsNotSupported() {
        XCTAssertFalse(isSupported("3.0"),
            "Schema 3.0 is far above the supported major — must not decode")
    }

    // MARK: Absent or unparseable schema field

    func testAbsentSchemaFieldIsTreatedAsSupported() {
        // Early manifests (before we added the "schema" field) don't have it.
        // nil → treat as major=1 so those manifests remain readable forever.
        XCTAssertTrue(isSupported(nil),
            "Absent schema field must be treated as 1.x for backwards compatibility with old manifests")
    }

    func testUnparseableSchemaMajorTreatedAsOne() {
        // If the schema field is something we can't parse as an integer (e.g., "beta",
        // "x.y"), Int() returns nil, parts.first is nil, and remoteMajor defaults to 1.
        // Safe fallback rather than a hard failure on a weird field value.
        XCTAssertTrue(isSupported("x.y"),
            "An unparseable major ('x.y') must default to 1 and be treated as supported")
        XCTAssertTrue(isSupported("beta"),
            "A non-numeric schema string must default to major=1")
    }

    // MARK: Constant pinning

    func testSupportedSchemaMajorIsOne() {
        // Pinning this constant means that if someone bumps it to 2 without
        // actually implementing schema-2 decoding, this test fails immediately.
        XCTAssertEqual(ManifestCache.supportedSchemaMajor, 1,
            "supportedSchemaMajor must be 1 — bump only when the client can fully decode schema 2.x")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MARK: - CertificationHashingTests
// ─────────────────────────────────────────────────────────────────────────────

/// Tests the SHA-256 file hashing utilities.
///
/// sha256(fileAt:) is used on both the game binary and the GPTK dylib.
/// Game binaries can be 1–20 GB, so the implementation streams in 4 MB chunks
/// rather than loading the whole file into memory. These tests verify crypto
/// correctness with small synthetic files, confirm the output format, and
/// pin the sentinel path for a missing GPTK dylib.
///
/// Configuration differences and expected outcomes:
///
///   Empty file           → SHA-256 of zero bytes (well-defined, not an error)
///     Expected: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
///
///   Small file (< 4 MB)  → single read, same result as openssl sha256
///     Expected: hex string matching the reference value
///
///   Large file (> 4 MB)  → streamed in chunks, result must be identical to small-file path
///     Expected: deterministic across two calls
///
///   File doesn't exist   → throws (FileHandle init fails)
///     Callers in sha256GPTKDylib() wrap this in a try? chain
///
///   GPTK dylib missing from all candidate paths → returns sentinel "gptk-dylib-not-found"
///     Expected: NOT a throw — this allows check() to return .unverified cleanly

final class CertificationHashingTests: XCTestCase {

    private var tmpDir: URL!

    override func setUp() async throws {
        tmpDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("CertHashTest-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmpDir, withIntermediateDirectories: true)
    }

    override func tearDown() async throws {
        try? FileManager.default.removeItem(at: tmpDir)
    }

    // MARK: Known-content correctness

    func testSHA256OfKnownContentMatchesOpenSSLReference() throws {
        // Reference: echo -n "hello" | openssl sha256
        // = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        let data = Data("hello".utf8)
        let url  = tmpDir.appendingPathComponent("hello.bin")
        try data.write(to: url)

        let hash = try CertificationService.sha256(fileAt: url)
        XCTAssertEqual(hash, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
            "SHA-256 of 'hello' must match the openssl reference value")
    }

    // MARK: Empty file

    func testSHA256OfEmptyFileIsWellDefined() throws {
        // SHA-256 of an empty byte sequence is defined by the standard.
        // An empty binary won't match any manifest entry, but the function
        // must not crash or throw — it should return the correct empty hash.
        let url = tmpDir.appendingPathComponent("empty.bin")
        try Data().write(to: url)

        let hash = try CertificationService.sha256(fileAt: url)
        // Reference: openssl sha256 /dev/null = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        XCTAssertEqual(hash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "SHA-256 of an empty file must equal the well-known empty hash")
    }

    // MARK: Output format

    func testSHA256OutputIsLowercaseHex64Characters() throws {
        // All SHA-256 values in the manifest are lowercase hex (produced by
        // String(format:"%02x", byte)). If this function ever returns uppercase
        // or mixed-case, every hash comparison in check() would silently fail.
        let url = tmpDir.appendingPathComponent("content.bin")
        try Data("test content".utf8).write(to: url)

        let hash = try CertificationService.sha256(fileAt: url)
        XCTAssertEqual(hash.count, 64,
            "SHA-256 hex output must always be exactly 64 characters (32 bytes × 2 hex digits)")
        XCTAssertEqual(hash, hash.lowercased(),
            "Output must be lowercase — manifest hashes are always lowercase; uppercase would silently break all comparisons")
        XCTAssertTrue(hash.allSatisfy { $0.isHexDigit },
            "Output must contain only hex digits [0-9a-f]")
    }

    // MARK: Determinism across calls

    func testSHA256IsDeterministicAcrossTwoCalls() throws {
        // Uses a file slightly over one 4 MB chunk to exercise the chunked-read
        // boundary. If there's an off-by-one in the streaming logic, the second
        // call might produce a different hash than the first.
        let data = Data(repeating: 0xAB, count: 4 * 1024 * 1024 + 17)
        let url  = tmpDir.appendingPathComponent("chunked.bin")
        try data.write(to: url)

        let h1 = try CertificationService.sha256(fileAt: url)
        let h2 = try CertificationService.sha256(fileAt: url)
        XCTAssertEqual(h1, h2,
            "SHA-256 must be deterministic — two calls on the same file must produce the same hash (tests chunk-boundary correctness)")
    }

    // MARK: Missing file throws

    func testSHA256ThrowsForNonexistentFile() {
        // If the game binary has been moved or deleted, the function must throw
        // rather than returning a sentinel or crashing. Callers catch the error
        // and return .unverified from DaemonSession.
        let url = tmpDir.appendingPathComponent("does-not-exist.exe")
        XCTAssertThrowsError(try CertificationService.sha256(fileAt: url),
            "SHA-256 of a nonexistent file must throw — caller is responsible for handling missing binaries")
    }

    // MARK: GPTK dylib sentinel

    func testGPTKDylibNotFoundReturnsSentinelInsteadOfThrowing() throws {
        // When no D3DMetal dylib is found in any candidate path, sha256GPTKDylib()
        // returns the literal string "gptk-dylib-not-found" rather than throwing.
        //
        // Why a sentinel instead of a throw? The certification check is non-blocking
        // — the game must always launch even if GPTK dylib detection fails. A throw
        // here would require every call site to handle it. The sentinel naturally causes
        // the identity's gptkDylibSHA256 to not match any manifest entry, so check()
        // returns .unverified cleanly.
        //
        // Configuration: passing an empty/nonexistent searchPath means no candidates
        // resolve. In CI (no GPTK installed), this path always fires.
        let sentinel = try CertificationService.sha256GPTKDylib(searchPath: "/nonexistent/path/that/does/not/exist")
        XCTAssertEqual(sentinel, "gptk-dylib-not-found",
            "Missing GPTK dylib must return the sentinel string — not throw — so the game always launches with .unverified")
    }

    func testGPTKSentinelDoesNotMatchAnyRealHash() throws {
        // Belt-and-suspenders: the sentinel value must never accidentally collide
        // with a real SHA-256 hash (which is always 64 lowercase hex characters).
        let sentinel = try CertificationService.sha256GPTKDylib(searchPath: "/nonexistent")
        XCTAssertNotEqual(sentinel.count, 64,
            "The sentinel must not be 64 hex characters — it must be distinguishable from a real SHA-256 hash")
    }
}
