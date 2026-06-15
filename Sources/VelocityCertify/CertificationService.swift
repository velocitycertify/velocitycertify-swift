import Foundation
import CryptoKit

// MARK: - VelocityCertify
//
// Answers: "Is this exact game binary, under this exact GPTK build, certified by Skyfire?"
//
// Architecture:
//   CertificationService  — looks up a (binaryHash, gptkHash) pair against the live manifest
//   ManifestCache         — fetches, Ed25519-verifies, and TTL-caches the manifest from R2
//
// The public key is BUNDLED in the app — never fetched at runtime.
// Fetching the pubkey at runtime would allow a MITM to substitute it, defeating the
// entire trust model. The bundled key is the trust anchor.
//
// Verification:
//   openssl pkeyutl -verify -pubin -inkey pubkey.pem \
//     -sigfile manifest.sig -in manifest.json
//
// Drop the public key at:
//   Velocity/Velocity/Resources/velocitycertify-pubkey.pem
// and add it to the app bundle in Xcode.

// MARK: - Identity

/// The three inputs that uniquely identify a tested (game × GPTK) combination.
struct CertificationIdentity: Equatable, Sendable {
    let gameSlug:        String      // matches manifest slug (e.g. "hades-2")
    let binarySHA256:    String      // hex SHA-256 of the game's primary .exe on disk
    let gptkDylibSHA256: String      // hex SHA-256 of the active D3DMetal dylib
    let velocityVersion: String
    let gptkVersion:     String
}

// MARK: - Status

enum CertificationStatus: String, Codable, Sendable {
    /// Green: hashes match, tested performance meets the fps target.
    case certified             = "certified"
    /// Yellow: hashes match, but fps target was not met; known issues noted.
    case certifiedDegraded     = "certified_degraded"
    /// Red: hashes match, title was tested and failed certification.
    case notCertified          = "not_certified"
    /// Red: previously certified, now explicitly revoked (see manifest revoked_titles list).
    case revoked               = "revoked"
    /// Gray: title not in any manifest, OR binary/GPTK has changed since last cert.
    case unverified            = "unverified"
    /// Gray (silent): manifest could not be fetched or verified (offline, sig mismatch).
    case manifestUnavailable   = "manifest_unavailable"
}

// MARK: - Result

struct CertificationResult: Sendable {
    let identity:       CertificationIdentity
    let status:         CertificationStatus

    // Performance
    let avgFPS:         Int?
    let p1FPS:          Int?
    let fpsTarget:      Int?

    // General compatibility
    let knownIssues:    [String]
    let macAdvantages:  [String]

    // Controller
    let mfiSupported:           Bool?
    let dualSenseHaptics:       Bool?
    let buttonPromptsAccurate:  Bool?
    let gyroSupported:          Bool?
    let mapperRequired:         Bool?
    let controllerTestedWith:   String?

    // Power / battery
    let batteryRuntimeMinutes:   Int?
    let chargerWattsRequired:    Int?
    let pluggedVsBatteryDeltaPct: Int?

    // Stability
    let crashesPerHour:          Double?
    let memoryGrowthMBPerHour:   Double?
    let swapHighWaterGB:         Double?
    let saveCompatibility:       String?

    // GPTK coverage
    let d3dFeatureLevel:         String?
    let rayTracingStatus:        String?
    let antiCheatStatus:         String?
    let drmStatus:               String?

    // Display
    let hdrStatus:               String?
    let externalDisplayBehavior: String?
    let notchSafeAreaHandled:    Bool?
    let promotionVariableRate:   Bool?

    // Network
    let multiplayerStatus:       String?
    let vpnSensitive:            Bool?

    // macOS integration
    let commandTabBehavior:       String?
    let fullscreenQuality:        String?
    let sleepPrevented:           Bool?
    let stageManagerCompatible:   Bool?

    // Version matrix
    let versionMatrix:            [ManifestVersionEntry]

    // Meta
    let certifiedDate:     String?
    let certifierNotes:    String?
    let hardwareLabel:     String?

    // Tool stack
    let translationLayer:        String?
    let translationLayerVersion: String?
    let velocityOptimizations:   [String]

    // Apple Silicon metrics
    let avgBandwidthSaturationPct:  Double?
    let peakBandwidthSaturationPct: Double?
    let gpuBubbleCount:             Int?
    let gpuBubbleAvgMs:             Double?
    let eCoreContentionPct:         Double?
    let avgWindowServerMs:          Double?
    let compressionStress:          Bool?
    let psoStallCount:              Int?
    let aneActivePct:               Double?

    // Protocol tests
    let sleepRecoverySurvived:    Bool?
    let sleepRecoverySeconds:     Double?
    let audioSyncRating:          String?
    let audioSyncAvgDriftMs:      Double?
    let cacheReWarmupMinutes:     Double?
    let displayMatrixResults:     [ManifestDisplayMatrixEntry]
    let memoryPressureLadder:     [ManifestMemoryPressureEntry]
    let gptkVersionComparison:    [ManifestGPTKVersionComparison]

    // Run provenance
    let sourceRunId:       String?
    let machineFingerprint: String?

    // Trust & verification
    let witnessCount:           Int
    let confirmingConfigs:      Int
    let runCount:               Int?
    let fpsStdDev:              Double?
    let hasVideoEvidence:       Bool
    let isCommunityConfirmed:   Bool
    let crossToolComparisons:   [ManifestCrossToolResult]
    let failedRunCount:         Int?

    private static func empty(_ identity: CertificationIdentity, status: CertificationStatus) -> CertificationResult {
        CertificationResult(
            identity: identity, status: status,
            avgFPS: nil, p1FPS: nil, fpsTarget: nil,
            knownIssues: [], macAdvantages: [],
            mfiSupported: nil, dualSenseHaptics: nil, buttonPromptsAccurate: nil,
            gyroSupported: nil, mapperRequired: nil, controllerTestedWith: nil,
            batteryRuntimeMinutes: nil, chargerWattsRequired: nil, pluggedVsBatteryDeltaPct: nil,
            crashesPerHour: nil, memoryGrowthMBPerHour: nil, swapHighWaterGB: nil, saveCompatibility: nil,
            d3dFeatureLevel: nil, rayTracingStatus: nil, antiCheatStatus: nil, drmStatus: nil,
            hdrStatus: nil, externalDisplayBehavior: nil, notchSafeAreaHandled: nil, promotionVariableRate: nil,
            multiplayerStatus: nil, vpnSensitive: nil,
            commandTabBehavior: nil, fullscreenQuality: nil, sleepPrevented: nil, stageManagerCompatible: nil,
            versionMatrix: [],
            certifiedDate: nil, certifierNotes: nil, hardwareLabel: nil,
            translationLayer: nil, translationLayerVersion: nil, velocityOptimizations: [],
            avgBandwidthSaturationPct: nil, peakBandwidthSaturationPct: nil,
            gpuBubbleCount: nil, gpuBubbleAvgMs: nil, eCoreContentionPct: nil,
            avgWindowServerMs: nil, compressionStress: nil, psoStallCount: nil, aneActivePct: nil,
            sleepRecoverySurvived: nil, sleepRecoverySeconds: nil,
            audioSyncRating: nil, audioSyncAvgDriftMs: nil, cacheReWarmupMinutes: nil,
            displayMatrixResults: [], memoryPressureLadder: [], gptkVersionComparison: [],
            sourceRunId: nil, machineFingerprint: nil,
            witnessCount: 0, confirmingConfigs: 0, runCount: nil, fpsStdDev: nil,
            hasVideoEvidence: false, isCommunityConfirmed: false,
            crossToolComparisons: [], failedRunCount: nil)
    }

    static func unavailable(identity: CertificationIdentity) -> CertificationResult {
        empty(identity, status: .manifestUnavailable)
    }

    static func unverified(identity: CertificationIdentity) -> CertificationResult {
        empty(identity, status: .unverified)
    }

    static func revoked(identity: CertificationIdentity) -> CertificationResult {
        empty(identity, status: .revoked)
    }
}

// MARK: - CertificationService

actor CertificationService {

    static let shared = CertificationService()

    private let cache: ManifestCache

    init(cache: ManifestCache = ManifestCache()) {
        self.cache = cache
    }

    /// Called by DaemonSession after launch — non-blocking, game always runs regardless.
    func check(identity: CertificationIdentity) async -> CertificationResult {
        guard let manifest = await cache.currentManifest() else {
            return .unavailable(identity: identity)
        }

        // Check revocation list first
        if let revoked = manifest.revokedTitles?.first(where: { $0.slug == identity.gameSlug }) {
            NSLog("[CertificationService] \(identity.gameSlug) is REVOKED: \(revoked.reason)")
            return .revoked(identity: identity)
        }

        // Find title entry by slug
        guard let entry = manifest.titles.first(where: { $0.slug == identity.gameSlug }) else {
            return .unverified(identity: identity)
        }

        // Compare hashes — if either changed, cert does not apply
        guard entry.identity.binarySHA256 == identity.binarySHA256,
              entry.identity.gptkDylibSHA256 == identity.gptkDylibSHA256 else {
            NSLog("[CertificationService] Hash mismatch for \(identity.gameSlug) — binary or GPTK changed since certification")
            return .unverified(identity: identity)
        }

        let status = CertificationStatus(rawValue: entry.status) ?? .unverified
        NSLog("[CertificationService] \(identity.gameSlug): \(status.rawValue)")

        let ctrl = entry.controller
        let pwr  = entry.power
        let stab = entry.stability
        let cov  = entry.gptkCoverage
        let disp = entry.display
        let net  = entry.network
        let mac  = entry.macOSIntegration

        return CertificationResult(
            identity:       identity,
            status:         status,
            avgFPS:         entry.performance?.coldAvgFPS,
            p1FPS:          entry.performance?.coldP1FPS,
            fpsTarget:      entry.performance?.fpsTarget,
            knownIssues:    entry.compatibility?.knownIssues ?? [],
            macAdvantages:  entry.compatibility?.macAdvantages ?? [],
            mfiSupported:           ctrl?.mfiSupported,
            dualSenseHaptics:       ctrl?.dualSenseHaptics,
            buttonPromptsAccurate:  ctrl?.buttonPromptsAccurate,
            gyroSupported:          ctrl?.gyroSupported,
            mapperRequired:         ctrl?.mapperRequired,
            controllerTestedWith:   ctrl?.testedWith,
            batteryRuntimeMinutes:  pwr?.batteryRuntimeMinutes,
            chargerWattsRequired:   pwr?.chargerWattsRequired,
            pluggedVsBatteryDeltaPct: pwr?.pluggedVsBatteryDeltaPct,
            crashesPerHour:         stab?.crashesPerHour,
            memoryGrowthMBPerHour:  stab?.memoryGrowthMBPerHour,
            swapHighWaterGB:        stab?.swapHighWaterGB,
            saveCompatibility:      stab?.saveCompatibility,
            d3dFeatureLevel:        cov?.d3dFeatureLevel,
            rayTracingStatus:       cov?.rayTracingStatus,
            antiCheatStatus:        cov?.antiCheatStatus,
            drmStatus:              cov?.drmStatus,
            hdrStatus:              disp?.hdrStatus,
            externalDisplayBehavior: disp?.externalDisplayBehavior,
            notchSafeAreaHandled:   disp?.notchSafeAreaHandled,
            promotionVariableRate:  disp?.promotionVariableRate,
            multiplayerStatus:      net?.multiplayerStatus,
            vpnSensitive:           net?.vpnSensitive,
            commandTabBehavior:     mac?.commandTabBehavior,
            fullscreenQuality:      mac?.fullscreenQuality,
            sleepPrevented:         mac?.sleepPrevented,
            stageManagerCompatible: mac?.stageManagerCompatible,
            versionMatrix:          entry.versionMatrix ?? [],
            certifiedDate:          entry.certifiedDate,
            certifierNotes:         entry.certifierNotes,
            hardwareLabel:          manifest.environment.hardwareLabel,
            translationLayer:       entry.toolStack?.translationLayer,
            translationLayerVersion: entry.toolStack?.translationLayerVersion,
            velocityOptimizations:  entry.toolStack?.velocityOptimizations ?? [],
            avgBandwidthSaturationPct:  entry.appleSilicon?.avgBandwidthSaturationPct,
            peakBandwidthSaturationPct: entry.appleSilicon?.peakBandwidthSaturationPct,
            gpuBubbleCount:             entry.appleSilicon?.gpuBubbleCount,
            gpuBubbleAvgMs:             entry.appleSilicon?.gpuBubbleAvgMs,
            eCoreContentionPct:         entry.appleSilicon?.eCoreContentionPct,
            avgWindowServerMs:          entry.appleSilicon?.avgWindowServerMs,
            compressionStress:          entry.appleSilicon?.compressionStress,
            psoStallCount:              entry.appleSilicon?.psoStallCount,
            aneActivePct:               entry.appleSilicon?.aneActivePct,
            sleepRecoverySurvived:    entry.protocolTests?.sleepRecoverySurvived,
            sleepRecoverySeconds:     entry.protocolTests?.sleepRecoverySeconds,
            audioSyncRating:          entry.protocolTests?.audioSyncRating,
            audioSyncAvgDriftMs:      entry.protocolTests?.audioSyncAvgDriftMs,
            cacheReWarmupMinutes:     entry.protocolTests?.cacheReWarmupMinutes,
            displayMatrixResults:     entry.protocolTests?.displayMatrixResults ?? [],
            memoryPressureLadder:     entry.protocolTests?.memoryPressureLadder ?? [],
            gptkVersionComparison:    entry.protocolTests?.gptkVersionComparison ?? [],
            sourceRunId:            entry.sourceRunId,
            machineFingerprint:     entry.machineFingerprint,
            witnessCount:           entry.witnessSignatures?.count ?? 0,
            confirmingConfigs:      entry.confirmingConfigs ?? 0,
            runCount:               entry.runCount,
            fpsStdDev:              entry.fpsStdDev,
            hasVideoEvidence:       entry.videoWitnessHash != nil,
            isCommunityConfirmed:   (entry.confirmingConfigs ?? 0) >= 3,
            crossToolComparisons:   entry.crossToolComparison ?? [],
            failedRunCount:         entry.failedRunCount)
    }
}

// MARK: - Hashing

extension CertificationService {

    /// SHA-256 of the file at `url`. Returns lowercase hex string.
    /// Streams the file in 4 MB chunks — safe for large game binaries (1–20 GB).
    static func sha256(fileAt url: URL) throws -> String {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }

        var hasher = SHA256()
        let chunkSize = 4 * 1024 * 1024   // 4 MB

        while true {
            guard let data = try handle.read(upToCount: chunkSize), !data.isEmpty else { break }
            hasher.update(data: data)
        }

        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    /// SHA-256 of the primary D3DMetal dylib.
    /// `dylibSearchPath` is typically the value from DYLD_LIBRARY_PATH in the Wine env.
    static func sha256GPTKDylib(searchPath: String?) throws -> String {
        // GPTK 4: D3DMetal.framework/Versions/A/D3DMetal (framework bundle)
        // GPTK 3: libD3DMetal.dylib (flat dylib)
        let candidates: [String]
        if let base = searchPath?.components(separatedBy: ":").first {
            candidates = [
                base + "/D3DMetal.framework/Versions/A/D3DMetal",
                base + "/libD3DMetal.dylib",
                base + "/libd3dmetal.dylib",
            ]
        } else {
            // Default GPTK install location
            let defaultBase = "/usr/local/lib/gptk"
            candidates = [
                defaultBase + "/D3DMetal.framework/Versions/A/D3DMetal",
                defaultBase + "/libD3DMetal.dylib",
            ]
        }

        for path in candidates {
            let url = URL(fileURLWithPath: path)
            if FileManager.default.fileExists(atPath: path) {
                return try sha256(fileAt: url)
            }
        }

        // GPTK dylib not found — return a sentinel so the cert check
        // correctly returns .unverified rather than crashing.
        NSLog("[CertificationService] D3DMetal dylib not found in candidates: \(candidates)")
        return "gptk-dylib-not-found"
    }
}

// MARK: - ManifestCache

actor ManifestCache {

    // The highest schema major version this build can fully interpret.
    // Bump this in lockstep with any breaking VelocityCertifyManifest change.
    static let supportedSchemaMajor = 1

    private var cached: VelocityCertifyManifest?
    private var lastFetched: Date?
    private let ttl: TimeInterval

    private let session:      URLSession
    private let overridePEM:  String?    // non-nil in tests: bypasses Bundle.main pubkey lookup

    // internal so test targets can stub these URLs via MockURLProtocol
    static let manifestURL = URL(string: "https://velocitycertify.com/manifests/latest.json")!
    static let sigURL      = URL(string: "https://velocitycertify.com/manifests/latest.json.sig")!

    /// Production init — uses URLSession.shared and pubkey from app bundle.
    init() {
        self.session     = .shared
        self.overridePEM = nil
        self.ttl         = 3600
    }

    /// Test init — inject a custom session (for URLProtocol mocking) and pubkey PEM.
    /// Also accepts a custom TTL so tests can force cache expiry.
    init(session: URLSession, pubkeyPEM: String, ttl: TimeInterval = 3600) {
        self.session     = session
        self.overridePEM = pubkeyPEM
        self.ttl         = ttl
    }

    func currentManifest() async -> VelocityCertifyManifest? {
        if let m = cached, let t = lastFetched, Date().timeIntervalSince(t) < ttl {
            return m
        }
        return await fetchAndVerify()
    }

    func fetchAndVerify() async -> VelocityCertifyManifest? {
        do {
            // 1. Fetch manifest JSON
            let (manifestData, _) = try await session.data(from: Self.manifestURL)

            // 2. Fetch detached signature
            let (sigData, _) = try await session.data(from: Self.sigURL)

            // 3. Verify Ed25519 signature.
            //    In production: pubkey is read from the app bundle (BUNDLED, never fetched).
            //    In tests: overridePEM is injected via init(session:pubkeyPEM:).
            let pubkeyPEM: String
            if let override = overridePEM {
                pubkeyPEM = override
            } else {
                guard let pubkeyURL = Bundle.main.url(forResource: "velocitycertify-pubkey", withExtension: "pem"),
                      let pem = try? String(contentsOf: pubkeyURL, encoding: .utf8) else {
                    NSLog("[ManifestCache] velocitycertify-pubkey.pem not found in app bundle")
                    return nil
                }
                pubkeyPEM = pem
            }

            guard verifyEd25519(data: manifestData, signature: sigData, pubkeyPEM: pubkeyPEM) else {
                NSLog("[ManifestCache] Ed25519 signature verification FAILED — manifest rejected")
                return nil
            }

            // 4. Schema version check — parse only the top-level "schema" key before
            //    committing to a full decode.  Format: "MAJOR.MINOR" (e.g. "1.3").
            //    If the manifest's MAJOR is higher than we support, the structure may
            //    contain fields or shapes we cannot safely interpret, so we degrade to
            //    nil rather than storing a potentially corrupt cache entry.
            if let schemaVersion = (try? JSONSerialization.jsonObject(with: manifestData) as? [String: Any])?["schema"] as? String {
                let parts = schemaVersion.split(separator: ".").compactMap { Int($0) }
                let remoteMajor = parts.first ?? 1
                if remoteMajor > Self.supportedSchemaMajor {
                    NSLog("[ManifestCache] Manifest schema \(schemaVersion) is newer than supported major \(Self.supportedSchemaMajor) — treating as unverified")
                    return nil
                }
            }

            // 5. Decode JSON
            let manifest = try JSONDecoder().decode(VelocityCertifyManifest.self, from: manifestData)

            cached      = manifest
            lastFetched = Date()
            NSLog("[ManifestCache] Manifest loaded: schema \(manifest.schema), \(manifest.titles.count) titles, generated \(manifest.generated)")
            return manifest

        } catch {
            NSLog("[ManifestCache] Fetch/verify failed: \(error.localizedDescription)")
            return cached   // return stale cache on network error rather than nil
        }
    }

    /// Ed25519 signature verification using CryptoKit.
    /// The public key PEM is in PKCS#8 SubjectPublicKeyInfo format (what openssl genpkey produces).
    private func verifyEd25519(data: Data, signature: Data, pubkeyPEM: String) -> Bool {
        // Strip PEM headers and base64-decode the key bytes
        let stripped = pubkeyPEM
            .components(separatedBy: "\n")
            .filter { !$0.hasPrefix("-----") && !$0.isEmpty }
            .joined()
        guard let derData = Data(base64Encoded: stripped) else { return false }

        // PKCS#8 SubjectPublicKeyInfo for Ed25519 is 44 bytes:
        //   30 2a 30 05 06 03 2b 65 70 03 21 00 <32-byte raw key>
        // The raw key starts at offset 12.
        guard derData.count == 44 else {
            NSLog("[ManifestCache] Unexpected pubkey DER length: \(derData.count)")
            return false
        }
        let rawKeyData = derData.subdata(in: 12..<44)

        do {
            let pubkey = try Curve25519.Signing.PublicKey(rawRepresentation: rawKeyData)
            return pubkey.isValidSignature(signature, for: data)
        } catch {
            NSLog("[ManifestCache] PublicKey init failed: \(error)")
            return false
        }
    }
}

// MARK: - Manifest JSON Types
// Mirror of VelocityCertifyTools/ManifestTypes.swift — kept separate so the app
// target has no dependency on the tools package.

struct ManifestRevocation: Codable, Sendable {
    let slug:      String
    let revokedAt: String
    let reason:    String

    enum CodingKeys: String, CodingKey {
        case slug; case revokedAt = "revoked_at"; case reason
    }
}

struct VelocityCertifyManifest: Codable, Sendable {
    let schema:       String
    let generated:    String
    let environment:  ManifestEnvironment
    let titles:       [ManifestTitle]
    let revokedTitles: [ManifestRevocation]?

    enum CodingKeys: String, CodingKey {
        case schema, generated, environment, titles
        case revokedTitles = "revoked_titles"
    }

    struct ManifestEnvironment: Codable, Sendable {
        let velocityVersion: String
        let gptkVersion:     String
        let hardwareId:      String
        let hardwareLabel:   String
        let macosVersion:    String

        enum CodingKeys: String, CodingKey {
            case velocityVersion = "velocity_version"
            case gptkVersion     = "gptk_version"
            case hardwareId      = "hardware_id"
            case hardwareLabel   = "hardware_label"
            case macosVersion    = "macos_version"
        }
    }
}

struct ManifestTitle: Codable, Sendable {
    let slug:             String
    let name:             String
    let steamAppId:       Int?
    let versionLabel:     String?
    let identity:         ManifestIdentity
    let performance:      ManifestPerformance?
    let compatibility:    ManifestCompatibility?
    let controller:       ManifestController?
    let stability:        ManifestStability?
    let power:            ManifestPower?
    let display:          ManifestDisplay?
    let network:          ManifestNetwork?
    let macOSIntegration: ManifestMacOSIntegration?
    let gptkCoverage:     ManifestGPTKCoverage?
    let versionMatrix:     [ManifestVersionEntry]?
    let status:            String
    let certifiedDate:     String?
    let certifierNotes:    String?
    let toolStack:         ManifestToolStack?
    let appleSilicon:      ManifestAppleSilicon?
    let protocolTests:     ManifestProtocolTests?
    let sourceRunId:       String?
    let machineFingerprint: String?

    // Trust & verification
    let witnessSignatures:      [ManifestWitnessSignature]?
    let confirmingConfigs:      Int?
    let confirmingFingerprints: [String]?
    let runCount:               Int?
    let fpsStdDev:              Double?
    let videoWitnessHash:       String?
    let stressSceneName:        String?
    let crossToolComparison:    [ManifestCrossToolResult]?
    let failedRunCount:         Int?

    enum CodingKeys: String, CodingKey {
        case slug, name, identity, performance, compatibility
        case controller, stability, power, display, network
        case steamAppId        = "steam_app_id"
        case versionLabel      = "version_label"
        case macOSIntegration  = "macos_integration"
        case gptkCoverage      = "gptk_coverage"
        case versionMatrix     = "version_matrix"
        case certifiedDate     = "certified_date"
        case certifierNotes    = "certifier_notes"
        case toolStack         = "tool_stack"
        case appleSilicon      = "apple_silicon"
        case protocolTests     = "protocol_tests"
        case sourceRunId       = "source_run_id"
        case machineFingerprint = "machine_fingerprint"
        case witnessSignatures     = "witness_signatures"
        case confirmingConfigs     = "confirming_configs"
        case confirmingFingerprints = "confirming_fingerprints"
        case runCount              = "run_count"
        case fpsStdDev             = "fps_std_dev"
        case videoWitnessHash      = "video_witness_hash"
        case stressSceneName       = "stress_scene_name"
        case crossToolComparison   = "cross_tool_comparison"
        case failedRunCount        = "failed_run_count"
        case status
    }
}

struct ManifestIdentity: Codable, Sendable {
    let binarySHA256:    String
    let binaryPathHint:  String?
    let gptkDylibSHA256: String

    enum CodingKeys: String, CodingKey {
        case binarySHA256    = "binary_sha256"
        case binaryPathHint  = "binary_path_hint"
        case gptkDylibSHA256 = "gptk_dylib_sha256"
    }
}

struct ManifestPerformance: Codable, Sendable {
    let fpsTarget:   Int?
    let cold:        ManifestFrameStats?
    let warm:        ManifestFrameStats?
    let thermal:     ManifestThermal?

    var coldAvgFPS: Int? { cold.flatMap { $0.avgFPS.map { Int($0) } } }
    var coldP1FPS:  Int? { cold.flatMap { $0.p99FrameMs.map { Int(1000.0 / $0) } } }

    enum CodingKeys: String, CodingKey {
        case fpsTarget = "fps_target"
        case cold, warm, thermal
    }
}

struct ManifestFrameStats: Codable, Sendable {
    let avgFPS:       Double?
    let p50FrameMs:   Double?
    let p95FrameMs:   Double?
    let p99FrameMs:   Double?
    let maxFrameMs:   Double?
    let stutterCount: Int?

    enum CodingKeys: String, CodingKey {
        case avgFPS       = "avg_fps"
        case p50FrameMs   = "p50_frametime_ms"
        case p95FrameMs   = "p95_frametime_ms"
        case p99FrameMs   = "p99_frametime_ms"
        case maxFrameMs   = "max_frametime_ms"
        case stutterCount = "stutter_count"
    }
}

struct ManifestThermal: Codable, Sendable {
    let throttleOnsetMinutes:      Int?
    let fpsAt5min:                 Double?
    let fpsAt15min:                Double?
    let fpsAt30min:                Double?
    let sustainedPerformanceRating: String?

    enum CodingKeys: String, CodingKey {
        case throttleOnsetMinutes        = "throttle_onset_minutes"
        case fpsAt5min                   = "fps_at_5min"
        case fpsAt15min                  = "fps_at_15min"
        case fpsAt30min                  = "fps_at_30min"
        case sustainedPerformanceRating  = "sustained_performance_rating"
    }
}

struct ManifestCompatibility: Codable, Sendable {
    let savesFunctional:      Bool?
    let controllerFunctional: Bool?
    let crashOnLaunch:        Bool?
    let audioFunctional:      Bool?
    let knownIssues:          [String]?
    let macAdvantages:        [String]?

    enum CodingKeys: String, CodingKey {
        case savesFunctional      = "saves_functional"
        case controllerFunctional = "controller_functional"
        case crashOnLaunch        = "crash_on_launch"
        case audioFunctional      = "audio_functional"
        case knownIssues          = "known_issues"
        case macAdvantages        = "mac_advantages"
    }
}

struct ManifestController: Codable, Sendable {
    let mfiSupported:          Bool?
    let dualSenseHaptics:      Bool?
    let buttonPromptsAccurate: Bool?
    let gyroSupported:         Bool?
    let mapperRequired:        Bool?
    let testedWith:            String?

    enum CodingKeys: String, CodingKey {
        case mfiSupported          = "mfi_supported"
        case dualSenseHaptics      = "dualsense_haptics"
        case buttonPromptsAccurate = "button_prompts_accurate"
        case gyroSupported         = "gyro_supported"
        case mapperRequired        = "mapper_required"
        case testedWith            = "tested_with"
    }
}

struct ManifestStability: Codable, Sendable {
    let crashesPerHour:        Double?
    let crashTypes:            [String]?
    let memoryGrowthMBPerHour: Double?
    let swapHighWaterGB:       Double?
    let saveCompatibility:     String?

    enum CodingKeys: String, CodingKey {
        case crashesPerHour        = "crashes_per_hour"
        case crashTypes            = "crash_types"
        case memoryGrowthMBPerHour = "memory_growth_mb_per_hour"
        case swapHighWaterGB       = "swap_high_water_gb"
        case saveCompatibility     = "save_compatibility"
    }
}

struct ManifestPower: Codable, Sendable {
    let avgPackageWatts:          Double?
    let peakPackageWatts:         Double?
    let joulesPerFrame:           Double?
    let batteryRuntimeMinutes:    Int?
    let chargerWattsRequired:     Int?
    let pluggedVsBatteryDeltaPct: Int?

    enum CodingKeys: String, CodingKey {
        case avgPackageWatts          = "avg_package_watts"
        case peakPackageWatts         = "peak_package_watts"
        case joulesPerFrame           = "joules_per_frame"
        case batteryRuntimeMinutes    = "battery_runtime_minutes"
        case chargerWattsRequired     = "charger_watts_required"
        case pluggedVsBatteryDeltaPct = "plugged_vs_battery_delta_pct"
    }
}

struct ManifestDisplay: Codable, Sendable {
    let promotionAligned:        Bool?
    let promotionVariableRate:   Bool?
    let tearingObserved:         Bool?
    let vsyncMode:               String?
    let hdrStatus:               String?
    let externalDisplayBehavior: String?
    let notchSafeAreaHandled:    Bool?

    enum CodingKeys: String, CodingKey {
        case promotionAligned        = "promotion_aligned"
        case promotionVariableRate   = "promotion_variable_rate"
        case tearingObserved         = "tearing_observed"
        case vsyncMode               = "vsync_mode"
        case hdrStatus               = "hdr_status"
        case externalDisplayBehavior = "external_display_behavior"
        case notchSafeAreaHandled    = "notch_safe_area_handled"
    }
}

struct ManifestNetwork: Codable, Sendable {
    let multiplayerStatus: String?
    let vpnSensitive:      Bool?

    enum CodingKeys: String, CodingKey {
        case multiplayerStatus = "multiplayer_status"
        case vpnSensitive      = "vpn_sensitive"
    }
}

struct ManifestMacOSIntegration: Codable, Sendable {
    let commandTabBehavior:        String?
    let fullscreenQuality:         String?
    let sleepPrevented:            Bool?
    let notificationsInFullscreen: String?
    let stageManagerCompatible:    Bool?

    enum CodingKeys: String, CodingKey {
        case commandTabBehavior        = "command_tab_behavior"
        case fullscreenQuality         = "fullscreen_quality"
        case sleepPrevented            = "sleep_prevented"
        case notificationsInFullscreen = "notifications_in_fullscreen"
        case stageManagerCompatible    = "stage_manager_compatible"
    }
}

struct ManifestGPTKCoverage: Codable, Sendable {
    let d3dFeatureLevel:   String?
    let rayTracingStatus:  String?
    let failingExtensions: [String]?
    let antiCheatStatus:   String?
    let drmStatus:         String?

    enum CodingKeys: String, CodingKey {
        case d3dFeatureLevel   = "d3d_feature_level"
        case rayTracingStatus  = "ray_tracing_status"
        case failingExtensions = "failing_extensions"
        case antiCheatStatus   = "anti_cheat_status"
        case drmStatus         = "drm_status"
    }
}

struct ManifestVersionEntry: Codable, Sendable {
    let macosVersion: String
    let gptkVersion:  String
    let status:       String
    let notes:        String?

    enum CodingKeys: String, CodingKey {
        case macosVersion = "macos_version"
        case gptkVersion  = "gptk_version"
        case status, notes
    }
}

// MARK: - Tool Stack (app-side mirror of VCToolStack)

struct ManifestToolStack: Codable, Sendable {
    let translationLayer:        String
    let translationLayerVersion: String
    let gptkVersion:             String
    let dxvkEnabled:             Bool
    let vkd3dEnabled:            Bool
    let metalFXEnabled:          Bool
    let velocityOptimizations:   [String]
    let macosVersion:            String

    enum CodingKeys: String, CodingKey {
        case translationLayer        = "translation_layer"
        case translationLayerVersion = "translation_layer_version"
        case gptkVersion             = "gptk_version"
        case dxvkEnabled             = "dxvk_enabled"
        case vkd3dEnabled            = "vkd3d_enabled"
        case metalFXEnabled          = "metalfx_enabled"
        case velocityOptimizations   = "velocity_optimizations"
        case macosVersion            = "macos_version"
    }
}

// MARK: - Apple Silicon (app-side mirror of VCAppleSilicon)

struct ManifestAppleSilicon: Codable, Sendable {
    let avgBandwidthSaturationPct:  Double?
    let peakBandwidthSaturationPct: Double?
    let gpuBubbleCount:             Int?
    let gpuBubbleAvgMs:             Double?
    let gpuBubbleMaxMs:             Double?
    let aneActive:                  Bool?
    let aneActivePct:               Double?
    let eCoreContentionPct:         Double?
    let avgWindowServerMs:          Double?
    let compressionStress:          Bool?
    let psoStallCount:              Int?
    let psoStallAvgMs:              Double?

    enum CodingKeys: String, CodingKey {
        case avgBandwidthSaturationPct  = "avg_bandwidth_saturation_pct"
        case peakBandwidthSaturationPct = "peak_bandwidth_saturation_pct"
        case gpuBubbleCount             = "gpu_bubble_count"
        case gpuBubbleAvgMs             = "gpu_bubble_avg_ms"
        case gpuBubbleMaxMs             = "gpu_bubble_max_ms"
        case aneActive                  = "ane_active"
        case aneActivePct               = "ane_active_pct"
        case eCoreContentionPct         = "e_core_contention_pct"
        case avgWindowServerMs          = "avg_window_server_ms"
        case compressionStress          = "compression_stress"
        case psoStallCount              = "pso_stall_count"
        case psoStallAvgMs              = "pso_stall_avg_ms"
    }
}

// MARK: - Protocol Tests (app-side mirror of VCProtocolTests)

struct ManifestProtocolTests: Codable, Sendable {
    let sleepRecoverySurvived:    Bool?
    let sleepRecoverySeconds:     Double?
    let audioSyncRating:          String?
    let audioSyncAvgDriftMs:      Double?
    let cacheReWarmupMinutes:     Double?
    let cacheStutterDuringWarmup: Bool?
    let displayMatrixResults:     [ManifestDisplayMatrixEntry]?
    let memoryPressureLadder:     [ManifestMemoryPressureEntry]?
    let gptkVersionComparison:    [ManifestGPTKVersionComparison]?

    enum CodingKeys: String, CodingKey {
        case sleepRecoverySurvived    = "sleep_recovery_survived"
        case sleepRecoverySeconds     = "sleep_recovery_seconds"
        case audioSyncRating          = "audio_sync_rating"
        case audioSyncAvgDriftMs      = "audio_sync_avg_drift_ms"
        case cacheReWarmupMinutes     = "cache_re_warmup_minutes"
        case cacheStutterDuringWarmup = "cache_stutter_during_warmup"
        case displayMatrixResults     = "display_matrix"
        case memoryPressureLadder     = "memory_pressure_ladder"
        case gptkVersionComparison    = "gptk_version_comparison"
    }
}

struct ManifestDisplayMatrixEntry: Codable, Sendable {
    let displayType: String;  let resolution: String;  let refreshHz: Double
    let result: String;       let notes: String?
    enum CodingKeys: String, CodingKey {
        case displayType = "display_type"; case resolution; case refreshHz = "refresh_hz"
        case result; case notes
    }
}

struct ManifestMemoryPressureEntry: Codable, Sendable {
    let simulatedGB: Int;  let survived: Bool;  let avgFPS: Double?;  let crashedAt: Double?
    enum CodingKeys: String, CodingKey {
        case simulatedGB = "simulated_gb"; case survived
        case avgFPS = "avg_fps"; case crashedAt = "crashed_at_sec"
    }
}

struct ManifestGPTKVersionComparison: Codable, Sendable {
    let gptkVersion: String;  let avgFPS: Double?;  let relativeRating: String?
    enum CodingKeys: String, CodingKey {
        case gptkVersion = "gptk_version"; case avgFPS = "avg_fps"
        case relativeRating = "relative_rating"
    }
}

// MARK: - Trust & Verification types

struct ManifestWitnessSignature: Codable, Sendable {
    let signerHandle:       String
    let pubkeyURL:          String
    let signature:          String
    let hardwareLabel:      String
    let machineFingerprint: String
    let runId:              String
    let signedAt:           String

    enum CodingKeys: String, CodingKey {
        case signerHandle       = "signer_handle"
        case pubkeyURL          = "pubkey_url"
        case signature
        case hardwareLabel      = "hardware_label"
        case machineFingerprint = "machine_fingerprint"
        case runId              = "run_id"
        case signedAt           = "signed_at"
    }
}

struct ManifestCrossToolResult: Codable, Sendable {
    let translationLayer:    String
    let avgFPS:              Double?
    let p1FPS:               Double?
    let crashesPerHour:      Double?
    let relativeRating:      String?
    let runId:               String?

    enum CodingKeys: String, CodingKey {
        case translationLayer = "translation_layer"
        case avgFPS           = "avg_fps"
        case p1FPS            = "p1_fps"
        case crashesPerHour   = "crashes_per_hour"
        case relativeRating   = "relative_rating"
        case runId            = "run_id"
    }
}
