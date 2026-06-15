import Foundation
import Metal
import IOKit
import IOKit.ps
import CryptoKit

// MARK: - CertificationRunRecorder
//
// Drives the VelocityCertify 30-minute test protocol and produces a RawCertificationRun
// that can be signed and published as a manifest entry.
//
// Protocol summary (from velocitycertify-mac-testing-methodology.md):
//   Phase 1 (cold, 5 min)   — fresh shader cache, measures first-launch stutter
//   Phase 2 (sustained, 30 min) — measures fps@5/15/30min, thermal cliff, power draw
//   Phase 3 (warm, last 5 min)  — cached shader perf, cadence alignment
//
// All frame time capture is via MTLCommandBuffer completion handlers — below GPTK,
// below the game, at the Metal driver boundary. No game modification required.
//
// Usage:
//   let recorder = CertificationRunRecorder(device: MTLCreateSystemDefaultDevice()!, gameSlug: "hades-2")
//   recorder.start()
//   // ...30 min passes...
//   let run = recorder.stop()
//   // run is a RawCertificationRun ready to feed vcertify-sign

// MARK: - Raw Run (output of test protocol, pre-signing)

struct RawCertificationRun: Codable, Sendable {
    let gameSlug:    String
    let capturedAt:  Date
    let durationSec: TimeInterval

    // Frame time samples — one per MTLCommandBuffer completion
    let frameTimes:  [Double]   // ms, in chronological order

    // Wall-clock fps snapshots (for thermal time series)
    let fpsTimeline: [FPSSnapshot]

    // Shader compilation events
    let shaderEvents: [ShaderEvent]

    // Thermal / power samples (1Hz)
    let powerSamples: [PowerSample]

    // Memory pressure samples (1Hz)
    let memorySamples: [MemorySample]

    // ProMotion cadence slip (MacBook Pro only)
    let cadenceSlips: [Double]   // ms per display link fire

    // Process crash events — appended by the daemon when it observes an unexpected exit
    let crashEvents: [CrashEvent]

    // MARK: Tool stack — what software ran the game
    let toolStack: ToolStack

    // MARK: Apple Silicon specific (1Hz samples, unique to unified-memory architecture)
    let memoryBandwidthSamples:   [MemoryBandwidthSample]
    let commandBufferGaps:        [CommandBufferGap]
    let aneSamples:               [ANESample]
    let coreSchedulingSamples:    [CoreSchedulingSample]
    let memoryCompressionSamples: [MemoryCompressionSample]
    let displayLatencySamples:    [DisplayLatencySample]

    // MARK: Protocol test results (populated by vcertify-run; nil during live in-app capture)
    let sleepRecovery:        SleepRecoveryResult?
    let audioSync:            AudioSyncResult?
    let inputLatency:         InputLatencyResult?
    let cacheRecovery:        CacheRecoveryResult?
    let displayMatrix:        [DisplayMatrixEntry]
    let memoryPressureLadder: [MemoryPressureLadderEntry]
    let gptkVersionMatrix:    [GPTKVersionResult]

    // MARK: Hardware provenance
    let hardwareLabel:       String   // e.g. "Apple M4 · 16 GB (Mac mini)"
    let machineFingerprint:  String   // SHA-256(hw.model + hw.memsize)

    // MARK: Run identity
    // SHA-256 of canonical JSON of this struct with runID = "".
    // Manifest entries reference this so the chain run → entry → signature is auditable.
    let runID: String
}

extension RawCertificationRun {
    /// Compute the canonical run ID: SHA-256 of the JSON bytes with runID set to empty string.
    /// Call this on a run constructed with runID: "" to get the real ID, then reconstruct with it.
    static func computeRunID(for run: RawCertificationRun) throws -> String {
        let data = try JSONEncoder.canonical.encode(run)
        let digest = SHA256.hash(data: data)
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}

struct FPSSnapshot: Codable, Sendable {
    let elapsedSec: Double
    let fps:        Double
}

struct ShaderEvent: Codable, Sendable {
    let elapsedSec:    Double
    let compilationMs: Double   // frame time during the stutter
    let isColdCache:   Bool
    /// "shader" = GLSL/MSL compilation; "pso" = pipeline state object creation.
    /// PSO stalls are shorter (<500ms) and recur after state changes.
    /// Shader stalls are long (500ms+) and concentrated at cold-cache launch.
    let type:          String
}

struct PowerSample: Codable, Sendable {
    let elapsedSec:  Double
    let packageWatts: Double
    let cpuWatts:     Double
    let gpuWatts:     Double
}

struct MemorySample: Codable, Sendable {
    let elapsedSec:       Double
    let compressorPages:  UInt64
    let swapIns:          UInt64
    let swapOuts:         UInt64
    let gameMemoryMB:     Double
}

struct CrashEvent: Codable, Sendable {
    let elapsedSec: Double
    /// "gpu_timeout" | "memory_exhaustion" | "gptk_assertion" | "signal_kill" | "unknown"
    let type:       String
}

// MARK: - Tool Stack
// What software stack produced this run. Lets anyone reading the manifest know
// exactly what ran the game — Velocity's optimized Wine, vanilla Wine, CrossOver, Whisky, etc.
// This is the provenance anchor: two cert entries for the same game can differ by tool stack,
// and both are valid, honest results for their respective environments.

struct ToolStack: Codable, Sendable {
    /// "velocity" | "wine" | "crossover" | "whisky" | "gptk-only" | "other"
    let translationLayer:        String
    let translationLayerVersion: String   // e.g. "9.7" for Wine, "24.0.1" for CrossOver
    let gptkVersion:             String   // e.g. "4.1"
    let gptkDylibSHA256:         String
    let dxvkEnabled:             Bool
    let vkd3dEnabled:            Bool
    let metalFXEnabled:          Bool
    /// Velocity-specific optimizations active during this run.
    /// e.g. ["shader-precompile", "memory-pool-tuning", "game-mode", "async-pipeline"]
    let velocityOptimizations:   [String]
    /// macOS version the test ran on. e.g. "15.4.1"
    let macosVersion:            String

    enum CodingKeys: String, CodingKey {
        case translationLayer        = "translation_layer"
        case translationLayerVersion = "translation_layer_version"
        case gptkVersion             = "gptk_version"
        case gptkDylibSHA256         = "gptk_dylib_sha256"
        case dxvkEnabled             = "dxvk_enabled"
        case vkd3dEnabled            = "vkd3d_enabled"
        case metalFXEnabled          = "metalfx_enabled"
        case velocityOptimizations   = "velocity_optimizations"
        case macosVersion            = "macos_version"
    }
}

// MARK: - Apple Silicon Specific Samples
// These are unique to unified-memory Apple Silicon and cannot be collected on any other platform.

/// Unified memory bandwidth sample. CPU and GPU share the same physical pool —
/// a game that saturates bandwidth will stutter even if GPU utilization looks fine.
struct MemoryBandwidthSample: Codable, Sendable {
    let elapsedSec:   Double
    let readGBps:     Double
    let writeGBps:    Double
    let totalGBps:    Double
    /// Percentage of theoretical peak bandwidth (M4 = ~120 GB/s, M4 Pro = ~273 GB/s).
    let saturatedPct: Double
}

/// GPU command buffer gap — idle time between end of one buffer and start of the next.
/// Gaps > 2ms indicate over-synchronization: GPTK is translating D3D barriers into Metal
/// fences that the GPU is already past. These bubbles are invisible to fps meters.
struct CommandBufferGap: Codable, Sendable {
    let elapsedSec: Double
    let gapMs:      Double
}

/// Apple Neural Engine activity sample. ANE contention from background tasks
/// (Siri, Photos ML, Spotlight) can cause frame spikes in games using MetalFX or
/// any ANE-adjacent compute path.
struct ANESample: Codable, Sendable {
    let elapsedSec: Double
    let aneWatts:   Double
    let active:     Bool
}

/// P-core vs E-core scheduling sample for GPTK translation threads.
/// Translation work must stay on P-cores; E-core demotion under thermal pressure
/// tanks frame times without any visible signal in fps counters.
struct CoreSchedulingSample: Codable, Sendable {
    let elapsedSec:              Double
    let gptkThreadsOnPCore:      Int
    let gptkThreadsOnECore:      Int    // > 0 is a scheduling problem
    let thermalPressureLevel:    String // "nominal" | "fair" | "serious" | "critical"
}

/// Memory compression ratio sample. Apple Silicon's compressor is aggressive —
/// games with compressible memory (UI, audio) survive pressure better than those
/// with incompressible data (textures, random buffers). Compressor losing = swap imminent.
struct MemoryCompressionSample: Codable, Sendable {
    let elapsedSec:        Double
    let compressionRatio:  Double    // compressor_page_count / uncompressed equivalent
    let compressorLosing:  Bool      // true when swap pressure is building
}

/// WindowServer compositing overhead — time between Metal gpuEndTime and actual display vsync.
/// On Windows, games write directly to the display. On macOS, WindowServer always composites.
/// This delta is irreducible overhead unique to Mac.
struct DisplayLatencySample: Codable, Sendable {
    let elapsedSec:       Double
    let gpuEndToVsyncMs:  Double    // Metal done → next vsync
    let windowServerMs:   Double    // estimated WS compositing slice
}

// MARK: - Protocol Test Results
// These are run as part of the 30-min vcertify-run test protocol, not during live gameplay.

/// Result of sleep/wake cycle test. Metal resources can be evicted on suspend.
/// No other compatibility tool tests this.
struct SleepRecoveryResult: Codable, Sendable {
    let tested:              Bool
    let survived:            Bool
    let recoverySeconds:     Double?    // time from wake until game rendered a valid frame
    let metalResourcesValid: Bool?      // false = GPU resources corrupted on wake
    let notes:               String?
}

/// Audio/video sync measurement. Wine routes DirectSound/XAudio2 through CoreAudio.
/// Drift > 50ms is perceptible; > 100ms is disqualifying for rhythm/music games.
struct AudioSyncResult: Codable, Sendable {
    let tested:      Bool
    let sampleCount: Int
    let avgDriftMs:  Double?
    let maxDriftMs:  Double?
    /// "excellent" (<16ms) | "good" (<33ms) | "fair" (<66ms) | "poor" (>66ms)
    let rating:      String?
}

/// End-to-end input latency: HID event → Wine input stack → game logic → rendered frame.
/// Measured by correlating input timestamps with the first frame showing a visible response.
struct InputLatencyResult: Codable, Sendable {
    let tested:        Bool
    let sampleCount:   Int
    let deviceType:    String?   // "keyboard" | "mouse" | "controller"
    let avgMs:         Double?
    let p95Ms:         Double?
    /// Overhead attributable to Wine/GPTK input translation vs a native macOS app baseline.
    let gptkOverheadMs: Double?
}

/// Shader/PSO cache wipe recovery. Users hit this after every macOS update.
/// We delete the Metal shader cache mid-run and measure re-warmup duration.
struct CacheRecoveryResult: Codable, Sendable {
    let tested:              Bool
    let reWarmupMinutes:     Double?   // time until stutter-free after cache wipe
    let stutterDuringWarmup: Bool?
    let avgFPSDuringWarmup:  Double?   // fps while re-warming — is it still playable?
}

/// Result of testing on one display configuration.
struct DisplayMatrixEntry: Codable, Sendable {
    /// "builtin" | "external-thunderbolt-4k" | "external-hdmi-4k" | "external-ultrawide"
    let displayType:   String
    let resolutionDesc: String
    let refreshHz:     Double
    /// "ok" | "degraded" | "failed"
    let result:        String
    let notes:         String?

    enum CodingKeys: String, CodingKey {
        case displayType    = "display_type"
        case resolutionDesc = "resolution"
        case refreshHz      = "refresh_hz"
        case result, notes
    }
}

/// One step in the memory pressure ladder test.
/// We simulate constrained RAM using mach_vm_allocate to fill the pool,
/// revealing whether the game's stated minimum RAM is actually sufficient.
struct MemoryPressureLadderEntry: Codable, Sendable {
    let simulatedGB:  Int       // available RAM headroom we allowed
    let survived:     Bool
    let notes:        String?   // optional observations (OOM kill reason, crash message, etc.)
    let avgFPS:       Double?
    let crashedAt:    Double?   // elapsed seconds if game crashed

    enum CodingKeys: String, CodingKey {
        case simulatedGB = "simulated_gb"
        case survived, notes
        case avgFPS    = "avg_fps"
        case crashedAt = "crashed_at_sec"
    }
}

/// Result of one GPTK version crossover test.
/// Same binary, different GPTK dylib — reveals which version actually runs best.
struct GPTKVersionResult: Codable, Sendable {
    let gptkVersion:     String
    let gptkDylibSHA256: String
    let avgFPS:          Double?
    let p1FPS:           Double?
    let crashesPerHour:  Double?
    /// "faster" | "same" | "slower" | "broken" — relative to the primary certified version
    let relativeRating:  String?

    enum CodingKeys: String, CodingKey {
        case gptkVersion     = "gptk_version"
        case gptkDylibSHA256 = "gptk_dylib_sha256"
        case avgFPS          = "avg_fps"
        case p1FPS           = "p1_fps"
        case crashesPerHour  = "crashes_per_hour"
        case relativeRating  = "relative_rating"
    }
}

// MARK: - Recorder

final class CertificationRunRecorder: @unchecked Sendable {

    private let device:    MTLDevice
    let gameSlug:          String
    let toolStack:         ToolStack

    // Frame time log (appended from MTLCommandBuffer completion handlers)
    private var frameTimes    = [Double]()
    private var fpsTimeline   = [FPSSnapshot]()
    private var shaderEvents  = [ShaderEvent]()
    private var powerSamples  = [PowerSample]()
    private var memorySamples = [MemorySample]()
    private var cadenceSlips  = [Double]()
    private var crashEvents   = [CrashEvent]()

    // Apple Silicon specific samples
    private var memoryBandwidthSamples:   [MemoryBandwidthSample]   = []
    private var commandBufferGaps:        [CommandBufferGap]         = []
    private var aneSamples:               [ANESample]                = []
    private var coreSchedulingSamples:    [CoreSchedulingSample]     = []
    private var memoryCompressionSamples: [MemoryCompressionSample]  = []
    private var displayLatencySamples:    [DisplayLatencySample]     = []

    // Protocol test results (set externally by vcertify-run CLI after each sub-test)
    var sleepRecovery:        SleepRecoveryResult?     = nil
    var audioSync:            AudioSyncResult?          = nil
    var inputLatency:         InputLatencyResult?       = nil
    var cacheRecovery:        CacheRecoveryResult?      = nil
    var displayMatrix:        [DisplayMatrixEntry]      = []
    var memoryPressureLadder: [MemoryPressureLadderEntry] = []
    var gptkVersionMatrix:    [GPTKVersionResult]       = []

    private let lock = NSLock()
    private var startDate: Date?
    private var samplerTimer: DispatchSourceTimer?
    private var powermetricsProcess: Process?
    private var powerPipe: Pipe?

    // Command buffer gap tracking
    private var lastCommandBufferEndTime: CFTimeInterval = 0

    private var isColdCachePhase = true    // true until first-launch stutter settles

    init(device: MTLDevice, gameSlug: String, toolStack: ToolStack) {
        self.device    = device
        self.gameSlug  = gameSlug
        self.toolStack = toolStack
    }

    // MARK: - Start / Stop

    func start() {
        startDate = Date()
        startSamplingTimer()
        startPowermetrics()
        NSLog("[CertificationRunRecorder] Started run for '\(gameSlug)'")
    }

    func stop() -> RawCertificationRun {
        let elapsed = Date().timeIntervalSince(startDate ?? Date())
        samplerTimer?.cancel()
        samplerTimer = nil
        stopPowermetrics()

        let (label, fingerprint) = Self.captureHardwareIdentity()

        lock.lock()
        var run = RawCertificationRun(
            gameSlug:                 gameSlug,
            capturedAt:               startDate ?? Date(),
            durationSec:              elapsed,
            frameTimes:               frameTimes,
            fpsTimeline:              fpsTimeline,
            shaderEvents:             shaderEvents,
            powerSamples:             powerSamples,
            memorySamples:            memorySamples,
            cadenceSlips:             cadenceSlips,
            crashEvents:              crashEvents,
            toolStack:                toolStack,
            memoryBandwidthSamples:   memoryBandwidthSamples,
            commandBufferGaps:        commandBufferGaps,
            aneSamples:               aneSamples,
            coreSchedulingSamples:    coreSchedulingSamples,
            memoryCompressionSamples: memoryCompressionSamples,
            displayLatencySamples:    displayLatencySamples,
            sleepRecovery:            sleepRecovery,
            audioSync:                audioSync,
            inputLatency:             inputLatency,
            cacheRecovery:            cacheRecovery,
            displayMatrix:            displayMatrix,
            memoryPressureLadder:     memoryPressureLadder,
            gptkVersionMatrix:        gptkVersionMatrix,
            hardwareLabel:            label,
            machineFingerprint:       fingerprint,
            runID:                    "")
        lock.unlock()

        if let id = try? RawCertificationRun.computeRunID(for: run) {
            run = RawCertificationRun(
                gameSlug:                 run.gameSlug,
                capturedAt:               run.capturedAt,
                durationSec:              run.durationSec,
                frameTimes:               run.frameTimes,
                fpsTimeline:              run.fpsTimeline,
                shaderEvents:             run.shaderEvents,
                powerSamples:             run.powerSamples,
                memorySamples:            run.memorySamples,
                cadenceSlips:             run.cadenceSlips,
                crashEvents:              run.crashEvents,
                toolStack:                run.toolStack,
                memoryBandwidthSamples:   run.memoryBandwidthSamples,
                commandBufferGaps:        run.commandBufferGaps,
                aneSamples:               run.aneSamples,
                coreSchedulingSamples:    run.coreSchedulingSamples,
                memoryCompressionSamples: run.memoryCompressionSamples,
                displayLatencySamples:    run.displayLatencySamples,
                sleepRecovery:            run.sleepRecovery,
                audioSync:                run.audioSync,
                inputLatency:             run.inputLatency,
                cacheRecovery:            run.cacheRecovery,
                displayMatrix:            run.displayMatrix,
                memoryPressureLadder:     run.memoryPressureLadder,
                gptkVersionMatrix:        run.gptkVersionMatrix,
                hardwareLabel:            run.hardwareLabel,
                machineFingerprint:       run.machineFingerprint,
                runID:                    id)
        }

        NSLog("[CertificationRunRecorder] Stopped. \(frameTimes.count) frames over \(Int(elapsed))s  runID=\(run.runID.prefix(12))…")
        return run
    }

    // MARK: - Hardware identity

    private static func captureHardwareIdentity() -> (label: String, fingerprint: String) {
        let model    = sysctlString("hw.model")         ?? "unknown"
        let memBytes = sysctlUInt64("hw.memsize")       ?? 0
        let cpuBrand = sysctlString("machdep.cpu.brand_string") ?? ""
        let memGB    = memBytes / (1024 * 1024 * 1024)

        // Human-readable label: "Apple M4 · 16 GB  (Mac mini)"
        let label = "\(cpuBrand.isEmpty ? model : cpuBrand) · \(memGB) GB  (\(model))"

        // Fingerprint: SHA-256 of stable inputs — not personally identifying
        let input = "\(model)|\(memBytes)".data(using: .utf8) ?? Data()
        let digest = SHA256.hash(data: input)
        let fingerprint = digest.map { String(format: "%02x", $0) }.joined()

        return (label, fingerprint)
    }

    private static func sysctlString(_ name: String) -> String? {
        var size = 0
        sysctlbyname(name, nil, &size, nil, 0)
        guard size > 0 else { return nil }
        var buf = [CChar](repeating: 0, count: size)
        sysctlbyname(name, &buf, &size, nil, 0)
        return String(cString: buf)
    }

    private static func sysctlUInt64(_ name: String) -> UInt64? {
        var value: UInt64 = 0
        var size = MemoryLayout<UInt64>.size
        sysctlbyname(name, &value, &size, nil, 0)
        return value > 0 ? value : nil
    }

    // MARK: - MTLCommandBuffer Frame Capture
    //
    // Attach this to every command buffer the game's Metal layer submits.
    // In Velocity, the Metal compositor layer routes all game command buffers
    // through a single submission point — hook there.
    //
    // Call site: wherever Velocity's Metal layer calls commandBuffer.commit()
    //   recorder.attachCompletionHandler(to: commandBuffer)

    func attachCompletionHandler(to buffer: MTLCommandBuffer) {
        buffer.addCompletedHandler { [weak self] cb in
            guard let self else { return }
            let frameMs = (cb.gpuEndTime - cb.gpuStartTime) * 1000.0
            let elapsed = Date().timeIntervalSince(self.startDate ?? Date())

            self.lock.lock()
            defer { self.lock.unlock() }

            // GPU command buffer gap detection.
            // Gaps > 2ms between end of one buffer and start of the next indicate
            // over-synchronization — GPTK is inserting Metal fences the GPU has already passed.
            // These bubbles are invisible to fps counters but cause latency and stutters.
            if self.lastCommandBufferEndTime > 0 {
                let gapMs = (cb.gpuStartTime - self.lastCommandBufferEndTime) * 1000.0
                if gapMs > 2.0 {
                    self.commandBufferGaps.append(CommandBufferGap(
                        elapsedSec: elapsed,
                        gapMs:      gapMs))
                }
            }
            self.lastCommandBufferEndTime = cb.gpuEndTime

            self.frameTimes.append(frameMs)

            // Classify stall type:
            // "shader" — long stalls (>500ms) during cold cache phase = GLSL/MSL compilation
            // "pso"    — shorter stalls (50–500ms) or warm-cache stalls = pipeline state object creation
            // PSO stalls recur throughout a session as the game hits new draw-call state combinations.
            // Shader stalls concentrate at cold-cache launch and don't recur once the cache is warm.
            if frameMs > 50 {
                let stallType = (frameMs > 500 && self.isColdCachePhase) ? "shader" : "pso"
                self.shaderEvents.append(ShaderEvent(
                    elapsedSec:    elapsed,
                    compilationMs: frameMs,
                    isColdCache:   self.isColdCachePhase,
                    type:          stallType))
            }
        }
    }

    // MARK: - 1Hz Sampling Timer

    private func startSamplingTimer() {
        let timer = DispatchSource.makeTimerSource(queue: .global(qos: .utility))
        timer.schedule(deadline: .now(), repeating: .seconds(1))
        timer.setEventHandler { [weak self] in self?.takeSample() }
        timer.resume()
        samplerTimer = timer
    }

    private func takeSample() {
        guard let start = startDate else { return }
        let elapsed = Date().timeIntervalSince(start)

        let fps = rollingFPS(windowSec: 1.0)
        let mem = sampleMemory()
        let compression = sampleMemoryCompression()
        let coreSchedule = sampleCoreScheduling(elapsed: elapsed)

        lock.lock()
        defer { lock.unlock() }

        fpsTimeline.append(FPSSnapshot(elapsedSec: elapsed, fps: fps))

        if let m = mem {
            memorySamples.append(MemorySample(
                elapsedSec:      elapsed,
                compressorPages: m.compressorPages,
                swapIns:         m.swapIns,
                swapOuts:        m.swapOuts,
                gameMemoryMB:    m.gameMemoryMB))
        }

        if let c = compression {
            memoryCompressionSamples.append(MemoryCompressionSample(
                elapsedSec:       elapsed,
                compressionRatio: c.ratio,
                compressorLosing: c.losing))
        }

        if let cs = coreSchedule {
            coreSchedulingSamples.append(cs)
        }

        // Cold-cache phase ends when shader stutter rate drops to baseline.
        if isColdCachePhase && elapsed > 30 {
            let recentEvents = shaderEvents.filter { $0.elapsedSec > elapsed - 60 }
            if recentEvents.isEmpty { isColdCachePhase = false }
        }
    }

    // MARK: - Apple Silicon Specific Samplers

    private struct CompressionStats {
        let ratio:  Double
        let losing: Bool
    }

    private func sampleMemoryCompression() -> CompressionStats? {
        var vmInfo = vm_statistics64()
        var count  = mach_msg_type_number_t(MemoryLayout<vm_statistics64>.size / MemoryLayout<integer_t>.size)
        let result = withUnsafeMutablePointer(to: &vmInfo) { ptr in
            ptr.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { buf in
                host_statistics64(mach_host_self(), HOST_VM_INFO64, buf, &count)
            }
        }
        guard result == KERN_SUCCESS else { return nil }

        let compressed = Double(vmInfo.compressor_page_count)
        let wired      = Double(vmInfo.wire_count)
        guard compressed > 0 else { return nil }

        // Rough compression ratio: compressor holds N pages that represent ~2–4x uncompressed.
        // When swapouts increase the compressor is losing — it can't compress fast enough.
        let ratio  = compressed > 0 ? (compressed + wired) / compressed : 1.0
        let losing = vmInfo.swapouts > 0

        return CompressionStats(ratio: ratio, losing: losing)
    }

    /// Sample GPTK translation thread QoS to detect E-core demotion under thermal pressure.
    /// When the scheduler moves translation threads to E-cores, frame times spike without
    /// any visible signal in fps counters or GPU metrics.
    private func sampleCoreScheduling(elapsed: Double) -> CoreSchedulingSample? {
        // Read thermal pressure level from IOKit
        let thermalLevel = Self.thermalPressureLevel()

        // Thread QoS sampling: query the current process's threads and check their QoS class.
        // Translation threads should be .userInteractive or .userInitiated (P-core eligible).
        // E-core demotion happens when QoS drops to .utility or .background under pressure.
        var threadList: thread_act_array_t?
        var threadCount: mach_msg_type_number_t = 0
        let kr = task_threads(mach_task_self_, &threadList, &threadCount)
        guard kr == KERN_SUCCESS, let threads = threadList else { return nil }
        defer {
            for i in 0..<Int(threadCount) { mach_port_deallocate(mach_task_self_, threads[i]) }
            vm_deallocate(mach_task_self_, vm_address_t(bitPattern: threads),
                          vm_size_t(Int(threadCount) * MemoryLayout<thread_act_t>.size))
        }

        var pCoreCount = 0
        var eCoreCount = 0
        for i in 0..<Int(threadCount) {
            var policy = thread_extended_policy(timeshare: 0)
            var count  = mach_msg_type_number_t(MemoryLayout<thread_extended_policy>.size / MemoryLayout<integer_t>.size)
            let r = withUnsafeMutablePointer(to: &policy) { ptr in
                ptr.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { buf in
                    thread_policy_get(threads[i], thread_policy_flavor_t(THREAD_EXTENDED_POLICY), buf, &count, nil)
                }
            }
            if r == KERN_SUCCESS {
                // timeshare = 1 means eligible for P-cores; 0 = fixed/E-core only
                if policy.timeshare != 0 { pCoreCount += 1 } else { eCoreCount += 1 }
            }
        }

        return CoreSchedulingSample(
            elapsedSec:           elapsed,
            gptkThreadsOnPCore:   pCoreCount,
            gptkThreadsOnECore:   eCoreCount,
            thermalPressureLevel: thermalLevel)
    }

    private static func thermalPressureLevel() -> String {
        // IOPMrootDomain exposes thermal pressure level
        let service = IOServiceGetMatchingService(kIOMainPortDefault,
                        IOServiceMatching("IOPMrootDomain"))
        defer { if service != 0 { IOObjectRelease(service) } }
        guard service != 0 else { return "nominal" }
        let key = "thermalState" as CFString
        if let val = IORegistryEntryCreateCFProperty(service, key, kCFAllocatorDefault, 0)?
                        .takeRetainedValue() as? Int {
            switch val {
            case 0:  return "nominal"
            case 1:  return "fair"
            case 2:  return "serious"
            default: return "critical"
            }
        }
        return "nominal"
    }

    /// Record a display latency sample from the Metal compositor layer.
    /// Call this from the CADisplayLink callback with the time the display will refresh.
    /// gpuEndTime is the timestamp from the last completed MTLCommandBuffer.
    func recordDisplayLatency(gpuEndTime: CFTimeInterval, nextVsync: CFTimeInterval, elapsed: Double) {
        let gpuToVsync = max(0, (nextVsync - gpuEndTime) * 1000.0)
        // WindowServer typically takes 1–4ms of the gap between GPU done and vsync.
        // Estimate: anything beyond a single refresh interval overhead is WS compositing.
        let refreshMs   = 1000.0 / 120.0   // conservative; actual refresh queried at start
        let windowServerMs = max(0, gpuToVsync - refreshMs)
        lock.lock()
        displayLatencySamples.append(DisplayLatencySample(
            elapsedSec:      elapsed,
            gpuEndToVsyncMs: gpuToVsync,
            windowServerMs:  windowServerMs))
        lock.unlock()
    }

    /// Record a memory bandwidth sample. Call from the IOReport callback in vcertify-run.
    /// In-app use is limited — IOReport requires privileged entitlements; the daemon has them.
    func recordMemoryBandwidth(readGBps: Double, writeGBps: Double, theoreticalMaxGBps: Double, elapsed: Double) {
        let total = readGBps + writeGBps
        let saturatedPct = theoreticalMaxGBps > 0 ? (total / theoreticalMaxGBps) * 100.0 : 0
        lock.lock()
        memoryBandwidthSamples.append(MemoryBandwidthSample(
            elapsedSec:   elapsed,
            readGBps:     readGBps,
            writeGBps:    writeGBps,
            totalGBps:    total,
            saturatedPct: saturatedPct))
        lock.unlock()
    }

    /// Record an ANE activity sample. Call from the IOReport/powermetrics callback.
    func recordANESample(watts: Double, elapsed: Double) {
        lock.lock()
        aneSamples.append(ANESample(elapsedSec: elapsed, aneWatts: watts, active: watts > 0.1))
        lock.unlock()
    }

    // Compute fps over the last `windowSec` seconds of frame time data
    private func rollingFPS(windowSec: Double) -> Double {
        lock.lock()
        defer { lock.unlock() }
        guard !frameTimes.isEmpty else { return 0 }
        // Sum frame times until we fill the window
        var windowMs = windowSec * 1000
        var count = 0
        for ft in frameTimes.reversed() {
            windowMs -= ft
            count += 1
            if windowMs <= 0 { break }
        }
        guard count > 0 else { return 0 }
        return Double(count) / windowSec
    }

    // MARK: - Memory Pressure (host_statistics64)

    private struct MemStats {
        let compressorPages: UInt64
        let swapIns:         UInt64
        let swapOuts:        UInt64
        let gameMemoryMB:    Double
    }

    private func sampleMemory() -> MemStats? {
        var vmInfo  = vm_statistics64()
        var count   = mach_msg_type_number_t(MemoryLayout<vm_statistics64>.size / MemoryLayout<integer_t>.size)
        let result  = withUnsafeMutablePointer(to: &vmInfo) { ptr in
            ptr.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { buf in
                host_statistics64(mach_host_self(), HOST_VM_INFO64, buf, &count)
            }
        }
        guard result == KERN_SUCCESS else { return nil }

        // Game memory: use Metal device's currentAllocatedSize as the GPU resource footprint
        let gameMemMB = Double(device.currentAllocatedSize) / (1024 * 1024)

        return MemStats(
            compressorPages: UInt64(vmInfo.compressor_page_count),
            swapIns:         UInt64(vmInfo.swapins),
            swapOuts:        UInt64(vmInfo.swapouts),
            gameMemoryMB:    gameMemMB)
    }

    // MARK: - Power (powermetrics subprocess)
    //
    // powermetrics requires root or the com.apple.private.iokit.powermetrics entitlement.
    // For the test harness (run from a developer workstation), sudo is acceptable.
    // The vcertify-run CLI runs with appropriate privileges.

    private func startPowermetrics() {
        let proc = Process()
        let pipe = Pipe()

        proc.executableURL = URL(fileURLWithPath: "/usr/bin/powermetrics")
        proc.arguments = [
            "--samplers", "gpu_power,cpu_power,ane_power",
            "-i", "1000",       // 1Hz
            "--format", "plist"
        ]
        proc.standardOutput = pipe
        proc.standardError  = FileHandle.nullDevice

        pipe.fileHandleForReading.readabilityHandler = { [weak self] fh in
            let data = fh.availableData
            guard let self, !data.isEmpty else { return }
            self.parsePowermetricsChunk(data)
        }

        do {
            try proc.run()
            powermetricsProcess = proc
            powerPipe           = pipe
            NSLog("[CertificationRunRecorder] powermetrics started (PID \(proc.processIdentifier))")
        } catch {
            NSLog("[CertificationRunRecorder] powermetrics failed to start: \(error.localizedDescription)")
            NSLog("[CertificationRunRecorder] Power samples will be absent — run vcertify with sudo for power data")
        }
    }

    private func stopPowermetrics() {
        powerPipe?.fileHandleForReading.readabilityHandler = nil
        powermetricsProcess?.terminate()
        powermetricsProcess = nil
        powerPipe = nil
    }

    private func parsePowermetricsChunk(_ data: Data) {
        // powermetrics --format plist emits one plist document per sample separated by NUL bytes.
        // Split on NUL and parse each complete plist.
        let chunks = data.split(separator: 0, omittingEmptySubsequences: true)
        for chunk in chunks {
            guard let dict = try? PropertyListSerialization.propertyList(
                from: Data(chunk), format: nil) as? [String: Any] else { continue }

            let elapsed = Date().timeIntervalSince(startDate ?? Date())
            let gpu = (dict["gpu_power"] as? Double) ?? 0
            let cpu = (dict["cpu_power"] as? Double) ?? 0
            let ane = (dict["ane_power"] as? Double) ?? 0
            let pkg = cpu + gpu + ane

            lock.lock()
            powerSamples.append(PowerSample(
                elapsedSec:   elapsed,
                packageWatts: pkg,
                cpuWatts:     cpu,
                gpuWatts:     gpu))
            aneSamples.append(ANESample(
                elapsedSec: elapsed,
                aneWatts:   ane,
                active:     ane > 0.1))
            lock.unlock()
        }
    }

    // MARK: - Crash Recording
    //
    // Called by DaemonSession when it observes the game process exit unexpectedly.
    // The type string is determined by the exit code / signal / last Metal error.

    func recordCrash(type: String) {
        let elapsed = Date().timeIntervalSince(startDate ?? Date())
        lock.lock()
        crashEvents.append(CrashEvent(elapsedSec: elapsed, type: type))
        lock.unlock()
        NSLog("[CertificationRunRecorder] Crash recorded: \(type) at \(Int(elapsed))s")
    }

    // MARK: - ProMotion Cadence (MacBook Pro only)
    //
    // Wire this into a CADisplayLink in the Metal compositor layer.
    // Call it from the displayLink callback.

    private var lastDisplayLinkTimestamp: Double = 0

    func recordDisplayLinkFire(timestamp: Double, targetTimestamp: Double) {
        let expectedInterval = targetTimestamp - timestamp
        if lastDisplayLinkTimestamp > 0 {
            let actualInterval = timestamp - lastDisplayLinkTimestamp
            let slip = abs(actualInterval - expectedInterval) * 1000   // convert to ms
            lock.lock()
            cadenceSlips.append(slip)
            lock.unlock()
        }
        lastDisplayLinkTimestamp = timestamp
    }
}

// MARK: - Run Analysis
//
// Reduces a RawCertificationRun to the numbers that go in the manifest.

struct CertificationRunAnalysis {

    let run: RawCertificationRun

    /// P50/P95/P99/max frame times and stutter count for a time window.
    func frameStats(fromSec: Double, toSec: Double) -> ManifestFrameStats {
        let subset = timeslice(frameTimes: run.frameTimes, fromSec: fromSec, toSec: toSec)
        guard !subset.isEmpty else {
            return ManifestFrameStats(avgFPS: nil, p50FrameMs: nil, p95FrameMs: nil,
                                      p99FrameMs: nil, maxFrameMs: nil, stutterCount: nil)
        }
        let sorted    = subset.sorted()
        let median    = sorted[sorted.count / 2]
        let stutter   = subset.filter { $0 > median * 2 }.count
        let avg       = subset.reduce(0, +) / Double(subset.count)
        return ManifestFrameStats(
            avgFPS:       1000.0 / avg,
            p50FrameMs:   percentile(sorted, 0.50),
            p95FrameMs:   percentile(sorted, 0.95),
            p99FrameMs:   percentile(sorted, 0.99),
            maxFrameMs:   sorted.last,
            stutterCount: stutter)
    }

    /// FPS at elapsed minute marks (for thermal profile).
    func fpsAt(minutes: Double) -> Double? {
        let target = minutes * 60
        let window = 30.0    // average over a 30s window around the target
        let snaps  = run.fpsTimeline.filter { abs($0.elapsedSec - target) < window }
        guard !snaps.isEmpty else { return nil }
        return snaps.map(\.fps).reduce(0, +) / Double(snaps.count)
    }

    /// Average package watts over the run.
    var avgPackageWatts: Double? {
        guard !run.powerSamples.isEmpty else { return nil }
        return run.powerSamples.map(\.packageWatts).reduce(0, +) / Double(run.powerSamples.count)
    }

    var peakPackageWatts: Double? { run.powerSamples.map(\.packageWatts).max() }

    var joulesPerFrame: Double? {
        guard let watts = avgPackageWatts, let fps = avgFPS, fps > 0 else { return nil }
        return watts / fps
    }

    var avgFPS: Double? {
        guard !run.frameTimes.isEmpty else { return nil }
        let avg = run.frameTimes.reduce(0, +) / Double(run.frameTimes.count)
        return avg > 0 ? 1000.0 / avg : nil
    }

    var shaderCompilationSummary: (firstLaunchCount: Int, firstLaunchTotalMs: Double,
                                    cachedCount: Int, cachedTotalMs: Double,
                                    warmupMinutes: Double) {
        let cold  = run.shaderEvents.filter { $0.isColdCache && $0.type == "shader" }
        let warm  = run.shaderEvents.filter { !$0.isColdCache && $0.type == "shader" }
        let warmupSec = cold.last.map { $0.elapsedSec } ?? 0
        return (cold.count, cold.map(\.compilationMs).reduce(0, +),
                warm.count, warm.map(\.compilationMs).reduce(0, +),
                warmupSec / 60)
    }

    /// PSO stall summary — pipeline state object creation stalls, distinct from shader compilation.
    /// These recur throughout the session as the game hits new draw-call state combinations.
    var psoStallSummary: (count: Int, totalMs: Double, avgMs: Double) {
        let pso = run.shaderEvents.filter { $0.type == "pso" }
        let total = pso.map(\.compilationMs).reduce(0, +)
        let avg   = pso.isEmpty ? 0 : total / Double(pso.count)
        return (pso.count, total, avg)
    }

    // MARK: - Apple Silicon Derived Metrics

    /// Average memory bandwidth saturation over the run.
    /// > 80% sustained = bandwidth is the bottleneck, not GPU compute.
    var avgMemoryBandwidthSaturationPct: Double? {
        guard !run.memoryBandwidthSamples.isEmpty else { return nil }
        return run.memoryBandwidthSamples.map(\.saturatedPct).reduce(0, +)
               / Double(run.memoryBandwidthSamples.count)
    }

    var peakMemoryBandwidthSaturationPct: Double? {
        run.memoryBandwidthSamples.map(\.saturatedPct).max()
    }

    /// GPU command buffer gaps: total count, average gap, and max gap.
    /// Large avg gap = persistent over-synchronization in GPTK barrier translation.
    var gpuBubbleSummary: (count: Int, avgMs: Double, maxMs: Double) {
        let gaps = run.commandBufferGaps
        guard !gaps.isEmpty else { return (0, 0, 0) }
        let avg = gaps.map(\.gapMs).reduce(0, +) / Double(gaps.count)
        let max = gaps.map(\.gapMs).max() ?? 0
        return (gaps.count, avg, max)
    }

    /// Whether ANE was active during the run, and what fraction of samples showed activity.
    var aneActivitySummary: (wasActive: Bool, activePct: Double, peakWatts: Double) {
        let active = run.aneSamples.filter { $0.active }
        let pct    = run.aneSamples.isEmpty ? 0 : Double(active.count) / Double(run.aneSamples.count) * 100
        let peak   = run.aneSamples.map(\.aneWatts).max() ?? 0
        return (!active.isEmpty, pct, peak)
    }

    /// Fraction of sampled time where GPTK threads were demoted to E-cores.
    /// Any non-zero value is a scheduling problem — translation work must stay on P-cores.
    var eCoreContentionPct: Double? {
        let samples = run.coreSchedulingSamples
        guard !samples.isEmpty else { return nil }
        let demoted = samples.filter { $0.gptkThreadsOnECore > 0 }
        return Double(demoted.count) / Double(samples.count) * 100.0
    }

    /// Average WindowServer compositing overhead per frame.
    var avgWindowServerMs: Double? {
        guard !run.displayLatencySamples.isEmpty else { return nil }
        return run.displayLatencySamples.map(\.windowServerMs).reduce(0, +)
               / Double(run.displayLatencySamples.count)
    }

    /// Whether the memory compressor was losing (unable to keep up) during any part of the run.
    var compressionStress: Bool {
        run.memoryCompressionSamples.contains { $0.compressorLosing }
    }

    var promotionAligned: Bool? {
        guard !run.cadenceSlips.isEmpty else { return nil }
        let avg = run.cadenceSlips.reduce(0, +) / Double(run.cadenceSlips.count)
        return avg < 0.5   // <0.5ms avg slip = aligned
    }

    var peakMemoryPressure: String {
        let maxSwap = run.memorySamples.map(\.swapIns).max() ?? 0
        let maxComp = run.memorySamples.map(\.compressorPages).max() ?? 0
        if maxSwap > 0 { return "critical" }
        if maxComp > 10_000 { return "warning" }
        return "normal"
    }

    /// Crashes per hour, derived from crash events recorded during the run.
    var crashesPerHour: Double {
        guard run.durationSec > 0 else { return 0 }
        return Double(run.crashEvents.count) / (run.durationSec / 3600.0)
    }

    /// Types of crashes observed (deduplicated).
    var observedCrashTypes: [String] {
        Array(Set(run.crashEvents.map(\.type))).sorted()
    }

    /// Rate of game memory growth in MB per hour, computed from Metal allocation deltas.
    /// A non-zero value suggests a memory leak in the game or GPTK translation layer.
    var memoryGrowthMBPerHour: Double? {
        guard run.memorySamples.count >= 2 else { return nil }
        let first = run.memorySamples.first!.gameMemoryMB
        let last  = run.memorySamples.last!.gameMemoryMB
        let hours = run.durationSec / 3600.0
        guard hours > 0 else { return nil }
        return (last - first) / hours
    }

    /// Peak swap usage observed, in GB. Non-zero indicates the system hit memory pressure
    /// severe enough to write to the SSD — significant for unified memory Macs.
    var swapHighWaterGB: Double? {
        // swapOuts accumulates over the run — peak delta gives us high-water mark
        let pageSize = Double(vm_page_size)   // typically 16 KB on Apple Silicon
        let maxSwapOuts = run.memorySamples.map(\.swapOuts).max() ?? 0
        let firstSwapOuts = run.memorySamples.first?.swapOuts ?? 0
        let deltaPages = Double(maxSwapOuts - firstSwapOuts)
        guard deltaPages > 0 else { return nil }
        return (deltaPages * pageSize) / (1024 * 1024 * 1024)
    }

    // MARK: - Helpers

    private func timeslice(frameTimes: [Double], fromSec: Double, toSec: Double) -> [Double] {
        // Reconstruct time axis from frame times (each frame time = elapsed ms)
        var elapsed = 0.0
        var result  = [Double]()
        for ft in frameTimes {
            elapsed += ft / 1000.0
            if elapsed >= fromSec && elapsed <= toSec {
                result.append(ft)
            }
            if elapsed > toSec { break }
        }
        return result
    }

    private func percentile(_ sorted: [Double], _ p: Double) -> Double {
        guard !sorted.isEmpty else { return 0 }
        let idx = Int(Double(sorted.count - 1) * p)
        return sorted[idx]
    }
}

// MARK: - Canonical JSON encoder (sorted keys, no pretty-print — stable bytes for signing)

extension JSONEncoder {
    static var canonical: JSONEncoder {
        let e = JSONEncoder()
        e.outputFormatting = [.sortedKeys]
        e.dateEncodingStrategy = .iso8601
        return e
    }
}
