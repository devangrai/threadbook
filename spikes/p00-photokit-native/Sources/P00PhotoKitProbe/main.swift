import AppKit
import Darwin
import Foundation
import P00PhotoKitCore

func block(_ message: StaticString, status: Int32 = EX_CONFIG) -> Never {
    message.withUTF8Buffer { buffer in
        _ = write(STDERR_FILENO, buffer.baseAddress, buffer.count)
        _ = write(STDERR_FILENO, "\n", 1)
    }
    exit(status)
}

let environment = ProcessInfo.processInfo.environment
guard let nonce = environment[LiveChallenge.evidenceNonceEnvironmentKey],
      let rawChallenge = environment[LiveChallenge.challengeEnvironmentKey] else {
    block("P00 Photos live probe blocked: challenge environment is absent")
}

let challenge: LiveChallenge
do {
    challenge = try LiveChallenge(evidenceNonce: nonce, rawJSON: rawChallenge)
} catch {
    block("P00 Photos live probe blocked: challenge is invalid")
}

guard let executableURL = Bundle.main.executableURL,
      let bundleID = Bundle.main.bundleIdentifier else {
    block("P00 Photos live probe blocked: bundle identity is unavailable")
}

let executableSHA256: String
do {
    executableSHA256 = try AliasFactory.sha256Hex(fileURL: executableURL)
} catch {
    block("P00 Photos live probe blocked: executable cannot be verified")
}
guard bundleID == challenge.outputContract.bundleID,
      executableSHA256 == challenge.executableSHA256 else {
    block("P00 Photos live probe blocked: bundle does not match challenge")
}

let manager = FileManager.default
let supportDirectory: URL
do {
    supportDirectory = try manager.url(
        for: .applicationSupportDirectory,
        in: .userDomainMask,
        appropriateFor: nil,
        create: true
    ).standardizedFileURL
} catch {
    block("P00 Photos live probe blocked: container is unavailable")
}
let runsDirectory = supportDirectory
    .appendingPathComponent("P00PhotoKitNative", isDirectory: true)
do {
    try manager.createDirectory(
        at: runsDirectory,
        withIntermediateDirectories: true,
        attributes: [.posixPermissions: 0o700]
    )
    try manager.setAttributes(
        [.posixPermissions: 0o700],
        ofItemAtPath: runsDirectory.path
    )
} catch {
    block("P00 Photos live probe blocked: run parent cannot be created")
}

let approvedRunDirectory = runsDirectory
    .appendingPathComponent(challenge.runID, isDirectory: true)
    .standardizedFileURL

let outputStore: PrivateRunOutputStore
do {
    outputStore = try PrivateRunOutputStore(
        createFreshRunDirectory: approvedRunDirectory
    )
} catch {
    block("P00 Photos live probe blocked: run is not fresh", status: EX_CANTCREAT)
}

let aliases = AliasFactory(nonce: challenge.nonce)
let evidenceContext = LiveEvidenceContext(challenge: challenge)
let emitter = LiveRecordEmitter(nonce: challenge.nonce)
let application = NSApplication.shared
application.setActivationPolicy(.regular)
let viewController = ProbeViewController(
    challenge: challenge,
    evidenceContext: evidenceContext,
    emitter: emitter,
    aliases: aliases,
    outputStore: outputStore
)
let delegate = AppDelegate(viewController: viewController)
application.delegate = delegate
application.run()
