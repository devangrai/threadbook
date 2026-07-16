import CryptoKit
import Foundation

public struct AliasFactory: Sendable {
    private let nonceKey: SymmetricKey

    public init(nonce: String) {
        nonceKey = SymmetricKey(data: Data(nonce.utf8))
    }

    public func assetAlias(localIdentifier: String) -> String {
        runAlias(context: "asset-v1", value: localIdentifier)
    }

    public func resourceAlias(binding: String) -> String {
        runAlias(context: "resource-v1", value: binding)
    }

    public func runAlias(context: String, value: String) -> String {
        let input = Data("p00-photokit-native:\(context):\(value)".utf8)
        let digest = HMAC<SHA256>.authenticationCode(for: input, using: nonceKey)
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    public static func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    public static func sha256Hex(fileURL: URL) throws -> String {
        let handle = try FileHandle(forReadingFrom: fileURL)
        defer { try? handle.close() }
        var digest = SHA256()
        while let data = try handle.read(upToCount: TransferStateMachine.maximumChunkBytes),
              !data.isEmpty {
            digest.update(data: data)
        }
        return digest.finalize().map { String(format: "%02x", $0) }.joined()
    }
}
