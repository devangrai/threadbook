import CoreFoundation
import Foundation
import WardrobePhotoKitObjC

enum NativeProtocol {
    static let version: UInt64 = 1
    static let maximumIdentifierBytes = 512
    static let maximumLabelBytes = 512
    static let maximumAssets = 500
    static let maximumAlbums = 100
    static let maximumResourceBytes = 40 * 1_024 * 1_024
    static let maximumPendingBinaryBytes = 8 * 1_024 * 1_024
    static let maximumConcurrentTransfers = 2
    static let binaryHeaderBytes = 80
}

struct OperationIdentity: Hashable {
    let operationID: UUID
    let enrollmentEpoch: UUID
    let reconciliationFence: UInt64
    let generation: UInt64
    let requestSequence: UInt64
}

enum NativeCommandKind: String {
    case inspectAuthorization = "inspect_authorization"
    case requestAuthorization = "request_authorization"
    case listAlbums = "list_albums"
    case enumerateAlbum = "enumerate_album"
    case streamResource = "stream_resource"
    case cancelOperation = "cancel_operation"
}

struct NativeCommand {
    let kind: NativeCommandKind
    let identity: OperationIdentity
    let albumIdentifier: String?
    let resourceToken: String?
    let allowNetwork: Bool?
}

enum ProtocolFailure: Error, Equatable {
    case invalidJSON
    case invalidShape
    case unknownField
    case missingField
    case invalidValue
}

enum StrictCommandDecoder {
    private static let commonKeys: Set<String> = [
        "protocol_version",
        "command",
        "operation_id",
        "enrollment_epoch",
        "reconciliation_fence",
        "generation",
        "sequence",
    ]

    static func decode(_ data: Data) -> Result<NativeCommand, ProtocolFailure> {
        let object: Any
        do {
            object = try JSONSerialization.jsonObject(
                with: data,
                options: [.fragmentsAllowed]
            )
        } catch {
            return .failure(.invalidJSON)
        }
        guard let dictionary = object as? [String: Any] else {
            return .failure(.invalidShape)
        }
        guard
            let commandName = strictString(dictionary["command"]),
            let kind = NativeCommandKind(rawValue: commandName)
        else {
            return .failure(.invalidValue)
        }

        var allowedKeys = commonKeys
        switch kind {
        case .enumerateAlbum:
            allowedKeys.insert("album_identifier")
        case .streamResource:
            allowedKeys.formUnion(["resource_token", "allow_network"])
        case .inspectAuthorization, .requestAuthorization, .listAlbums, .cancelOperation:
            break
        }
        guard Set(dictionary.keys).isSubset(of: allowedKeys) else {
            return .failure(.unknownField)
        }
        guard Set(dictionary.keys).isSuperset(of: commonKeys) else {
            return .failure(.missingField)
        }
        guard strictUInt64(dictionary["protocol_version"]) == NativeProtocol.version else {
            return .failure(.invalidValue)
        }
        guard
            let operationID = strictUUID(dictionary["operation_id"]),
            let enrollmentEpoch = strictUUID(dictionary["enrollment_epoch"]),
            let fence = strictUInt64(dictionary["reconciliation_fence"]),
            let generation = strictUInt64(dictionary["generation"]),
            let sequence = strictUInt64(dictionary["sequence"]),
            fence > 0,
            generation > 0,
            sequence > 0
        else {
            return .failure(.invalidValue)
        }

        var albumIdentifier: String?
        var resourceToken: String?
        var allowNetwork: Bool?
        if kind == .enumerateAlbum {
            guard let value = boundedIdentifier(dictionary["album_identifier"]) else {
                return .failure(.invalidValue)
            }
            albumIdentifier = value
        }
        if kind == .streamResource {
            guard
                let value = boundedResourceToken(dictionary["resource_token"]),
                let network = strictBool(dictionary["allow_network"])
            else {
                return .failure(.invalidValue)
            }
            resourceToken = value
            allowNetwork = network
        }

        return .success(
            NativeCommand(
                kind: kind,
                identity: OperationIdentity(
                    operationID: operationID,
                    enrollmentEpoch: enrollmentEpoch,
                    reconciliationFence: fence,
                    generation: generation,
                    requestSequence: sequence
                ),
                albumIdentifier: albumIdentifier,
                resourceToken: resourceToken,
                allowNetwork: allowNetwork
            )
        )
    }

    private static func strictString(_ value: Any?) -> String? {
        value as? String
    }

    private static func boundedIdentifier(_ value: Any?) -> String? {
        guard
            let string = strictString(value),
            !string.isEmpty,
            string.utf8.count <= NativeProtocol.maximumIdentifierBytes,
            !string.utf8.contains(0)
        else {
            return nil
        }
        return string
    }

    private static func boundedResourceToken(_ value: Any?) -> String? {
        guard
            let string = strictString(value),
            !string.isEmpty,
            string.utf8.count <= 128,
            string.utf8.allSatisfy({
                ($0 >= 0x30 && $0 <= 0x39)
                    || ($0 >= 0x61 && $0 <= 0x7a)
                    || $0 == 0x2d
            })
        else {
            return nil
        }
        return string
    }

    private static func strictUUID(_ value: Any?) -> UUID? {
        guard
            let string = strictString(value),
            string.utf8.count == 36,
            string == string.lowercased(),
            let uuid = UUID(uuidString: string),
            uuid.uuidString.lowercased() == string
        else {
            return nil
        }
        return uuid
    }

    private static func strictBool(_ value: Any?) -> Bool? {
        guard let number = value as? NSNumber else {
            return nil
        }
        guard CFGetTypeID(number) == CFBooleanGetTypeID() else {
            return nil
        }
        return number.boolValue
    }

    private static func strictUInt64(_ value: Any?) -> UInt64? {
        guard let number = value as? NSNumber else {
            return nil
        }
        guard CFGetTypeID(number) != CFBooleanGetTypeID() else {
            return nil
        }
        let decimal = number.stringValue
        guard
            !decimal.isEmpty,
            decimal.allSatisfy({ $0 >= "0" && $0 <= "9" }),
            let parsed = UInt64(decimal)
        else {
            return nil
        }
        return parsed
    }
}

enum ControlEventEncoder {
    static func encode(
        identity: OperationIdentity,
        event: String,
        fields: [String: Any] = [:]
    ) -> Data? {
        var object: [String: Any] = [
            "protocol_version": NativeProtocol.version,
            "event": event,
            "operation_id": identity.operationID.uuidString.lowercased(),
            "enrollment_epoch": identity.enrollmentEpoch.uuidString.lowercased(),
            "reconciliation_fence": identity.reconciliationFence,
            "generation": identity.generation,
            "sequence": identity.requestSequence,
        ]
        for (key, value) in fields {
            guard object[key] == nil else {
                return nil
            }
            object[key] = value
        }
        guard JSONSerialization.isValidJSONObject(object) else {
            return nil
        }
        guard
            let data = try? JSONSerialization.data(
                withJSONObject: object,
                options: [.sortedKeys]
            ),
            data.count <= Int(WK_PHOTOKIT_MAX_CONTROL_V1)
        else {
            return nil
        }
        return data
    }
}

enum BinaryChunkEncoder {
    static func encode(
        identity: OperationIdentity,
        chunkIndex: UInt64,
        bytes: Data
    ) -> Data? {
        guard
            !bytes.isEmpty,
            bytes.count <= Int(WK_PHOTOKIT_MAX_BINARY_V1)
                - NativeProtocol.binaryHeaderBytes
        else {
            return nil
        }
        var result = Data(capacity: NativeProtocol.binaryHeaderBytes + bytes.count)
        result.append(contentsOf: [0x57, 0x4b, 0x50, 0x42])
        append(UInt32(NativeProtocol.version), to: &result)
        append(UInt32(NativeProtocol.binaryHeaderBytes), to: &result)
        append(UInt32(0), to: &result)
        append(identity.requestSequence, to: &result)
        append(identity.reconciliationFence, to: &result)
        append(identity.generation, to: &result)
        append(chunkIndex, to: &result)
        append(uuid: identity.operationID, to: &result)
        append(uuid: identity.enrollmentEpoch, to: &result)
        result.append(bytes)
        return result.count == NativeProtocol.binaryHeaderBytes + bytes.count
            ? result
            : nil
    }

    private static func append<T: FixedWidthInteger>(_ value: T, to data: inout Data) {
        var littleEndian = value.littleEndian
        withUnsafeBytes(of: &littleEndian) { data.append(contentsOf: $0) }
    }

    private static func append(uuid: UUID, to data: inout Data) {
        var raw = uuid.uuid
        withUnsafeBytes(of: &raw) { data.append(contentsOf: $0) }
    }
}
