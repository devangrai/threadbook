import Foundation
import WardrobePhotoKitObjC
import XCTest
@testable import WardrobePhotoKit

final class ProtocolTests: XCTestCase {
    private let operationID = "aaaaaaaa-1111-4111-8111-111111111111"
    private let enrollmentEpoch = "22222222-2222-4222-8222-222222222222"

    func testStrictDecoderAcceptsBoundedVersionedCommand() throws {
        let command = try XCTUnwrap(decode(baseCommand()))
        XCTAssertEqual(command.kind, .inspectAuthorization)
        XCTAssertEqual(command.identity.reconciliationFence, 7)
        XCTAssertEqual(command.identity.generation, 9)
        XCTAssertEqual(command.identity.requestSequence, 11)
    }

    func testStrictDecoderRejectsUnknownFieldsBooleansAndNonCanonicalUUIDs() {
        var unknown = baseCommand()
        unknown["extra"] = "no"
        XCTAssertNil(decode(unknown))

        var booleanFence = baseCommand()
        booleanFence["reconciliation_fence"] = true
        XCTAssertNil(decode(booleanFence))

        var uppercase = baseCommand()
        uppercase["operation_id"] = operationID.uppercased()
        XCTAssertNil(decode(uppercase))
    }

    func testStreamCommandRequiresExactFieldsAndBounds() {
        var stream = baseCommand()
        stream["command"] = "stream_resource"
        stream["resource_token"] = "aaaaaaaa-1111-4111-8111-111111111111"
        stream["allow_network"] = false
        XCTAssertEqual(decode(stream)?.allowNetwork, false)

        stream["resource_token"] = String(
            repeating: "a",
            count: 129
        )
        XCTAssertNil(decode(stream))
    }

    func testBinaryFrameHasFixedIdentityHeaderAndBoundedPayload() throws {
        let identity = OperationIdentity(
            operationID: try XCTUnwrap(UUID(uuidString: operationID)),
            enrollmentEpoch: try XCTUnwrap(UUID(uuidString: enrollmentEpoch)),
            reconciliationFence: 7,
            generation: 9,
            requestSequence: 11
        )
        let payload = Data([1, 2, 3])
        let encoded = try XCTUnwrap(
            BinaryChunkEncoder.encode(
                identity: identity,
                chunkIndex: 13,
                bytes: payload
            )
        )
        XCTAssertEqual(encoded.count, NativeProtocol.binaryHeaderBytes + 3)
        XCTAssertEqual(Array(encoded.prefix(4)), [0x57, 0x4b, 0x50, 0x42])
        XCTAssertEqual(encoded.suffix(3), payload)
        XCTAssertNil(
            BinaryChunkEncoder.encode(
                identity: identity,
                chunkIndex: 0,
                bytes: Data(
                    count: Int(WK_PHOTOKIT_MAX_BINARY_V1)
                        - NativeProtocol.binaryHeaderBytes + 1
                )
            )
        )
    }

    private func baseCommand() -> [String: Any] {
        [
            "protocol_version": 1,
            "command": "inspect_authorization",
            "operation_id": operationID,
            "enrollment_epoch": enrollmentEpoch,
            "reconciliation_fence": 7,
            "generation": 9,
            "sequence": 11,
        ]
    }

    private func decode(_ object: [String: Any]) -> NativeCommand? {
        guard
            let data = try? JSONSerialization.data(
                withJSONObject: object,
                options: [.sortedKeys]
            )
        else {
            return nil
        }
        return try? StrictCommandDecoder.decode(data).get()
    }
}
