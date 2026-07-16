import Darwin
import Foundation
import WardrobePhotoKitObjC

private struct ABIFrameHeader {
    var abiVersion: UInt32
    var kind: UInt32
    var sequence: UInt64
    var length: Int
}

@_cdecl("wk_photokit_create_v1")
public func wkPhotoKitCreateV1(
    _ requestedABI: UInt32,
    _ outHandle: UnsafeMutablePointer<OpaquePointer?>?
) -> Int32 {
    guard let outHandle else {
        return ABIStatus.invalid.rawValue
    }
    outHandle.pointee = nil
    guard requestedABI == UInt32(WK_PHOTOKIT_ABI_V1) else {
        return ABIStatus.invalid.rawValue
    }
    let retained = Unmanaged.passRetained(BridgeHandle())
    outHandle.pointee = OpaquePointer(retained.toOpaque())
    return ABIStatus.ok.rawValue
}

@_cdecl("wk_photokit_send_v1")
public func wkPhotoKitSendV1(
    _ opaqueHandle: OpaquePointer?,
    _ bytes: UnsafePointer<UInt8>?,
    _ length: Int
) -> Int32 {
    guard
        let handle = bridge(from: opaqueHandle),
        length > 0,
        length <= Int(WK_PHOTOKIT_MAX_CONTROL_V1),
        let bytes
    else {
        return ABIStatus.invalid.rawValue
    }
    guard handle.beginABICall() else {
        return ABIStatus.closed.rawValue
    }
    defer { handle.endABICall() }
    let copied = Data(bytes: bytes, count: length)
    return handle.send(copied).rawValue
}

@_cdecl("wk_photokit_next_v1")
public func wkPhotoKitNextV1(
    _ opaqueHandle: OpaquePointer?,
    _ timeoutMilliseconds: UInt32,
    _ outFrame: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> Int32 {
    guard let outFrame else {
        return ABIStatus.invalid.rawValue
    }
    outFrame.pointee = nil
    guard let handle = bridge(from: opaqueHandle) else {
        return ABIStatus.invalid.rawValue
    }
    guard handle.beginABICall() else {
        return ABIStatus.closed.rawValue
    }
    defer { handle.endABICall() }
    let (status, frame) = handle.next(timeoutMilliseconds: timeoutMilliseconds)
    guard status == .ok, let frame else {
        return status.rawValue
    }
    guard let allocation = allocate(frame: frame) else {
        return ABIStatus.internal.rawValue
    }
    outFrame.pointee = allocation
    return ABIStatus.ok.rawValue
}

@_cdecl("wk_photokit_frame_free_v1")
public func wkPhotoKitFrameFreeV1(_ frame: UnsafeMutableRawPointer?) {
    free(frame)
}

@_cdecl("wk_photokit_quiesce_v1")
public func wkPhotoKitQuiesceV1(
    _ opaqueHandle: OpaquePointer?,
    _ timeoutMilliseconds: UInt32
) -> Int32 {
    guard let handle = bridge(from: opaqueHandle) else {
        return ABIStatus.invalid.rawValue
    }
    guard handle.beginABICall() else {
        return ABIStatus.closed.rawValue
    }
    defer { handle.endABICall() }
    return handle.quiesce(timeoutMilliseconds: timeoutMilliseconds).rawValue
}

@_cdecl("wk_photokit_destroy_v1")
public func wkPhotoKitDestroyV1(
    _ opaqueHandle: UnsafeMutablePointer<OpaquePointer?>?
) -> Int32 {
    guard let opaqueHandle, let pointer = opaqueHandle.pointee else {
        return ABIStatus.invalid.rawValue
    }
    let unmanaged = Unmanaged<BridgeHandle>.fromOpaque(UnsafeRawPointer(pointer))
    let handle = unmanaged.takeUnretainedValue()
    let status = handle.prepareDestroy()
    guard status == .ok else {
        return status.rawValue
    }
    opaqueHandle.pointee = nil
    unmanaged.release()
    return ABIStatus.ok.rawValue
}

@_cdecl("wk_photokit_validate_image_fd_v1")
public func wkPhotoKitValidateImageFDV1(
    _ duplicatedReadOnlyFD: Int32,
    _ uti: UnsafePointer<UInt8>?,
    _ utiLength: Int,
    _ outWidth: UnsafeMutablePointer<UInt32>?,
    _ outHeight: UnsafeMutablePointer<UInt32>?,
    _ outFrameCount: UnsafeMutablePointer<UInt32>?
) -> Int32 {
    ImageValidator.validate(
        duplicatedReadOnlyFD: duplicatedReadOnlyFD,
        uti: uti,
        utiLength: utiLength,
        outWidth: outWidth,
        outHeight: outHeight,
        outFrameCount: outFrameCount
    ).rawValue
}

private func bridge(from pointer: OpaquePointer?) -> BridgeHandle? {
    guard let pointer else {
        return nil
    }
    return Unmanaged<BridgeHandle>
        .fromOpaque(UnsafeRawPointer(pointer))
        .takeUnretainedValue()
}

private func allocate(frame: QueuedFrame) -> UnsafeMutableRawPointer? {
    let headerBytes = MemoryLayout<ABIFrameHeader>.stride
    guard headerBytes == 24 else {
        return nil
    }
    let (allocationBytes, overflow) = headerBytes.addingReportingOverflow(
        frame.bytes.count
    )
    guard !overflow, let allocation = malloc(allocationBytes) else {
        return nil
    }
    allocation.assumingMemoryBound(to: ABIFrameHeader.self).initialize(
        to: ABIFrameHeader(
            abiVersion: UInt32(WK_PHOTOKIT_ABI_V1),
            kind: frame.kind.rawValue,
            sequence: frame.sequence,
            length: frame.bytes.count
        )
    )
    frame.bytes.withUnsafeBytes { source in
        guard let sourceAddress = source.baseAddress else {
            return
        }
        allocation.advanced(by: headerBytes).copyMemory(
            from: sourceAddress,
            byteCount: frame.bytes.count
        )
    }
    return allocation
}
