import Foundation

// Type metadata and witness operations come from actual ordinary Swift types.
// These fixture types have no original HID or old N2 metadata identity.
private var payloadCreated: UInt32 = 0
private var payloadDestroyed: UInt32 = 0
private final class VM27Payload {
    let value: UInt64
    init(_ value: UInt64) { self.value = value; payloadCreated += 1 }
    deinit { payloadDestroyed += 1 }
}
@_cdecl("VM27FixturePayloadStats")
public func vm27FixturePayloadStats() -> UInt64 { UInt64(payloadCreated) << 32 | UInt64(payloadDestroyed) }
private enum VM27ModelError: Error { case requested }
private var controlMode: Int32 = 0
@_cdecl("VM27FixtureSetMode")
public func vm27FixtureSetMode(_ mode: Int32) { controlMode = mode }
@_silgen_name("VM27FixtureReturnOptional")
public func vm27FixtureReturnOptional<R>() throws -> R? {
    if controlMode == 1 { throw VM27ModelError.requested }
    if R.self == UInt64.self { return UInt64(0x81781717) as? R }
    if R.self == String.self { return String(repeating: "owned-value-", count: 32) as? R }
    if R.self == VM27Payload.self { return VM27Payload(0x81781717) as? R }
    fatalError("Unknown owned fixture type")
}
@_cdecl("VM27FixtureSomeCheck")
public func vm27FixtureSomeCheck(_ storage: UnsafeRawPointer, _ kind: Int32) -> Bool {
    switch kind {
    case 0: return storage.assumingMemoryBound(to: UInt64.self).pointee == 0x81781717
    case 1: return storage.assumingMemoryBound(to: String.self).pointee == String(repeating: "owned-value-", count: 32)
    case 2: return storage.assumingMemoryBound(to: VM27Payload.self).pointee.value == 0x81781717
    default: return false
    }
}
@_cdecl("VM27FixtureSomeDestroy")
public func vm27FixtureSomeDestroy(_ storage: UnsafeMutableRawPointer, _ kind: Int32) {
    switch kind {
    case 0: storage.assumingMemoryBound(to: UInt64.self).deinitialize(count: 1)
    case 1: storage.assumingMemoryBound(to: String.self).deinitialize(count: 1)
    case 2: storage.assumingMemoryBound(to: VM27Payload.self).deinitialize(count: 1)
    default: fatalError("Unknown owned fixture destroy type")
    }
}
@_cdecl("VM27FixtureUInt64Metadata")
public func vm27FixtureUInt64Metadata() -> UnsafeRawPointer {
    unsafeBitCast(UInt64.self, to: UnsafeRawPointer.self)
}
@_cdecl("VM27FixtureStringMetadata")
public func vm27FixtureStringMetadata() -> UnsafeRawPointer {
    unsafeBitCast(String.self, to: UnsafeRawPointer.self)
}
@_cdecl("VM27FixtureClassMetadata")
public func vm27FixtureClassMetadata() -> UnsafeRawPointer {
    unsafeBitCast(VM27Payload.self, to: UnsafeRawPointer.self)
}
@_cdecl("VM27FixtureNilCheck")
public func vm27FixtureNilCheck(_ storage: UnsafeRawPointer, _ kind: Int32) -> Bool {
    switch kind {
    case 0: return storage.assumingMemoryBound(to: Optional<UInt64>.self).pointee == nil
    case 1: return storage.assumingMemoryBound(to: Optional<String>.self).pointee == nil
    case 2: return storage.assumingMemoryBound(to: Optional<VM27Payload>.self).pointee == nil
    default: return false
    }
}
@_cdecl("VM27FixtureClassName")
public func vm27FixtureClassName(_ metadata: UnsafeRawPointer) -> Bool {
    let type = unsafeBitCast(metadata, to: Any.Type.self)
    return _typeName(type, qualified: true) == "VM27FixedModel.OwnStaticStorage"
}
