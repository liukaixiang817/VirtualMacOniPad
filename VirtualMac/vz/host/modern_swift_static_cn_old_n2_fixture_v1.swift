// Native standard Swift only. No original StaticCN type, Foundation or HID.
@_cdecl("VM27OldN2ClassName")
public func vm27OldN2ClassName(_ metadata: UnsafeRawPointer) -> Bool {
    let type=unsafeBitCast(metadata,to:Any.Type.self)
    return _typeName(type,qualified:true)=="VM27OldN2Model.OwnStaticStorage"
}
@_cdecl("VM27OldN2UInt64Metadata")
public func vm27OldN2UInt64Metadata() -> UnsafeRawPointer {
    unsafeBitCast(UInt64.self,to:UnsafeRawPointer.self)
}
@_cdecl("VM27OldN2NilUInt64")
public func vm27OldN2NilUInt64(_ storage: UnsafeRawPointer) -> Bool {
    storage.assumingMemoryBound(to:Optional<UInt64>.self).pointee==nil
}
