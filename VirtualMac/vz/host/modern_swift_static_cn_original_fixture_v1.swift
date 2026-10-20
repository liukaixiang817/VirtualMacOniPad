// A finite ordinary type-name check. No class factory or metadata alias.
@_cdecl("VM27OriginalCNClassName")
public func vm27OriginalCNClassName(_ metadata: UnsafeRawPointer) -> Bool {
    let type = unsafeBitCast(metadata, to: Any.Type.self)
    return _typeName(type, qualified: true) == "Swift.__StaticArrayStorage"
}
