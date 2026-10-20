// Scoped Swift class-metadata compatibility experiment, not a CN data export.
// Parent and private Tq layouts are pinned to actual old/native descriptors.
import Swift
// Match the original non-generic, no-tail-destruction static storage semantics.
@_fixed_layout
@usableFromInline
@_objc_non_lazy_realization
internal final class VM27StaticArrayStorage: __ContiguousArrayStorageBase {
 @inlinable @nonobjc internal init(_doNotCallMe: ()) { fatalError("Static array storage must not be allocated") }
 @inlinable override internal func canStoreElements(ofDynamicType: Any.Type) -> Bool { false }
 @inlinable override internal var staticElementType: Any.Type { fatalError("Static storage has no dynamic element metadata") }
}

// The builder adds exact private parent-Tq override records. The real runtime
// owns subclass metadata allocation, superclass resolution and vtable signing.
@_silgen_name("VM27StaticArrayVerbatimNil")
public func vm27VerbatimNil<R>(_ body: (UnsafeBufferPointer<AnyObject>) throws -> R) rethrows -> R? { nil }
@_cdecl("VM27StaticArrayMetadataOracle")
public func vm27MetadataOracle() -> UnsafeRawPointer { unsafeBitCast(VM27StaticArrayStorage.self,to:UnsafeRawPointer.self) }

@_silgen_name("VM27StaticArrayForbiddenBridge")
public func vm27ForbiddenBridge() -> Never { fatalError("Static storage cannot supply the old non-verbatim bridging buffer") }
