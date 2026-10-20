// Ordinary Mac fixture: real Swift metadata, Error witness and ARC payload.
final class ThrowToken {
    let identity: Int
    init(_ identity: Int) { self.identity = identity }
}
struct ThrowValue: Error {
    let token: ThrowToken
    let code: Int
    let message: String
}
@_silgen_name("vm27_typed_fixture_initialize") func initializeFixture()
@_silgen_name("vm27_typed_fixture_run")
func runFixture(_ value: UnsafeMutableRawPointer, _ metadata: UnsafeRawPointer,
                _ size: Int, _ concurrent: Int32)
@_silgen_name("vm27_typed_fixture_release_saved") func releaseSavedFixture()
@_silgen_name("vm27_typed_fixture_finish") func finishFixture()

@_cdecl("vm27_typed_fixture_values_equal")
func valuesEqual(_ first: UnsafeRawPointer, _ second: UnsafeRawPointer) -> Int32 {
    let a = first.assumingMemoryBound(to: ThrowValue.self).pointee
    let b = second.assumingMemoryBound(to: ThrowValue.self).pointee
    return a.token === b.token && a.code == b.code && a.message == b.message ? 1 : 0
}

initializeFixture()
let metadata = unsafeBitCast(ThrowValue.self, to: UnsafeRawPointer.self)
for index in 0..<256 {
    weak var weakToken: ThrowToken?
    do {
        let token = ThrowToken(index)
        weakToken = token
        var value = ThrowValue(token: token, code: index - 128,
            message: String(repeating: "typed-value-\(index)", count: index % 9 + 1))
        withUnsafeMutablePointer(to: &value) {
            runFixture(UnsafeMutableRawPointer($0), metadata, MemoryLayout<ThrowValue>.size, 0)
        }
    }
    // The retained real error box owns its copied ARC payload after the source
    // has gone away. Releasing that box must release the final token reference.
    precondition(weakToken != nil)
    releaseSavedFixture()
    precondition(weakToken == nil)
}
var shared = ThrowValue(token: ThrowToken(999), code: 999, message: "concurrent-real-value")
withUnsafeMutablePointer(to: &shared) {
    runFixture(UnsafeMutableRawPointer($0), metadata, MemoryLayout<ThrowValue>.size, 1)
}
finishFixture()
