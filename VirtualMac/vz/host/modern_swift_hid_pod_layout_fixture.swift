import Foundation
// A genuine SDK struct descriptor/value, used only for isolated ABI copies.
struct EventReportSenderID {
    let uuid: UUID
    let serial: UInt64
}
@_silgen_name("vm27_hid_pod_fixture_run")
func runPODFixture(_ metadata: UnsafeRawPointer, _ uuid: UnsafeRawPointer,
                   _ integer: UnsafeRawPointer, _ value: UnsafeRawPointer)
@_silgen_name("vm27_hid_pod_fixture_finish") func finishPODFixture()
let metadata = unsafeBitCast(EventReportSenderID.self, to: UnsafeRawPointer.self)
let uuid = unsafeBitCast(UUID.self, to: UnsafeRawPointer.self)
let integer = unsafeBitCast(UInt64.self, to: UnsafeRawPointer.self)
for index in 0..<8 {
    var value = EventReportSenderID(uuid: UUID(uuid: (UInt8(index), 1, 2, 3, 4, 5, 6, 7,
        8, 9, 10, 11, 12, 13, 14, 15)), serial: UInt64.max - UInt64(index))
    withUnsafePointer(to: &value) { runPODFixture(metadata, uuid, integer, UnsafeRawPointer($0)) }
}
finishPODFixture()
