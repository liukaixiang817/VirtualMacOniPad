import Foundation
struct EventReportSenderID { var uuid: UUID; var serial: UInt64 }
var created = 0
var destroyed = 0
final class Owner {
    let serial: Int
    init(_ serial: Int) { self.serial = serial; created += 1 }
    deinit { destroyed += 1 }
}
struct OwnedRecord { var owner: Owner; var text: String; var integers: [Int] }
struct WeakRecord { weak var owner: Owner?; var serial: UInt64 }
@_silgen_name("vm27_hid_take_fixture_run")
func runTake(_ metadata: UnsafeRawPointer, _ value: UnsafeRawPointer, _ object: UnsafeRawPointer?)
@_silgen_name("vm27_hid_take_fixture_finish")
func finishTake(_ created: UInt32, _ destroyed: UInt32)
func compare<T>(_ value: inout T, _ owner: Owner? = nil) {
    withUnsafePointer(to: &value) {
        runTake(unsafeBitCast(T.self, to: UnsafeRawPointer.self), UnsafeRawPointer($0),
            owner.map { UnsafeRawPointer(Unmanaged.passUnretained($0).toOpaque()) })
    }
}
@inline(never) func oneCase(_ index: Int) {
    let owner = Owner(index)
    var pod = EventReportSenderID(uuid: UUID(uuid: (UInt8(index),1,2,3,4,5,6,7,8,9,10,11,12,13,14,15)), serial: UInt64.max - UInt64(index))
    compare(&pod)
    var reference = owner
    compare(&reference, owner)
    var record = OwnedRecord(owner: owner, text: String(repeating: "owned-\(index)", count: 32), integers: Array(0..<128))
    compare(&record, owner)
    var weak = WeakRecord(owner: owner, serial: UInt64(index))
    compare(&weak)
}
for index in 0..<8 { oneCase(index) }
finishTake(UInt32(created), UInt32(destroyed))
