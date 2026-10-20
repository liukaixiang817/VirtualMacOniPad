import Foundation

var created = 0
var destroyed = 0
final class Owner {
    let serial: Int
    init(_ serial: Int) { self.serial = serial; created += 1 }
    deinit { destroyed += 1 }
}
final class ObjCOwner: NSObject {
    let serial: Int
    init(_ serial: Int) { self.serial = serial; created += 1; super.init() }
    deinit { destroyed += 1 }
}
struct OwnedRecord { var owner: Owner; var text: String; var integers: [Int] }
enum Choice {
    case first(UInt64, Owner)
    case second(UInt64, Owner)
    case third(UInt64, Owner)
    case empty0
    case empty1
}
@_silgen_name("vm27_hid_cvw_fixture_run")
func runCVW(_ metadata: UnsafeRawPointer, _ left: UnsafeRawPointer,
            _ right: UnsafeRawPointer, _ schema: UInt32,
            _ firstOwner: UnsafeRawPointer?, _ secondOwner: UnsafeRawPointer?,
            _ leftTag: UInt32, _ rightTag: UInt32)
@_silgen_name("vm27_hid_cvw_fixture_finish")
func finishCVW(_ created: UInt32, _ destroyed: UInt32)
func compare<T>(_ left: inout T, _ right: inout T, _ schema: UInt32,
                _ first: Owner? = nil, _ second: Owner? = nil,
                _ leftTag: UInt32 = 0, _ rightTag: UInt32 = 0) {
    withUnsafePointer(to: &left) { a in
        withUnsafePointer(to: &right) { b in
            runCVW(unsafeBitCast(T.self, to: UnsafeRawPointer.self),
                UnsafeRawPointer(a), UnsafeRawPointer(b), schema,
                first.map { UnsafeRawPointer(Unmanaged.passUnretained($0).toOpaque()) },
                second.map { UnsafeRawPointer(Unmanaged.passUnretained($0).toOpaque()) },
                leftTag, rightTag)
        }
    }
}
@inline(never) func oneCase(_ index: Int) {
    let first = Owner(index), second = Owner(index + 100)
    var a = UInt64(index), b = UInt64.max - UInt64(index)
    compare(&a, &b, 0)
    var ownerA = first, ownerB = second
    compare(&ownerA, &ownerB, 1, first, second)
    var sameOwner = ownerA
    compare(&ownerA, &sameOwner, 1, first, first)
    var stringA = String(repeating: "left-\(index)", count: 64)
    var stringB = String(repeating: "right-\(index)", count: 64)
    compare(&stringA, &stringB, 2)
    var smallStringA = "a", smallStringB = "b"
    compare(&smallStringA, &smallStringB, 2)
    var objectA: NSObject = ObjCOwner(index), objectB: NSObject = ObjCOwner(index + 100)
    compare(&objectA, &objectB, 3)
    var recordA = OwnedRecord(owner: first, text: stringA, integers: Array(0..<128))
    var recordB = OwnedRecord(owner: second, text: stringB, integers: Array(128..<256))
    compare(&recordA, &recordB, 4, first, second)
    var anyA: Any = first, anyB: Any = second
    compare(&anyA, &anyB, 5, first, second)
    anyA = recordA; anyB = recordB
    compare(&anyA, &anyB, 5, first, second)
    anyA = first; anyB = recordB
    compare(&anyA, &anyB, 5, first, second)
    anyA = recordA; anyB = second
    compare(&anyA, &anyB, 5, first, second)
    anyA = UInt64(index); anyB = stringB
    compare(&anyA, &anyB, 5)
    let choicesA: [Choice] = [.first(1, first), .second(2, first), .third(3, first), .empty0, .empty1]
    let choicesB: [Choice] = [.first(11, second), .second(12, second), .third(13, second), .empty0, .empty1]
    for leftTag in 0..<5 {
        for rightTag in 0..<5 {
            var lhs = choicesA[leftTag], rhs = choicesB[rightTag]
            compare(&lhs, &rhs, 6, first, second, UInt32(leftTag), UInt32(rightTag))
        }
    }
}
for index in 0..<4 { oneCase(index) }
finishCVW(UInt32(created), UInt32(destroyed))
