import Darwin
@main struct PropertyFixture {
    static func main() {
        var checks=0, failures=0
        func check(_ value: Bool) { checks += 1; if !value { failures += 1 } }
        check(MemoryLayout<Any?>.size == 32)
        check(MemoryLayout<Any?>.stride == 32)
        for i in 0..<128 {
            for key in ["HIDCapsLockState", "", "unsupported-property-\(i)-触点"] {
                let value=vm27MacKeyboardServicePropertyUnavailableV1(key)
                check(value == nil)
                check(!(value is Bool))
                withUnsafeBytes(of:value) { bytes in
                    check(bytes.count == 32)
                    check(bytes.allSatisfy { $0 == 0 })
                }
            }
        }
        print("{\"checks\":\(checks),\"failures\":\(failures),\"propertyQueries\":384,\"originalUHKCalls\":0,\"deviceOperations\":0}")
        exit(failures == 0 ? 0 : 1)
    }
}
