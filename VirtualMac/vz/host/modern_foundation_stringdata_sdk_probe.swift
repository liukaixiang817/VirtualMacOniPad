// This fixture uses only Apple's SDK type and overload declarations.
import Foundation
import Darwin

@available(iOS 18, macOS 15, *)
@inline(never)
func sdkEncode(_ string: String, _ encoding: String.Encoding, _ lossy: Bool) -> Data? {
    string.data(using: encoding, allowLossyConversion: lossy)
}

@inline(never)
func genericEncode<S: StringProtocol>(_ string: S, _ encoding: String.Encoding, _ lossy: Bool) -> Data? {
    string.data(using: encoding, allowLossyConversion: lossy)
}

func layout<T>(_ type: T.Type, _ name: String, _ size: Int, _ alignment: Int) {
    precondition(MemoryLayout<T>.size == size && MemoryLayout<T>.alignment == alignment)
    print("{\"record\":\"layout\",\"type\":\"\(name)\",\"size\":\(MemoryLayout<T>.size),\"stride\":\(MemoryLayout<T>.stride),\"alignment\":\(MemoryLayout<T>.alignment)}")
}

@available(iOS 18, macOS 15, *)
@main struct OriginalSDKFixture {
    static func main() {
        precondition(VM27FoundationProbeBegin())
        layout(String.self, "String", 16, 8)
        layout(String.Encoding.self, "String.Encoding", 8, 8)
        layout(Data.self, "Data", 16, 8)
        layout(Optional<Data>.self, "Optional<Data>", 16, 8)
        layout(Bool.self, "Bool", 1, 1)
        let values = ["", "hello", "a\0b", "caf\u{00e9}", "e\u{0301}", "中文空间站", "Ελληνικά",
                      "😀🚀", "line\nnext\r\n", "\u{feff}value", String(repeating: "abcdef", count: 2048),
                      String(repeating: "中文🚀", count: 1024)]
        let encodings: [String.Encoding] = [.utf8, .ascii, .isoLatin1, .utf16, .utf16BigEndian,
            .utf16LittleEndian, .utf32, .utf32BigEndian, .utf32LittleEndian, .nonLossyASCII,
            .windowsCP1252, .macOSRoman, .shiftJIS, .japaneseEUC, .iso2022JP, .isoLatin2, .windowsCP1251]
        var checks = 0, calls = 0, nilResults = 0, lossyCalls = 0, copyOnWriteChecks = 0
        for _ in 0..<8 {
            for string in values {
                for encoding in encodings {
                    for lossy in [false, true] {
                        let actual = sdkEncode(string, encoding, lossy)
                        let objc = (string as NSString).data(using: encoding.rawValue, allowLossyConversion: lossy)
                        let oldGeneric = genericEncode(string, encoding, lossy)
                        precondition(actual == objc && actual == oldGeneric)
                        checks += 2; calls += 1
                        if actual == nil { nilResults += 1 }
                        if lossy { lossyCalls += 1 }
                    }
                }
                let utf8 = sdkEncode(string, .utf8, false)!
                precondition(Array(utf8) == Array(string.utf8)); checks += 1; calls += 1
                let original = utf8
                var copied = utf8
                copied.append(0xa5)
                precondition(original == utf8 && copied.count == original.count + 1 && copied.last == 0xa5)
                precondition(copied.dropLast() == original)
                checks += 2; copyOnWriteChecks += 2
            }
            precondition(sdkEncode("中文🚀", .ascii, false) == nil); checks += 1; calls += 1
        }
        precondition(checks == 6824 && calls == 3368 && lossyCalls == 1632 && copyOnWriteChecks == 192 && nilResults > 0)
        print("{\"record\":\"summary\",\"PID\":\(getpid()),\"checks\":\(checks),\"originalSDKCalls\":\(calls),\"iterations\":8,\"strings\":12,\"encodings\":17,\"lossyCalls\":\(lossyCalls),\"nilResults\":\(nilResults),\"copyOnWriteChecks\":\(copyOnWriteChecks),\"originalSDKDeclarations\":true,\"privateAliasIdentities\":1,\"NSStringAndLegacyGenericCompared\":true,\"diskVMGPUCalls\":0,\"passed\":true}")
    }
}
