// The concrete String overload was introduced in iOS 18 / macOS 15.
// Keep Apple's String, Encoding and Data types, and delegate conversion to the
// already available NSString implementation. This does not install a global
// Foundation override: consumers opt in through one private export alias.
import Foundation

extension String {
    @inline(never)
    public func vm27Data(using encoding: String.Encoding, allowLossyConversion: Bool) -> Data? {
        (self as NSString).data(using: encoding.rawValue, allowLossyConversion: allowLossyConversion)
    }
}
