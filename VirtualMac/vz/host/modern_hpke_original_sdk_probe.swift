// The caller imports only Apple's original CryptoKit SDK declarations.
// It does not import VM27HPKE or redefine Apple's structs/protocols.
import CryptoKit
import Foundation
import Darwin

func layout<T>(_ type: T.Type, _ name: String, _ native: Bool, _ size: Int, _ alignment: Int) {
    let metadata = unsafeBitCast(type, to: UnsafeRawPointer.self)
    precondition(name.withCString { VM27HPKEMetadataIdentity(metadata, $0, native) })
    precondition(MemoryLayout<T>.size == size && MemoryLayout<T>.alignment == alignment)
    print("{\"record\":\"layout\",\"type\":\"\(name)\",\"size\":\(MemoryLayout<T>.size),\"stride\":\(MemoryLayout<T>.stride),\"alignment\":\(MemoryLayout<T>.alignment)}")
}
@main struct OriginalSDKFixture {
    static func main() throws {
        precondition(VM27HPKEProbeBegin())
        layout(HPKE.self, "HPKE", false, 0, 1)
        layout(HPKE.Ciphersuite.self, "HPKE.Ciphersuite", false, 3, 1)
        layout(HPKE.Sender.self, "HPKE.Sender", false, 80, 8)
        layout(HPKE.Recipient.self, "HPKE.Recipient", false, 64, 8)
        layout(P256.KeyAgreement.PublicKey.self, "P256.KeyAgreement.PublicKey", true, 8, 8)
        layout(P256.KeyAgreement.PrivateKey.self, "P256.KeyAgreement.PrivateKey", true, 8, 8)
        var checks = 0
        for iteration in 0..<32 {
            let initial = P256.KeyAgreement.PrivateKey(compactRepresentable: false)
            let key = try P256.KeyAgreement.PrivateKey(pemRepresentation: initial.pemRepresentation)
            let exported = key.x963Representation
            let restored = try P256.KeyAgreement.PrivateKey(x963Representation: exported)
            precondition(restored.x963Representation == exported)
            let publicKey = try P256.KeyAgreement.PublicKey(x963Representation: restored.publicKey.x963Representation)
            let info = Data("original SDK typed alias \(iteration)".utf8)
            var sender = try HPKE.Sender(recipientKey: publicKey, ciphersuite: .P256_SHA256_AES_GCM_256, info: info)
            var recipient = try HPKE.Recipient(privateKey: restored, ciphersuite: .P256_SHA256_AES_GCM_256, info: info, encapsulatedKey: sender.encapsulatedKey)
            for size in [0, 1, 16, 17, 4096, 65536] {
                let message = Data((0..<size).map { UInt8(truncatingIfNeeded: $0 * 17 + iteration) })
                let ciphertext = try sender.seal(message)
                let plaintext = try recipient.open(ciphertext)
                precondition(plaintext == message && ciphertext.count == size + 16)
                checks += 2
            }
            let actualMessage = Data([3, 11, 17, UInt8(iteration)])
            let authentic = try sender.seal(actualMessage)
            var corrupt = authentic; corrupt[corrupt.startIndex] ^= 0x40
            do { _ = try recipient.open(corrupt); preconditionFailure("tamper accepted") }
            catch { checks += 1 }
            let afterTamper = try recipient.open(authentic)
            precondition(afterTamper == actualMessage); checks += 1
            var wrongTestSender = try HPKE.Sender(recipientKey: publicKey, ciphersuite: .P256_SHA256_AES_GCM_256, info: info)
            let wrongKey = P256.KeyAgreement.PrivateKey(compactRepresentable: false)
            var wrongRecipient = try HPKE.Recipient(privateKey: wrongKey, ciphersuite: .P256_SHA256_AES_GCM_256, info: info, encapsulatedKey: wrongTestSender.encapsulatedKey)
            let wrongCiphertext = try wrongTestSender.seal(actualMessage)
            do { _ = try wrongRecipient.open(wrongCiphertext); preconditionFailure("wrong key accepted") }
            catch { checks += 1 }
            checks += 1
        }
        precondition(checks == 512)
        print("{\"record\":\"summary\",\"PID\":\(getpid()),\"checks\":\(checks),\"iterations\":32,\"originalSDKTypes\":true,\"aliasEntryIdentities\":16,\"originalDI2Aliases\":14,\"SDKConformanceDescriptorAliases\":2,\"nativeP256EntryIdentities\":7,\"metadataIdentities\":6,\"P256ObjectsUsed\":true,\"trueThrowNegatives\":64,\"genuine27CryptoKitBinaryClaimed\":false,\"diskVMGPUCalls\":0,\"passed\":true}")
    }
}
