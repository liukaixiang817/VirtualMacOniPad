import CryptoKit
extension P256.KeyAgreement.PrivateKey: DiffieHellmanKeyAgreement {}
extension P384.KeyAgreement.PrivateKey: DiffieHellmanKeyAgreement {}
extension P521.KeyAgreement.PrivateKey: DiffieHellmanKeyAgreement {}
extension Curve25519.KeyAgreement.PrivateKey: DiffieHellmanKeyAgreement {}
