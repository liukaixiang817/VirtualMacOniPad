"""BTVC software link encryption primitives for the audited 25G83 profile.

The native BTVCEncryption implementation starts counters at one, uses a
13-byte nonce and authenticates the fixed one-byte value 0x02. This module
contains no radio, socket, pairing permission, or device discovery behavior.
Direction is explicit so the transport must supply its audited native role.
Keys and protocol payloads must never be included in diagnostic logs.
"""
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM


MAX_PAYLOAD = 251
MAX_COUNTER = (1 << 39) - 1
AUTHENTICATED_HEADER = b"\x02"


def derive_session_key(ltk_le: bytes, central_skd: bytes, peripheral_skd: bytes) -> bytes:
    """Return the AES key in BTVCEncryption's native block-cipher byte order.

    The audited getSk helper reverses the Bluetooth LTK and combined SKD
    before AES-128 ECB, and passes that AES output directly to BTVCEncryption.
    """
    if len(ltk_le) != 16 or len(central_skd) != 8 or len(peripheral_skd) != 8:
        raise ValueError("invalid link key material length")
    encryptor = Cipher(algorithms.AES(ltk_le[::-1]), modes.ECB()).encryptor()
    return encryptor.update((central_skd + peripheral_skd)[::-1]) + encryptor.finalize()


def packet_nonce(iv: bytes, counter: int, direction: int) -> bytes:
    if len(iv) != 8 or not 0 <= counter <= MAX_COUNTER or direction not in (0, 1):
        raise ValueError("invalid link nonce parameters")
    encoded = bytearray(counter.to_bytes(5, "little"))
    encoded[4] |= direction << 7
    return bytes(encoded) + iv


class BTVCEncryptionV1:
    """Per-connection counters. A failed MIC must terminate the connection."""

    def __init__(self, key: bytes, iv: bytes, tx_direction: int):
        if len(key) != 16 or len(iv) != 8 or tx_direction not in (0, 1):
            raise ValueError("invalid link encryption parameters")
        self._cipher = AESCCM(key, tag_length=4)
        self._iv = bytes(iv)
        self._tx_direction = tx_direction
        self._tx = self._rx = 1
        self._failed = False

    def __repr__(self):
        return "<BTVCEncryptionV1: redacted>"

    def _check(self, payload: bytes, counter: int):
        if self._failed:
            raise RuntimeError("link encryption is no longer usable")
        if len(payload) > MAX_PAYLOAD or counter > MAX_COUNTER:
            self._failed = True
            raise ValueError("link packet or counter limit exceeded")

    def encrypt(self, payload: bytes) -> tuple[bytes, bytes]:
        self._check(payload, self._tx)
        encoded = self._cipher.encrypt(
            packet_nonce(self._iv, self._tx, self._tx_direction), payload, AUTHENTICATED_HEADER
        )
        self._tx += 1
        return encoded[:-4], encoded[-4:]

    def decrypt(self, payload: bytes, mic: bytes) -> bytes:
        self._check(payload, self._rx)
        if len(mic) != 4:
            self._failed = True
            raise ValueError("invalid link MIC length")
        try:
            decoded = self._cipher.decrypt(
                packet_nonce(self._iv, self._rx, 1 - self._tx_direction),
                payload + mic, AUTHENTICATED_HEADER,
            )
        except Exception:
            self._failed = True
            raise
        self._rx += 1
        return decoded
