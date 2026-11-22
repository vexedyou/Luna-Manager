"""Luna session crypto.

X25519 ECDH -> HKDF-SHA256 -> directional AES-256-GCM frame cipher.

Each session has two independent keys, one per direction, so a nonce counter can
never be reused across directions even at high frame volume. The nonce is a
4-byte epoch followed by a 64-bit big-endian counter; both sides reject frames
whose counter does not advance, which makes replay and reordering fail closed.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
import time
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PROTO_VERSION = 1
AAD = b"luna-v1"
INFO_RX = b"luna/v1/rx"
INFO_TX = b"luna/v1/tx"
KEY_LEN = 32
NONCE_LEN = 12
TAG_LEN = 16
PUB_LEN = 32


class CryptoError(Exception):
    """Raised on any handshake or framing failure."""


def b64e(raw: bytes) -> str:
    import base64

    return base64.b64encode(raw).decode("ascii")


def b64d(text: str) -> bytes:
    import base64

    try:
        return base64.b64decode(text, validate=True)
    except Exception as exc:  # noqa: BLE001
        raise CryptoError(f"bad base64: {exc}") from exc


def new_keypair() -> "KeyPair":
    priv = X25519PrivateKey.generate()
    raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return KeyPair(private=priv, public=raw)


@dataclass
class KeyPair:
    private: X25519PrivateKey
    public: bytes

    @property
    def public_b64(self) -> str:
        return b64e(self.public)


def load_peer(public_raw: bytes) -> X25519PublicKey:
    if len(public_raw) != PUB_LEN:
        raise CryptoError(f"peer public key must be {PUB_LEN} bytes")
    # reject the low-order points that would collapse the shared secret to zero
    if public_raw.count(0) == PUB_LEN:
        raise CryptoError("peer public key is the identity element")
    return X25519PublicKey.from_public_bytes(public_raw)


def _hkdf(shared: bytes, salt: bytes, info: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        info=info,
    ).derive(shared)


@dataclass
class SessionKeys:
    """Directional keys as seen from the initiator (the implant)."""

    send_key: bytes
    recv_key: bytes

    def mirrored(self) -> "SessionKeys":
        """The responder's view: its send key is the initiator's recv key."""
        return SessionKeys(send_key=self.recv_key, recv_key=self.send_key)

    def key_fingerprint(self) -> str:
        return hashlib.sha256(self.send_key + self.recv_key).hexdigest()[:16]


def derive_keys(
    own_private: X25519PrivateKey,
    peer_public: bytes,
    salt: bytes,
) -> SessionKeys:
    shared = own_private.exchange(load_peer(peer_public))
    if shared == b"\x00" * 32:
        raise CryptoError("degenerate shared secret")
    return SessionKeys(
        send_key=_hkdf(shared, salt, INFO_TX),
        recv_key=_hkdf(shared, salt, INFO_RX),
    )


@dataclass
class FrameCipher:
    """One direction of a session: AES-256-GCM with a monotonic counter nonce."""

    key: bytes
    epoch: int = 0
    _send_ctr: int = 0
    _recv_ctr: int = 0
    _seen_high: int = -1
    _aead: AESGCM = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if len(self.key) != KEY_LEN:
            raise CryptoError("AES-256-GCM key must be 32 bytes")
        self._aead = AESGCM(self.key)

    def _nonce(self, counter: int) -> bytes:
        return struct.pack(">IQ", self.epoch, counter)

    def seal(self, plaintext: bytes) -> bytes:
        if self._send_ctr >= 2**64 - 1:
            raise CryptoError("send counter exhausted; re-handshake required")
        nonce = self._nonce(self._send_ctr)
        self._send_ctr += 1
        return nonce + self._aead.encrypt(nonce, plaintext, AAD)

    def open(self, frame: bytes) -> bytes:
        if len(frame) < NONCE_LEN + TAG_LEN:
            raise CryptoError("frame too short")
        nonce, body = frame[:NONCE_LEN], frame[NONCE_LEN:]
        epoch, counter = struct.unpack(">IQ", nonce)
        if epoch != self.epoch:
            raise CryptoError("frame epoch mismatch")
        if counter <= self._seen_high:
            raise CryptoError("replayed or reordered frame rejected")
        try:
            plaintext = self._aead.decrypt(nonce, body, AAD)
        except Exception as exc:  # noqa: BLE001
            raise CryptoError("frame authentication failed") from exc
        self._seen_high = counter
        self._recv_ctr = counter + 1
        return plaintext


def registration_proof(reg_key: bytes, public_raw: bytes, nonce: bytes) -> str:
    """Prove possession of the build-time registration key without sending it."""
    mac = hmac.new(reg_key, b"luna-reg-v1" + public_raw + nonce, hashlib.sha256)
    return mac.hexdigest()


def verify_registration(
    reg_key: bytes, public_raw: bytes, nonce: bytes, proof: str
) -> bool:
    return hmac.compare_digest(
        registration_proof(reg_key, public_raw, nonce), proof.lower()
    )


# --- operator authentication -------------------------------------------------


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or os.urandom(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32
    )
    return f"scrypt${b64e(salt)}${b64e(digest)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, salt_b64, digest_b64 = stored.split("$", 2)
    except ValueError:
        return False
    if scheme != "scrypt":
        return False
    salt = b64d(salt_b64)
    expected = b64d(digest_b64)
    actual = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32
    )
    return hmac.compare_digest(actual, expected)


def issue_token(secret: bytes, operator: str, ttl: int = 12 * 3600) -> str:
    exp = int(time.time()) + ttl
    body = f"{operator}:{exp}".encode("utf-8")
    sig = hmac.new(secret, b"luna-tok-v1" + body, hashlib.sha256).digest()
    return f"{b64e(body)}.{b64e(sig)}"


def check_token(secret: bytes, token: str) -> str | None:
    try:
        body_b64, sig_b64 = token.split(".", 1)
        body = b64d(body_b64)
        sig = b64d(sig_b64)
    except Exception:  # noqa: BLE001
        return None
    expected = hmac.new(secret, b"luna-tok-v1" + body, hashlib.sha256).digest()
    if not hmac.compare_digest(sig, expected):
        return None
    try:
        operator, exp = body.decode("utf-8").rsplit(":", 1)
        if int(exp) < int(time.time()):
            return None
    except Exception:  # noqa: BLE001
        return None
    return operator
