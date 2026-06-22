"""
crypto_utils.py - handshake + per-packet encryption for the toy VPN.

Handshake:
    Each side generates a fresh (ephemeral) X25519 keypair per session
    and exchanges public keys. Both sides run ECDH to get a shared
    secret, then run it through HKDF-SHA256 to get a 256-bit session
    key. Because the keys are ephemeral and thrown away after the
    session, this gives forward secrecy: recording traffic today and
    stealing a long-term key later still doesn't decrypt it.

Per-packet encryption:
    AES-256-GCM (AEAD) - encryption + integrity in one primitive, so a
    tampered packet fails to decrypt rather than silently corrupting
    data. Nonces are built from an explicit 8-byte send counter per
    direction, which doubles as a sequence number for replay checks.

This is the crypto you'd actually want for a real VPN. What's
simplified for a portfolio project (vs. WireGuard/OpenVPN) is noted in
the README - mainly: no mutual authentication of identity (trust on
first connect, like SSH before you verify a host key) and no key
rotation within a session.
"""
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HANDSHAKE_INFO = b"toy-vpn handshake v1"


def generate_keypair():
    priv = X25519PrivateKey.generate()
    return priv, priv.public_key()


def pubkey_bytes(pub: X25519PublicKey) -> bytes:
    return pub.public_bytes_raw()


def load_pubkey(data: bytes) -> X25519PublicKey:
    return X25519PublicKey.from_public_bytes(data)


def derive_session_key(priv: X25519PrivateKey, peer_pub: X25519PublicKey, salt: bytes) -> bytes:
    shared_secret = priv.exchange(peer_pub)
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=salt, info=HANDSHAKE_INFO
    ).derive(shared_secret)


class SessionCipher:
    """
    AES-256-GCM wrapper for one session key.

    Both sides of a session derive the SAME key via ECDH, so encrypting
    in both directions with that one key needs disjoint nonce spaces or
    you get nonce reuse, which breaks AES-GCM's confidentiality and
    integrity guarantees outright. The is_server flag picks a 4-byte
    direction prefix so client-to-server and server-to-client packets
    can never collide on (key, nonce), even if both sides happen to be
    at the same counter value.
    """

    def __init__(self, key: bytes, is_server: bool):
        self.aead = AESGCM(key)
        self.send_counter = 0
        self.send_prefix = b"\x01\x00\x00\x00" if is_server else b"\x00\x00\x00\x00"
        self.recv_prefix = b"\x00\x00\x00\x00" if is_server else b"\x01\x00\x00\x00"

    def encrypt(self, plaintext: bytes) -> bytes:
        counter_bytes = self.send_counter.to_bytes(8, "big")
        nonce = self.send_prefix + counter_bytes # 12 bytes total
        ciphertext = self.aead.encrypt(nonce, plaintext, None)
        self.send_counter += 1
        return counter_bytes + ciphertext

    def decrypt(self, wire_data: bytes) -> bytes:
        if len(wire_data) < 8:
            raise ValueError("data too short to extract counter")
        counter_bytes, ciphertext = wire_data[:8], wire_data[8:]
        nonce = self.recv_prefix + counter_bytes
        return self.aead.decrypt(nonce, ciphertext, None) # raises on bad tag

    @staticmethod
    def counter_of(wire_data: bytes) -> int:
        if len(wire_data) < 8:
            return -1
        return int.from_bytes(wire_data[:8], "big")
