import base64
import base58
from typing import Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from nacl.public import PublicKey, SealedBox
from nacl import bindings


class EncryptionService:
    @staticmethod
    def generate_aes_key() -> bytes:
        return os.urandom(32)

    @staticmethod
    def encrypt_audio(audio_data: bytes, aes_key: bytes) -> Tuple[bytes, bytes]:
        nonce = os.urandom(12)  # AES-GCM standard nonce
        encrypted = AESGCM(aes_key).encrypt(nonce, audio_data, None)
        return encrypted, nonce

    @staticmethod
    def decrypt_audio(encrypted_data: bytes, aes_key: bytes, nonce: bytes) -> bytes:
        return AESGCM(aes_key).decrypt(nonce, encrypted_data, None)

    @staticmethod
    def encrypt_key_for_wallet(aes_key: bytes, wallet_public_key_b58: str) -> str:
        """
        Solana pubkey is Ed25519 (32 bytes).
        SealedBox needs Curve25519 (X25519) public key.
        So we convert Ed25519 -> Curve25519 first.
        """
        ed25519_pk = base58.b58decode(wallet_public_key_b58)
        if len(ed25519_pk) != 32:
            raise ValueError("Invalid Solana public key length (expected 32 bytes)")

        curve25519_pk = bindings.crypto_sign_ed25519_pk_to_curve25519(ed25519_pk)
        sealed_box = SealedBox(PublicKey(curve25519_pk))
        encrypted_key = sealed_box.encrypt(aes_key)

        return base64.b64encode(encrypted_key).decode("utf-8")

    @staticmethod
    def decrypt_key_with_ed25519_secret(
        encrypted_key_b64: str, wallet_ed25519_secret_64bytes: bytes
    ) -> bytes:
        """
        Only usable if you have the 64-byte Ed25519 secret key material.
        NOTE: Most Solana wallets DO NOT expose this for decryption.
        """
        if len(wallet_ed25519_secret_64bytes) != 64:
            raise ValueError("Ed25519 secret must be 64 bytes (seed+pk)")

        encrypted_key = base64.b64decode(encrypted_key_b64)
        curve_sk = bindings.crypto_sign_ed25519_sk_to_curve25519(wallet_ed25519_secret_64bytes)

        from nacl.public import PrivateKey
        sealed_box = SealedBox(PrivateKey(curve_sk))
        return sealed_box.decrypt(encrypted_key)
