"""
End-to-End Encryption Service
- Audio encrypted with AES-256-GCM
- AES key encrypted with user's Solana wallet public key
- Backend NEVER sees unencrypted content
"""
import os
import base64
import hashlib
from typing import Tuple

import base58
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from nacl.public import PublicKey, SealedBox, PrivateKey
from nacl import bindings


class EncryptionService:
    """
    Encryption flow:
    1. Generate random AES-256 key
    2. Encrypt audio with AES-256-GCM
    3. Encrypt AES key with user's Solana public key (X25519)
    4. Only user with private key can decrypt
    """

    # ─────────────────────────────────────────────────────────────
    # Base64 helpers
    # ─────────────────────────────────────────────────────────────

    @staticmethod
    def b64encode(data: bytes) -> str:
        """Encode bytes to base64 string"""
        return base64.b64encode(data).decode("utf-8")

    @staticmethod
    def b64decode(data: str) -> bytes:
        """Decode base64 string to bytes"""
        return base64.b64decode(data)

    # ─────────────────────────────────────────────────────────────
    # Hashing
    # ─────────────────────────────────────────────────────────────

    @staticmethod
    def sha256_hex(data: bytes) -> str:
        """Generate SHA-256 hash as hex string"""
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def hash_audio(audio_data: bytes) -> str:
        """Alias for sha256_hex"""
        return EncryptionService.sha256_hex(audio_data)

    @staticmethod
    def hash_encrypted(encrypted_data: bytes) -> str:
        """Alias for sha256_hex"""
        return EncryptionService.sha256_hex(encrypted_data)

    # ─────────────────────────────────────────────────────────────
    # AES-256-GCM Encryption
    # ─────────────────────────────────────────────────────────────

    @staticmethod
    def generate_aes_key() -> bytes:
        """Generate random 256-bit AES key"""
        return os.urandom(32)

    @staticmethod
    def encrypt_audio(audio_data: bytes, aes_key: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypt audio with AES-256-GCM
        Returns: (encrypted_data, nonce)
        """
        nonce = os.urandom(12)  # 96-bit nonce for GCM
        aesgcm = AESGCM(aes_key)
        encrypted = aesgcm.encrypt(nonce, audio_data, None)
        return encrypted, nonce

    @staticmethod
    def decrypt_audio(encrypted_data: bytes, aes_key: bytes, nonce: bytes) -> bytes:
        """Decrypt audio with AES-256-GCM"""
        aesgcm = AESGCM(aes_key)
        return aesgcm.decrypt(nonce, encrypted_data, None)

    # ─────────────────────────────────────────────────────────────
    # Asymmetric Encryption (Solana Wallet)
    # ─────────────────────────────────────────────────────────────

    @staticmethod
    def encrypt_key_for_wallet(aes_key: bytes, wallet_public_key_b58: str) -> str:
        """
        Encrypt AES key with Solana wallet's public key.
        
        Solana pubkey is Ed25519 (32 bytes).
        SealedBox needs Curve25519 (X25519) public key.
        So we convert Ed25519 -> Curve25519 first.
        
        Returns: base64 encoded encrypted key
        """
        ed25519_pk = base58.b58decode(wallet_public_key_b58)
        if len(ed25519_pk) != 32:
            raise ValueError("Invalid Solana public key length (expected 32 bytes)")

        # Convert Ed25519 public key to Curve25519
        curve25519_pk = bindings.crypto_sign_ed25519_pk_to_curve25519(ed25519_pk)
        
        # Encrypt using NaCl sealed box
        sealed_box = SealedBox(PublicKey(curve25519_pk))
        encrypted_key = sealed_box.encrypt(aes_key)

        return base64.b64encode(encrypted_key).decode("utf-8")

    @staticmethod
    def decrypt_key_with_ed25519_secret(
        encrypted_key_b64: str, 
        wallet_ed25519_secret_64bytes: bytes
    ) -> bytes:
        """
        Decrypt AES key using Ed25519 secret key.
        
        Only usable if you have the 64-byte Ed25519 secret key material.
        NOTE: Most Solana wallets DO NOT expose this for decryption.
        This is mainly for testing purposes.
        """
        if len(wallet_ed25519_secret_64bytes) != 64:
            raise ValueError("Ed25519 secret must be 64 bytes (seed+pk)")

        encrypted_key = base64.b64decode(encrypted_key_b64)
        
        # Convert Ed25519 secret key to Curve25519
        curve_sk = bindings.crypto_sign_ed25519_sk_to_curve25519(wallet_ed25519_secret_64bytes)

        sealed_box = SealedBox(PrivateKey(curve_sk))
        return sealed_box.decrypt(encrypted_key)


class ClientSideEncryption:
    """
    Instructions for client-side (mobile app) encryption.
    This code should run ON THE DEVICE, not on server.
    """

    @staticmethod
    def get_mobile_encryption_code() -> dict:
        """
        Returns code/instructions for mobile app to implement E2E encryption
        """
        return {
            "description": "E2E Encryption - Run this on mobile device, NOT on server",
            "steps": [
                "1. Generate random AES-256 key on device",
                "2. Encrypt audio with AES-256-GCM on device",
                "3. Get user's Solana wallet public key",
                "4. Encrypt AES key with wallet public key (X25519)",
                "5. Upload encrypted audio + encrypted key to blockchain service",
                "6. Sign Solana transaction with wallet",
                "7. Only user with wallet private key can decrypt"
            ],
            "javascript_example": """
// ============================================
// JAVASCRIPT / REACT NATIVE EXAMPLE
// ============================================

import nacl from 'tweetnacl';
import { Buffer } from 'buffer';

// 1. Generate random AES key (32 bytes)
const aesKey = nacl.randomBytes(32);

// 2. Encrypt audio with AES (using tweetnacl secretbox)
const nonce = nacl.randomBytes(24);
const encryptedAudio = nacl.secretbox(audioBytes, nonce, aesKey);

// 3. Get wallet public key from Phantom/Solflare
const walletPublicKey = wallet.publicKey.toBytes();

// 4. Convert Ed25519 to X25519 for encryption
// Note: Use 'ed2curve' library for this conversion
import ed2curve from 'ed2curve';
const x25519PublicKey = ed2curve.convertPublicKey(walletPublicKey);

// 5. Encrypt AES key with wallet's X25519 public key
const encryptedKey = nacl.box.seal(aesKey, x25519PublicKey);

// 6. Send to blockchain service
const response = await fetch('http://localhost:8001/api/v1/vault/store', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
        wallet_address: wallet.publicKey.toString(),
        encrypted_audio_base64: Buffer.from(encryptedAudio).toString('base64'),
        encrypted_key_base64: Buffer.from(encryptedKey).toString('base64'),
        nonce_base64: Buffer.from(nonce).toString('base64'),
        original_filename: 'recording.wav',
        audio_hash: sha256(originalAudioBytes),
        duration_seconds: 60
    })
});
""",
            "react_native_example": """
// ============================================
// REACT NATIVE WITH EXPO EXAMPLE
// ============================================

import * as Crypto from 'expo-crypto';
import nacl from 'tweetnacl';
import ed2curve from 'ed2curve';
import { Buffer } from 'buffer';

const encryptAndUpload = async (audioBase64, wallet) => {
    // Convert audio to bytes
    const audioBytes = Buffer.from(audioBase64, 'base64');
    
    // Calculate hash of original audio
    const audioHash = await Crypto.digestStringAsync(
        Crypto.CryptoDigestAlgorithm.SHA256,
        audioBase64
    );
    
    // Generate random AES key
    const aesKey = nacl.randomBytes(32);
    
    // Generate nonce
    const nonce = nacl.randomBytes(24);
    
    // Encrypt audio
    const encryptedAudio = nacl.secretbox(
        new Uint8Array(audioBytes), 
        nonce, 
        aesKey
    );
    
    // Convert wallet public key for encryption
    const walletPubKeyBytes = wallet.publicKey.toBytes();
    const x25519PubKey = ed2curve.convertPublicKey(walletPubKeyBytes);
    
    // Encrypt AES key with wallet public key
    const encryptedKey = nacl.box.seal(aesKey, x25519PubKey);
    
    // Upload to blockchain service
    const response = await fetch('http://YOUR_SERVER:8001/api/v1/vault/store', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            wallet_address: wallet.publicKey.toString(),
            encrypted_audio_base64: Buffer.from(encryptedAudio).toString('base64'),
            encrypted_key_base64: Buffer.from(encryptedKey).toString('base64'),
            nonce_base64: Buffer.from(nonce).toString('base64'),
            original_filename: 'recording.wav',
            audio_hash: audioHash,
            duration_seconds: null
        })
    });
    
    return await response.json();
};

// Decryption (only wallet owner can do this)
const decryptAudio = async (encryptedAudioB64, encryptedKeyB64, nonceB64, wallet) => {
    const encryptedAudio = Buffer.from(encryptedAudioB64, 'base64');
    const encryptedKey = Buffer.from(encryptedKeyB64, 'base64');
    const nonce = Buffer.from(nonceB64, 'base64');
    
    // Convert wallet keys for decryption
    const walletSecretKey = wallet.secretKey; // 64 bytes
    const x25519SecretKey = ed2curve.convertSecretKey(walletSecretKey);
    
    // Decrypt AES key
    const aesKey = nacl.box.open.seal(encryptedKey, x25519SecretKey);
    
    // Decrypt audio
    const decryptedAudio = nacl.secretbox.open(encryptedAudio, nonce, aesKey);
    
    return Buffer.from(decryptedAudio).toString('base64');
};
""",
            "dependencies": {
                "npm": [
                    "tweetnacl",
                    "ed2curve", 
                    "buffer",
                    "@solana/web3.js"
                ],
                "expo": [
                    "expo-crypto"
                ]
            },
            "security_notes": [
                "⚠️ NEVER send unencrypted audio to any server",
                "⚠️ NEVER send AES key unencrypted",
                "⚠️ Encryption MUST happen on user's device",
                "⚠️ Only the wallet owner can decrypt their audio",
                "✅ Server only sees encrypted blobs",
                "✅ Even if server is hacked, audio is safe"
            ]
        }