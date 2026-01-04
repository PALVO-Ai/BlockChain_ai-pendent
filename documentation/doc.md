# 🔐 Blockchain Audio Vault - Complete Documentation

## 📋 Overview

A **separate microservice** that adds blockchain-based E2E encryption to your existing Audio Memory Backend.

```
┌─────────────────────────────────────────────────────────────────────┐
│                         SYSTEM ARCHITECTURE                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   📱 Mobile App                                                     │
│        │                                                            │
│        │ (Option 1: Direct E2E)        (Option 2: Migrate)          │
│        ▼                                      │                     │
│   ┌─────────────┐                             │                     │
│   │ Encrypt on  │                             │                     │
│   │ Device      │                             ▼                     │
│   └──────┬──────┘                    ┌─────────────────┐            │
│          │                           │ Audio Memory    │            │
│          │                           │ Backend         │            │
│          │                           │ (Port 8000)     │            │
│          │                           │                 │            │
│          │                           │ • Auth          │            │
│          │                           │ • S3 Storage    │            │
│          │                           │ • Transcription │            │
│          │                           └────────┬────────┘            │
│          │                                    │                     │
│          ▼                                    ▼                     │
│   ┌─────────────────────────────────────────────────────┐           │
│   │              BLOCKCHAIN SERVICE (Port 8001)         │           │
│   │                                                     │           │
│   │  • /store        → Store E2E encrypted audio        │           │
│   │  • /store-from-backend → Migrate from S3            │           │
│   │  • /retrieve     → Get encrypted audio              │           │
│   │  • /verify       → Verify on blockchain             │           │
│   └──────────────────────┬──────────────────────────────┘           │
│                          │                                          │
│          ┌───────────────┴───────────────┐                          │
│          ▼                               ▼                          │
│   ┌─────────────┐                 ┌─────────────┐                   │
│   │    IPFS     │                 │   Solana    │                   │
│   │  (Pinata)   │                 │ Blockchain  │                   │
│   │             │                 │             │                   │
│   │ Encrypted   │                 │ Metadata    │                   │
│   │ Audio Blob  │                 │ Pointer     │                   │
│   └─────────────┘                 └─────────────┘                   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 🗂️ Project Structure

```
blockchain-service/
├── app/
│   ├── __init__.py
│   ├── main.py                    # FastAPI application
│   ├── config.py                  # Environment configuration
│   │
│   ├── routers/
│   │   ├── __init__.py
│   │   └── vault.py               # API endpoints
│   │
│   ├── schemas/
│   │   ├── __init__.py
│   │   └── vault.py               # Request/Response models
│   │
│   └── services/
│       ├── __init__.py
│       ├── backend_client.py      # Calls existing backend API
│       ├── encryption.py          # AES-256 + Solana wallet encryption
│       ├── ipfs_service.py        # Pinata IPFS upload/download
│       └── solana_service.py      # Solana blockchain operations
│
├── test/
│   └── test_vault.py              # Test script
│
├── .env                           # Configuration
├── requirements.txt               # Dependencies
└── README.md
```

---

## 🔧 Configuration (.env)

```properties
# Application
APP_NAME=BlockchainService
DEBUG=true
PORT=8001

# Your Existing Backend (for migration feature)
BACKEND_API_URL=http://localhost:8000
BACKEND_API_VERSION=v1

# Solana Blockchain
SOLANA_NETWORK=devnet
SOLANA_RPC_URL=https://api.devnet.solana.com

# Pinata IPFS (https://app.pinata.cloud)
PINATA_API_KEY=your_api_key
PINATA_SECRET_KEY=your_secret_key
PINATA_GATEWAY=https://gateway.pinata.cloud/ipfs

# CORS
CORS_ORIGINS=http://localhost:3000,http://localhost:8081
```

---

## 🔌 API Endpoints

### Base URL: `http://localhost:8001/api/v1/vault`

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/health` | No | Health check (Solana + IPFS status) |
| GET | `/encryption-guide` | No | E2E encryption guide for mobile devs |
| POST | `/store` | No | Store encrypted audio (client-side encrypted) |
| POST | `/store-from-backend` | Yes | Migrate from existing S3 storage |
| POST | `/retrieve` | No | Get encrypted audio from IPFS |
| POST | `/verify` | No | Verify audio on blockchain |
| GET | `/wallet/{address}/records` | No | List wallet's vault records |

---

## 🔐 Encryption Flow

### Option 1: True E2E (Client-Side Encryption) - RECOMMENDED

```
📱 Mobile Device                    🖥️ Blockchain Service
─────────────────                   ────────────────────

1. Record Audio
   "Hello world..."
        │
        ▼
2. Generate AES-256 Key
   (random 32 bytes)
        │
        ▼
3. Encrypt Audio
   AES-256-GCM(audio, key)
   → encrypted_audio
        │
        ▼
4. Get Wallet Public Key
   (Phantom/Solflare)
        │
        ▼
5. Encrypt AES Key
   SealedBox(key, wallet_pubkey)
   → encrypted_key
        │
        ▼
6. Send to Server ─────────────────► 7. Upload to IPFS
   {                                    encrypted_audio → CID
     encrypted_audio,                        │
     encrypted_key,                          ▼
     nonce,                             8. Upload Metadata
     audio_hash                            {cid, key, hash} → meta_CID
   }                                         │
                                             ▼
                                        9. Prepare Solana Tx
                                           memo: "palvo:1:{meta_CID}:{hash}"
        │                                        │
        ◄────────────────────────────────────────┘
        │
        ▼
10. Sign Solana Transaction
    (with wallet)
        │
        ▼
11. Submit to Blockchain
    → Transaction Signature

✅ Server NEVER sees:
   - Original audio
   - AES key (unencrypted)
```

### Option 2: Server-Side Encryption (Migration)

For migrating existing audio from your S3 to blockchain:

```
📱 Mobile App                🖥️ Audio Memory Backend        🖥️ Blockchain Service
─────────────                ───────────────────────        ────────────────────

1. Request Migration
   upload_id + wallet_address ─────────────────────────────► 2. Fetch from Backend
                                                                │
                                                                ▼
                                                            3. Download Audio
                                      audio_bytes ◄─────────── GET /uploads/{id}/download
                                                                │
                                                                ▼
                                                            4. Generate AES Key
                                                               Encrypt Audio
                                                               Encrypt Key with Wallet
                                                                │
                                                                ▼
                                                            5. Upload to IPFS
                                                               Store on Solana
                                                                │
        ◄───────────────────────────────────────────────────────┘
        │
        ▼
6. Sign Solana Transaction

⚠️ WARNING: Server sees audio during encryption.
   Use Option 1 for true E2E privacy.
```

---

## 📡 API Details

### POST /store

Store encrypted audio (client encrypts first).

**Request:**
```json
{
  "wallet_address": "7xKXtg2CW87d97TXJsdt...",
  "encrypted_audio_base64": "SGVsbG8gV29ybGQh...",
  "encrypted_key_base64": "ZW5jcnlwdGVkX2tleQ==",
  "nonce_base64": "bm9uY2UxMjM0NTY=",
  "original_filename": "recording.wav",
  "audio_hash": "a591a6d40bf420404a011733cfb7b190...",
  "duration_seconds": 60
}
```

**Response:**
```json
{
  "success": true,
  "audio_cid": "QmX4zdJk7K8r9n2B5m...",
  "metadata_cid": "QmY7abc123...",
  "audio_gateway_url": "https://gateway.pinata.cloud/ipfs/QmX4zdJk7K8r9n2B5m...",
  "metadata_gateway_url": "https://gateway.pinata.cloud/ipfs/QmY7abc123...",
  "solana_tx": {
    "status": "prepared",
    "memo": "palvo:1:QmY7abc123:a591a6d40bf4",
    "recent_blockhash": "...",
    "message": "Sign with your wallet."
  },
  "message": "Encrypted audio stored. Sign the Solana transaction."
}
```

---

### POST /store-from-backend

Migrate audio from existing S3 storage.

**Request:**
```json
{
  "upload_id": "550e8400-e29b-41d4-a716-446655440000",
  "wallet_address": "7xKXtg2CW87d97TXJsdt..."
}
```

**Headers:**
```
Authorization: Bearer <your_backend_jwt_token>
```

**Response:** Same as `/store`

---

### POST /retrieve

Get encrypted audio from IPFS.

**Request:**
```json
{
  "audio_cid": "QmX4zdJk7K8r9n2B5m..."
}
```

**Response:**
```json
{
  "audio_cid": "QmX4zdJk7K8r9n2B5m...",
  "encrypted_audio_base64": "SGVsbG8gV29ybGQh...",
  "file_size": 1024,
  "message": "Encrypted audio retrieved."
}
```

---

### POST /verify

Verify audio integrity on blockchain.

**Request:**
```json
{
  "metadata_cid": "QmY7abc123...",
  "solana_signature": "5UfDuX..."
}
```

**Response:**
```json
{
  "verified": true,
  "metadata_cid": "QmY7abc123...",
  "solana_signature": "5UfDuX...",
  "memo": "palvo:1:QmY7abc123:a591a6d40bf4",
  "message": "Verified"
}
```

---

## 🔗 Connecting to Existing Backend

### Method 1: Call from Mobile App

```javascript
// Mobile app calls BOTH backends

// 1. Regular upload to Audio Memory Backend
const uploadResponse = await fetch('http://localhost:8000/api/v1/uploads/initiate', {
  method: 'POST',
  headers: { 'Authorization': `Bearer ${token}` },
  body: formData
});

// 2. Also store encrypted version on blockchain
const blockchainResponse = await fetch('http://localhost:8001/api/v1/vault/store', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    wallet_address: wallet.publicKey.toString(),
    encrypted_audio_base64: encryptedAudio,
    encrypted_key_base64: encryptedKey,
    nonce_base64: nonce,
    original_filename: filename,
    audio_hash: hash
  })
});
```

### Method 2: Backend-to-Backend (Migration)

```python
# In your Audio Memory Backend, add endpoint to trigger migration

@router.post("/uploads/{upload_id}/migrate-to-blockchain")
async def migrate_to_blockchain(
    upload_id: str,
    wallet_address: str,
    token: str = Depends(get_current_user)
):
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "http://localhost:8001/api/v1/vault/store-from-backend",
            json={
                "upload_id": upload_id,
                "wallet_address": wallet_address
            },
            headers={"Authorization": f"Bearer {token}"}
        )
        return response.json()
```

### Method 3: Add Download Endpoint to Your Backend

The blockchain service needs to download audio from your backend. Make sure you have:

```python
# In audio-memory-backend/app/routers/uploads.py

@router.get("/{upload_id}/download")
async def get_download_url(upload_id: str, user = Depends(get_current_user)):
    """Get presigned download URL for audio file"""
    upload = await get_upload(upload_id, user.id)
    download_url = s3_service.generate_presigned_download_url(upload.s3_key)
    return {"download_url": download_url}
```

---

## 📱 Mobile Integration (React Native)

### Install Dependencies

```bash
npm install tweetnacl ed2curve buffer @solana/web3.js
```

### Encryption Helper

```javascript
// utils/encryption.js
import nacl from 'tweetnacl';
import ed2curve from 'ed2curve';
import { Buffer } from 'buffer';
import * as Crypto from 'expo-crypto';

export const encryptAudio = async (audioBase64, walletPublicKey) => {
  // Convert audio to bytes
  const audioBytes = Buffer.from(audioBase64, 'base64');
  
  // Hash original audio
  const audioHash = await Crypto.digestStringAsync(
    Crypto.CryptoDigestAlgorithm.SHA256,
    audioBase64
  );
  
  // Generate AES key
  const aesKey = nacl.randomBytes(32);
  
  // Generate nonce
  const nonce = nacl.randomBytes(24);
  
  // Encrypt audio with AES (using secretbox)
  const encryptedAudio = nacl.secretbox(
    new Uint8Array(audioBytes),
    nonce,
    aesKey
  );
  
  // Convert wallet Ed25519 pubkey to X25519
  const walletPubKeyBytes = walletPublicKey.toBytes();
  const x25519PubKey = ed2curve.convertPublicKey(walletPubKeyBytes);
  
  // Encrypt AES key with wallet public key
  const encryptedKey = nacl.box.seal(aesKey, x25519PubKey);
  
  return {
    encryptedAudioBase64: Buffer.from(encryptedAudio).toString('base64'),
    encryptedKeyBase64: Buffer.from(encryptedKey).toString('base64'),
    nonceBase64: Buffer.from(nonce).toString('base64'),
    audioHash
  };
};

export const decryptAudio = (encryptedAudioBase64, encryptedKeyBase64, nonceBase64, walletSecretKey) => {
  const encryptedAudio = Buffer.from(encryptedAudioBase64, 'base64');
  const encryptedKey = Buffer.from(encryptedKeyBase64, 'base64');
  const nonce = Buffer.from(nonceBase64, 'base64');
  
  // Convert wallet secret key to X25519
  const x25519SecretKey = ed2curve.convertSecretKey(walletSecretKey);
  
  // Decrypt AES key
  const aesKey = nacl.box.seal.open(encryptedKey, x25519SecretKey);
  
  // Decrypt audio
  const decryptedAudio = nacl.secretbox.open(encryptedAudio, nonce, aesKey);
  
  return Buffer.from(decryptedAudio).toString('base64');
};
```

### Store Audio

```javascript
// screens/RecordingScreen.js
import { encryptAudio } from '../utils/encryption';

const storeOnBlockchain = async (audioBase64, filename, wallet) => {
  // 1. Encrypt on device
  const encrypted = await encryptAudio(audioBase64, wallet.publicKey);
  
  // 2. Send to blockchain service
  const response = await fetch('http://YOUR_SERVER:8001/api/v1/vault/store', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      wallet_address: wallet.publicKey.toString(),
      encrypted_audio_base64: encrypted.encryptedAudioBase64,
      encrypted_key_base64: encrypted.encryptedKeyBase64,
      nonce_base64: encrypted.nonceBase64,
      original_filename: filename,
      audio_hash: encrypted.audioHash,
      duration_seconds: null
    })
  });
  
  const result = await response.json();
  
  // 3. Sign Solana transaction
  // (Use wallet adapter to sign)
  
  return result;
};
```

---

## 🚀 Running the Service

### Development

```bash
# Terminal 1: Start Audio Memory Backend (if needed)
cd audio-memory-backend
uvicorn app.main:app --reload --port 8000

# Terminal 2: Start Blockchain Service
cd blockchain-service
source venv/bin/activate
uvicorn app.main:app --reload --port 8001
```

### Production

```bash
# With Gunicorn
gunicorn app.main:app -w 4 -k uvicorn.workers.UvicornWorker -b 0.0.0.0:8001

# With Docker (create Dockerfile)
docker build -t blockchain-vault .
docker run -p 8001:8001 --env-file .env blockchain-vault
```

---

## 🧪 Testing

```bash
# From project root
cd blockchain-service
python test_vault.py
```

---

## 🔒 Security Notes

| Feature | Security Level |
|---------|----------------|
| `/store` (client encryption) | ✅ **HIGH** - True E2E, server never sees audio |
| `/store-from-backend` | ⚠️ **MEDIUM** - Server encrypts, sees audio briefly |
| IPFS Storage | ✅ Encrypted blob, useless without key |
| Solana Record | ✅ Immutable, tamper-proof |
| Decryption | ✅ Only wallet owner can decrypt |

---

## 📊 Data Flow Summary

| Storage | What's Stored | Who Can Read |
|---------|---------------|--------------|
| IPFS (Audio) | Encrypted audio blob | No one (encrypted) |
| IPFS (Metadata) | CID + encrypted key + hash | No one (key encrypted) |
| Solana | Pointer to metadata + hash | Public (but just pointers) |
| User's Wallet | Private key | Only user |

---

## 🐛 Troubleshooting

| Issue | Solution |
|-------|----------|
| `get_health` error | Update `solana_service.py` (uses `get_slot` instead) |
| IPFS 404 on retrieve | Wait 5-10 seconds after upload, IPFS propagation delay |
| Pinata auth error | Check API keys in `.env` |
| Solana connection error | Try different RPC: `https://api.devnet.solana.com` |
| Import errors | Run from project root, not `test/` folder |

---

## 📝 Next Steps

1. **Deploy to production** (use mainnet Solana)
2. **Add database** to track user's vault records locally
3. **Add Solana transaction signing** in mobile app
4. **Add notifications** when upload completes
5. **Add sharing** (encrypt for multiple wallets)