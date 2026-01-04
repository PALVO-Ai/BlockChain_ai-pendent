"""
Blockchain Vault API Endpoints
Correct design:
- Encrypted audio → IPFS
- Metadata JSON (key, nonce, hashes) → IPFS
- Solana memo stores only CID + SHA256(metadata)
"""
import base64
import json
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, Header
from typing import Optional

from app.schemas.vault import (
    StoreEncryptedAudioRequest,
    StoreFromBackendRequest,
    VerifyVaultRecordRequest,
    RetrieveEncryptedAudioRequest,
    StoreAudioResponse,
    VerifyAudioResponse,
    RetrieveAudioResponse,
    WalletRecordsResponse,
    VaultRecordResponse,
    HealthResponse,
    EncryptionGuideResponse,
)
from app.services.backend_client import BackendClient
from app.services.encryption import EncryptionService, ClientSideEncryption
from app.services.ipfs_service import IPFSService
from app.services.solana_service import SolanaService

router = APIRouter(prefix="/api/v1/vault", tags=["Blockchain Vault"])
from pydantic import BaseModel


# -------------------------------------------------
# Helpers
# -------------------------------------------------

def _require_bearer(auth_header: Optional[str]) -> str:
    if not auth_header:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="Invalid Authorization header")
    return parts[1]


# -------------------------------------------------
# Health
# -------------------------------------------------

@router.get("/health", response_model=HealthResponse)
async def health_check():
    ipfs = None
    sol = None

    try:
        sol = SolanaService()
        sol_status = await sol.health_check()

        try:
            ipfs = IPFSService()
            ipfs_ok = await ipfs.test_connection()
            ipfs_status = {"status": "ok" if ipfs_ok else "error"}
        except Exception as e:
            ipfs_status = {"status": "error", "error": str(e)}

        status = (
            "healthy"
            if sol_status.get("status") == "connected"
            and ipfs_status.get("status") == "ok"
            else "degraded"
        )

        return HealthResponse(
            status=status,
            solana=sol_status,
            ipfs=ipfs_status,
            backend={"status": "unknown"},
        )
    finally:
        if ipfs:
            await ipfs.close()
        if sol:
            await sol.close()


# -------------------------------------------------
# Encryption guide
# -------------------------------------------------

@router.get("/encryption-guide", response_model=EncryptionGuideResponse)
async def encryption_guide():
    return ClientSideEncryption.get_mobile_encryption_code()


# -------------------------------------------------
# Store (client-side encrypted)
# -------------------------------------------------

@router.post("/store", response_model=StoreAudioResponse)
async def store_encrypted_audio(req: StoreEncryptedAudioRequest):
    ipfs = IPFSService()
    sol = SolanaService()

    try:
        encrypted_audio = EncryptionService.b64decode(req.encrypted_audio_base64)

        # 1️⃣ Upload encrypted audio
        audio_upload = await ipfs.upload_encrypted_audio(
            encrypted_data=encrypted_audio,
            filename=req.original_filename,
            metadata={"wallet": req.wallet_address, "type": "palvo_audio"},
        )

        audio_cid = audio_upload["cid"]

        # 2️⃣ Build metadata JSON (THIS is the source of truth)
        metadata = {
            "type": "audio_vault",
            "version": "1",
            "wallet": req.wallet_address,
            "audio_cid": audio_cid,
            "encrypted_key_base64": req.encrypted_key_base64,
            "nonce_base64": req.nonce_base64,
            "audio_hash": req.audio_hash,
            "enc_audio_hash": EncryptionService.sha256_hex(encrypted_audio),
            "filename": req.original_filename,
            "duration": req.duration_seconds,
            "size": audio_upload["size"],
            "ts": int(datetime.now(timezone.utc).timestamp()),
        }

        meta_upload = await ipfs.upload_metadata(
            metadata, name=f"palvo-meta-{audio_cid}"
        )
        metadata_cid = meta_upload["cid"]

        metadata_bytes = json.dumps(
            metadata, separators=(",", ":"), sort_keys=True
        ).encode()

        # 3️⃣ Prepare Solana memo pointer (unsigned tx)
        memo = sol.build_memo_pointer(metadata_cid, metadata_bytes)
        solana_tx = await sol.prepare_memo_transaction(
            req.wallet_address, memo
        )

        return StoreAudioResponse(
            success=True,
            audio_cid=audio_cid,
            metadata_cid=metadata_cid,
            audio_gateway_url=audio_upload["gateway_url"],
            metadata_gateway_url=meta_upload["gateway_url"],
            solana_tx=solana_tx,
            message="Encrypted audio stored. Sign the Solana transaction to anchor metadata.",
        )
    finally:
        await ipfs.close()
        await sol.close()


# -------------------------------------------------
# Store from backend (server-side encryption)
# -------------------------------------------------

@router.post("/store-from-backend", response_model=StoreAudioResponse)
async def store_from_backend(
    req: StoreFromBackendRequest,
    authorization: str = Header(...),
):
    token = _require_bearer(authorization)

    backend = BackendClient(token)
    ipfs = IPFSService()
    sol = SolanaService()

    try:
        audio_bytes = await backend.download_audio(req.upload_id)

        aes_key = EncryptionService.generate_aes_key()
        encrypted_audio, nonce = EncryptionService.encrypt_audio(audio_bytes, aes_key)

        encrypted_key_b64 = EncryptionService.encrypt_key_for_wallet(
            aes_key, req.wallet_address
        )

        audio_upload = await ipfs.upload_encrypted_audio(
            encrypted_data=encrypted_audio,
            filename=f"{req.upload_id}.bin",
            metadata={"wallet": req.wallet_address, "type": "palvo_audio"},
        )

        metadata = {
            "type": "audio_vault",
            "version": "1",
            "wallet": req.wallet_address,
            "audio_cid": audio_upload["cid"],
            "encrypted_key_base64": encrypted_key_b64,
            "nonce_base64": EncryptionService.b64encode(nonce),
            "audio_hash": EncryptionService.sha256_hex(audio_bytes),
            "enc_audio_hash": EncryptionService.sha256_hex(encrypted_audio),
            "upload_id": req.upload_id,
            "size": audio_upload["size"],
            "ts": int(datetime.now(timezone.utc).timestamp()),
        }

        meta_upload = await ipfs.upload_metadata(
            metadata, name=f"palvo-meta-{audio_upload['cid']}"
        )

        metadata_bytes = json.dumps(
            metadata, separators=(",", ":"), sort_keys=True
        ).encode()

        memo = sol.build_memo_pointer(meta_upload["cid"], metadata_bytes)
        solana_tx = await sol.prepare_memo_transaction(
            req.wallet_address, memo
        )

        return StoreAudioResponse(
            success=True,
            audio_cid=audio_upload["cid"],
            metadata_cid=meta_upload["cid"],
            audio_gateway_url=audio_upload["gateway_url"],
            metadata_gateway_url=meta_upload["gateway_url"],
            solana_tx=solana_tx,
            message="Audio encrypted and stored. Sign the Solana transaction.",
        )
    finally:
        await backend.close()
        await ipfs.close()
        await sol.close()


# -------------------------------------------------
# Verify
# -------------------------------------------------

@router.post("/verify", response_model=VerifyAudioResponse)
async def verify_vault_record(req: VerifyVaultRecordRequest):
    ipfs = IPFSService()
    sol = SolanaService()

    try:
        metadata_bytes = await ipfs.get_file(req.metadata_cid)

        verify = await sol.verify_pointer_memo(
            signature=req.solana_signature,
            metadata_cid=req.metadata_cid,
            expected_metadata_json_bytes=metadata_bytes,
        )

        return VerifyAudioResponse(
            verified=bool(verify.get("verified")),
            metadata_cid=req.metadata_cid,
            solana_signature=req.solana_signature,
            memo=verify.get("memo"),
            message="Verified"
            if verify.get("verified")
            else "Verification failed",
        )
    finally:
        await ipfs.close()
        await sol.close()


# -------------------------------------------------
# Retrieve encrypted audio
# -------------------------------------------------

@router.post("/retrieve", response_model=RetrieveAudioResponse)
async def retrieve_encrypted_audio(req: RetrieveEncryptedAudioRequest):
    ipfs = IPFSService()
    try:
        data = await ipfs.get_file(req.audio_cid)
        return RetrieveAudioResponse(
            audio_cid=req.audio_cid,
            encrypted_audio_base64=base64.b64encode(data).decode(),
            file_size=len(data),
            message="Encrypted audio retrieved.",
        )
    finally:
        await ipfs.close()


# -------------------------------------------------
# Wallet records
# -------------------------------------------------

@router.get("/wallet/{wallet_address}/records", response_model=WalletRecordsResponse)
async def get_wallet_records(wallet_address: str, limit: int = 10):
    sol = SolanaService()
    try:
        sigs = await sol.get_recent_records(wallet_address, limit)
        records = [
            VaultRecordResponse(
                metadata_cid=None,
                audio_cid=None,
                audio_gateway_url=None,
                solana_signature=s["signature"],
                created_at=datetime.fromtimestamp(
                    s["block_time"] or datetime.now().timestamp(), tz=timezone.utc
                ),
                verified=False,
            )
            for s in sigs
        ]

        return WalletRecordsResponse(
            wallet_address=wallet_address,
            records=records,
            total_count=len(records),
        )
    finally:
        await sol.close()
class DecryptRequest(BaseModel):
    audio_cid: str
    metadata_cid: str

class DecryptResponse(BaseModel):
    success: bool
    audio_base64: Optional[str] = None
    content_type: str = "audio/mpeg"
    file_size: Optional[int] = None
    error: Optional[str] = None

@router.post("/decrypt", response_model=DecryptResponse)
async def decrypt_audio(request: DecryptRequest):
    """
    DEV ONLY: Decrypt audio using dev wallet.
    In production, decryption happens client-side with user's wallet.
    """
    from pathlib import Path
    
    ipfs = None
    try:
        # Load dev wallet
        wallet_path = Path(__file__).parent.parent.parent / "dev_wallet.json"
        if not wallet_path.exists():
            return DecryptResponse(success=False, error="Dev wallet not found")
        
        with open(wallet_path) as f:
            dev_wallet = json.load(f)
        
        secret_key_bytes = bytes(dev_wallet["secret_key_bytes"])
        
        # Get metadata from IPFS
        ipfs = IPFSService()
        metadata_bytes = await ipfs.get_file(request.metadata_cid)
        metadata = json.loads(metadata_bytes.decode())
        
        # Get encrypted audio from IPFS
        encrypted_audio_bytes = await ipfs.get_file(request.audio_cid)
        
        # Decrypt AES key using wallet private key
        encrypted_key_b64 = metadata.get("encrypted_key_base64")
        nonce_b64 = metadata.get("nonce_base64")
        
        if not encrypted_key_b64 or not nonce_b64:
            return DecryptResponse(success=False, error=f"Missing encryption metadata. Keys found: {list(metadata.keys())}")
        
        nonce = base64.b64decode(nonce_b64)
        
        # Decrypt AES key
        aes_key = EncryptionService.decrypt_key_with_ed25519_secret(
            encrypted_key_b64,
            secret_key_bytes
        )
        
        # Decrypt audio
        decrypted_audio = EncryptionService.decrypt_audio(
            encrypted_audio_bytes,
            aes_key,
            nonce
        )
        
        return DecryptResponse(
            success=True,
            audio_base64=base64.b64encode(decrypted_audio).decode(),
            content_type=metadata.get("content_type", "audio/mpeg"),
            file_size=len(decrypted_audio)
        )
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return DecryptResponse(success=False, error=str(e))
    finally:
        if ipfs:
            await ipfs.close()
