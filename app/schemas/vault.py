from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime


# ============================================
# Request Schemas
# ============================================

class StoreEncryptedAudioRequest(BaseModel):
    wallet_address: str = Field(..., description="User's Solana wallet address")
    encrypted_audio_base64: str = Field(..., description="Base64 encoded encrypted audio")
    encrypted_key_base64: str = Field(..., description="Base64 encoded encrypted AES key")
    nonce_base64: str = Field(..., description="Base64 encoded nonce for decryption")
    original_filename: str = Field(..., description="Original audio filename")
    duration_seconds: Optional[int] = Field(None, description="Audio duration in seconds")
    audio_hash: str = Field(..., description="SHA-256 hash of original audio")


class StoreFromBackendRequest(BaseModel):
    upload_id: str = Field(..., description="Audio upload ID from your backend")
    wallet_address: str = Field(..., description="User's Solana wallet address")


class VerifyVaultRecordRequest(BaseModel):
    metadata_cid: str = Field(..., description="IPFS CID of metadata JSON")
    solana_signature: str = Field(..., description="Solana transaction signature")
    metadata_sha256: Optional[str] = Field(None, description="Optional expected sha256 of metadata JSON")


class RetrieveEncryptedAudioRequest(BaseModel):
    audio_cid: str = Field(..., description="IPFS CID of encrypted audio")


# ============================================
# Response Schemas
# ============================================

class StoreAudioResponse(BaseModel):
    success: bool
    audio_cid: str
    metadata_cid: str
    audio_gateway_url: str
    metadata_gateway_url: str
    solana_tx: dict
    message: str


class VerifyAudioResponse(BaseModel):
    verified: bool
    metadata_cid: str
    solana_signature: str
    memo: Optional[str] = None
    message: str


class RetrieveAudioResponse(BaseModel):
    audio_cid: str
    encrypted_audio_base64: str
    file_size: int
    message: str


class VaultRecordResponse(BaseModel):
    metadata_cid: Optional[str]
    audio_cid: Optional[str]
    audio_gateway_url: Optional[str]
    solana_signature: Optional[str]
    created_at: datetime
    verified: bool


class WalletRecordsResponse(BaseModel):
    wallet_address: str
    records: List[VaultRecordResponse]
    total_count: int


class HealthResponse(BaseModel):
    status: str
    solana: dict
    ipfs: dict
    backend: dict


class EncryptionGuideResponse(BaseModel):
    description: str
    steps: list[str]
    javascript_example: str
    react_native_example: str
