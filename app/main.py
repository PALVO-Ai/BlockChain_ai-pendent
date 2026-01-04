"""
Blockchain Service - Private Audio Vault
Connects to your existing Audio Memory Backend via API
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from app.config import get_settings
from app.routers import vault
from app.services.solana_service import SolanaService
from app.services.ipfs_service import IPFSService

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events"""
    # Startup
    print("=" * 60)
    print("🔐 STARTING BLOCKCHAIN AUDIO VAULT SERVICE")
    print("=" * 60)
    
    # Check Solana connection
    solana = SolanaService()
    solana_health = await solana.health_check()
    if solana_health.get("status") == "connected":
        print(f"   ✅ Solana: {settings.solana_network} (slot: {solana_health.get('current_slot')})")
    else:
        print(f"   ⚠️  Solana: {solana_health.get('error', 'Not connected')}")
    
    # Check IPFS/Pinata connection
    ipfs = IPFSService()
    ipfs_ok = await ipfs.test_connection()
    if ipfs_ok:
        print("   ✅ IPFS (Pinata): Connected")
    else:
        print("   ⚠️  IPFS (Pinata): Not configured or not connected")
    
    print(f"\n   📡 Backend URL: {settings.backend_api_url}")
    print(f"\n   📍 Endpoints:")
    print(f"      • API:     http://localhost:{settings.port}")
    print(f"      • Swagger: http://localhost:{settings.port}/docs")
    print(f"      • Health:  http://localhost:{settings.port}/api/v1/vault/health")
    print("=" * 60)
    print("✅ Blockchain service ready!\n")
    
    yield
    
    # Shutdown
    await solana.close()
    print("\n🔐 Blockchain service stopped")


app = FastAPI(
    title="Blockchain Audio Vault",
    description="""
## 🔐 Private Audio Vault Service

Connects to your Audio Memory Backend and adds:

- **E2E Encryption**: Audio encrypted on device, backend cannot see content
- **IPFS Storage**: Decentralized, permanent storage
- **Solana Blockchain**: Immutable proof of existence and ownership
- **Privacy**: Only wallet owner can decrypt their audio

### Flow:
1. Mobile app encrypts audio with AES-256
2. AES key encrypted with user's Solana wallet
3. Encrypted audio uploaded to IPFS
4. Metadata stored on Solana blockchain
5. Only user with wallet private key can decrypt

### Endpoints:
- `POST /store` - Store encrypted audio (client-side encryption)
- `POST /store-from-backend` - Encrypt and store from existing backend
- `POST /verify` - Verify audio integrity
- `POST /retrieve` - Get encrypted audio from IPFS
- `GET /wallet/{address}/records` - List user's vault records
    """,
    version="1.0.0",
    lifespan=lifespan
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(vault.router)


@app.get("/")
async def root():
    return {
        "service": "Blockchain Audio Vault",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/api/v1/vault/health"
    }