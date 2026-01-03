"""
IPFS Service using Pinata
Free tier: 1GB storage, 100 pins
"""
import json
import httpx
from typing import Optional
from app.config import get_settings

settings = get_settings()


class IPFSService:
    """Upload encrypted files to IPFS via Pinata"""

    PINATA_API_URL = "https://api.pinata.cloud"

    def __init__(self):
        if not settings.pinata_api_key or not settings.pinata_secret_key:
            raise RuntimeError("Pinata API keys are not configured")

        self.api_key = settings.pinata_api_key
        self.secret_key = settings.pinata_secret_key
        self.gateway = settings.pinata_gateway

        self.client = httpx.AsyncClient(
            base_url=self.PINATA_API_URL,
            headers={
                "pinata_api_key": self.api_key,
                "pinata_secret_api_key": self.secret_key,
            },
            timeout=httpx.Timeout(120.0),
        )

    async def close(self):
        await self.client.aclose()

    async def upload_encrypted_audio(
        self,
        encrypted_data: bytes,
        filename: str,
        metadata: Optional[dict] = None,
    ) -> dict:
        """Upload encrypted audio to IPFS"""

        files = {
            "file": (filename, encrypted_data, "application/octet-stream")
        }

        data = {}
        if metadata:
            data["pinataMetadata"] = json.dumps(
                {"name": filename, "keyvalues": metadata}
            )

        response = await self.client.post(
            "/pinning/pinFileToIPFS",
            files=files,
            data=data,
        )
        response.raise_for_status()
        result = response.json()

        cid = result["IpfsHash"]
        return {
            "cid": cid,
            "ipfs_url": f"ipfs://{cid}",
            "gateway_url": f"{self.gateway}/{cid}",
            "size": result["PinSize"],
            "timestamp": result["Timestamp"],
        }

    async def upload_metadata(self, metadata: dict, name: str) -> dict:
        """Upload JSON metadata to IPFS"""

        payload = {
            "pinataContent": metadata,
            "pinataMetadata": {"name": name},
        }

        response = await self.client.post(
            "/pinning/pinJSONToIPFS",
            json=payload,
        )
        response.raise_for_status()
        result = response.json()

        cid = result["IpfsHash"]
        return {
            "cid": cid,
            "ipfs_url": f"ipfs://{cid}",
            "gateway_url": f"{self.gateway}/{cid}",
        }

    async def get_file(self, cid: str) -> bytes:
        """Download file from IPFS gateway"""
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.get(f"{self.gateway}/{cid}")
            response.raise_for_status()
            return response.content

    async def unpin(self, cid: str) -> None:
        """Unpin file from Pinata"""
        response = await self.client.delete(f"/pinning/unpin/{cid}")
        response.raise_for_status()

    async def get_pin_list(self, limit: int = 10) -> list:
        """List pinned files"""
        response = await self.client.get(
            "/data/pinList",
            params={"pageLimit": limit},
        )
        response.raise_for_status()
        return response.json().get("rows", [])

    async def test_connection(self) -> bool:
        """Test Pinata API authentication"""
        response = await self.client.get("/data/testAuthentication")
        return response.status_code == 200
