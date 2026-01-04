"""
IPFS Service using Pinata
"""
import asyncio
import httpx
import json
from typing import Optional
from app.config import get_settings

settings = get_settings()


class IPFSService:
    PINATA_API_URL = "https://api.pinata.cloud"

    def __init__(self):
        self.api_key = settings.pinata_api_key
        self.secret_key = settings.pinata_secret_key
        self.gateway = settings.pinata_gateway
        self._client: Optional[httpx.AsyncClient] = None

    @property
    def headers(self) -> dict:
        return {
            "pinata_api_key": self.api_key or "",
            "pinata_secret_api_key": self.secret_key or ""
        }

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=120.0)
        return self._client

    async def close(self):
        if self._client:
            await self._client.aclose()
            self._client = None

    async def upload_encrypted_audio(
        self,
        encrypted_data: bytes,
        filename: str,
        metadata: Optional[dict] = None
    ) -> dict:
        if not self.api_key or not self.secret_key:
            raise ValueError("Pinata API keys not configured")

        client = await self._get_client()
        
        files = {"file": (filename, encrypted_data, "application/octet-stream")}
        data = {}
        
        if metadata:
            pinata_metadata = {"name": filename, "keyvalues": metadata}
            data["pinataMetadata"] = json.dumps(pinata_metadata)

        response = await client.post(
            f"{self.PINATA_API_URL}/pinning/pinFileToIPFS",
            headers=self.headers,
            files=files,
            data=data
        )
        response.raise_for_status()
        result = response.json()

        cid = result["IpfsHash"]
        return {
            "cid": cid,
            "ipfs_url": f"ipfs://{cid}",
            "gateway_url": f"{self.gateway}/{cid}",
            "size": result["PinSize"],
            "timestamp": result["Timestamp"]
        }

    async def upload_metadata(self, metadata: dict, name: str) -> dict:
        if not self.api_key or not self.secret_key:
            raise ValueError("Pinata API keys not configured")

        client = await self._get_client()
        
        payload = {
            "pinataContent": metadata,
            "pinataMetadata": {"name": name}
        }

        response = await client.post(
            f"{self.PINATA_API_URL}/pinning/pinJSONToIPFS",
            headers={**self.headers, "Content-Type": "application/json"},
            json=payload
        )
        response.raise_for_status()
        result = response.json()

        cid = result["IpfsHash"]
        return {
            "cid": cid,
            "ipfs_url": f"ipfs://{cid}",
            "gateway_url": f"{self.gateway}/{cid}"
        }

    async def get_file(self, cid: str, retries: int = 3, delay: float = 2.0) -> bytes:
        """
        Download file from IPFS with retry logic.
        Pinata gateway can take a few seconds to propagate new files.
        """
        client = await self._get_client()
        last_error = None
        
        for attempt in range(retries):
            try:
                response = await client.get(f"{self.gateway}/{cid}")
                response.raise_for_status()
                return response.content
            except httpx.HTTPStatusError as e:
                last_error = e
                if e.response.status_code == 404 and attempt < retries - 1:
                    # Wait and retry for 404 (propagation delay)
                    await asyncio.sleep(delay)
                    continue
                raise
            except Exception as e:
                last_error = e
                if attempt < retries - 1:
                    await asyncio.sleep(delay)
                    continue
                raise
        
        raise last_error

    async def unpin(self, cid: str) -> bool:
        client = await self._get_client()
        response = await client.delete(
            f"{self.PINATA_API_URL}/pinning/unpin/{cid}",
            headers=self.headers
        )
        return response.status_code == 200

    async def test_connection(self) -> bool:
        if not self.api_key or not self.secret_key:
            return False
        try:
            client = await self._get_client()
            response = await client.get(
                f"{self.PINATA_API_URL}/data/testAuthentication",
                headers=self.headers
            )
            return response.status_code == 200
        except:
            return False