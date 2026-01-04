"""
Client to call your existing Audio Memory Backend APIs
"""
import httpx
from typing import Optional
from app.config import get_settings

settings = get_settings()


class BackendClient:
    """Connects to your existing audio-memory-backend"""

    def __init__(self, access_token: str):
        self.base_url = settings.backend_base_url
        self.headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=60.0)
        return self._client

    async def close(self):
        """Close the HTTP client"""
        if self._client:
            await self._client.aclose()
            self._client = None

    async def get_user_profile(self) -> dict:
        """GET /api/v1/auth/me"""
        client = await self._get_client()
        response = await client.get(
            f"{self.base_url}/auth/me",
            headers=self.headers
        )
        response.raise_for_status()
        return response.json()

    async def get_user_uploads(self, limit: int = 50, offset: int = 0) -> list:
        """GET /api/v1/uploads"""
        client = await self._get_client()
        response = await client.get(
            f"{self.base_url}/uploads",
            headers=self.headers,
            params={"limit": limit, "offset": offset}
        )
        response.raise_for_status()
        return response.json()

    async def get_upload_details(self, upload_id: str) -> dict:
        """GET /api/v1/uploads/{upload_id}"""
        client = await self._get_client()
        response = await client.get(
            f"{self.base_url}/uploads/{upload_id}",
            headers=self.headers
        )
        response.raise_for_status()
        return response.json()

    async def get_download_url(self, upload_id: str) -> str:
        """Get presigned download URL for audio file"""
        client = await self._get_client()
        response = await client.get(
            f"{self.base_url}/uploads/{upload_id}/download",
            headers=self.headers
        )
        response.raise_for_status()
        return response.json().get("download_url")

    async def download_audio(self, upload_id: str) -> bytes:
        """Download actual audio file bytes"""
        download_url = await self.get_download_url(upload_id)
        client = await self._get_client()
        response = await client.get(download_url)
        response.raise_for_status()
        return response.content

    async def get_transcript(self, upload_id: str) -> Optional[dict]:
        """GET /api/v1/transcripts/upload/{upload_id}/status"""
        client = await self._get_client()
        try:
            response = await client.get(
                f"{self.base_url}/transcripts/upload/{upload_id}/status",
                headers=self.headers
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError:
            return None