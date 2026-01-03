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
            "Content-Type": "application/json",
        }
        self.client = httpx.AsyncClient(
            base_url=self.base_url,
            headers=self.headers,
            timeout=httpx.Timeout(10.0),
        )

    async def close(self):
        await self.client.aclose()

    async def get_user_profile(self) -> dict:
        """GET /api/v1/auth/me"""
        response = await self.client.get("/auth/me")
        response.raise_for_status()
        return response.json()

    async def get_user_uploads(self, limit: int = 50, offset: int = 0) -> list[dict]:
        """GET /api/v1/uploads"""
        response = await self.client.get(
            "/uploads",
            params={"limit": limit, "offset": offset},
        )
        response.raise_for_status()
        return response.json()

    async def get_upload_details(self, upload_id: str) -> dict:
        """GET /api/v1/uploads/{upload_id}"""
        response = await self.client.get(f"/uploads/{upload_id}")
        response.raise_for_status()
        return response.json()

    async def get_download_url(self, upload_id: str) -> str:
        """Get presigned download URL"""
        response = await self.client.get(f"/uploads/{upload_id}/download")
        response.raise_for_status()
        return response.json()["download_url"]

    async def download_audio(self, upload_id: str) -> bytes:
        """Download actual audio file bytes"""
        download_url = await self.get_download_url(upload_id)
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(download_url)
            response.raise_for_status()
            return response.content

    async def get_transcript(self, upload_id: str) -> Optional[dict]:
        """GET /api/v1/transcripts/upload/{upload_id}/status"""
        response = await self.client.get(
            f"/transcripts/upload/{upload_id}/status"
        )

        if response.status_code == 404:
            return None

        response.raise_for_status()
        return response.json()
