from functools import lru_cache
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Application
    app_name: str = "BlockchainService"
    debug: bool = True
    port: int = 8001

    # Your existing backend
    backend_api_url: str = "http://localhost:8000"
    backend_api_version: str = "v1"

    # Solana
    solana_network: str = "devnet"
    solana_rpc_url: str = "https://api.devnet.solana.com"

    # Pinata IPFS
    pinata_api_key: str | None = None
    pinata_secret_key: str | None = None
    pinata_gateway: str = "https://gateway.pinata.cloud/ipfs"

    # CORS
    cors_origins: str = "http://localhost:3000,http://localhost:8081"

    @property
    def backend_base_url(self) -> str:
        return f"{self.backend_api_url}/api/{self.backend_api_version}"

    @property
    def cors_origins_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",")]

    class Config:
        env_file = ".env"
        case_sensitive = False


@lru_cache()
def get_settings() -> Settings:
    return Settings()