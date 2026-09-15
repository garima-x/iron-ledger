import os
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    sepolia_rpc_url: str = ""
    private_key: str = ""
    contract_address: str = ""
    database_url: str = "sqlite:///./ironledger.db"
    cors_origins: str = "*"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @property
    def chain_configured(self) -> bool:
        """True only once all three Sepolia settings are present. Until then
        the app runs in local mode: full hash-chain + tamper-detection logic,
        just without an actual on-chain transaction."""
        return bool(self.sepolia_rpc_url and self.private_key and self.contract_address)

    @property
    def contract_abi_path(self) -> Path:
        return BASE_DIR / "contracts" / "IronLedgerABI.json"


settings = Settings()
