from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class SecretCreate(BaseModel):
    secret: str
    passphrase: Optional[str] = None
    ttl_seconds: Optional[int] = None


class SecretResponse(BaseModel):
    secret_key: str


class SecretRead(BaseModel):
    secret: str


class SecretDeleteResponse(BaseModel):
    status: str


class SecretLogResponse(BaseModel):
    id: int
    secret_id: int
    action: str
    ip_address: str
    created_at: datetime
    log_metadata: Optional[str] = None

    class Config:
        from_attributes = True 