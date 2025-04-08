from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func
from datetime import datetime

Base = declarative_base()


class Secret(Base):
    __tablename__ = "secrets"

    id = Column(Integer, primary_key=True, index=True)
    secret_key = Column(String, unique=True, index=True)
    encrypted_secret = Column(Text)
    passphrase_hash = Column(String, nullable=True)
    created_at = Column(DateTime, default=func.now())
    expires_at = Column(DateTime, nullable=True)
    is_accessed = Column(Integer, default=0)
    is_deleted = Column(Integer, default=0)


class SecretLog(Base):
    __tablename__ = "secret_logs"

    id = Column(Integer, primary_key=True, index=True)
    secret_id = Column(Integer, ForeignKey("secrets.id"))
    action = Column(String)  # create, read, delete
    ip_address = Column(String)
    created_at = Column(DateTime, default=func.now())
    metadata = Column(Text, nullable=True)  # JSON string with additional data 