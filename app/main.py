from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.orm import Session
from typing import Optional
import uuid
from datetime import datetime, timedelta
import json
from jose import jwt

from app.database import get_db
from app.redis import get_redis
from app import models, schemas, crypto
from app.config import get_settings

app = FastAPI(title="Secret Service", description="Сервис для хранения одноразовых секретов")

settings = get_settings()


@app.get("/")
async def root():
    return RedirectResponse(url="/docs")


@app.get("/health")
async def health_check():
    return {"status": "ok"}


@app.middleware("http")
async def add_cache_control_header(request: Request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@app.post("/secret", response_model=schemas.SecretResponse)
async def create_secret(
    secret_data: schemas.SecretCreate,
    request: Request,
    db: Session = Depends(get_db),
    redis_client=Depends(get_redis)
):
    secret_key = str(uuid.uuid4())
    expires_at = None
    
    if secret_data.ttl_seconds:
        expires_at = datetime.utcnow() + timedelta(seconds=secret_data.ttl_seconds)
    
    # Создаем запись в базе данных
    db_secret = models.Secret(
        secret_key=secret_key,
        encrypted_secret=crypto.create_access_token({"secret": secret_data.secret}),
        passphrase_hash=crypto.get_password_hash(secret_data.passphrase) if secret_data.passphrase else None,
        expires_at=expires_at
    )
    db.add(db_secret)
    db.commit()
    db.refresh(db_secret)
    
    # Сохраняем в Redis на 5 минут
    redis_client.setex(
        f"secret:{secret_key}",
        300,  # 5 минут
        json.dumps({
            "secret": secret_data.secret,
            "passphrase": secret_data.passphrase,
            "expires_at": expires_at.isoformat() if expires_at else None
        })
    )
    
    # Логируем создание секрета
    log_entry = models.SecretLog(
        secret_id=db_secret.id,
        action="create",
        ip_address=request.client.host,
        log_metadata=json.dumps({
            "ttl_seconds": secret_data.ttl_seconds,
            "has_passphrase": bool(secret_data.passphrase)
        })
    )
    db.add(log_entry)
    db.commit()
    
    return {"secret_key": secret_key}


@app.get("/secret/{secret_key}", response_model=schemas.SecretRead)
async def read_secret(
    secret_key: str,
    request: Request,
    db: Session = Depends(get_db),
    redis_client=Depends(get_redis)
):
    # Проверяем в Redis
    cached_secret = redis_client.get(f"secret:{secret_key}")
    if cached_secret:
        secret_data = json.loads(cached_secret)
        redis_client.delete(f"secret:{secret_key}")
        return {"secret": secret_data["secret"]}
    
    # Если нет в Redis, проверяем в базе
    db_secret = db.query(models.Secret).filter(
        models.Secret.secret_key == secret_key,
        models.Secret.is_accessed == 0,
        models.Secret.is_deleted == 0
    ).first()
    
    if not db_secret:
        raise HTTPException(status_code=404, detail="Secret not found or already accessed")
    
    if db_secret.expires_at and db_secret.expires_at < datetime.utcnow():
        raise HTTPException(status_code=404, detail="Secret has expired")
    
    # Помечаем как прочитанный
    db_secret.is_accessed = 1
    db.commit()
    
    # Логируем чтение
    log_entry = models.SecretLog(
        secret_id=db_secret.id,
        action="read",
        ip_address=request.client.host
    )
    db.add(log_entry)
    db.commit()
    
    return {"secret": jwt.decode(db_secret.encrypted_secret, crypto.SECRET_KEY, algorithms=["HS256"])["secret"]}


@app.delete("/secret/{secret_key}", response_model=schemas.SecretDeleteResponse)
async def delete_secret(
    secret_key: str,
    request: Request,
    passphrase: Optional[str] = None,
    db: Session = Depends(get_db),
    redis_client=Depends(get_redis)
):
    # Удаляем из Redis
    redis_client.delete(f"secret:{secret_key}")
    
    # Проверяем в базе
    db_secret = db.query(models.Secret).filter(
        models.Secret.secret_key == secret_key,
        models.Secret.is_deleted == 0
    ).first()
    
    if not db_secret:
        raise HTTPException(status_code=404, detail="Secret not found or already deleted")
    
    if db_secret.passphrase_hash and not crypto.verify_password(passphrase, db_secret.passphrase_hash):
        raise HTTPException(status_code=403, detail="Invalid passphrase")
    
    # Помечаем как удаленный
    db_secret.is_deleted = 1
    db.commit()
    
    # Логируем удаление
    log_entry = models.SecretLog(
        secret_id=db_secret.id,
        action="delete",
        ip_address=request.client.host,
        log_metadata=json.dumps({"used_passphrase": bool(passphrase)})
    )
    db.add(log_entry)
    db.commit()
    
    return {"status": "secret_deleted"} 