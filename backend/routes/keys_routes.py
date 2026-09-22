"""
Foydalanuvchilarning UZOQ MUDDATLI Ed25519 identity ochiq kalitini
saqlaydi/beradi (kabutar/auth/key_service.py bilan bir xil mantiq: server
FAQAT ochiq kalitni saqlaydi, imzoni tekshirish javobgarligi qabul qiluvchi
CLIENT'da). Bu kalit qo'ng'iroq boshlashda ikkinchi tomonning DH ephemeral
kalitini imzo orqali tasdiqlash (MITM'dan himoya) uchun ishlatiladi.
"""
from __future__ import annotations

import base64

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from database import get_user_by_username, set_identity_public_key
from security.dependencies import get_current_username

router = APIRouter(prefix="/keys", tags=["keys"])

EXPECTED_ED25519_PUBLIC_KEY_BYTES = 32


class UploadKeyBody(BaseModel):
    identity_public_key: str  # base64, 32 bayt (Ed25519 ochiq kaliti)


def _is_valid_b64_len(value: str, expected_bytes: int) -> bool:
    try:
        return len(base64.b64decode(value, validate=True)) == expected_bytes
    except Exception:  # noqa: BLE001
        return False


@router.post("/upload")
async def upload_identity_key(
    body: UploadKeyBody, current_username: str = Depends(get_current_username)
) -> dict:
    if not _is_valid_b64_len(body.identity_public_key, EXPECTED_ED25519_PUBLIC_KEY_BYTES):
        raise HTTPException(status_code=400, detail="identity_public_key formati noto'g'ri (32 bayt, base64 bo'lishi kerak)")
    await set_identity_public_key(current_username, body.identity_public_key)
    return {"ok": True}


@router.get("/{username}")
async def get_identity_key(
    username: str, current_username: str = Depends(get_current_username)
) -> dict:
    user = await get_user_by_username(username)
    if user is None or not user.get("identity_public_key"):
        raise HTTPException(status_code=404, detail="Bu foydalanuvchi hali identity kalitini yuklamagan")
    return {"username": username, "identity_public_key": user["identity_public_key"]}
