from __future__ import annotations

from fastapi import APIRouter, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from fastapi import Depends

from database import get_user_by_username
from security.jwt_utils import create_access_token
from security.password import check_password

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login")
async def login(form: OAuth2PasswordRequestForm = Depends()) -> dict:
    """
    Ro'yxatdan o'tish YO'Q — hisob faqat admin_cli.py orqali oldindan
    yaratilgan bo'lishi kerak. Noto'g'ri login/parolda ataylab bir xil
    xatolik qaytariladi (foydalanuvchi mavjudligini aniqlashning oldini olish).
    """
    user = await get_user_by_username(form.username)
    if user is None or not check_password(form.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Login yoki parol noto'g'ri",
        )
    token = create_access_token(user["username"])
    return {"access_token": token, "token_type": "bearer", "username": user["username"]}
