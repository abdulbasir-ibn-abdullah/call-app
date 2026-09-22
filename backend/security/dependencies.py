from __future__ import annotations

from fastapi import Depends, HTTPException, WebSocket, status
from fastapi.security import OAuth2PasswordBearer

from database import get_user_by_username
from .jwt_utils import decode_access_token

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


async def get_current_username(token: str = Depends(oauth2_scheme)) -> str:
    username = decode_access_token(token)
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token yaroqsiz yoki muddati tugagan",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = await get_user_by_username(username)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Foydalanuvchi topilmadi")
    return username


async def get_username_from_ws(websocket: WebSocket) -> str | None:
    """
    Brauzer WebSocket'ga custom Authorization header qo'sha olmaydi,
    shuning uchun token query-param orqali uzatiladi: /ws/call?token=...
    """
    token = websocket.query_params.get("token")
    if not token:
        return None
    username = decode_access_token(token)
    if username is None:
        return None
    user = await get_user_by_username(username)
    if user is None:
        return None
    return username
