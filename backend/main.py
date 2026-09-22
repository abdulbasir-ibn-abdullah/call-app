from __future__ import annotations

import os

from fastapi import APIRouter, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from config import ALLOWED_ORIGINS, BASE_PATH
from database import init_db
from routes import auth_routes, call_ws, keys_routes

app = FastAPI(title="Video va Audio Qo'ng'iroq", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Barcha route'lar BASE_PATH prefiksi bilan o'raladi (masalan "/call-app").
# BASE_PATH bo'sh bo'lsa (standart), ildizda avvalgidek ishlayveradi.
_api = APIRouter(prefix=BASE_PATH)
_api.include_router(auth_routes.router)
_api.include_router(keys_routes.router)
_api.include_router(call_ws.router)
app.include_router(_api)


@app.on_event("startup")
async def on_startup() -> None:
    await init_db()


# Frontend'ni shu backend orqali xizmat qilish (alohida server kerak emas).
# {BASE_PATH}/static/login.html va {BASE_PATH}/static/call.html orqali ochiladi.
# Ishga tushirish papkasidan (cwd) qat'i nazar to'g'ri topilishi uchun bu
# faylning joylashuviga nisbatan hisoblanadi (backend/../frontend).
FRONTEND_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "frontend")
app.mount(f"{BASE_PATH}/static", StaticFiles(directory=FRONTEND_DIR, html=True), name="static")


@app.get("/")
async def root_redirect():
    return RedirectResponse(url=f"{BASE_PATH}/static/login.html")


# BASE_PATH sozlangan bo'lsa, .../call-app va .../call-app/ ham to'g'ridan-to'g'ri
# login sahifasiga yo'naltiriladi (foydalanuvchi domenni to'liq yozmasa ham).
if BASE_PATH:
    @app.get(BASE_PATH)
    @app.get(f"{BASE_PATH}/")
    async def base_path_redirect():
        return RedirectResponse(url=f"{BASE_PATH}/static/login.html")
