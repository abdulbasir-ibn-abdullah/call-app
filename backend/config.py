"""
Konfiguratsiya — barcha maxfiy qiymatlar .env fayldan o'qiladi.
Ishlab chiqarishga chiqarishdan oldin SECRET_KEY va ADMIN_TOKEN'ni
albatta o'zgartiring (pastdagi generate_secret.py yordam beradi).
"""
from __future__ import annotations

import os
import sys

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv o'rnatilmagan bo'lsa ham muhit o'zgaruvchilari orqali ishlayveradi

SECRET_KEY = os.getenv("SECRET_KEY", "")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "1440"))

DB_PATH = os.getenv("DB_PATH", "family_call.db")

# Ilova qaysi subpath ostida joylashganini bildiradi, masalan "/call-app".
# Ildizda (https://domen/...) ishlasa — bo'sh qoldiring.
# nginx'dagi "location /call-app/ { proxy_pass ...; }" bilan BIR XIL bo'lishi kerak.
BASE_PATH = os.getenv("BASE_PATH", "").rstrip("/")

# CORS uchun ruxsat etilgan originlar (vergul bilan ajratilgan)
ALLOWED_ORIGINS = [
    o.strip() for o in os.getenv("ALLOWED_ORIGINS", "http://localhost:8000").split(",")
    if o.strip()
]

if not SECRET_KEY or len(SECRET_KEY) < 32:
    print(
        "\n\U0001F6A8 XATO: SECRET_KEY topilmadi yoki juda qisqa (kamida 32 belgi).\n"
        "   .env faylida SECRET_KEY o'rnating. Generatsiya qilish uchun:\n"
        "   python -c \"import secrets; print(secrets.token_urlsafe(48))\"\n",
        file=sys.stderr,
    )
    sys.exit(1)
