"""
RAM'dagi vaqtinchalik xotira: har bir client_id (ya'ni har bir ANIQ WebSocket
ulanish) uchun handshake tugagunicha serverning private key'ini saqlaydi.

MUHIM XAVFSIZLIK QOIDALARI:
1. Bu yerda saqlangan hech narsa HECH QACHON diskka/DB'ga yozilmaydi.
2. Har bir kalit BIR MARTA o'qiladi (`pop`) — o'qilgach darhol xotiradan o'chadi.
3. Handshake belgilangan TTL ichida tugamasa, kalit avtomatik o'chib ketadi
   (aks holda ulanmay qolgan millionlab "chala handshake" xotirani to'ldirib,
   DoS holatiga olib kelishi mumkin edi).

Nega client_id bo'yicha alohida yozuv?
Bir foydalanuvchi bir vaqtning o'zida bir nechta qurilmadan/oynadan ulanishi
mumkin. Shuning uchun client_id — bu user_id emas, balki har bir ANIQ
WebSocket ulanishiga xos identifikator (masalan JWT tekshiruvidan keyin
generatsiya qilingan connection_id/session_id) bo'lishi kerak.
"""

from __future__ import annotations

import threading
import time
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .config import DH_HANDSHAKE_TTL_SECONDS, DH_MAX_PENDING_HANDSHAKES

try:
    from cachetools import TTLCache

    _HAS_CACHETOOLS = True
except ImportError:  # cachetools o'rnatilmagan bo'lsa, oddiy fallback ishlatiladi
    _HAS_CACHETOOLS = False


class EphemeralKeyStore:
    """
    Millionlab bir vaqtdagi handshake'ni hisobga olib yozilgan store.

    - `cachetools` mavjud bo'lsa: TTLCache ishlatiladi — O(1) qo'shish/o'qish,
      eskirgan yozuvlar avtomatik (lazy) tozalanadi, xotira cheklangan
      (`maxsize`) bo'lgani uchun DoS xavfi past.
    - `cachetools` yo'q bo'lsa: oddiy dict + qo'lda tozalash (`sweep_expired`)
      ishlatiladi — buni davriy background task orqali chaqirish kerak
      (pastdagi `start_cleanup_task` ga qarang).

    Eslatma: bitta worker process ichida bitta shared store yetarli, chunki
    bitta WebSocket ulanish butun umri davomida bitta workerda qoladi.
    Ko'p workerli (masalan `uvicorn --workers 4`) rejimda har worker o'zining
    mustaqil store'iga ega bo'ladi — bu muammo emas.
    """

    def __init__(
        self,
        ttl_seconds: int = DH_HANDSHAKE_TTL_SECONDS,
        max_size: int = DH_MAX_PENDING_HANDSHAKES,
    ) -> None:
        self._ttl = ttl_seconds
        self._lock = threading.Lock()

        if _HAS_CACHETOOLS:
            self._store: dict = TTLCache(maxsize=max_size, ttl=ttl_seconds)
        else:
            self._store = {}

    def put(self, client_id: str, private_key: X25519PrivateKey) -> None:
        """Handshake boshlanganda serverning vaqtinchalik private key'ini saqlaydi."""
        with self._lock:
            if _HAS_CACHETOOLS:
                self._store[client_id] = private_key
            else:
                self._store[client_id] = (private_key, time.monotonic())

    def pop(self, client_id: str) -> Optional[X25519PrivateKey]:
        """
        Kalitni BIR MARTA qaytaradi va DARHOL xotiradan o'chiradi.
        Topilmasa yoki muddati o'tgan bo'lsa None qaytaradi — bu holda
        chaqiruvchi tomon clientdan qayta ulanishni so'rashi kerak.
        """
        with self._lock:
            if _HAS_CACHETOOLS:
                return self._store.pop(client_id, None)

            entry = self._store.pop(client_id, None)
            if entry is None:
                return None
            private_key, created_at = entry
            if time.monotonic() - created_at > self._ttl:
                return None
            return private_key

    def sweep_expired(self) -> int:
        """
        Faqat `cachetools` mavjud bo'lmaganda kerak bo'ladi.
        Muddati o'tgan, hech qachon yakunlanmagan handshake'larni tozalaydi.
        Qaytaradi: o'chirilgan yozuvlar soni.
        """
        if _HAS_CACHETOOLS:
            return 0

        now = time.monotonic()
        removed = 0
        with self._lock:
            expired_ids = [
                cid for cid, (_, created_at) in self._store.items()
                if now - created_at > self._ttl
            ]
            for cid in expired_ids:
                del self._store[cid]
                removed += 1
        return removed

    def __len__(self) -> int:
        return len(self._store)


def start_cleanup_task(store: EphemeralKeyStore, interval_seconds: int = 10):
    """
    `cachetools` o'rnatilmagan holatlar uchun fallback background tozalagich.
    FastAPI ilovasining startup eventida chaqiring:

        @app.on_event("startup")
        async def _start_bg():
            asyncio.create_task(start_cleanup_task(key_store))

    `cachetools` o'rnatilgan bo'lsa, bu funksiyani chaqirish shart emas
    (TTLCache o'z-o'zini tozalaydi).
    """
    import asyncio

    async def _loop():
        while True:
            await asyncio.sleep(interval_seconds)
            store.sweep_expired()

    return _loop()
