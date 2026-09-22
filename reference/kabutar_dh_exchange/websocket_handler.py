"""
Kabutar uchun FastAPI WebSocket + X25519 DH handshake integratsiyasi.

Oqim (protocol):
  1. Client WebSocket orqali ulanadi, o'zining client_id'sini (masalan
     JWT tekshiruvidan keyin olingan connection_id) beradi.
  2. Server o'zining efemeral kalit juftligini generatsiya qiladi, private
     key'ni FAQAT RAM'da client_id bo'yicha vaqtincha saqlaydi va public
     key'ini clientga yuboradi ("dh_server_hello").
  3. Client o'zining kalit juftligini generatsiya qilib, public key'ini
     serverga yuboradi ("dh_client_hello").
  4. Server private key'ni RAM'dan (bir martalik) olib, umumiy sirni
     hisoblaydi, HKDF orqali yakuniy simmetrik kalitni chiqaradi.
  5. Shu kalit shu WebSocket ulanishi uchun mahalliy o'zgaruvchida qoladi
     (masalan AES-256-GCM bilan xabarlarni shifrlash uchun) — hech qachon
     diskka yozilmaydi.

MITM haqida eslatma: xom Diffie-Hellman o'z-o'zidan "kim bilan gaplashyapman"
degan savolga javob bermaydi. Ishlab chiqarishda server_public_key'ni
JWT/session imzosi bilan bog'lash (masalan uni JWT payload'iga hash qilib
qo'shish) yoki mTLS/TLS transport xavfsizligiga tayanish tavsiya etiladi —
bu WebSocket allaqachon wss:// (TLS) ustida ishlayotgan bo'lsa, MITM xavfi
allaqachon katta darajada yopilgan bo'ladi.
"""

from __future__ import annotations

import json
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from .dh_exchange import DHKeyExchange
from .session_store import EphemeralKeyStore

logger = logging.getLogger("kabutar.dh")

# Butun ilova (worker process) bo'ylab BITTA store yetarli.
key_store = EphemeralKeyStore()

router = APIRouter()


async def perform_dh_handshake(websocket: WebSocket, client_id: str) -> bytes:
    """
    Bitta WebSocket ulanish uchun to'liq DH handshake'ni bajaradi va
    shu ulanishga xos 32 baytlik simmetrik kalitni qaytaradi.

    `client_id` — bu ANIQ ulanishga xos identifikator bo'lishi kerak
    (oddiy user_id emas, chunki bitta foydalanuvchi bir nechta ulanish
    ochishi mumkin — masalan telefon + kompyuter bir vaqtda).
    """
    # 1) Serverning efemeral kalit juftligi
    private_key, public_key = DHKeyExchange.generate_keypair()
    key_store.put(client_id, private_key)

    await websocket.send_json({
        "type": "dh_server_hello",
        "server_public_key": DHKeyExchange.serialize_public_key(public_key),
        # MUHIM (tuzatilgan xato): compute_shared_key() HKDF "salt" sifatida
        # aynan shu client_id (= connection_id)ni ishlatadi. Buni clientga
        # yubormasak, ikki tomon boshqa-boshqa session_key chiqarib oladi va
        # BARCHA keyingi WS xabarlari decrypt xatosi bilan tugaydi. Avvalgi
        # versiyada bu maydon ATAYLAB yuborilmagan edi ("client buni bilishi
        # shart emas" degan noto'g'ri taxmin bilan) — bu xato edi, tuzatildi.
        "connection_id": client_id,
    })

    # 2) Clientning javobini kutish
    raw = await websocket.receive_text()
    try:
        msg = json.loads(raw)
    except json.JSONDecodeError as exc:
        key_store.pop(client_id)  # xavfsizlik uchun tozalab qo'yamiz
        raise ValueError("Handshake xabari JSON emas") from exc

    if msg.get("type") != "dh_client_hello" or "client_public_key" not in msg:
        key_store.pop(client_id)
        raise ValueError("Handshake xabari kutilgan formatda emas")

    client_public_key = DHKeyExchange.deserialize_public_key(msg["client_public_key"])

    # 3) Bir martalik private key'ni olish (shu bilan RAM'dan o'chadi)
    stored_private_key = key_store.pop(client_id)
    if stored_private_key is None:
        raise ValueError(
            "Handshake muddati tugagan yoki client_id topilmadi — qayta ulaning"
        )

    # 4) Umumiy sir -> HKDF -> yakuniy session kaliti
    session_key = DHKeyExchange.compute_shared_key(
        stored_private_key, client_public_key, client_id
    )

    logger.info("DH handshake muvaffaqiyatli: client_id=%s", client_id)
    return session_key


@router.websocket("/ws/{client_id}")
async def websocket_endpoint(websocket: WebSocket, client_id: str) -> None:
    """
    Namuna endpoint. Haqiqiy loyihada `client_id`ni to'g'ridan-to'g'ri
    URL'dan olish o'rniga, avval JWT/token orqali autentifikatsiya qilib,
    shundan keyin ulanishga xos identifikator generatsiya qilish tavsiya
    etiladi.
    """
    await websocket.accept()

    try:
        session_key = await perform_dh_handshake(websocket, client_id)
    except Exception as exc:  # noqa: BLE001
        logger.warning("DH handshake muvaffaqiyatsiz tugadi: %s", exc)
        await websocket.close(code=4000)
        return

    # `session_key` shu funksiya doirasidagi mahalliy o'zgaruvchi —
    # boshqa hech qanday joyga (fayl, DB, global dict) yozilmaydi.
    # Bu yerdan keyin kabutar messaging logikasi + AES-256-GCM shifrlash
    # shu kalit yordamida amalga oshiriladi.

    try:
        while True:
            data = await websocket.receive_text()
            # TODO: session_key bilan deshifrlash/shifrlash + kabutar logikasi
            await websocket.send_text(f"[shifrlangan kanal tayyor] {data}")
    except WebSocketDisconnect:
        logger.info("Client uzildi: client_id=%s", client_id)