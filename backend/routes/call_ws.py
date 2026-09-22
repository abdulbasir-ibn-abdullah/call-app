"""
QO'NG'IROQ SIGNALIZATSIYASI — KO'R RELAY + YENGIL XONA (ROOM) HISOBI.
========================================================================
Server DH ephemeral kalitlar, imzolar yoki shifrlangan SDP/ICE mazmunini
HECH QACHON deshifrlamaydi/tekshirmaydi — bularning barchasi client-client
(brauzer ichida) amalga oshadi. Server faqat ikki narsani biladi (buni
allaqachon "kim kimga xabar yubordi" darajasida bilishi kerak edi):
  1) kim kimga ulanishga ruxsatli (kontaktlar jadvali orqali)
  2) qaysi "xona"da (guruh qo'ng'iroqda) hozir kimlar bor

KO'P KISHILIK QO'NG'IROQ (mesh arxitektura): markaziy media-server (SFU)
YO'Q — har bir juftlik o'zaro TO'G'RIDAN-TO'G'RI (P2P) WebRTC ulanish
o'rnatadi, o'zining DH handshake'i bilan. N kishi = N*(N-1)/2 juft ulanish.
Server faqat "xonada hozir kimlar bor"ni yangi qo'shilgan kishiga aytadi —
qolgan hamma narsa (kim kimga qachon taklif/DH yuboradi) client tomonida
lug'aviy tartib qoidasi bilan (call.js'dagi initiator qoidasi) hal qilinadi.

Protokol (barcha xabarlar JSON, "type" maydoni bilan):
  presence_update    server -> client  {"type":"presence_update","online":[...]}
                     (FAQAT shu foydalanuvchining KONTAKTLARI ko'rsatiladi)
  room_invite        client -> server -> client  {"to":"bob","room_id":...}
  room_invite_reject client -> server -> client  {"to":"alice","room_id":...}
  room_join          client -> server (maxsus)   {"room_id":...}
  room_members       server -> client (javob)    {"room_id":...,"members":[...]}
  peer_joined        server -> client (xabar)     {"room_id":...,"peer":"carol"}
  room_leave         client -> server (maxsus)    {"room_id":...}
  peer_left          server -> client (xabar)     {"room_id":...,"peer":"carol"}
  dh_hello           client -> server -> client  (opaque, faqat "to" ko'riladi)
  dh_hello_reply     xuddi shunday
  signal             client -> server -> client  (shifrlangan SDP/ICE, opaque)
  error              server -> client

Xavfsizlik: "to" maydoni bo'lgan HAR BIR xabar uchun yuboruvchi va qabul
qiluvchi KONTAKT bo'lishi shart (admin_cli.py link orqali bog'langan) —
aks holda relay qilinmaydi. Shu orqali bitta serverda bir-biridan bexabar
bir nechta guruh (masalan oila va alohida do'st) yashay oladi.
"""
from __future__ import annotations

import json
import logging

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect

from database import are_contacts, get_contacts
from security.dependencies import get_current_username, get_username_from_ws

logger = logging.getLogger("family_call.ws")
router = APIRouter()

_ONLINE: dict[str, WebSocket] = {}
_ROOMS: dict[str, set[str]] = {}  # room_id -> hozir shu xonada bo'lgan usernamelar

# Oddiy "to"ga qarab yo'naltiriladigan, mazmuni server uchun opaque xabarlar.
_RELAY_TYPES = {"room_invite", "room_invite_reject", "dh_hello", "dh_hello_reply", "signal"}
# Server tomonida maxsus ishlov beriladigan (xona a'zoligini o'zgartiruvchi) turlar.
_ROOM_CONTROL_TYPES = {"room_join", "room_leave"}


async def _send(username: str, payload: dict) -> None:
    ws = _ONLINE.get(username)
    if ws is None:
        return
    try:
        await ws.send_text(json.dumps(payload))
    except Exception:  # noqa: BLE001
        pass


async def _send_presence_to(username: str) -> None:
    if username not in _ONLINE:
        return
    contacts = await get_contacts(username)
    online_contacts = sorted(u for u in contacts if u in _ONLINE)
    await _send(username, {"type": "presence_update", "online": online_contacts})


async def _refresh_presence_after_change(username: str) -> None:
    """username onlayn/offlayn bo'lganda — o'zi (agar onlayn bo'lsa) va
    barcha KONTAKTLARI (agar ular ham onlayn bo'lsa) uchun ro'yxatni yangilaydi."""
    contacts = await get_contacts(username)
    recipients = set(contacts)
    if username in _ONLINE:
        recipients.add(username)
    for r in recipients:
        await _send_presence_to(r)


async def _room_join(username: str, room_id: str) -> None:
    members_before = sorted(_ROOMS.get(room_id, set()))
    _ROOMS.setdefault(room_id, set()).add(username)
    await _send(username, {"type": "room_members", "room_id": room_id, "members": members_before})
    for m in members_before:
        await _send(m, {"type": "peer_joined", "room_id": room_id, "peer": username})


async def _room_leave(username: str, room_id: str) -> None:
    if room_id not in _ROOMS or username not in _ROOMS[room_id]:
        return
    _ROOMS[room_id].discard(username)
    remaining = list(_ROOMS[room_id])
    if not remaining:
        del _ROOMS[room_id]
    for m in remaining:
        await _send(m, {"type": "peer_left", "room_id": room_id, "peer": username})


async def _leave_all_rooms(username: str) -> None:
    for room_id in [rid for rid, members in _ROOMS.items() if username in members]:
        await _room_leave(username, room_id)


@router.get("/presence/online")
async def online_contacts(current_username: str = Depends(get_current_username)) -> dict:
    """Sahifa yuklanganda, WS ulanguncha, boshlang'ich ro'yxat uchun.
    FAQAT joriy foydalanuvchining kontaktlaridan onlayn bo'lganlari."""
    contacts = await get_contacts(current_username)
    return {"online": sorted(u for u in contacts if u in _ONLINE)}


@router.websocket("/ws/call")
async def call_ws_endpoint(websocket: WebSocket) -> None:
    username = await get_username_from_ws(websocket)
    if username is None:
        await websocket.close(code=4401)
        return

    await websocket.accept()

    old = _ONLINE.get(username)
    if old is not None:
        try:
            await old.close(code=4409)  # boshqa joydan ulandi
        except Exception:  # noqa: BLE001
            pass
        await _leave_all_rooms(username)

    _ONLINE[username] = websocket
    logger.info("online: %s", username)
    await _refresh_presence_after_change(username)

    try:
        while True:
            raw = await websocket.receive_text()
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                await websocket.send_text(json.dumps({"type": "error", "detail": "JSON emas"}))
                continue

            msg_type = msg.get("type")

            if msg_type in _ROOM_CONTROL_TYPES:
                room_id = msg.get("room_id")
                if not room_id or not isinstance(room_id, str):
                    await websocket.send_text(json.dumps({"type": "error", "detail": "room_id kerak"}))
                    continue
                if msg_type == "room_join":
                    await _room_join(username, room_id)
                else:
                    await _room_leave(username, room_id)
                continue

            to = msg.get("to")
            if msg_type not in _RELAY_TYPES or not to:
                await websocket.send_text(json.dumps({"type": "error", "detail": "noto'g'ri xabar formati"}))
                continue

            if not await are_contacts(username, to):
                await websocket.send_text(json.dumps({"type": "error", "detail": "ruxsat yo'q"}))
                continue

            if to not in _ONLINE:
                await websocket.send_text(json.dumps({"type": "error", "detail": f"{to} onlayn emas"}))
                continue

            msg["from"] = username
            await _send(to, msg)

    except WebSocketDisconnect:
        pass
    finally:
        if _ONLINE.get(username) is websocket:
            del _ONLINE[username]
            logger.info("offline: %s", username)
            await _leave_all_rooms(username)
            await _refresh_presence_after_change(username)
