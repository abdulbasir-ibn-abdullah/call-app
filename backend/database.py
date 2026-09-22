"""
Yengil SQLite qatlami (aiosqlite). Oilaviy foydalanish uchun (bir nechta
foydalanuvchi) alohida Postgres server kerak emas — bitta fayl yetarli.

MUHIM: bu yerda ro'yxatdan o'tish (self-registration) YO'Q. Yagona yo'l —
admin_cli.py orqali administrator hisobni qo'lda bazaga kiritadi.

KONTAKTLAR: foydalanuvchilar standart holatda BIR-BIRINI KO'RMAYDI.
Faqat admin_cli.py orqali ikkita hisob bir-biriga "bog'langan" (link) bo'lsa,
ular bir-birining onlayn holatini ko'radi va qo'ng'iroq qila oladi. Shu orqali
bitta serverda bir nechta ALOHIDA guruh (masalan oila va do'stlar) bir-birini
bilmagan holda yashashi mumkin.
"""
from __future__ import annotations

import aiosqlite

from config import DB_PATH

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    username              TEXT UNIQUE NOT NULL,
    password_hash         TEXT NOT NULL,
    identity_public_key   TEXT,               -- base64 Ed25519 ochiq kaliti (birinchi loginda yuklanadi)
    is_admin              INTEGER NOT NULL DEFAULT 0,
    created_at            TEXT NOT NULL DEFAULT (datetime('now')),
    disabled              INTEGER NOT NULL DEFAULT 0
);

-- Har bir bog'lanish IKKI qator sifatida saqlanadi (a->b va b->a), shunda
-- "user_a uchun kontaktlar" so'rovi oddiy bo'ladi.
CREATE TABLE IF NOT EXISTS contacts (
    user_a TEXT NOT NULL,
    user_b TEXT NOT NULL,
    PRIMARY KEY (user_a, user_b)
);
"""


async def init_db() -> None:
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executescript(_SCHEMA)
        await db.commit()


async def get_user_by_username(username: str) -> dict | None:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT * FROM users WHERE username = ? AND disabled = 0;", (username,)
        )
        row = await cur.fetchone()
        return dict(row) if row else None


async def create_user(username: str, password_hash: str, is_admin: bool = False) -> None:
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?);",
            (username, password_hash, int(is_admin)),
        )
        await db.commit()


async def set_identity_public_key(username: str, identity_public_key: str) -> None:
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE users SET identity_public_key = ? WHERE username = ?;",
            (identity_public_key, username),
        )
        await db.commit()


async def list_usernames() -> list[str]:
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute("SELECT username FROM users WHERE disabled = 0;")
        rows = await cur.fetchall()
        return [r[0] for r in rows]


async def disable_user(username: str) -> bool:
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "UPDATE users SET disabled = 1 WHERE username = ?;", (username,)
        )
        await db.commit()
        return cur.rowcount > 0


# ---------------- Kontaktlar ----------------

async def add_contact_link(user_a: str, user_b: str) -> None:
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT OR IGNORE INTO contacts (user_a, user_b) VALUES (?, ?);", (user_a, user_b)
        )
        await db.execute(
            "INSERT OR IGNORE INTO contacts (user_a, user_b) VALUES (?, ?);", (user_b, user_a)
        )
        await db.commit()


async def remove_contact_link(user_a: str, user_b: str) -> None:
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "DELETE FROM contacts WHERE (user_a = ? AND user_b = ?) OR (user_a = ? AND user_b = ?);",
            (user_a, user_b, user_b, user_a),
        )
        await db.commit()


async def get_contacts(username: str) -> set[str]:
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute("SELECT user_b FROM contacts WHERE user_a = ?;", (username,))
        rows = await cur.fetchall()
        return {r[0] for r in rows}


async def are_contacts(user_a: str, user_b: str) -> bool:
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "SELECT 1 FROM contacts WHERE user_a = ? AND user_b = ?;", (user_a, user_b)
        )
        return await cur.fetchone() is not None
