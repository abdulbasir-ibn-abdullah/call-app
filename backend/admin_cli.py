"""
ADMIN CLI — yagona hisob yaratish yo'li. HTTP admin endpoint ATAYLAB
qo'shilmagan (kichik oilaviy ilovada bu keraksiz hujum yuzasi bo'lar edi) —
hisoblarni faqat serverga terminal orqali kira oladigan admin qo'sha oladi.

KONTAKTLAR: yangi hisob yaratilganda u HECH KIMNI ko'rmaydi va HECH KIM
uni ko'rmaydi — standart holat "izolyatsiya". Ikkita hisobni bir-biriga
ko'rsatish uchun 'link' buyrug'ini ishlatasiz. Shu orqali bitta serverda
bir nechta bir-biridan bexabar guruh (masalan oila va alohida do'st)
yashashi mumkin.

Ishlatish:
    cd backend
    python admin_cli.py add alice
    python admin_cli.py add bob --admin
    python admin_cli.py list
    python admin_cli.py disable bob

    python admin_cli.py link ota ona          # ota <-> ona bir-birini ko'radi
    python admin_cli.py link ota farzand
    python admin_cli.py link ona farzand
    python admin_cli.py contacts ota          # ota kimlarni ko'rishini tekshirish
    python admin_cli.py unlink ota dost        # kerak bo'lsa aloqani uzish
"""
from __future__ import annotations

import argparse
import asyncio
import getpass
import sys

from database import (
    add_contact_link,
    create_user,
    disable_user,
    get_contacts,
    get_user_by_username,
    init_db,
    list_usernames,
    remove_contact_link,
)
from security.password import hash_password


async def cmd_add(username: str, is_admin: bool) -> None:
    await init_db()
    existing = await get_user_by_username(username)
    if existing is not None:
        print(f"XATO: '{username}' allaqachon mavjud.", file=sys.stderr)
        sys.exit(1)

    password = getpass.getpass(f"'{username}' uchun parol: ")
    password2 = getpass.getpass("Parolni takrorlang: ")
    if password != password2:
        print("XATO: parollar mos emas.", file=sys.stderr)
        sys.exit(1)
    if len(password) < 8:
        print("XATO: parol kamida 8 belgidan iborat bo'lishi kerak.", file=sys.stderr)
        sys.exit(1)

    await create_user(username, hash_password(password), is_admin=is_admin)
    print(f"OK: '{username}' yaratildi{' (admin)' if is_admin else ''}.")
    print("Diqqat: hozircha hech kimni ko'rmaydi/ko'rinmaydi — 'link' bilan bog'lang.")


async def cmd_list() -> None:
    await init_db()
    for u in await list_usernames():
        print(u)


async def cmd_disable(username: str) -> None:
    await init_db()
    ok = await disable_user(username)
    print("OK: o'chirildi." if ok else f"XATO: '{username}' topilmadi.")


async def _require_users(*usernames: str) -> None:
    for u in usernames:
        if await get_user_by_username(u) is None:
            print(f"XATO: '{u}' degan hisob topilmadi.", file=sys.stderr)
            sys.exit(1)


async def cmd_link(user_a: str, user_b: str) -> None:
    await init_db()
    if user_a == user_b:
        print("XATO: bir xil hisobni o'ziga bog'lab bo'lmaydi.", file=sys.stderr)
        sys.exit(1)
    await _require_users(user_a, user_b)
    await add_contact_link(user_a, user_b)
    print(f"OK: '{user_a}' <-> '{user_b}' bog'landi (bir-birini ko'radi/chaqira oladi).")


async def cmd_unlink(user_a: str, user_b: str) -> None:
    await init_db()
    await remove_contact_link(user_a, user_b)
    print(f"OK: '{user_a}' <-> '{user_b}' aloqasi uzildi.")


async def cmd_contacts(username: str) -> None:
    await init_db()
    await _require_users(username)
    contacts = sorted(await get_contacts(username))
    if not contacts:
        print(f"'{username}' hech kimga bog'lanmagan.")
        return
    for c in contacts:
        print(c)


def main() -> None:
    parser = argparse.ArgumentParser(description="Video va Audio Qo'ng'iroq — admin CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p_add = sub.add_parser("add", help="Yangi hisob qo'shish")
    p_add.add_argument("username")
    p_add.add_argument("--admin", action="store_true", help="Admin huquqi bilan")

    sub.add_parser("list", help="Barcha hisoblarni ko'rsatish")

    p_disable = sub.add_parser("disable", help="Hisobni o'chirish (login qila olmay qoladi)")
    p_disable.add_argument("username")

    p_link = sub.add_parser("link", help="Ikkita hisobni bir-biriga ko'rsatish (bir-birini ko'radi/chaqiradi)")
    p_link.add_argument("user_a")
    p_link.add_argument("user_b")

    p_unlink = sub.add_parser("unlink", help="Ikkita hisob orasidagi bog'lanishni uzish")
    p_unlink.add_argument("user_a")
    p_unlink.add_argument("user_b")

    p_contacts = sub.add_parser("contacts", help="Bir hisob kimlarni ko'rishini chiqarish")
    p_contacts.add_argument("username")

    args = parser.parse_args()

    if args.command == "add":
        asyncio.run(cmd_add(args.username, args.admin))
    elif args.command == "list":
        asyncio.run(cmd_list())
    elif args.command == "disable":
        asyncio.run(cmd_disable(args.username))
    elif args.command == "link":
        asyncio.run(cmd_link(args.user_a, args.user_b))
    elif args.command == "unlink":
        asyncio.run(cmd_unlink(args.user_a, args.user_b))
    elif args.command == "contacts":
        asyncio.run(cmd_contacts(args.username))


if __name__ == "__main__":
    main()
