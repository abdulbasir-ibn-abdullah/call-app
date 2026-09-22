"""
X25519 (Elliptic-Curve Diffie-Hellman) asosidagi efemeral kalit almashinuvi.

Nega classic (modular) DH emas, X25519?
- Klassik 2048-bit DH har bir ulanishda og'ir modular exponentiation talab qiladi.
- X25519 kalitlari atigi 32 bayt va hisoblash tezligi bir necha barobar yuqori —
  millionlab bir vaqtdagi WebSocket ulanish uchun bu farq juda muhim.
- Xavfsizlik darajasi taxminan 2048-3072 bit klassik DH ga teng.

Bu modul faqat KRIPTOGRAFIK operatsiyalarni bajaradi — hech qanday holatni
(state) o'zida saqlamaydi. Holatni EphemeralKeyStore boshqaradi.
"""

from __future__ import annotations

import base64

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .config import HKDF_KEY_LENGTH, HKDF_INFO_TAG


class DHKeyExchange:
    """Bitta ulanish (bir martalik, ephemeral) uchun X25519 kalit almashinuvi."""

    @staticmethod
    def generate_keypair() -> tuple[X25519PrivateKey, X25519PublicKey]:
        """Har chaqirilganda YANGI, tasodifiy kalit juftligini qaytaradi."""
        private_key = X25519PrivateKey.generate()
        return private_key, private_key.public_key()

    @staticmethod
    def serialize_public_key(public_key: X25519PublicKey) -> str:
        """Ochiq kalitni tarmoq orqali yuborish uchun base64 stringga aylantiradi."""
        raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return base64.b64encode(raw).decode("ascii")

    @staticmethod
    def deserialize_public_key(b64_str: str) -> X25519PublicKey:
        """Clientdan kelgan base64 ochiq kalitni obyektga qaytaradi."""
        try:
            raw = base64.b64decode(b64_str, validate=True)
        except Exception as exc:  # noqa: BLE001
            raise ValueError("Ochiq kalit formati noto'g'ri (base64 emas)") from exc

        if len(raw) != 32:
            raise ValueError("X25519 ochiq kaliti aynan 32 bayt bo'lishi kerak")

        return X25519PublicKey.from_public_bytes(raw)

    @staticmethod
    def compute_shared_key(
        private_key: X25519PrivateKey,
        peer_public_key: X25519PublicKey,
        client_id: str,
        key_len: int = HKDF_KEY_LENGTH,
    ) -> bytes:
        """
        Umumiy sirni (raw ECDH natijasi) hisoblaydi va uni HKDF-SHA256 orqali
        xavfsiz simmetrik kalitga aylantiradi.

        Xom ECDH natijasini to'g'ridan-to'g'ri AES kaliti sifatida ishlatish
        XATO — u yetarlicha "tekis taqsimlangan" (uniform) emas. HKDF shu
        muammoni yechadi va client_id'ni "salt" sifatida qo'shib, har bir
        ulanish uchun mustaqil kalit hosil qilinishini kafolatlaydi.
        """
        shared_secret = private_key.exchange(peer_public_key)

        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=key_len,
            salt=client_id.encode("utf-8"),
            info=HKDF_INFO_TAG,
        ).derive(shared_secret)

        return derived_key
