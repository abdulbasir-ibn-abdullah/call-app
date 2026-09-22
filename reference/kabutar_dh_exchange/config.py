# Handshake tugallanishi kutiladigan maksimal vaqt (soniya).
# Shu vaqt ichida client javob bermasa, server o'z private key'ini
# xotiradan avtomatik o'chirib tashlaydi (memory-leak / DoS oldini olish uchun).
DH_HANDSHAKE_TTL_SECONDS = 30

# Bir vaqtning o'zida RAM'da saqlanishi mumkin bo'lgan maksimal
# "kutilayotgan handshake" soni (eng eski/eskirganlar avtomatik siqib chiqariladi).
DH_MAX_PENDING_HANDSHAKES = 2_000_000

# HKDF orqali olinadigan yakuniy simmetrik kalit uzunligi (bayt).
# 32 bayt = AES-256-GCM uchun mos.
HKDF_KEY_LENGTH = 32

# HKDF "info" parametri — domain separation uchun.
HKDF_INFO_TAG = b"kabutar-dh-session-key-v1"
