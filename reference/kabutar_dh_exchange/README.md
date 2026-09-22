# Kabutar — Efemeral DH Kalit Almashinuvi (X25519)

Har bir WebSocket ulanishida **yangi, bir martalik** kalit juftligi hosil qilinadi,
ikki tomon umumiy simmetrik kalitga (session key) kelishib oladi. Kalitlar
**faqat RAM'da** turadi, diskka hech qachon yozilmaydi.

## Fayllar

| Fayl                               | Vazifasi |
|------------------------------------|---|
| `dh_exchange/dh_exchange.py`       | X25519 kalit generatsiyasi, serialize/deserialize, HKDF orqali yakuniy kalit chiqarish |
| `dh_exchange/session_store.py`     | RAM'dagi vaqtinchalik store: `client_id` bo'yicha private key, TTL bilan avtomatik tozalanadi |
| `dh_exchange/websocket_handler.py` | FastAPI WebSocket endpoint namunasi — to'liq handshake oqimi |
| `dh_exchange/config.py`            | TTL, kalit uzunligi va boshqa sozlamalar |
| `dh_exchange/test_dh_exchange.py`  | Handshake, TTL va tezlik (scale) testlari |

## Nega classic (modular) DH emas, X25519?

Test uchun yozilgan avvalgi versiya 2048-bit klassik Diffie-Hellman edi.
Bu **matematik jihatdan to'g'ri**, lekin har bir ulanishda og'ir modular
exponentiation talab qiladi. Millionlab bir vaqtdagi WebSocket ulanish uchun
bu CPU'ni tez tuzatib qo'yadi. X25519 (elliptik egri chiziqli DH):

- Kalit hajmi bor-yo'g'i 32 bayt (2048-bit DH'da bu ~256 bayt)
- Hisoblash bir necha barobar tezroq
- Xavfsizlik darajasi ~3072-bit klassik DH'ga teng
- `cryptography` kutubxonasida tayyor, sinovdan o'tgan implementatsiya bor
  (Signal, WhatsApp, TLS 1.3 shu bilan ishlaydi)

## Protokol oqimi

```
Client                                   Server
  |--- WS ulanish (client_id bilan) ---->|
  |                                       | efemeral (priv, pub) generatsiya
  |                                       | priv -> RAM store[client_id]
  |<---- {type: dh_server_hello,          |
  |       server_public_key} ------------|
  | efemeral (priv, pub) generatsiya      |
  |--- {type: dh_client_hello,            |
  |     client_public_key} ------------->|
  |                                       | priv = store.pop(client_id)  # bir martalik
  |                                       | shared = ECDH(priv, client_pub)
  |                                       | session_key = HKDF(shared, salt=client_id)
  | session_key = HKDF(shared, ...)       |
  |<==== bundan keyin session_key bilan shifrlangan xabarlar ====>|
```

## Xavfsizlik bo'yicha muhim eslatmalar

1. **Private key hech qachon diskka yozilmaydi.** Faqat `EphemeralKeyStore`
   ichidagi RAM lug'atida (yoki `TTLCache`da) turadi.
2. **Bir martalik ishlatish.** `store.pop(client_id)` chaqirilgan zahoti kalit
   xotiradan o'chadi — qayta ishlatib bo'lmaydi.
3. **TTL bilan avtomatik tozalash.** Client javob bermay qolsa (masalan
   tarmoq uzilsa), kalit belgilangan vaqtdan keyin (standart: 30 soniya)
   o'z-o'zidan yo'qoladi. Bu millionlab "chala handshake" bilan xotirani
   to'ldirib yuborish (DoS) xavfini yopadi.
4. **HKDF majburiy.** Xom ECDH natijasini to'g'ridan-to'g'ri AES kaliti
   qilib ishlatish xato — u yetarlicha tasodifiy taqsimlangan emas. HKDF-SHA256
   orqali to'g'ri simmetrik kalit chiqariladi, `client_id` esa "salt" sifatida
   qo'shilib, har bir ulanish mustaqil kalitga ega bo'lishini kafolatlaydi.
5. **MITM haqida.** Xom Diffie-Hellman "kim bilan gaplashyapman" degan
   savolga javob bermaydi. Agar WebSocket allaqachon `wss://` (TLS) ustida
   ishlasa, MITM xavfi katta darajada yopiladi. Qo'shimcha himoya uchun
   `server_public_key`ni JWT/session imzosiga bog'lash tavsiya etiladi.

## Millionlab ulanishni qo'llab-quvvatlash

- `client_id` — bu **oddiy user_id emas**, balki har bir ANIQ WebSocket
  ulanishga xos identifikator bo'lishi kerak (bir user bir nechta qurilmadan
  bir vaqtda ulanishi mumkin).
- `cachetools.TTLCache` ishlatilganda qo'shish/o'qish O(1), eskirgan
  yozuvlar lazy (kerak bo'lganda) tozalanadi — qo'lda background task
  shart emas.
- `cachetools` o'rnatilmagan bo'lsa, kod avtomatik oddiy `dict` + qo'lda
  tozalash (`sweep_expired`) rejimiga o'tadi. Bu holda FastAPI startup
  eventida `start_cleanup_task(key_store)` ni ishga tushiring.
- Ko'p workerli ishga tushirish (`uvicorn --workers 4`) da har worker
  o'zining mustaqil RAM store'iga ega bo'ladi — bu muammo emas, chunki
  bitta WebSocket ulanish butun umri davomida bitta workerda qoladi.

## O'rnatish

```bash
pip install -r requirements.txt --break-system-packages
python3 test_dh_exchange.py
```

## Kabutar backendiga ulash

`websocket_handler.py` dagi `router`ni asosiy FastAPI ilovangizga qo'shing:

```python
from fastapi import FastAPI
from dh_exchange.websocket_handler import router as dh_router

app = FastAPI()

app.include_router(dh_router)
```

`client_id`ni URL'dan olish o'rniga, avval mavjud auth middleware/JWT
tekshiruvidan o'tkazib, shundan keyin generatsiya qilingan ulanishga xos
identifikator sifatida berish tavsiya etiladi.
