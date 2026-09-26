# Family Call

Oilaviy foydalanish uchun real-time audio/video qo'ng'iroq ilovasi.
Ro'yxatdan o'tish YO'Q — hisoblarni faqat admin `admin_cli.py` orqali
qo'lda yaratadi.

## Arxitektura — nima uchun shunday qurilgan

Har bir qo'ng'iroq boshlanishida ikki tomon (caller/callee) **bevosita
bir-biri bilan** X25519 Diffie-Hellman almashinuvini bajaradi. Backend
(FastAPI) faqat "kimga yo'naltirish" darajasida xabar tashiydi — u DH
ephemeral kalitlarni, imzolarni yoki SDP/ICE mazmunini HECH QACHON
ochmaydi/tekshirmaydi (`backend/routes/call_ws.py`dagi `_RELAY_TYPES`ga
qarang). Shu ma'noda bu ilovada matn/media xabar almashinuvi umuman yo'q —
faqat bitta funksiya: qo'ng'iroq, va shifrlash faqat shu funksiya doirasida.

```
1. Caller  --call_invite-->  Server  --call_invite-->  Callee
2. Callee accept -> getUserMedia -> dh_hello (ephemeral X25519 pub,
   Ed25519 identity bilan imzolangan)  -->  Server (ko'r relay)  --> Caller
3. Caller signature'ni Callee'ning UZOQ MUDDATLI identity ochiq kaliti
   bilan tekshiradi (server DB'dan /keys/{username} orqali olingan) ->
   dh_hello_reply (o'z ephemeral pub'i + imzo)  -->  Server  --> Callee
4. Callee ham signature'ni tekshiradi -> ikkala tomon X25519(shared secret)
   -> HKDF-SHA256(salt=call_id) -> AES-256-GCM session key
5. Shu kalit bilan SHIFRLANGAN "signal" xabarlari (SDP offer/answer, ICE
   candidate) almashiladi — server ularni faqat yo'naltiradi, ichini
   ko'rmaydi.
6. Haqiqiy audio/video WebRTC (RTCPeerConnection) orqali P2P, o'zining
   DTLS-SRTP shifrlashi bilan boradi — server hech qachon media oqimini
   ko'rmaydi (agar TURN relay ishlatilmasa).
```

**Nega Ed25519 imzo kerak?** Xom DH o'zi "kim bilan gaplashyapman" degan
savolga javob bermaydi — agar server (yoki tarmoqdagi kimdir) ephemeral
kalitni yo'lda almashtirsa, MITM bo'ladi. Har bir foydalanuvchi birinchi
loginda uzoq muddatli Ed25519 "identity" kalit juftligi generatsiya qiladi
(brauzerda, `localStorage`da), faqat OCHIQ qismini serverga yuklaydi.
Har bir ephemeral X25519 kalit shu identity kalit bilan imzolanadi, qabul
qiluvchi tomon imzoni identity ochiq kalit orqali tekshiradi.

**Kabutar'dan nima olib kelindi, nima yangi:** `dh_exchange.py`dagi
X25519 -> HKDF-SHA256(salt) -> AES-256-GCM konstruksiyasi va
`session_store.py`dagi TTL/bir martalik kalit g'oyasi aynan kabutar'dan
(`reference/kabutar_dh_exchange/`da asl nusxasi saqlangan — solishtirish
uchun). LEKIN kabutar'da bu handshake **client<->server** edi (WS
transportini himoyalash uchun); bu yerda esa **client<->client**
(server ko'r relay) — shuning uchun butun kripto qatlami Python'dan JS'ga
(`frontend/js/crypto.js`) ko'chirildi, backend endi faqat marshrutlovchi.
Ed25519 identity-bog'lash (imzo) — kabutar'ning `key_service.py`/
`user_keys_repository.py` patternidan ilhomlangan, yangi qo'shilgan qism.

## O'rnatish

```bash
cd backend
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"   # natijani .env'dagi SECRET_KEY'ga qo'ying
```

## Hisob qo'shish (faqat shu yo'l bilan — ro'yxatdan o'tish yo'q)

```bash
cd backend
python admin_cli.py add ota          # parolni so'raydi (terminalda ko'rinmaydi)
python admin_cli.py add ona
python admin_cli.py add farzand
python admin_cli.py list             # tekshirish
```

## Ishga tushirish

```bash
cd backend
uvicorn main:app --host 0.0.0.0 --port 8000
```

Brauzerda: `http://<server-ip>:8000/` — login sahifasiga yo'naltiradi.

**MUHIM:** `getUserMedia` (kamera/mikrofon) faqat "secure context"da ishlaydi
— ya'ni `https://` yoki `http://localhost`. Uyda bir nechta qurilmadan
sinash uchun `localhost`dan tashqarida albatta HTTPS kerak bo'ladi (masalan
Caddy/nginx + Let's Encrypt, yoki Tailscale orqali ochib, Tailscale'ning
o'z HTTPS sertifikatidan foydalanish — sizda `remote-access-setup`da
Tailscale allaqachon bor, shuni ishlatish eng qulay yo'l).

## Cheklovlar / keyingi qadamlar

- Faqat ochiq STUN server (`stun.l.google.com`) ishlatilgan. Agar bir a'zo
  qattiq (symmetric) NAT ortida bo'lsa, ulanish o'rnatilmasligi mumkin —
  shunda TURN server (masalan `coturn`) kerak bo'ladi.
- Bir hisob — bir vaqtda bitta ulanish (oddiylik uchun). Ko'p qurilma kerak
  bo'lsa, `_ONLINE` dict'ini kengaytirish kerak.
- Identity private key brauzer `localStorage`da (shifrlanmagan) turadi —
  qurilma diskini fizik olib ketishga qarshi himoya emas, faqat tarmoqdagi
  MITM'ga qarshi. Yuqori xavf darajasi uchun WebAuthn/hardware key kerak
  bo'ladi.
- `frontend/js/crypto.js` `@noble/curves` kutubxonasini CDN (`esm.sh`)dan
  yuklaydi — internet kerak. Offline ishlatish uchun paketni lokal
  yuklab, `<script type="module">` import yo'lini shunga o'zgartiring.
# Yangilanish
