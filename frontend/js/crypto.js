// Qo'ng'iroq E2E shifrlash moduli.
//
// Arxitektura kabutar/backend/auth/dh_exchange/dh_exchange.py bilan bir xil
// g'oyaga asoslangan (X25519 -> HKDF-SHA256 -> AES-256-GCM), lekin BU YERDA
// almashinuv CLIENT<->CLIENT (server faqat ko'r relay). Qo'shimcha: har bir
// ephemeral X25519 kalit Ed25519 identity kalit bilan IMZOLANADI — shu orqali
// server (yoki tarmoqdagi boshqa MITM) ephemeral kalitni almashtira olmaydi.
//
// Kutubxona: @noble/curves (audit qilingan, kichik, bog'liqliklarsiz).
//import { ed25519, x25519 } from "https://esm.sh/@noble/curves@1.7.0/ed25519";
import { ed25519, x25519 } from "./vendor/noble-ed25519.js";
// ---------- base64 yordamchi funksiyalar ----------
export function toB64(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}
export function fromB64(str) {
  const bin = atob(str);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

// ---------- 1) Uzoq muddatli IDENTITY kalit (Ed25519) ----------
// Brauzerda localStorage'da saqlanadi. Diqqat: bu qattiq disk darajasidagi
// himoya emas (masalan Secure Enclave emas) — oilaviy shaxsiy ilova uchun
// yetarli, lekin yuqori xavfli stsenariy uchun emas.
const LS_PRIV = "family_call_identity_priv";
const LS_PUB = "family_call_identity_pub";

export function getOrCreateIdentityKeyPair() {
  let privB64 = localStorage.getItem(LS_PRIV);
  let pubB64 = localStorage.getItem(LS_PUB);
  if (privB64 && pubB64) {
    return { privateKey: fromB64(privB64), publicKey: fromB64(pubB64) };
  }
  const privateKey = ed25519.utils.randomPrivateKey();
  const publicKey = ed25519.getPublicKey(privateKey);
  localStorage.setItem(LS_PRIV, toB64(privateKey));
  localStorage.setItem(LS_PUB, toB64(publicKey));
  return { privateKey, publicKey };
}

export function signBytes(privateKey, message) {
  return ed25519.sign(message, privateKey);
}
export function verifyBytes(signature, message, publicKey) {
  try {
    return ed25519.verify(signature, message, publicKey);
  } catch {
    return false;
  }
}

// ---------- 2) Bir martalik EPHEMERAL kalit (X25519) ----------
export function generateEphemeralKeyPair() {
  const privateKey = x25519.utils.randomPrivateKey();
  const publicKey = x25519.getPublicKey(privateKey);
  return { privateKey, publicKey };
}

export function computeSharedSecret(ephPrivateKey, peerEphPublicKey) {
  return x25519.getSharedSecret(ephPrivateKey, peerEphPublicKey);
}

// ---------- 3) HKDF-SHA256 -> AES-256-GCM session key ----------
// salt = call_id (har chaqiruv uchun yagona) — kabutar'da connection_id bilan
// bir xil rol: ikki tomon bir xil session key chiqarishini kafolatlaydi.
export async function deriveSessionKey(sharedSecret, callId) {
  const keyMaterial = await crypto.subtle.importKey("raw", sharedSecret, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new TextEncoder().encode(callId),
      info: new TextEncoder().encode("family-call-v1-signal-key"),
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

// ---------- 4) AES-256-GCM shifrlash — faqat signalizatsiya (SDP/ICE) uchun ----------
export async function encryptJSON(sessionKey, obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = new TextEncoder().encode(JSON.stringify(obj));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, sessionKey, data);
  return { iv: toB64(iv), ciphertext: toB64(new Uint8Array(ciphertext)) };
}

export async function decryptJSON(sessionKey, ivB64, ciphertextB64) {
  const iv = fromB64(ivB64);
  const ciphertext = fromB64(ciphertextB64);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, sessionKey, ciphertext);
  return JSON.parse(new TextDecoder().decode(plain));
}
