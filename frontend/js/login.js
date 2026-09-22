import { BASE_PATH, saveSession } from "./api.js";
import { getOrCreateIdentityKeyPair, toB64 } from "./crypto.js";

const form = document.getElementById("login-form");
const errorBox = document.getElementById("error-box");

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  errorBox.textContent = "";

  const username = document.getElementById("username").value.trim();
  const password = document.getElementById("password").value;

  const body = new URLSearchParams();
  body.set("username", username);
  body.set("password", password);

  let res;
  try {
    res = await fetch(`${BASE_PATH}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
    });
  } catch (err) {
    errorBox.textContent = "Serverga ulanib bo'lmadi.";
    return;
  }

  if (!res.ok) {
    errorBox.textContent = "Login yoki parol noto'g'ri.";
    return;
  }

  const data = await res.json();
  saveSession(data.access_token, data.username);

  // Identity kalit hali yo'q bo'lsa generatsiya qilib serverga yuklaymiz
  // (faqat OCHIQ kalit — private kalit brauzerdan hech qachon chiqmaydi).
  const { publicKey } = getOrCreateIdentityKeyPair();
  try {
    await fetch(`${BASE_PATH}/keys/upload`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${data.access_token}`,
      },
      body: JSON.stringify({ identity_public_key: toB64(publicKey) }),
    });
  } catch (err) {
    console.warn("identity key yuklashda xato (keyinroq qayta urinib ko'riladi):", err);
  }

  window.location.href = `${BASE_PATH}/static/call.html`;
});

