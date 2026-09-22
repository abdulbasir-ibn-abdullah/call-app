const TOKEN_KEY = "family_call_token";
const USERNAME_KEY = "family_call_username";

// Ilova qaysi subpath ostida ochilganini SAHIFA URL'idan avtomatik topadi
// (masalan https://domen/call-app/static/login.html -> "/call-app").
// Backend .env'dagi BASE_PATH bilan mos bo'lishi shart — u yerda o'zgartirsangiz,
// bu yerda hech narsani qo'lda sozlash shart emas.
export const BASE_PATH = (() => {
  const idx = window.location.pathname.indexOf("/static/");
  return idx >= 0 ? window.location.pathname.slice(0, idx) : "";
})();

export function saveSession(token, username) {
  localStorage.setItem(TOKEN_KEY, token);
  localStorage.setItem(USERNAME_KEY, username);
}
export function getToken() {
  return localStorage.getItem(TOKEN_KEY);
}
export function getUsername() {
  return localStorage.getItem(USERNAME_KEY);
}
export function clearSession() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(USERNAME_KEY);
}
export function requireAuthOrRedirect() {
  if (!getToken()) {
    window.location.href = `${BASE_PATH}/static/login.html`;
    return false;
  }
  return true;
}

// path — ildizga nisbatan yoziladi, masalan "/presence/online" —
// BASE_PATH avtomatik oldiga qo'shiladi.
export async function apiGet(path) {
  const res = await fetch(`${BASE_PATH}${path}`, {
    headers: { Authorization: `Bearer ${getToken()}` },
  });
  if (res.status === 401) {
    clearSession();
    window.location.href = `${BASE_PATH}/static/login.html`;
    throw new Error("401");
  }
  if (!res.ok) throw new Error(`GET ${path} -> ${res.status}`);
  return res.json();
}

export async function apiPost(path, body) {
  const res = await fetch(`${BASE_PATH}${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${getToken()}`,
    },
    body: JSON.stringify(body),
  });
  if (res.status === 401) {
    clearSession();
    window.location.href = `${BASE_PATH}/static/login.html`;
    throw new Error("401");
  }
  if (!res.ok) throw new Error(`POST ${path} -> ${res.status}`);
  return res.json();
}

