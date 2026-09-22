import { apiGet, getToken, getUsername, requireAuthOrRedirect, clearSession, BASE_PATH } from "./api.js";
import {
  getOrCreateIdentityKeyPair,
  generateEphemeralKeyPair,
  computeSharedSecret,
  deriveSessionKey,
  encryptJSON,
  decryptJSON,
  signBytes,
  verifyBytes,
  toB64,
  fromB64,
} from "./crypto.js";

if (!requireAuthOrRedirect()) throw new Error("auth required");

const myUsername = getUsername();
document.getElementById("me").textContent = myUsername;

const identity = getOrCreateIdentityKeyPair();
const peerIdentityCache = new Map(); // username -> Uint8Array Ed25519 pubkey

const contactsEl = document.getElementById("contacts");
const startCallBtn = document.getElementById("start-call-btn");
const incomingEl = document.getElementById("incoming-call");
const inCallEl = document.getElementById("in-call");
const videoGrid = document.getElementById("video-grid");
const statusEl = document.getElementById("status");
const micBtn = document.getElementById("mic-btn");
const camBtn = document.getElementById("cam-btn");
const switchCamBtn = document.getElementById("switch-cam-btn");
const fullscreenBtn = document.getElementById("fullscreen-btn");

let ws = null;
let onlineContacts = [];
let selectedForCall = new Set();
let pendingRoomInvite = null; // {from, room_id}
let currentRoom = null; // {roomId, audioTrack, videoTrack, facingMode, peers: Map<username, PeerState>}

const ICE_SERVERS = [{ urls: "stun:stun.l.google.com:19302" }];

// ==================== Ovoz signallari (WebAudio, fayl kerak emas) ====================
const Tone = {
  ctx: null,
  intervalId: null,
  _ensure() {
    if (!this.ctx) this.ctx = new (window.AudioContext || window.webkitAudioContext)();
    if (this.ctx.state === "suspended") this.ctx.resume();
  },
  _beep(freq, durationMs, whenOffsetSec = 0) {
    const ctx = this.ctx;
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.type = "sine";
    osc.frequency.value = freq;
    gain.gain.value = 0.18;
    osc.connect(gain);
    gain.connect(ctx.destination);
    const startAt = ctx.currentTime + whenOffsetSec;
    osc.start(startAt);
    osc.stop(startAt + durationMs / 1000);
  },
  startRingback() {
    // Yuboruvchida eshitiladigan gudok — javob kutilayotganda
    this._ensure();
    this.stop();
    const cycle = () => this._beep(425, 1000);
    cycle();
    this.intervalId = setInterval(cycle, 3000);
  },
  startRingtone() {
    // Qabul qiluvchida eshitiladigan qo'ng'iroq signali
    this._ensure();
    this.stop();
    const cycle = () => {
      this._beep(750, 300, 0);
      this._beep(750, 300, 0.4);
    };
    cycle();
    this.intervalId = setInterval(cycle, 1500);
  },
  stop() {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
  },
};

// ==================== Peer identity key (keshlangan) ====================
async function getPeerIdentityKey(username) {
  if (peerIdentityCache.has(username)) return peerIdentityCache.get(username);
  const data = await apiGet(`/keys/${encodeURIComponent(username)}`);
  const pub = fromB64(data.identity_public_key);
  peerIdentityCache.set(username, pub);
  return pub;
}

// ==================== WebSocket ====================
function connectWs() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  ws = new WebSocket(`${proto}://${location.host}${BASE_PATH}/ws/call?token=${encodeURIComponent(getToken())}`);
  ws.onopen = () => setStatus("Ulandi.");
  ws.onclose = () => setStatus("Uzildi — sahifani yangilang.");
  ws.onerror = () => setStatus("Ulanish xatosi.");
  ws.onmessage = async (ev) => {
    const msg = JSON.parse(ev.data);
    try {
      await handleMessage(msg);
    } catch (err) {
      console.error("Xabarni qayta ishlashda xato:", err);
    }
  };
}
function send(obj) {
  ws.send(JSON.stringify(obj));
}
function setStatus(text) {
  statusEl.textContent = text;
}
function clog(peer, ...args) {
  console.log(`[qo'ng'iroq:${peer}]`, ...args);
}

// ==================== Kontaktlar ro'yxati (checkbox bilan tanlash) ====================
async function loadInitialPresence() {
  const data = await apiGet("/presence/online");
  onlineContacts = data.online;
  renderContacts();
}

function renderContacts() {
  contactsEl.innerHTML = "";
  if (onlineContacts.length === 0) {
    contactsEl.innerHTML = "<li class='muted'>Hech kim onlayn emas</li>";
    startCallBtn.disabled = true;
    return;
  }
  for (const username of onlineContacts) {
    const li = document.createElement("li");
    const label = document.createElement("label");
    label.className = "contact-row";
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.disabled = !!currentRoom;
    checkbox.checked = selectedForCall.has(username);
    checkbox.onchange = () => {
      if (checkbox.checked) selectedForCall.add(username);
      else selectedForCall.delete(username);
      startCallBtn.disabled = selectedForCall.size === 0;
    };
    label.appendChild(checkbox);
    label.append(` ${username}`);
    li.appendChild(label);
    contactsEl.appendChild(li);
  }
  startCallBtn.disabled = !!currentRoom || selectedForCall.size === 0;
}

startCallBtn.onclick = () => {
  Tone._ensure(); // AudioContext ALDIN, click ichida — brauzer autoplay siyosati shart qiladi
  startRoom([...selectedForCall]);
};

// ==================== Xabar marshrutlash ====================
async function handleMessage(msg) {
  switch (msg.type) {
    case "presence_update":
      onlineContacts = msg.online;
      selectedForCall = new Set([...selectedForCall].filter((u) => onlineContacts.includes(u)));
      renderContacts();
      break;
    case "room_invite":
      onRoomInvite(msg);
      break;
    case "room_invite_reject":
      setStatus(`${msg.from} chaqiruvni rad etdi.`);
      break;
    case "room_members":
      await onRoomMembers(msg);
      break;
    case "peer_joined":
      await onPeerJoined(msg);
      break;
    case "peer_left":
      onPeerLeft(msg);
      break;
    case "dh_hello":
      await onDhHello(msg);
      break;
    case "dh_hello_reply":
      await onDhHelloReply(msg);
      break;
    case "signal":
      await onSignal(msg);
      break;
    case "error":
      console.warn("Server xatosi:", msg.detail);
      setStatus(`Xato: ${msg.detail}`);
      break;
  }
}

// ==================== Pastki qatlam: lokal audio olish, xona yaratish ====================
function pairCallId(roomId, a, b) {
  return `${roomId}:${[a, b].sort().join("|")}`;
}

async function getLocalAudio() {
  const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
  return stream.getAudioTracks()[0];
}

function newRoomState(roomId, audioTrack) {
  return {
    roomId,
    audioTrack,
    videoTrack: null,
    facingMode: "user",
    videoEnabled: false,
    micEnabled: true,
    // Barcha peer-connection'lar shu BITTA MediaStream'ga "a'zo" bo'lib
    // qo'shiladi (addTrack/addTransceiver'ga uzatiladi) — shu orqali narigi
    // tarafda "ontrack" kelganda ev.streams[0] BO'SH bo'lib qolmaydi.
    outboundStream: new MediaStream([audioTrack]),
    peers: new Map(), // username -> PeerState
  };
}

// ==================== Xona boshlash (men — yaratuvchi) ====================
async function startRoom(invitees) {
  if (currentRoom || invitees.length === 0) return;
  const roomId = crypto.randomUUID();
  let audioTrack;
  try {
    audioTrack = await getLocalAudio();
  } catch (err) {
    setStatus("Mikrofonga ruxsat berilmadi.");
    return;
  }
  currentRoom = newRoomState(roomId, audioTrack);
  showCallUi();
  addLocalTile();
  updateControlButtons();
  setStatus("Kutilyapti...");
  Tone.startRingback();

  send({ type: "room_join", room_id: roomId });
  for (const to of invitees) {
    send({ type: "room_invite", to, room_id: roomId });
  }
}

// ==================== Kiruvchi xona taklifi ====================
function onRoomInvite(msg) {
  if (currentRoom) {
    send({ type: "room_invite_reject", to: msg.from, room_id: msg.room_id });
    return;
  }
  pendingRoomInvite = { from: msg.from, room_id: msg.room_id };
  document.getElementById("caller-name").textContent = msg.from;
  incomingEl.classList.remove("hidden");
  Tone.startRingtone();
}

document.getElementById("accept-btn").onclick = async () => {
  incomingEl.classList.add("hidden");
  Tone.stop();
  if (!pendingRoomInvite) return;
  const { room_id } = pendingRoomInvite;
  pendingRoomInvite = null;

  let audioTrack;
  try {
    audioTrack = await getLocalAudio();
  } catch (err) {
    setStatus("Mikrofonga ruxsat berilmadi.");
    return;
  }
  currentRoom = newRoomState(room_id, audioTrack);
  showCallUi();
  addLocalTile();
  updateControlButtons();
  setStatus("Xavfsiz kanal o'rnatilmoqda...");

  send({ type: "room_join", room_id });
};

document.getElementById("reject-btn").onclick = () => {
  incomingEl.classList.add("hidden");
  Tone.stop();
  if (!pendingRoomInvite) return;
  send({ type: "room_invite_reject", to: pendingRoomInvite.from, room_id: pendingRoomInvite.room_id });
  pendingRoomInvite = null;
};

// ==================== Xona a'zoligi (mesh koordinatsiyasi) ====================
async function onRoomMembers(msg) {
  if (!currentRoom || msg.room_id !== currentRoom.roomId) return;
  console.log("room_members OLDIM:", msg.members);
  for (const peerUsername of msg.members) {
    await connectToPeer(peerUsername);
  }
}

async function onPeerJoined(msg) {
  if (!currentRoom || msg.room_id !== currentRoom.roomId) return;
  console.log("peer_joined OLDIM:", msg.peer);
  Tone.stop(); // kamida bitta odam qo'shildi — gudokni to'xtatamiz
  setStatus(`${msg.peer} qo'shildi.`);
  await connectToPeer(msg.peer);
}

function onPeerLeft(msg) {
  if (!currentRoom || msg.room_id !== currentRoom.roomId) return;
  removePeer(msg.peer);
  setStatus(`${msg.peer} chiqib ketdi.`);
}

function buildDhSignPayload(ephPublicKey, callId) {
  const callIdBytes = new TextEncoder().encode(callId);
  const combined = new Uint8Array(ephPublicKey.length + callIdBytes.length);
  combined.set(ephPublicKey, 0);
  combined.set(callIdBytes, ephPublicKey.length);
  return combined;
}

// Ikki kishi orasidagi DH kimning boshlashini lug'aviy tartib bilan hal qiladi —
// markazlashtirilgan holat kerak emas, ikkala tomon mustaqil xulosaga keladi.
async function connectToPeer(peerUsername) {
  if (currentRoom.peers.has(peerUsername)) return;
  const callId = pairCallId(currentRoom.roomId, myUsername, peerUsername);
  const isDhInitiator = myUsername < peerUsername;
  const peerState = {
    callId,
    pc: null,
    ephKeyPair: generateEphemeralKeyPair(),
    sessionKey: null,
    remoteDescSet: false,
    pendingCandidates: [],
    pendingSignals: [],
    videoSender: null,
    audioSender: null,
  };
  currentRoom.peers.set(peerUsername, peerState);
  addRemoteTile(peerUsername);

  if (isDhInitiator) {
    clog(peerUsername, "DH boshlovchisiman -> dh_hello yubordim");
    const signature = signBytes(identity.privateKey, buildDhSignPayload(peerState.ephKeyPair.publicKey, callId));
    send({
      type: "dh_hello",
      to: peerUsername,
      room_id: currentRoom.roomId,
      call_id: callId,
      ephemeral_pub: toB64(peerState.ephKeyPair.publicKey),
      signature: toB64(signature),
    });
  } else {
    clog(peerUsername, "DH javob beruvchiman -> dh_hello kutyapman");
  }
  // Aks holda — passiv kutamiz: peerUsername o'zi bizga dh_hello yuboradi.
}

// DH_HELLO oldik -> biz JAVOB beruvchimiz -> SDP OFFER'ni HAM biz yaratamiz
async function onDhHello(msg) {
  if (!currentRoom || msg.room_id !== currentRoom.roomId) return;
  const peerUsername = msg.from;
  clog(peerUsername, "dh_hello OLDIM");
  const expectedCallId = pairCallId(currentRoom.roomId, myUsername, peerUsername);
  if (msg.call_id !== expectedCallId) {
    clog(peerUsername, "call_id MOS KELMADI, rad etildi", msg.call_id, "kutilgan:", expectedCallId);
    return;
  }

  let peerState = currentRoom.peers.get(peerUsername);
  if (!peerState) {
    peerState = {
      callId: expectedCallId,
      pc: null,
      ephKeyPair: generateEphemeralKeyPair(),
      sessionKey: null,
      remoteDescSet: false,
      pendingCandidates: [],
      pendingSignals: [],
      videoSender: null,
      audioSender: null,
    };
    currentRoom.peers.set(peerUsername, peerState);
    addRemoteTile(peerUsername);
  }

  const peerEphPub = fromB64(msg.ephemeral_pub);
  const signature = fromB64(msg.signature);
  const peerIdentityPub = await getPeerIdentityKey(peerUsername);
  const valid = verifyBytes(signature, buildDhSignPayload(peerEphPub, msg.call_id), peerIdentityPub);
  clog(peerUsername, "imzo tekshiruvi:", valid ? "TO'G'RI" : "NOTO'G'RI");
  if (!valid) {
    setStatus(`XAVFSIZLIK OGOHLANTIRISHI: ${peerUsername} imzosi mos kelmadi.`);
    removePeer(peerUsername);
    return;
  }

  const shared = computeSharedSecret(peerState.ephKeyPair.privateKey, peerEphPub);
  peerState.sessionKey = await deriveSessionKey(shared, expectedCallId);
  clog(peerUsername, "session key hosil qilindi, dh_hello_reply yubordim");

  const mySig = signBytes(identity.privateKey, buildDhSignPayload(peerState.ephKeyPair.publicKey, expectedCallId));
  send({
    type: "dh_hello_reply",
    to: peerUsername,
    room_id: currentRoom.roomId,
    call_id: expectedCallId,
    ephemeral_pub: toB64(peerState.ephKeyPair.publicKey),
    signature: toB64(mySig),
  });

  setupPeerConnection(peerUsername, peerState);
  await drainPendingSignals(peerUsername, peerState);

  const offer = await peerState.pc.createOffer();
  await peerState.pc.setLocalDescription(offer);
  clog(peerUsername, "SDP offer yaratdim va yubordim");
  await sendEncryptedSignal(peerUsername, peerState, { kind: "offer", sdp: offer.sdp });
}

// DH_HELLO_REPLY oldik -> biz DH boshlovchisi edik -> SDP taklifini KUTAMIZ
async function onDhHelloReply(msg) {
  if (!currentRoom || msg.room_id !== currentRoom.roomId) return;
  const peerUsername = msg.from;
  clog(peerUsername, "dh_hello_reply OLDIM");
  const peerState = currentRoom.peers.get(peerUsername);
  if (!peerState || msg.call_id !== peerState.callId) {
    clog(peerUsername, "peerState topilmadi yoki call_id mos emas — RAD ETILDI");
    return;
  }

  const peerEphPub = fromB64(msg.ephemeral_pub);
  const signature = fromB64(msg.signature);
  const peerIdentityPub = await getPeerIdentityKey(peerUsername);
  const valid = verifyBytes(signature, buildDhSignPayload(peerEphPub, msg.call_id), peerIdentityPub);
  clog(peerUsername, "imzo tekshiruvi:", valid ? "TO'G'RI" : "NOTO'G'RI");
  if (!valid) {
    setStatus(`XAVFSIZLIK OGOHLANTIRISHI: ${peerUsername} imzosi mos kelmadi.`);
    removePeer(peerUsername);
    return;
  }

  const shared = computeSharedSecret(peerState.ephKeyPair.privateKey, peerEphPub);
  peerState.sessionKey = await deriveSessionKey(shared, peerState.callId);
  clog(peerUsername, "session key hosil qilindi, SDP offer kutyapman");

  setupPeerConnection(peerUsername, peerState);
  await drainPendingSignals(peerUsername, peerState);
  // Offer yaratmaymiz — javob beruvchi tomon yaratadi, biz "signal" orqali kutamiz.
}

// ==================== WebRTC ====================
function setupPeerConnection(peerUsername, peerState) {
  const pc = new RTCPeerConnection({ iceServers: ICE_SERVERS });
  peerState.pc = pc;

  // MUHIM: addTrack/addTransceiver'ga stream ATAYLAB uzatiladi — aks holda
  // narigi tarafda "ontrack" kelganda ev.streams BO'SH bo'lib qolishi mumkin
  // va video elementga hech narsa ulanmaydi (aloqa o'zi to'g'ri ishlasa ham).
  peerState.audioSender = pc.addTrack(currentRoom.audioTrack, currentRoom.outboundStream).sender;
  // Video uchun m-line OLDINDAN band qilinadi (track'siz) — shu orqali kamera
  // keyinroq yoqilganda/o'chirilganda/almashtirilganda QAYTA KELISHUV (renegotiation)
  // kerak bo'lmaydi, faqat replaceTrack yetarli.
  const videoTransceiver = pc.addTransceiver("video", {
    direction: "sendrecv",
    streams: [currentRoom.outboundStream],
  });
  peerState.videoSender = videoTransceiver.sender;
  if (currentRoom.videoEnabled && currentRoom.videoTrack) {
    peerState.videoSender.replaceTrack(currentRoom.videoTrack);
  }

  pc.ontrack = (ev) => {
    const videoEl = document.getElementById(`video-${peerUsername}`);
    if (!videoEl) return;
    if (ev.streams && ev.streams[0]) {
      videoEl.srcObject = ev.streams[0];
    } else {
      // Zaxira yo'l — stream berilmagan holatlar uchun ham ishlashi kerak.
      if (!videoEl.srcObject) videoEl.srcObject = new MediaStream();
      videoEl.srcObject.addTrack(ev.track);
    }
  };

  pc.onicecandidate = (ev) => {
    if (ev.candidate) {
      sendEncryptedSignal(peerUsername, peerState, { kind: "candidate", candidate: ev.candidate.toJSON() });
    }
  };

  // Diagnostika: muammo qolsa, F12 -> Console'da aynan qaysi bosqichda
  // (ICE topilmadi / ulandi / uzildi) to'xtaganini ko'rish uchun.
  pc.oniceconnectionstatechange = () => {
    console.log(`[${peerUsername}] ICE holati:`, pc.iceConnectionState);
  };

  pc.onconnectionstatechange = () => {
    console.log(`[${peerUsername}] ulanish holati:`, pc.connectionState);
    if (["failed", "disconnected", "closed"].includes(pc.connectionState)) {
      setStatus(`${peerUsername} bilan ulanish uzildi.`);
    }
  };
}

async function sendEncryptedSignal(peerUsername, peerState, payload) {
  const { iv, ciphertext } = await encryptJSON(peerState.sessionKey, payload);
  send({ type: "signal", to: peerUsername, room_id: currentRoom.roomId, call_id: peerState.callId, iv, ciphertext });
}

async function onSignal(msg) {
  if (!currentRoom || msg.room_id !== currentRoom.roomId) return;
  const peerUsername = msg.from;
  const peerState = currentRoom.peers.get(peerUsername);
  if (!peerState) return; // butunlay notanish peer — e'tiborsiz

  if (!peerState.sessionKey || msg.call_id !== peerState.callId) {
    // MUHIM: bu yerda xabarni TASHLAB YUBORMAYMIZ. sessionKey hali tayyor
    // bo'lmasligi mumkin (masalan identity kalitni tarmoqdan yuklab olish
    // davom etayotgan bo'lishi mumkin) — lekin narigi taraf SDP offer'ni
    // ALLAQACHON yuborgan bo'lishi mumkin. Xabarni navbatga qo'yamiz,
    // sessionKey tayyor bo'lishi bilan ketma-ket qayta ishlanadi.
    clog(peerUsername, "signal keldi, sessionKey hali tayyor emas -> navbatga qo'ydim:", msg.call_id === peerState.callId ? "" : "(call_id ham hali noaniq)");
    peerState.pendingSignals = peerState.pendingSignals || [];
    peerState.pendingSignals.push(msg);
    return;
  }

  await processSignal(peerUsername, peerState, msg);
}

async function processSignal(peerUsername, peerState, msg) {
  const payload = await decryptJSON(peerState.sessionKey, msg.iv, msg.ciphertext);
  clog(peerUsername, "signal qayta ishlanmoqda:", payload.kind);
  const pc = peerState.pc;

  if (payload.kind === "offer") {
    await pc.setRemoteDescription({ type: "offer", sdp: payload.sdp });
    peerState.remoteDescSet = true;
    await flushPendingCandidates(peerState);
    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);
    clog(peerUsername, "SDP answer yaratdim va yubordim");
    await sendEncryptedSignal(peerUsername, peerState, { kind: "answer", sdp: answer.sdp });
  } else if (payload.kind === "answer") {
    await pc.setRemoteDescription({ type: "answer", sdp: payload.sdp });
    peerState.remoteDescSet = true;
    await flushPendingCandidates(peerState);
  } else if (payload.kind === "candidate") {
    if (peerState.remoteDescSet) {
      await pc.addIceCandidate(payload.candidate);
    } else {
      peerState.pendingCandidates.push(payload.candidate);
    }
  }
}

// sessionKey (va pc) tayyor bo'lgach, shu tayyor bo'lgunga qadar navbatga
// yig'ilib qolgan signal xabarlarini KELGAN TARTIBIDA qayta ishlaydi.
async function drainPendingSignals(peerUsername, peerState) {
  const queued = peerState.pendingSignals || [];
  peerState.pendingSignals = [];
  for (const msg of queued) {
    clog(peerUsername, "navbatdagi signal qayta ishlanmoqda:", msg.call_id === peerState.callId ? "" : "(call_id eskirgan, o'tkazib yuboriladi)");
    if (msg.call_id !== peerState.callId) continue;
    await processSignal(peerUsername, peerState, msg);
  }
}

async function flushPendingCandidates(peerState) {
  while (peerState.pendingCandidates.length) {
    const c = peerState.pendingCandidates.shift();
    await peerState.pc.addIceCandidate(c);
  }
}

function removePeer(peerUsername) {
  if (!currentRoom) return;
  const peerState = currentRoom.peers.get(peerUsername);
  if (peerState && peerState.pc) peerState.pc.close();
  currentRoom.peers.delete(peerUsername);
  removeTile(peerUsername);
}

// ==================== Video panjarasi (UI) ====================
function showCallUi() {
  inCallEl.classList.remove("hidden");
  videoGrid.innerHTML = "";
}

function makeTile(id, label, muted) {
  const tile = document.createElement("div");
  tile.className = "video-tile";
  tile.id = `tile-${id}`;
  const video = document.createElement("video");
  video.id = `video-${id}`;
  video.autoplay = true;
  video.playsInline = true;
  if (muted) video.muted = true;
  const tag = document.createElement("span");
  tag.className = "tile-label";
  tag.textContent = label;
  tile.appendChild(video);
  tile.appendChild(tag);
  videoGrid.appendChild(tile);
  return video;
}

function addLocalTile() {
  const video = makeTile("local", "Siz", true);
  video.classList.toggle("mirrored", currentRoom.facingMode === "user");
}

function addRemoteTile(username) {
  makeTile(username, username, false);
}

function removeTile(id) {
  const tile = document.getElementById(`tile-${id}`);
  if (tile) tile.remove();
}

function updateLocalPreview() {
  const video = document.getElementById("video-local");
  if (!video) return;
  const tracks = [currentRoom.audioTrack];
  if (currentRoom.videoTrack) tracks.push(currentRoom.videoTrack);
  video.srcObject = new MediaStream(tracks);
  // Old kamera — "oyna" effekti (o'zingizni ko'zguda ko'rgandek), orqa kamera — oddiy.
  video.classList.toggle("mirrored", currentRoom.videoEnabled && currentRoom.facingMode === "user");
}

// ==================== Mikrofon / Kamera / Old-orqa / To'liq ekran ====================
function updateControlButtons() {
  micBtn.textContent = currentRoom.micEnabled ? "🎤 Mikrofon" : "🔇 Mikrofon (o'chiq)";
  micBtn.classList.toggle("btn-off", !currentRoom.micEnabled);
  camBtn.textContent = currentRoom.videoEnabled ? "📷 Kamera" : "📷 Kamera (o'chiq)";
  camBtn.classList.toggle("btn-off", !currentRoom.videoEnabled);
  switchCamBtn.disabled = !currentRoom.videoEnabled;
}

micBtn.onclick = () => {
  if (!currentRoom) return;
  currentRoom.micEnabled = !currentRoom.micEnabled;
  currentRoom.audioTrack.enabled = currentRoom.micEnabled;
  updateControlButtons();
};

camBtn.onclick = async () => {
  if (!currentRoom) return;
  if (currentRoom.videoEnabled) {
    // O'CHIRISH — apparat darajasida (kamera chiroq o'chishi uchun track TO'XTATILADI).
    if (currentRoom.videoTrack) currentRoom.videoTrack.stop();
    currentRoom.videoTrack = null;
    currentRoom.videoEnabled = false;
    for (const peerState of currentRoom.peers.values()) {
      if (peerState.videoSender) peerState.videoSender.replaceTrack(null);
    }
  } else {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: currentRoom.facingMode },
      });
      currentRoom.videoTrack = stream.getVideoTracks()[0];
      currentRoom.videoEnabled = true;
      for (const peerState of currentRoom.peers.values()) {
        if (peerState.videoSender) peerState.videoSender.replaceTrack(currentRoom.videoTrack);
      }
    } catch (err) {
      setStatus("Kameraga ruxsat berilmadi.");
      return;
    }
  }
  updateLocalPreview();
  updateControlButtons();
};

switchCamBtn.onclick = async () => {
  if (!currentRoom || !currentRoom.videoEnabled) return;
  currentRoom.facingMode = currentRoom.facingMode === "user" ? "environment" : "user";
  try {
    const stream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: currentRoom.facingMode },
    });
    const newTrack = stream.getVideoTracks()[0];
    if (currentRoom.videoTrack) currentRoom.videoTrack.stop();
    currentRoom.videoTrack = newTrack;
    for (const peerState of currentRoom.peers.values()) {
      if (peerState.videoSender) peerState.videoSender.replaceTrack(newTrack);
    }
    updateLocalPreview();
  } catch (err) {
    setStatus("Kamera almashtirilmadi.");
  }
};

fullscreenBtn.onclick = () => {
  if (!document.fullscreenElement) {
    videoGrid.requestFullscreen().catch(() => {});
  } else {
    document.exitFullscreen().catch(() => {});
  }
};

// ==================== Xonadan chiqish ====================
document.getElementById("hangup-btn").onclick = () => {
  endRoom();
};

function endRoom() {
  Tone.stop();
  if (currentRoom) {
    send({ type: "room_leave", room_id: currentRoom.roomId });
    for (const peerState of currentRoom.peers.values()) {
      if (peerState.pc) peerState.pc.close();
    }
    if (currentRoom.audioTrack) currentRoom.audioTrack.stop();
    if (currentRoom.videoTrack) currentRoom.videoTrack.stop();
  }
  currentRoom = null;
  selectedForCall.clear();
  videoGrid.innerHTML = "";
  inCallEl.classList.add("hidden");
  setStatus("Tayyor.");
  renderContacts();
}

document.getElementById("logout-btn").onclick = () => {
  clearSession();
  window.location.href = `${BASE_PATH}/static/login.html`;
};

// ==================== Ishga tushirish ====================
// Brauzerning autoplay siyosati AudioContext'ni faqat foydalanuvchi
// "gesture"idan keyin ishga tushirishga ruxsat beradi. Kiruvchi qo'ng'iroq
// signali esa HECH QANDAY gesture'siz (WS xabaridan) chalinishi kerak —
// shuning uchun sahifadagi BIRINCHI bosishda AudioContext oldindan
// "isitib" qo'yamiz, shunda keyinroq kiruvchi qo'ng'iroq signali muammosiz chaladi.
document.addEventListener(
  "click",
  () => {
    try {
      Tone._ensure();
    } catch (err) {
      /* e'tiborsiz — keyingi bosishda urinib ko'radi */
    }
  },
  { once: true }
);

connectWs();
loadInitialPresence().catch((err) => console.error(err));
