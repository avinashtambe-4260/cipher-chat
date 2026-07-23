/**
 * Cipher — encrypted secret chat with offline queue
 * - Send anytime after entering a room (peer need not be online yet)
 * - Undelivered messages wait in an outbox and flush when the peer connects
 * - After the peer ACKs (has read them), pending flags clear; leaving wipes the room
 * Host peer id: cipher-v1- + SHA-256(room code)
 * Crypto: PBKDF2 + AES-GCM from room code
 */

(function () {
  "use strict";

  const PEER_PREFIX = "cipher-v1-";
  const PBKDF2_SALT = "cipher-secret-chat-v1";
  const PBKDF2_ITERATIONS = 120000;
  const OUTBOX_PREFIX = "cipher-outbox-v1:";

  const gateEl = document.getElementById("gate");
  const chatEl = document.getElementById("chat");
  const joinForm = document.getElementById("join-form");
  const roomCodeInput = document.getElementById("room-code");
  const gateError = document.getElementById("gate-error");
  const joinBtn = document.getElementById("join-btn");
  const leaveBtn = document.getElementById("leave-btn");
  const statusEl = document.getElementById("status");
  const chatTitle = document.getElementById("chat-title");
  const messagesEl = document.getElementById("messages");
  const sendForm = document.getElementById("send-form");
  const messageInput = document.getElementById("message-input");
  const sendBtn = document.getElementById("send-btn");

  let peer = null;
  let conn = null;
  let cryptoKey = null;
  let roomCode = "";
  let roomKey = "";
  let role = null;
  let destroyed = false;
  let guestRetryTimer = null;
  /** @type {{ id: string, text: string, payload: object, delivered: boolean }[]} */
  let outbox = [];
  /** message ids already shown from peer (dedupe) */
  const seenIncoming = new Set();

  function normalizeCode(raw) {
    return String(raw || "")
      .trim()
      .toLowerCase()
      .replace(/\s+/g, "-");
  }

  function uuid() {
    if (crypto.randomUUID) return crypto.randomUUID();
    return "m-" + Date.now().toString(36) + "-" + Math.random().toString(36).slice(2, 10);
  }

  function showGateError(msg) {
    gateError.hidden = !msg;
    gateError.textContent = msg || "";
  }

  function setStatus(text, kind) {
    statusEl.textContent = text;
    statusEl.classList.remove("is-ready", "is-waiting", "is-error");
    if (kind) statusEl.classList.add(kind);
  }

  function setComposerEnabled(on) {
    messageInput.disabled = !on;
    sendBtn.disabled = !on;
    if (on) messageInput.focus();
  }

  function isPeerLive() {
    return !!(conn && conn.open);
  }

  function refreshStatus() {
    if (isPeerLive()) {
      setStatus("Connected", "is-ready");
      return;
    }
    const pending = outbox.filter((m) => !m.delivered).length;
    if (pending > 0) {
      setStatus(
        pending === 1
          ? "Waiting — 1 message saved for them"
          : `Waiting — ${pending} messages saved for them`,
        "is-waiting"
      );
    } else {
      setStatus("Waiting for peer — you can send now", "is-waiting");
    }
  }

  function bufToHex(buf) {
    return Array.from(new Uint8Array(buf))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  function b64Encode(bytes) {
    let s = "";
    const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    for (let i = 0; i < arr.length; i++) s += String.fromCharCode(arr[i]);
    return btoa(s);
  }

  function b64Decode(str) {
    const bin = atob(str);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  async function sha256Hex(text) {
    const data = new TextEncoder().encode(text);
    const hash = await crypto.subtle.digest("SHA-256", data);
    return bufToHex(hash);
  }

  async function deriveHostPeerId(code) {
    const hex = await sha256Hex(code);
    return PEER_PREFIX + hex;
  }

  async function deriveAesKey(code) {
    const enc = new TextEncoder();
    const baseKey = await crypto.subtle.importKey(
      "raw",
      enc.encode(code),
      "PBKDF2",
      false,
      ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: enc.encode(PBKDF2_SALT),
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-256",
      },
      baseKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  async function encryptText(plaintext) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const cipher = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      cryptoKey,
      new TextEncoder().encode(plaintext)
    );
    return {
      v: 1,
      type: "msg",
      id: uuid(),
      iv: b64Encode(iv),
      ct: b64Encode(cipher),
    };
  }

  async function decryptPayload(payload) {
    if (!payload || payload.v !== 1 || !payload.iv || !payload.ct) {
      throw new Error("Invalid payload");
    }
    const plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: b64Decode(payload.iv) },
      cryptoKey,
      b64Decode(payload.ct)
    );
    return new TextDecoder().decode(plain);
  }

  function outboxStorageKey() {
    return OUTBOX_PREFIX + roomKey;
  }

  function persistOutbox() {
    if (!roomKey) return;
    try {
      const slim = outbox
        .filter((m) => !m.delivered)
        .map((m) => ({
          id: m.id,
          text: m.text,
          payload: m.payload,
          delivered: false,
        }));
      if (slim.length === 0) {
        localStorage.removeItem(outboxStorageKey());
      } else {
        localStorage.setItem(outboxStorageKey(), JSON.stringify(slim));
      }
    } catch (err) {
      console.warn("Could not persist outbox", err);
    }
  }

  function loadOutbox() {
    outbox = [];
    if (!roomKey) return;
    try {
      const raw = localStorage.getItem(outboxStorageKey());
      if (!raw) return;
      const parsed = JSON.parse(raw);
      if (!Array.isArray(parsed)) return;
      outbox = parsed.filter((m) => m && m.id && m.payload && m.text);
    } catch (_) {
      outbox = [];
    }
  }

  function clearPersistedOutbox() {
    if (!roomKey) return;
    try {
      localStorage.removeItem(outboxStorageKey());
    } catch (_) {
      /* ignore */
    }
  }

  function appendMessage(text, kind, opts) {
    const options = opts || {};
    const el = document.createElement("div");
    el.className = "msg msg-" + kind;
    if (options.id) el.dataset.msgId = options.id;
    if (options.pending) el.classList.add("is-pending");

    if (kind === "mine" || kind === "theirs") {
      const meta = document.createElement("span");
      meta.className = "msg-meta";
      if (kind === "mine") {
        meta.textContent = options.pending ? "You · waiting for them" : "You · delivered";
      } else {
        meta.textContent = "Peer";
      }
      el.appendChild(meta);
      const body = document.createElement("span");
      body.className = "msg-body";
      body.textContent = text;
      el.appendChild(body);
    } else {
      el.textContent = text;
    }

    messagesEl.appendChild(el);
    messagesEl.scrollTop = messagesEl.scrollHeight;
    return el;
  }

  function markMineDelivered(ids) {
    const idSet = new Set(ids || []);
    let changed = false;
    outbox.forEach((m) => {
      if (idSet.has(m.id) && !m.delivered) {
        m.delivered = true;
        changed = true;
      }
    });
    idSet.forEach((id) => {
      const el = messagesEl.querySelector('.msg-mine[data-msg-id="' + CSS.escape(id) + '"]');
      if (el) {
        el.classList.remove("is-pending");
        const meta = el.querySelector(".msg-meta");
        if (meta) meta.textContent = "You · delivered";
      }
    });
    if (changed) {
      outbox = outbox.filter((m) => !m.delivered);
      persistOutbox();
      refreshStatus();
    }
  }

  function clearMessages() {
    messagesEl.replaceChildren();
  }

  function sendPacket(obj) {
    if (!isPeerLive()) return false;
    try {
      conn.send(obj);
      return true;
    } catch (err) {
      console.error(err);
      return false;
    }
  }

  function flushOutbox() {
    if (!isPeerLive()) return;
    const pending = outbox.filter((m) => !m.delivered);
    pending.forEach((m) => {
      sendPacket(m.payload);
    });
    if (pending.length) {
      appendMessage(
        pending.length === 1
          ? "Sent 1 saved message to peer."
          : "Sent " + pending.length + " saved messages to peer.",
        "system"
      );
    }
  }

  function sendAcks(ids) {
    if (!ids.length) return;
    sendPacket({ v: 1, type: "ack", ids: ids });
  }

  async function handleIncoming(data) {
    let packet = data;
    if (typeof data === "string") {
      try {
        packet = JSON.parse(data);
      } catch (_) {
        return;
      }
    }
    if (!packet || packet.v !== 1) return;

    if (packet.type === "ack" && Array.isArray(packet.ids)) {
      markMineDelivered(packet.ids);
      return;
    }

    if (packet.type === "sync") {
      flushOutbox();
      return;
    }

    if (packet.type === "msg" || (packet.iv && packet.ct)) {
      const id = packet.id || uuid();
      if (seenIncoming.has(id)) {
        sendAcks([id]);
        return;
      }
      try {
        const text = await decryptPayload(packet);
        seenIncoming.add(id);
        appendMessage(text, "theirs", { id: id });
        sendAcks([id]);
        // Ephemeral: after we've read (shown) their message, tell them via ack;
        // we keep it on screen until leave — sender dissolves on ack.
      } catch (err) {
        console.error(err);
        appendMessage("Could not decrypt a message.", "system");
      }
    }
  }

  function wireConnection(c) {
    if (conn && conn !== c) {
      try {
        conn.close();
      } catch (_) {
        /* ignore */
      }
    }
    conn = c;

    c.on("open", () => {
      setStatus("Connected", "is-ready");
      appendMessage("Peer joined — delivering any saved messages…", "system");
      flushOutbox();
      sendPacket({ v: 1, type: "sync" });
      refreshStatus();
    });

    c.on("data", (data) => {
      handleIncoming(data);
    });

    c.on("close", () => {
      conn = null;
      refreshStatus();
      appendMessage("Peer left. New messages will wait until they return.", "system");
    });

    c.on("error", (err) => {
      console.error(err);
      setStatus("Connection error", "is-error");
    });
  }

  function stopGuestRetry() {
    if (guestRetryTimer) {
      window.clearInterval(guestRetryTimer);
      guestRetryTimer = null;
    }
  }

  function destroySession(opts) {
    const options = opts || {};
    destroyed = true;
    stopGuestRetry();
    setComposerEnabled(false);

    if (options.clearOutbox) {
      outbox = [];
      clearPersistedOutbox();
    } else {
      persistOutbox();
    }

    try {
      if (conn) conn.close();
    } catch (_) {
      /* ignore */
    }
    conn = null;
    try {
      if (peer) peer.destroy();
    } catch (_) {
      /* ignore */
    }
    peer = null;
    cryptoKey = null;
    roomCode = "";
    roomKey = "";
    role = null;
    seenIncoming.clear();
    clearMessages();
    chatEl.hidden = true;
    gateEl.hidden = false;
    showGateError("");
    setStatus("Connecting…", "is-waiting");
    joinBtn.disabled = false;
    roomCodeInput.focus();
    destroyed = false;
  }

  function createPeer(id) {
    if (id) return new Peer(id, { debug: 0 });
    return new Peer({ debug: 0 });
  }

  function becomeHost(hostId) {
    role = "host";
    peer = createPeer(hostId);

    peer.on("open", () => {
      if (destroyed) return;
      refreshStatus();
      appendMessage(
        "Room open. Send messages anytime — they’ll be waiting when your peer joins.",
        "system"
      );
      if (outbox.length) {
        outbox.forEach((m) => {
          appendMessage(m.text, "mine", { id: m.id, pending: !m.delivered });
        });
        refreshStatus();
      }
      setComposerEnabled(true);
    });

    peer.on("connection", (c) => {
      if (destroyed) {
        c.close();
        return;
      }
      if (conn && conn.open) {
        c.on("open", () => {
          try {
            c.send({ v: 1, type: "busy" });
          } catch (_) {
            /* ignore */
          }
          c.close();
        });
        return;
      }
      wireConnection(c);
    });

    peer.on("error", (err) => {
      if (destroyed) return;
      const type = err && err.type;
      if (type === "unavailable-id") {
        becomeGuest(hostId);
        return;
      }
      console.error(err);
      setStatus("Peer error", "is-error");
      showGateError(err.message || "Could not start peer connection.");
      destroySession({ clearOutbox: false });
      chatEl.hidden = true;
      gateEl.hidden = false;
    });

    peer.on("disconnected", () => {
      if (destroyed) return;
      setStatus("Reconnecting…", "is-waiting");
      try {
        peer.reconnect();
      } catch (_) {
        /* ignore */
      }
    });
  }

  function tryGuestConnect(hostId) {
    if (destroyed || isPeerLive() || !peer || peer.destroyed) return;
    try {
      const c = peer.connect(hostId, {
        reliable: true,
        serialization: "json",
      });
      wireConnection(c);
    } catch (err) {
      console.warn(err);
    }
  }

  function becomeGuest(hostId) {
    stopGuestRetry();
    if (peer) {
      try {
        peer.destroy();
      } catch (_) {
        /* ignore */
      }
      peer = null;
    }
    role = "guest";
    peer = createPeer();

    peer.on("open", () => {
      if (destroyed) return;
      setStatus("Connecting to peer…", "is-waiting");
      appendMessage(
        "Joining… You can write now; messages wait if the link isn’t ready yet.",
        "system"
      );
      if (outbox.length) {
        outbox.forEach((m) => {
          appendMessage(m.text, "mine", { id: m.id, pending: !m.delivered });
        });
      }
      setComposerEnabled(true);
      tryGuestConnect(hostId);
      stopGuestRetry();
      guestRetryTimer = window.setInterval(() => {
        if (destroyed || isPeerLive()) {
          stopGuestRetry();
          return;
        }
        tryGuestConnect(hostId);
        refreshStatus();
      }, 4000);
    });

    peer.on("error", (err) => {
      if (destroyed) return;
      console.error(err);
      setStatus("Could not reach peer yet", "is-waiting");
      setComposerEnabled(true);
      refreshStatus();
    });

    peer.on("disconnected", () => {
      if (destroyed) return;
      setStatus("Reconnecting…", "is-waiting");
      try {
        peer.reconnect();
      } catch (_) {
        /* ignore */
      }
    });
  }

  async function enterRoom(code) {
    destroyed = false;
    roomCode = code;
    roomKey = await sha256Hex("cipher-room:" + code);
    cryptoKey = await deriveAesKey(code);
    const hostId = await deriveHostPeerId(code);

    loadOutbox();
    seenIncoming.clear();

    gateEl.hidden = true;
    chatEl.hidden = false;
    chatTitle.textContent = code;
    clearMessages();
    setComposerEnabled(false);
    refreshStatus();
    showGateError("");

    becomeHost(hostId);
  }

  joinForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    showGateError("");
    const code = normalizeCode(roomCodeInput.value);
    if (code.length < 3) {
      showGateError("Use at least 3 characters after normalizing.");
      roomCodeInput.focus();
      return;
    }
    roomCodeInput.value = code;
    joinBtn.disabled = true;
    try {
      await enterRoom(code);
    } catch (err) {
      console.error(err);
      showGateError(err.message || "Failed to enter room.");
      destroySession({ clearOutbox: false });
    } finally {
      joinBtn.disabled = false;
    }
  });

  leaveBtn.addEventListener("click", () => {
    // Leaving clears the conversation; undelivered outbox is also cleared (secret chat)
    destroySession({ clearOutbox: true });
  });

  sendForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const text = messageInput.value.trim();
    if (!text || !cryptoKey) return;

    try {
      const payload = await encryptText(text);
      const entry = {
        id: payload.id,
        text: text,
        payload: payload,
        delivered: false,
      };
      outbox.push(entry);
      persistOutbox();
      appendMessage(text, "mine", { id: entry.id, pending: true });
      messageInput.value = "";
      messageInput.focus();

      if (isPeerLive()) {
        sendPacket(payload);
      }
      refreshStatus();
    } catch (err) {
      console.error(err);
      appendMessage("Failed to send encrypted message.", "system");
    }
  });

  window.addEventListener("beforeunload", () => {
    persistOutbox();
    try {
      if (conn) conn.close();
    } catch (_) {
      /* ignore */
    }
    try {
      if (peer) peer.destroy();
    } catch (_) {
      /* ignore */
    }
  });

  roomCodeInput.focus();
})();
