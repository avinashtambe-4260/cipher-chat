/**
 * Cipher — peer-to-peer encrypted secret chat
 * Host peer id: cipher-v1- + SHA-256(room code)
 * Crypto: PBKDF2 + AES-GCM from room code
 */

(function () {
  "use strict";

  const PEER_PREFIX = "cipher-v1-";
  const PBKDF2_SALT = "cipher-secret-chat-v1";
  const PBKDF2_ITERATIONS = 120000;
  const MAX_PEERS = 2;

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
  let role = null; // "host" | "guest"
  let destroyed = false;

  function normalizeCode(raw) {
    return String(raw || "")
      .trim()
      .toLowerCase()
      .replace(/\s+/g, "-");
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

  function appendMessage(text, kind) {
    const el = document.createElement("div");
    el.className = "msg msg-" + kind;
    if (kind === "mine" || kind === "theirs") {
      const meta = document.createElement("span");
      meta.className = "msg-meta";
      meta.textContent = kind === "mine" ? "You" : "Peer";
      el.appendChild(meta);
      const body = document.createElement("span");
      body.textContent = text;
      el.appendChild(body);
    } else {
      el.textContent = text;
    }
    messagesEl.appendChild(el);
    messagesEl.scrollTop = messagesEl.scrollHeight;
  }

  function clearMessages() {
    messagesEl.replaceChildren();
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
      setComposerEnabled(true);
      appendMessage("Secure link established.", "system");
    });
    c.on("data", async (data) => {
      try {
        let payload = data;
        if (typeof data === "string") payload = JSON.parse(data);
        const text = await decryptPayload(payload);
        appendMessage(text, "theirs");
      } catch (err) {
        console.error(err);
        appendMessage("Could not decrypt a message.", "system");
      }
    });
    c.on("close", () => {
      setComposerEnabled(false);
      setStatus("Peer disconnected", "is-error");
      appendMessage("Peer left the room.", "system");
      conn = null;
    });
    c.on("error", (err) => {
      console.error(err);
      setStatus("Connection error", "is-error");
    });
  }

  function destroySession() {
    destroyed = true;
    setComposerEnabled(false);
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
    role = null;
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
    return new Peer(id, {
      debug: 0,
      reliable: true,
    });
  }

  function becomeHost(hostId) {
    role = "host";
    peer = createPeer(hostId);

    peer.on("open", () => {
      if (destroyed) return;
      setStatus("Waiting for peer…", "is-waiting");
      appendMessage("You are hosting. Share the code and wait for one guest.", "system");
    });

    peer.on("connection", (c) => {
      if (destroyed) {
        c.close();
        return;
      }
      if (conn && conn.open) {
        c.on("open", () => {
          try {
            c.send(JSON.stringify({ v: 0, type: "busy" }));
          } catch (_) {
            /* ignore */
          }
          c.close();
        });
        return;
      }
      c.on("open", () => {
        /* reliable open handled in wireConnection */
      });
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
      destroySession();
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

  function becomeGuest(hostId) {
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
      setStatus("Connecting to host…", "is-waiting");
      appendMessage("Joining as guest…", "system");
      const c = peer.connect(hostId, {
        reliable: true,
        serialization: "json",
      });
      wireConnection(c);
    });

    peer.on("error", (err) => {
      if (destroyed) return;
      console.error(err);
      setStatus("Could not reach host", "is-error");
      appendMessage("Host may be offline. Try again in a moment.", "system");
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
    cryptoKey = await deriveAesKey(code);
    const hostId = await deriveHostPeerId(code);

    gateEl.hidden = true;
    chatEl.hidden = false;
    chatTitle.textContent = code;
    clearMessages();
    setComposerEnabled(false);
    setStatus("Connecting…", "is-waiting");
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
      destroySession();
    } finally {
      joinBtn.disabled = false;
    }
  });

  leaveBtn.addEventListener("click", () => {
    destroySession();
  });

  sendForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const text = messageInput.value.trim();
    if (!text || !conn || !conn.open || !cryptoKey) return;
    try {
      const payload = await encryptText(text);
      conn.send(payload);
      appendMessage(text, "mine");
      messageInput.value = "";
      messageInput.focus();
    } catch (err) {
      console.error(err);
      appendMessage("Failed to send encrypted message.", "system");
    }
  });

  window.addEventListener("beforeunload", () => {
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
