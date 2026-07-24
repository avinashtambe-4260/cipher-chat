/**
 * Mailbox Worker — encrypted messages until another DEVICE acks them.
 * Same-device readers (e.g. normal + incognito) can view but cannot clear / confirm delivery.
 */

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

const ROOM_HASH_RE = /^[0-9a-f]{64}$/i;
const DEVICE_RE = /^[0-9a-f]{16,64}$/i;
const MAX_BODY = 8 * 1024;
const MSG_TTL = 86400;
const MAX_MESSAGES = 100;

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      ...CORS,
    },
  });
}

function corsPreflight() {
  return new Response(null, { status: 204, headers: CORS });
}

function notFound() {
  return json({ error: "not found" }, 404);
}

function badRequest(msg) {
  return json({ error: msg }, 400);
}

function inboxKey(roomHash) {
  return `room:${roomHash}:inbox`;
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return corsPreflight();
    }

    const url = new URL(request.url);
    let path = url.pathname;
    if (path.endsWith("/") && path.length > 1) path = path.slice(0, -1);

    if (path === "/api/health" && request.method === "GET") {
      return json({ ok: true, storage: "inbox-v3-device" });
    }

    const roomMatch = path.match(/^\/api\/room\/([^/]+)\/(messages|ack)$/);
    if (!roomMatch) {
      return notFound();
    }

    const roomHash = roomMatch[1];
    const action = roomMatch[2];

    if (!ROOM_HASH_RE.test(roomHash)) {
      return badRequest("invalid roomHash");
    }

    if (action === "messages" && request.method === "POST") {
      return postMessage(request, env, roomHash);
    }
    if (action === "messages" && request.method === "GET") {
      return listMessages(env, roomHash);
    }
    if (action === "ack" && request.method === "POST") {
      return ackMessages(request, env, roomHash);
    }

    return notFound();
  },
};

async function readInbox(env, roomHash) {
  const raw = await env.MAILBOX.get(inboxKey(roomHash));
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

async function writeInbox(env, roomHash, messages) {
  const key = inboxKey(roomHash);
  if (!messages.length) {
    await env.MAILBOX.delete(key);
    return;
  }
  await env.MAILBOX.put(key, JSON.stringify(messages), {
    expirationTtl: MSG_TTL,
  });
}

async function postMessage(request, env, roomHash) {
  const contentLength = request.headers.get("content-length");
  if (contentLength && Number(contentLength) > MAX_BODY) {
    return badRequest("body too large");
  }

  let raw;
  try {
    raw = await request.text();
  } catch {
    return badRequest("invalid body");
  }
  if (raw.length > MAX_BODY) {
    return badRequest("body too large");
  }

  let body;
  try {
    body = JSON.parse(raw);
  } catch {
    return badRequest("invalid JSON");
  }

  const { id, iv, ct, from, fromDevice, ts } = body ?? {};
  if (typeof id !== "string" || id.length === 0) {
    return badRequest("id required");
  }
  if (typeof iv !== "string" || typeof ct !== "string" || typeof from !== "string") {
    return badRequest("iv, ct, from must be strings");
  }
  if (typeof fromDevice !== "string" || !DEVICE_RE.test(fromDevice)) {
    return badRequest("fromDevice required");
  }

  const entry = {
    id,
    iv,
    ct,
    from,
    fromDevice,
    ts: ts == null ? Date.now() : ts,
  };

  for (let attempt = 0; attempt < 8; attempt++) {
    const current = await readInbox(env, roomHash);
    const byId = new Map();
    for (const m of current) {
      if (m && m.id) byId.set(m.id, m);
    }
    if (byId.has(id)) {
      return json({ ok: true, duplicate: true });
    }
    byId.set(id, entry);
    const next = Array.from(byId.values())
      .sort((a, b) => (Number(a.ts) || 0) - (Number(b.ts) || 0))
      .slice(-MAX_MESSAGES);
    await writeInbox(env, roomHash, next);
    const verify = await readInbox(env, roomHash);
    if (verify.some((m) => m && m.id === id)) {
      return json({ ok: true });
    }
  }

  return json({ error: "could not persist message" }, 503);
}

async function listMessages(env, roomHash) {
  const messages = await readInbox(env, roomHash);
  messages.sort((a, b) => {
    const ta = Number(a && a.ts) || 0;
    const tb = Number(b && b.ts) || 0;
    return ta - tb;
  });
  return json({ messages });
}

async function ackMessages(request, env, roomHash) {
  let body;
  try {
    body = await request.json();
  } catch {
    return badRequest("invalid JSON");
  }

  const ids = body && body.ids;
  const readerDevice = body && body.readerDevice;
  if (!Array.isArray(ids)) {
    return badRequest("ids must be an array");
  }
  if (typeof readerDevice !== "string" || !DEVICE_RE.test(readerDevice)) {
    return badRequest("readerDevice required");
  }

  const idSet = new Set(
    ids.filter((id) => typeof id === "string" && id.length > 0)
  );
  if (!idSet.size) {
    return json({ ok: true, deleted: 0, ignored: 0 });
  }

  for (let attempt = 0; attempt < 8; attempt++) {
    const current = await readInbox(env, roomHash);
    let deleted = 0;
    let ignored = 0;
    const next = [];

    for (const m of current) {
      if (!m || !idSet.has(m.id)) {
        next.push(m);
        continue;
      }
      // Only a different device can confirm delivery / remove the message
      if (m.fromDevice && m.fromDevice === readerDevice) {
        ignored += 1;
        next.push(m);
        continue;
      }
      deleted += 1;
    }

    await writeInbox(env, roomHash, next);
    const verify = await readInbox(env, roomHash);
    const stillRemovable = verify.some(
      (m) =>
        m &&
        idSet.has(m.id) &&
        !(m.fromDevice && m.fromDevice === readerDevice)
    );
    if (!stillRemovable) {
      return json({ ok: true, deleted, ignored });
    }
  }

  return json({ ok: true, deleted: 0, ignored: 0, warning: "ack may still be propagating" });
}
