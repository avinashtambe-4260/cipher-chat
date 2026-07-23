# Cipher

Secret peer-to-peer chat for two people. Share a code, join the same room, and message with end-to-end AES-GCM encryption. No accounts. No server-stored messages.

**Live demo (GitHub Pages):** after deploy, open `https://<your-username>.github.io/cipher-chat/`

## How it works

1. Both people enter the same shared chat code.
2. Cipher derives a deterministic PeerJS host id from `SHA-256` of the code (`cipher-v1-` prefix).
3. The first client to claim that id becomes **host**; the second becomes **guest** and connects to the host.
4. A shared AES-GCM key is derived from the room code via PBKDF2 (salt `cipher-secret-chat-v1`, 120000 iterations).
5. Only ciphertext crosses the PeerJS data channel.

Codes are normalized: trim, lowercase, spaces → hyphens, minimum 3 characters.

## Local use

Open `index.html` via a static server (required for some browsers / crypto in strict contexts), or push to GitHub Pages.

```bash
# optional quick server
npx --yes serve .
```

## Stack

- Plain HTML / CSS / JS
- [PeerJS](https://peerjs.com/) 1.5.4 (CDN)
- Web Crypto API

## GitHub Pages

Enable Pages for this repo: **Settings → Pages → Deploy from branch → `main` / `/ (root)`**.

Relative asset paths (`styles.css`, `app.js`) work for project sites at `/cipher-chat/`.

## Privacy notes

- Room codes and keys never leave your browser except as PeerJS signaling metadata (peer ids).
- Choose a long, uncommon code. Anyone with the code can derive the same key and join if a seat is free.
- Only two participants; a third connection is rejected by the host.

## License

MIT
