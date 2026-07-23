# Cipher

Secret two-person chat. Share a code, join the same room, and message with end-to-end AES-GCM encryption. No accounts.

**Live:** https://avinashtambe-4260.github.io/cipher-chat/

## How it works

1. Both people enter the same shared chat code.
2. You can **send immediately** — the other person does not need to be online yet.
3. Undelivered messages wait in an encrypted outbox (kept in this browser until delivered or you leave).
4. When your peer joins, saved messages are delivered and marked **delivered** once they ACK (read) them.
5. Leaving the room clears the conversation (secret / ephemeral — nothing stays on a server).

Under the hood: PeerJS connects the two browsers; a shared AES-GCM key is derived from the room code (PBKDF2).

## Local use

```bash
npx --yes serve .
```

## Stack

- Plain HTML / CSS / JS
- [PeerJS](https://peerjs.com/) 1.5.4 (CDN)
- Web Crypto API

## Privacy notes

- Choose a long, uncommon code.
- Only two participants; a third connection is rejected.
- Messages that were never delivered are wiped when you leave the room.
- **Note:** If you close the tab before your peer ever joins, undelivered messages only exist on your device’s outbox for that code (same browser). For true “drop a message and go offline forever” delivery, a small cloud mailbox would be needed — say if you want that next.

## License

MIT
