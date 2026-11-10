# SecureShare Pro | Encrypted Clip Sharing

Share passwords, API keys and notes as encrypted links that **expire**, **burn after reading**, and can be **revoked**. The text is encrypted in your browser with AES-256-GCM; the server stores ciphertext it cannot read and enforces the lifecycle rules in Postgres.

- **Zero-knowledge by construction.** For links without a password, a fresh 256-bit key is generated per clip and carried in the URL fragment (`#k=…`). Browsers never send fragments to a server, so the key never reaches the database, the logs, or the CDN.
- **Real expiry and one-time reads.** Not client-side guesses: `read_clip()` runs in the database, increments the view counter atomically, and deletes the row when the last allowed open is used.
- **Revocation.** Every clip comes with a private manage link that can inspect how many times it was opened and delete it immediately.
- **Short links.** The payload lives in the database, so a link is an id plus a key, not a 2,000-character blob. QR codes work for any size of note.
- **Hardened client.** Sanitised Markdown, SRI-pinned CDN scripts, and a strict Content-Security-Policy.

## How it works

**Creating a clip**

1. The text is packed into `{v, t}` and encrypted with AES-256-GCM using a random 12-byte IV.
   - *No password:* a random 32-byte key is generated; it goes into the link fragment and nowhere else.
   - *Password:* the key is derived with PBKDF2-SHA256 (600,000 iterations, random 16-byte salt), and the salt is stored alongside the ciphertext.
2. The browser calls `create_clip(ciphertext, iv, salt, mode, expires_at, max_views, manage_token)`. Only the SHA-256 of the manage token is stored.
3. The response gives the clip id. The share link is `?c=<id>#k=<key>` (or `?c=<id>` in password mode); the manage link is `?m=<id>.<token>`.

**Reading a clip**

1. The page shows an explicit **Open clip** button. Nothing is fetched until you click, so link-preview bots and accidental refreshes cannot burn a one-time clip.
2. `read_clip(id)` checks expiry and the view limit, increments the counter, returns the ciphertext, and deletes the row if this was the last allowed open.
3. The ciphertext is held in memory for that tab, so a mistyped password can be retried without spending another view.
4. AES-GCM verifies the authentication tag while decrypting: a truncated or tampered payload fails loudly.
5. Markdown is rendered through a whitelist sanitiser, then the key is stripped from the address bar.

## Database

One table and four functions. `clips` has RLS enabled with **no policies**, so the publishable key cannot read or write it directly; all access is through `SECURITY DEFINER` functions.

| Function | Purpose |
| --- | --- |
| `create_clip(...)` | Validates the payload, enforces a per-IP rate limit of 30 clips/hour, prunes expired rows, inserts the ciphertext |
| `read_clip(id)` | Atomically consumes a view, enforces expiry, deletes the row on the last open |
| `clip_status(id, token)` | Owner-only: view count, timestamps, expiry state |
| `delete_clip(id, token)` | Owner-only: immediate revocation |

`manage_token` is stored only as a SHA-256 hash, so a database leak does not hand over the ability to delete clips.

## Security model

**Protected against**

- Anyone who sees the ciphertext without the link — server logs, backups, a proxy, a `Referer` header, the database itself. In key mode the key is never in any of them.
- Replaying an expired or exhausted link: the server refuses it.
- A clip injecting HTML, `onerror` handlers or `javascript:` URLs into the reader's page — that output is stripped.
- A compromised CDN silently swapping a library: both CDN scripts are pinned with Subresource Integrity, and the CSP blocks every other origin. `connect-src` allows only this project's API.
- A leaked publishable key: it grants nothing beyond calling the four functions, which are rate-limited and token-gated.

**Not protected against**

- **Whoever holds the complete link.** In key mode the key is in the link; in password mode it is whatever you tell the recipient.
- **The recipient.** They can screenshot, copy or re-share once they have read it. Burn-after-reading limits distribution, it does not prevent it.
- **Metadata.** The server sees a clip exists, its size, its timestamps and a hash of the creator's IP. It does not see the content.
- **Traffic analysis** by your network or the API host.
- **A malicious server operator.** The JS that encrypts is served by the same origin, so a compromised deployment could serve modified code. Verifying the source is the only defence.

## Deploying

Static hosting plus this Supabase project.

```
index.html   markup and CSP
styles.css   styles
app.js       crypto, API calls, UI
```

1. Host the three files anywhere static (GitHub Pages, Netlify, Vercel, Cloudflare Pages). Serve `index.html` at the root.
2. In `app.js`, set `API_URL` and `API_KEY` for your project.
3. Add your site's origin to the project's allowed CORS origins if you tighten the defaults.

`API_KEY` is the **publishable** key (`sb_publishable_…`). It is designed to be public and is protected by RLS plus the function-level checks above. The `service_role` key and the database password must never be committed to this repository — nothing here needs them.

## Local development

Open `index.html` over a local web server (`python3 -m http.server`) rather than `file://`, so the CSP and the API origin behave as they do in production.

## Roadmap

- Self-host the two remaining CDN libraries, removing the last third-party fetch.
- Optional passphrase-protected manage links.
- Per-clip access log (IP hashes only) for the owner.

## License

GNU General Public License v3.0 — see [LICENSE](LICENSE).
