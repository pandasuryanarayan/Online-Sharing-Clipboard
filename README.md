# SecureShare Pro | Encrypted Clip Sharing

Share passwords, API keys and notes as encrypted links that **expire** and **burn after reading**. The text is encrypted in your browser with AES-256-GCM; the server stores ciphertext it cannot read and enforces the lifecycle rules in Postgres.

- **Zero-knowledge by construction.** For links without a password, a fresh 256-bit key is generated per clip and carried in the URL fragment (`#k=…`). Browsers never send fragments to a server, so the key never reaches the database, the logs, or the CDN.
- **Real expiry and one-time reads.** Not client-side guesses: `read_clip()` runs in the database, increments the view counter atomically, and deletes the row when the last allowed open is used.
- **Short links.** The payload lives in the database, so a link is an id plus a key, not a 2,000-character blob. QR codes work for any size of note.
- **Hardened client.** Sanitised Markdown, SRI-pinned CDN scripts, and a strict Content-Security-Policy.

## How it works

**Creating a clip**

1. The text is packed into `{v, t}` and encrypted with AES-256-GCM using a random 12-byte IV.
   - *No password:* a random 32-byte key is generated; it goes into the link fragment and nowhere else.
   - *Password:* the key is derived with PBKDF2-SHA256 (600,000 iterations, random 16-byte salt), and the salt is stored alongside the ciphertext.
2. The browser calls `create_clip(ciphertext, iv, salt, mode, expires_at, max_views)`.
3. The response gives the clip id, and the share link becomes `?c=<id>#k=<key>` (or `?c=<id>` in password mode).

**Reading a clip**

1. The page shows an explicit **Open clip** button. Nothing is fetched until you click, so link-preview bots and accidental refreshes cannot burn a one-time clip.
2. `read_clip(id)` checks expiry and the view limit, increments the counter, returns the ciphertext, and deletes the row if this was the last allowed open.
3. The ciphertext is held in memory for that tab, so a mistyped password can be retried without spending another view.
4. AES-GCM verifies the authentication tag while decrypting: a truncated or tampered payload fails loudly.
5. Markdown is rendered through a whitelist sanitiser, then the key is stripped from the address bar.

## Database

One table and two public functions. `clips` has RLS enabled with **no policies**, so the publishable key cannot read or write it directly; all access is through `SECURITY DEFINER` functions.

| Function | Purpose |
| --- | --- |
| `create_clip(...)` | Validates the payload, enforces a per-IP rate limit of 30 clips/hour, prunes expired rows, inserts the ciphertext |
| `read_clip(id)` | Atomically consumes a view, enforces expiry, deletes the row on the last open |

There is deliberately no owner-side API: once a clip is created, nobody — not even the sender — can read it back or delete it early. It disappears on its own when it expires or when its opens run out.

## Security model

**Protected against**

- Anyone who sees the ciphertext without the link — server logs, backups, a proxy, a `Referer` header, the database itself. In key mode the key is never in any of them.
- Replaying an expired or exhausted link: the server refuses it.
- A clip injecting HTML, `onerror` handlers or `javascript:` URLs into the reader's page — that output is stripped.
- A compromised CDN silently swapping a library: both CDN scripts are pinned with Subresource Integrity, and the CSP blocks every other origin. `connect-src` allows only this project's API.
- Abuse of the API key: it grants nothing beyond calling the two functions, which are rate-limited and validate every input.

**Not protected against**

- **Whoever holds the complete link.** In key mode the key is in the link; in password mode it is whatever you tell the recipient.
- **The recipient.** They can screenshot, copy or re-share once they have read it. Burn-after-reading limits distribution, it does not prevent it.
- **Metadata.** The server sees a clip exists, its size, its timestamps and a hash of the creator's IP. It does not see the content.
- **Traffic analysis** by your network or the API host.
- **A malicious server operator.** The JS that encrypts is served by the same origin, so a compromised deployment could serve modified code. Verifying the source is the only defence.

## About the API key in the source

`app.js` contains a Supabase **publishable** key (`sb_publishable_…`). This is intentional, and it is not a leak: the key identifies the project, not a user, and it is designed to be shipped to browsers.

You cannot hide a key in a purely static site. Any value the browser needs in order to make a request is visible in DevTools, the network tab, or the file itself — obfuscating it, base64-ing it, or fetching it from a config endpoint only moves the string, it does not hide it. The choice is between a public key that is safe to publish and a secret that is proxied through a server.

This project takes the first route, and the key is made worthless by design:

- `clips` has RLS on with no policies, so the key cannot read or write the table.
- The only reachable operations are two functions, both of which validate their input.
- Creation is rate-limited per IP; reads require a UUID the attacker does not have.
- Nothing in the client can enumerate, list, update or delete clips.

If you want no key in the client at all, the only real option is a server in front of the database — a Cloudflare Worker, a Supabase Edge Function, or any small proxy that holds a secret and forwards calls. The browser then talks to your proxy, and your proxy talks to Supabase. That is a genuine architectural change with its own costs: a component to deploy and monitor, another place for bugs, and the proxy becomes the thing worth attacking. It does not make the site more private, only more centralised.

## Deploying

Static hosting plus this Supabase project.

```
index.html   markup and CSP
styles.css   styles
app.js       crypto, API calls, UI
```

1. Host the three files anywhere static (GitHub Pages, Netlify, Vercel, Cloudflare Pages). Serve `index.html` at the root.
2. In `app.js`, set `API_URL` and `API_KEY` for your project.
3. If you tighten CORS in the project settings, allow your site's origin.

The `service_role` key and the database password must never be committed to this repository — nothing here needs them.

## Local development

Open `index.html` over a local web server (`python3 -m http.server`) rather than `file://`, so the CSP and the API origin behave as they do in production.

## Roadmap

- Self-host the two remaining CDN libraries, removing the last third-party fetch.
- Optional password-protected link creation with a generated passphrase.

## License

GNU General Public License v3.0 — see [LICENSE](LICENSE).
