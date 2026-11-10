# SecureShare Pro | Encrypted Clip Sharing

Share passwords, API keys and notes as encrypted links that **expire** and **burn after reading**. The text is encrypted in your browser with AES-256-GCM; the server stores ciphertext it cannot read and enforces the lifecycle rules in Postgres.

- **Zero-knowledge by construction.** For links without a password, a fresh 256-bit key is generated per clip and carried in the URL fragment (`#k=…`). Browsers never send fragments to a server, so the key never reaches the database, the logs, or the CDN.
- **Real expiry and one-time reads.** Not client-side guesses: `read_clip()` runs in the database, increments the view counter atomically, and deletes the row when the last allowed open is used.
- **Short links.** The payload lives in the database, so a link is an id plus a key, not a 2,000-character blob. QR codes work for any size of note.
- **A 5-digit PIN on every clip.** Whoever you are sending to can go to the site, type the PIN, and skip the link entirely. Add a password when you want the PIN to be a doorbell rather than a key.
- **Hardened client.** Sanitised Markdown, SRI-pinned CDN scripts, and a strict Content-Security-Policy.

## How it works

**Creating a clip**

1. The text is packed into `{v, t}` and encrypted with AES-256-GCM using a random 12-byte IV.
   - *No password:* a random 32-byte key is generated; it goes into the link fragment and nowhere else.
   - *Password:* the key is derived with PBKDF2-SHA256 (600,000 iterations, random 16-byte salt), and the salt is stored alongside the ciphertext.
2. The browser calls `create_clip(ciphertext, iv, salt, mode, expires_at, max_views, pin, pin_wrapped, pin_salt)`.
3. The response gives the clip id, and the share link becomes `?c=<id>#k=<key>` (or `?c=<id>` in password mode).

**Reading a clip**

1. The page shows an explicit **Open clip** button. Nothing is fetched until you click, so link-preview bots and accidental refreshes cannot burn a one-time clip.
2. `read_clip(id)` checks expiry and the view limit, increments the counter, returns the ciphertext, and deletes the row if this was the last allowed open.
3. The ciphertext is held in memory for that tab, so a mistyped password can be retried without spending another view.
4. AES-GCM verifies the authentication tag while decrypting: a truncated or tampered payload fails loudly.
5. Markdown is rendered through a whitelist sanitiser, then the key is stripped from the address bar.

**Opening a clip by PIN**

Every clip gets a 5-digit PIN, and it plays one of two roles depending on whether you set a password.

*No password — the PIN is the key.* The browser wraps the content key under a key derived from the PIN (PBKDF2-SHA256, 600,000 iterations, random salt) and sends only that wrapped blob, so the server never holds a usable key. Redeeming the PIN returns the ciphertext and the wrapped key; the browser unwraps and decrypts.

*With a password — the PIN is a doorbell.* No wrapped key is stored at all, and the database refuses to accept one. Redeeming the PIN returns the ciphertext and the salt, then the page asks for the password, which is the only thing that can derive the key. A guessed PIN therefore yields ciphertext nobody can read.

In both cases the redemption consumes a view exactly like `read_clip`, so a one-time clip dies on the first PIN read too.

## Database

One table and three public functions. `clips` has row level security **forced on**, with RESTRICTIVE deny-all policies for `anon` and `authenticated`. Restrictive policies are ANDed with everything else, so a permissive policy added later by mistake still cannot open the table, and neither role holds any table privilege to begin with. Every read and write goes through the `SECURITY DEFINER` functions, which run as `postgres` and carry `BYPASSRLS`.

| Function | Purpose |
| --- | --- |
| `create_clip(...)` | Validates the payload, enforces a per-IP rate limit of 30 clips/hour, prunes expired rows, inserts the ciphertext |
| `read_clip(id)` | Atomically consumes a view, enforces expiry, deletes the row on the last open |
| `redeem_pin(pin)` | Verifies a PIN, rate-limits the attempt, consumes a view, returns the ciphertext and (in key mode) the wrapped key |

There is deliberately no owner-side API: once a clip is created, nobody — not even the sender — can read it back or delete it early. It disappears on its own when it expires or when its opens run out.

Guardrails the database enforces on its own:

- **5,000 live clips maximum.** Beyond that `create_clip` refuses with `at_capacity`, so the table cannot be flooded with junk and the 5-digit PIN space stays far from collision pressure.
- **Trivial PINs are refused server-side** (`weak_pin`): five identical digits, any straight run up or down, and a short list of favourites. The client already uses a CSPRNG; this covers a modified client.
- **Expired clips are purged every 15 minutes** by a `pg_cron` job, not only when someone happens to create a clip.
- **The PIN pepper lives in Vault**, encrypted at rest with a key that is not in a database dump, so a stolen row cannot be reversed by trying all 100,000 PINs.
- **A PIN is never reissued.** When a clip dies — burned, expired, or deleted — its PIN is retired for 30 days, so a code you were given can never later open somebody else's clip.
- **Both API roles are resource-limited.** `anon` and `authenticated` carry a 3-second statement timeout and a 10-second idle-in-transaction timeout, so neither a hostile query nor a client squatting on a transaction can tie up the database.

### Security self-check

`supabase/selfcheck.sql` asserts the invariants this design leans on, in one query, twelve of them: that `anon` and `authenticated` can each execute exactly `create_clip`, `read_clip` and `redeem_pin` and reach no table at all; that RLS is forced on `clips` with two restrictive deny-all policies; that the PIN-wrap constraint is present; that the PIN pepper lives only in Vault; that the purge job is active; that the private schema is out of reach; and that deleted PINs are retired and the retirement log is not exposed. Run it after any schema change — every row must read `passed = true`.

It is deliberately a query rather than a stored function: a check whose job is to prove the attack surface has not grown should not itself add to it. It has been tested the honest way — granting `anon` SELECT on `clips` makes the check fail with the offending table named, and revoking it makes it pass again.

## Security model

**Protected against**

- Anyone who sees the ciphertext without the link — server logs, backups, a proxy, a `Referer` header, the database itself. In key mode the key is never in any of them.
- Replaying an expired or exhausted link: the server refuses it.
- A clip injecting HTML, `onerror` handlers or `javascript:` URLs into the reader's page — that output is stripped.
- A compromised CDN silently swapping a library: both CDN scripts are pinned with Subresource Integrity, and the CSP blocks every other origin. `connect-src` allows only this project's API.
- Direct database access with the publishable key: RLS is forced on, restrictive deny-all policies apply to `anon` and `authenticated`, and neither role holds a table privilege. Confirmed by attempting a `SELECT` as `anon`, which returns permission denied.
- Abuse of the API key: it grants nothing beyond calling the three functions, which are rate-limited and validate every input.

### The 5-digit PIN, honestly

A PIN has 100,000 possible values. On its own that is still not much, so what protects it depends entirely on which mode you chose:

- **With a password**, the PIN is not a credential at all. It finds the row; the password does the work. Guessing PINs gets an attacker nothing but a password prompt.
- **Without a password**, the PIN is the credential, and the rules below are what stands between a guess and your text.

The rules that apply either way:

- The PIN is generated with `crypto.getRandomValues` and rejection sampling, so all 100,000 values are equally likely.
- No two live clips may share a PIN, so a hit is never ambiguous — and a PIN whose clip has died is retired for 30 days rather than reissued to someone else.
- 10 attempts per client per hour, plus a project-wide ceiling of 300 per hour. Walking 100,000 values at that ceiling takes about two weeks of continuous guessing, by which time any sane expiry has passed.
- A malformed PIN costs the same as a wrong one, and every failure looks identical, so nothing can be enumerated from error messages.
- The PIN is stored as a keyed HMAC, not a bare hash: without the server's pepper, a stolen row cannot be reversed by trying 100,000 values.
- The content key is wrapped under the PIN in key mode, so the database never holds a usable key there.

What this does **not** do: a passwordless clip is not protected against someone who has a copy of the database, because 100,000 guesses against a wrapped key is minutes of work on a laptop. If the content matters, set a password — that is exactly what the password is for, and the PIN keeps working as the easy way in.

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

- `clips` has RLS forced on with restrictive deny-all policies, so the key cannot read or write the table.
- The only reachable operations are three functions, all of which validate their input.
- Creation is rate-limited per IP; reads require a UUID or a PIN the attacker does not have.
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
- Raise the live-clip ceiling as demand grows; 5,000 is a guardrail, not a design limit.

## License

GNU General Public License v3.0 — see [LICENSE](LICENSE).
