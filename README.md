# SecureShare Pro

Encrypted, self-destructing clip sharing. Text is encrypted in the browser with AES-256-GCM; the server stores ciphertext it cannot read and enforces expiry, view limits and rate limits in PostgreSQL.

Live instance: <https://pandasuryanarayan.github.io/Online-Sharing-Clipboard/>

## Overview

A sender pastes a note, a password or a key, chooses an expiry and a number of opens, and optionally sets a password. The result is a short link and a 5-digit PIN, either of which the recipient can use. When the opens run out or the expiry passes, the clip is gone.

The lifecycle is enforced by the database, not by the browser. There is no account system and no owner-side API: a clip cannot be read back or deleted early by anyone, including its sender.

## Features

- **Client-side encryption.** AES-256-GCM through the Web Crypto API; no third-party crypto library.
- **Key never sent.** For passwordless clips the decryption key travels in the URL fragment, which browsers do not transmit.
- **Server-enforced lifecycle.** Expiry and view counting happen in PostgreSQL, atomically, inside the read call.
- **Short links.** A link is an id plus a key, so it fits in a QR code regardless of note length.
- **PIN access.** Every clip gets a 5-digit PIN, usable without the link.
- **Optional password.** With a password set, the PIN locates the clip and the password is what unlocks it.
- **Hardened client.** Strict Content-Security-Policy, SRI-pinned CDN scripts, whitelist Markdown sanitiser.

## Architecture

Two trust boundaries:

1. **Encryption is client-side.** The server never receives the content key for a passwordless clip, nor the password for a protected one. It receives ciphertext, an IV, and (for password clips) a PBKDF2 salt.
2. **The API surface is three functions.** The `clips` table is closed to the API roles by forced row level security and restrictive deny-all policies. Every read and write goes through a `SECURITY DEFINER` function that runs as the table owner.

## How it works

### Creating a clip

1. The text is packed into `{v, t}` and encrypted with AES-256-GCM under a random 12-byte IV.
   - No password: a random 32-byte key is generated. It is placed in the link fragment and stored nowhere else.
   - Password: the key is derived with PBKDF2-SHA256 (600,000 iterations, random 16-byte salt). The salt is stored alongside the ciphertext.
2. The browser calls `create_clip(...)` with the ciphertext, IV, salt, mode, expiry, view limit and PIN material.
3. The response returns the clip id. The share link is `?c=<id>#k=<key>`, or `?c=<id>` in password mode.

### Reading a clip

1. The page shows an explicit **Open clip** button; nothing is fetched on load. Link-preview bots and accidental refreshes therefore cannot consume a one-time clip.
2. `read_clip(id)` checks expiry and the view limit, increments the counter, returns the ciphertext, and deletes the row if that was the last allowed open.
3. The ciphertext stays in memory for the tab, so a mistyped password can be retried without spending another view.
4. AES-GCM verifies the authentication tag during decryption; a truncated or tampered payload fails.
5. Markdown is rendered through a whitelist sanitiser, and the key is stripped from the address bar.

### Opening by PIN

Every clip carries a 5-digit PIN, and its role depends on whether a password was set.

- **No password — the PIN is the key.** The content key is wrapped under a key derived from the PIN and sent as an opaque blob. Redeeming the PIN returns the ciphertext and the wrapped key; the browser unwraps and decrypts. The server never holds a usable key.
- **With a password — the PIN is a locator.** No wrapped key is stored, and the database rejects one. Redeeming the PIN returns the ciphertext and the salt, then the page requests the password, which is the only input that can derive the key.

In both modes a redemption consumes a view exactly as `read_clip` does, so a one-time clip dies on its first PIN read.

## Database

### Schema

One table, `public.clips`:

| Column | Purpose |
| --- | --- |
| `id` | Clip identifier (UUID), the `c` in the link |
| `ciphertext`, `iv` | Encrypted payload and its nonce |
| `salt` | PBKDF2 salt; password mode only |
| `mode` | `k` (key in fragment) or `p` (password) |
| `expires_at`, `max_views`, `views` | Lifecycle state |
| `created_at`, `creator_ip` | Creation time and hashed client IP, for rate limiting |
| `pin_lookup` | Keyed HMAC of the PIN; never the PIN itself |
| `pin_wrapped`, `pin_salt` | Content key wrapped under the PIN; key mode only |

Supporting tables live in the non-exposed `private` schema: `pin_attempts` (rate limiting), `pin_history` (retired PINs) and `config`.

### Functions

| Function | Purpose |
| --- | --- |
| `create_clip(...)` | Validates input, enforces the per-client rate limit and the live-clip ceiling, prunes expired rows, inserts the ciphertext |
| `read_clip(id)` | Atomically consumes a view, enforces expiry, deletes the row on the last open |
| `redeem_pin(pin)` | Verifies the PIN, rate-limits the attempt, consumes a view, returns the ciphertext and, in key mode, the wrapped key |

`secure_ip_hash`, `private.pin_lookup` and `private.retire_pin` are internal helpers and are not reachable from the API.

### Guardrails

- **5,000 live clips maximum.** Beyond that `create_clip` fails with `at_capacity`.
- **30 clips per client per hour.**
- **Trivial PINs rejected server-side** (`weak_pin`): repeated digits, straight ascending or descending runs, and a small blocklist.
- **10 PIN attempts per client per hour**, plus a project-wide ceiling of 300 per hour.
- **PINs are never reissued.** A deleted clip retires its PIN for 30 days via a `BEFORE DELETE` trigger.
- **Expiry is scheduled.** A `pg_cron` job every 15 minutes deletes expired clips, attempts older than 2 hours, and retired PINs older than 30 days.
- **The PIN pepper is stored in Supabase Vault**, so it is not present in a database dump.
- **API roles are resource-limited.** `anon` and `authenticated` carry a 3-second statement timeout and a 10-second idle-in-transaction timeout.

### Rebuild and verify

`supabase/schema.sql` contains the entire database — table, constraints, indexes, policies, functions, trigger, Vault secret, role settings and cron job. It was reconstructed from the live catalogue and each function body was hash-checked against the running database.

`supabase/selfcheck.sql` asserts the invariants in one query, thirteen in total: the exact function surface for both API roles, no table access, no function executable by `PUBLIC`, forced RLS with two restrictive policies, the PIN-wrap constraint, the pepper in Vault only, the purge job, the retirement trigger, and the private schema being unreachable.

```sh
# rebuild a fresh project
psql \"$DATABASE_URL\" -f supabase/schema.sql

# verify, in the SQL editor or via psql
psql \"$DATABASE_URL\" -f supabase/selfcheck.sql   # every row must read passed = true
```

## Security model

### Protected against

- Disclosure from anything holding only the ciphertext — server logs, backups, a proxy, a `Referer` header, the database.
- Replay of an expired or exhausted link.
- Markup injection through shared content: HTML, event handlers and `javascript:` URLs are stripped.
- A compromised CDN swapping a library: both CDN scripts are pinned with Subresource Integrity and the CSP blocks every other origin.
- Direct table access with the publishable key: RLS is forced, restrictive deny-all policies apply, and neither API role holds a table privilege.
- Abuse of the publishable key: it can reach three rate-limited, input-validating functions and nothing else.

### Not protected against

- **Anyone holding the complete link.** In key mode the key is in the link; in password mode it is whatever you tell the recipient.
- **The recipient.** They can copy or re-share once they have read it. Burn-after-reading limits distribution, it does not prevent it.
- **Metadata.** The server learns that a clip exists, its size, its timestamps and a hash of the creator's IP. It does not learn the content.
- **Traffic analysis** by the network or the API host.
- **A malicious operator.** The JavaScript that encrypts is served by the same origin, so a compromised deployment could serve modified code. Reviewing the source is the only defence.

### PIN strength

A 5-digit PIN has 100,000 combinations, so the PIN is not the security; the surrounding rules are.

- **With a password**, the PIN is not a credential. It locates a row; guessing PINs yields a password prompt.
- **Without a password**, the PIN is the credential. The controls are: uniform random generation, uniqueness among live clips, a keyed HMAC lookup, 10 attempts per client per hour, a 300-per-hour project ceiling, identical responses for every failure, and a content key wrapped under the PIN.

The remaining exposure is offline: anyone holding a database dump can test 100,000 PINs against a wrapped key in minutes. Use a password when the content matters.

### Why the publishable key is public

`app.js` contains a Supabase publishable key (`sb_publishable_...`). It identifies the project, not a user, and is designed to be shipped to browsers.

A key used by a static site cannot be hidden: any value the browser needs is visible in DevTools, the network tab or the file itself. The alternative is to proxy requests through a server that holds a secret, which adds a component to deploy and attack without making the site more private. This project publishes the key and makes it worthless: the table is closed, and the three reachable functions validate their input and are rate-limited.

The `service_role` key and the database password are never used by this project and must not be committed.

## Configuration

Two constants at the top of `app.js`:

| Constant | Meaning |
| --- | --- |
| `API_URL` | Supabase project URL, e.g. `https://<ref>.supabase.co` |
| `API_KEY` | Publishable (anon) key for that project |

The CSP `connect-src` directive in `index.html` must name the same origin as `API_URL`, or the browser will block every request.

## Deployment

Static hosting plus a Supabase project.

1. Build the database: run `supabase/schema.sql` against a fresh project, then `supabase/selfcheck.sql` and confirm every row passes.
2. Set `API_URL`, `API_KEY` and the CSP `connect-src` origin for your project.
3. Host `index.html`, `styles.css` and `app.js` at the root of any static host (GitHub Pages, Netlify, Vercel, Cloudflare Pages).
4. Serve over HTTPS. The Web Crypto API and the clipboard API require a secure context.

Operational notes:

- The free Supabase tier pauses a project after about a week of inactivity; the site returns errors until it is restored.
- CORS is open by default on Supabase. If you restrict it, allow your site origin.
- The publishable key can be rotated in the project settings without redeploying code, provided `API_KEY` is updated.

## Local development

Serve the directory over HTTP rather than opening the file directly, so the CSP and the API origin behave as they do in production:

```sh
python3 -m http.server 8080
# then open http://localhost:8080/
```

## Repository layout

```
index.html               markup, CSP, metadata
styles.css               styles
app.js                   crypto, API calls, UI
supabase/schema.sql      complete database definition
supabase/selfcheck.sql   security invariant check
LICENSE                  GPL-3.0
```

## Roadmap

- Self-host the two remaining CDN libraries, removing the last third-party fetch.
- Raise the live-clip ceiling as demand grows; 5,000 is a guardrail, not a design limit.

## License

GNU General Public License v3.0. See [LICENSE](LICENSE).
