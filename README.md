# SecureShare Pro | Encrypted Clipboard

SecureShare Pro is a single-file, zero-backend tool for sharing text that is encrypted in your browser. You type a note, it gets sealed with AES-256-GCM, and everything needed to read it travels inside the link itself — so there is no server, no database, and nothing for a hosting provider to hand over.

## Features

- **Client-side encryption** — AES-256-GCM through the browser's native Web Crypto API. No third-party crypto library is loaded.
- **Key in the URL fragment** — for links without a password, a fresh random 256-bit key is generated per clip and carried after the `#`. Browsers never send fragments to a server, so the ciphertext can sit in server logs and access logs without the key next to it.
- **Password mode** — optional password, stretched with PBKDF2-SHA256 (600,000 iterations) and a random 16-byte salt, then used as the AES-256-GCM key.
- **Markdown rendering** — Marked.js parses the note, and the result is rebuilt against a tag/attribute whitelist before it touches the page, so a clip cannot inject script into your origin.
- **Expiration** — a "read after" timestamp embedded in the encrypted payload (see the caveat below).
- **Burn after reading** — clears the link from the address bar once the clip is opened (again, see the caveat).
- **QR codes, local recents, dark mode, copy buttons** — quality-of-life extras that stay on your device.

## How it works

**Creating a clip**

1. Your text, the chosen expiry time and the burn flag are packed into a JSON payload and serialised.
2. A random 12-byte IV is generated and the payload is encrypted with AES-256-GCM.
   - *No password:* a random 32-byte key is generated for this one clip.
   - *Password:* the key is derived from your password with PBKDF2-SHA256 at 600,000 iterations.
3. The IV, the salt (password mode) and the ciphertext are wrapped in a small JSON envelope, base64url-encoded, and placed in the `?d=` query parameter. In no-password mode the raw key goes into the `#k=` fragment.

**Reading a clip**

1. The `?d=` parameter is decoded and the envelope is read.
2. In password mode you are asked for the password and the key is re-derived locally. In key mode the key is read from the fragment.
3. AES-GCM verifies the authentication tag as it decrypts, so a truncated or tampered link fails loudly instead of showing garbage.
4. The expiry timestamp is checked, the Markdown is sanitised, and the clip is displayed.

## Security model: what this does and does not protect

It is worth being precise, because "encrypted" and "self-destructing" are easy to over-promise.

**What it protects against**

- Someone who sees the link's query string without the fragment — a server access log, a proxy, a `Referer` header, a URL shortener's database — cannot read the note. In key mode the key is never in that part.
- Anyone who only has the ciphertext, without the link, has nothing usable.
- A clip that injects HTML, `onerror` handlers or `javascript:` URLs into the reader's page. That output is sanitised.

**What it does not protect against**

- **Anyone who holds the complete link can read the clip.** In key mode the key is in the link; in password mode the password is whatever you tell the recipient. Send links over a channel you trust.
- **Expiry is advisory.** The timestamp is checked by the recipient's browser, against the recipient's clock. Changing the system clock, or decoding the payload offline, defeats it.
- **Burn after reading is advisory.** It clears the address bar on the reading device. It cannot delete a link that is already in a chat thread, an email, a screenshot, or the recipient's clipboard.
- **No revocation.** Nothing is stored centrally, so a link you have sent cannot be withdrawn.
- **No read receipts.** You cannot tell whether a clip was opened.
- **Recents are stored locally in plain form.** The browser keeps the last ten links in `localStorage`, key included, so they can be reopened. Clear them on a shared machine.

If you need any of those, you need a server that stores the ciphertext and can delete it. That is the natural next step for this project — see the roadmap below.

## Limitations

- **Link length.** The whole payload lives in the URL. Long notes make long links, which some chat apps wrap or truncate. The app warns you as the link grows, and refuses to draw a QR code once the URL passes roughly 2,500 characters. The practical ceiling for a QR code is around 2,900 bytes.
- **Truncated links fail.** If the `#k=` fragment is cut off, the clip cannot be opened; the app says so rather than failing silently.
- **Links from before this version cannot be opened.** Clips made with the original CryptoJS-based build use a different payload format. The app recognises them and says so plainly.
- **Markdown support is Marked's**, minus anything the sanitiser strips: images, embedded frames, forms and inline event handlers do not survive.
- **HTTPS recommended.** Web Crypto and the Clipboard API both require a secure context. Opened over plain `http://`, copying falls back to the legacy path.

## Usage

Open `index.html` in any modern browser. There is no build step, no server and no install.

To publish it, drop the file on any static host:

- **GitHub Pages** — enable Pages for this repository and serve from the branch root; the site appears at `https://<user>.github.io/<repo>/`.
- **Netlify / Vercel / Cloudflare Pages** — point them at the repository, no build command, publish directory `/`.

Keep the file named `index.html` so the host serves it at the site root.

## Tech stack

- HTML5, CSS3 and vanilla JavaScript in one file.
- [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) — AES-256-GCM and PBKDF2-SHA256.
- [Marked](https://marked.js.org/) 4.3.0 — Markdown parsing.
- [QRCode.js](https://davidshimjs.github.io/qrcodejs/) 1.0.0 — QR generation.

Both CDN scripts are pinned with Subresource Integrity hashes and loaded with `crossorigin`, and the page ships a Content-Security-Policy that blocks every origin except `cdnjs.cloudflare.com` and forbids outbound connections entirely (`connect-src 'none'`). A compromised CDN therefore cannot silently swap the library, and no script on the page can phone home.

## Roadmap

- Server-side storage of the ciphertext (Cloudflare Workers + KV, Supabase, or similar) with the key still in the fragment, which would make one-time links, revocation, view limits and read receipts real rather than advisory.
- A self-hosted copy of the two remaining CDN libraries, removing the last third-party fetch.
- Payload version negotiation so future format changes can read older links.

## License

This project is licensed under the GNU General Public License v3.0 — see the [LICENSE](LICENSE) file for details.
