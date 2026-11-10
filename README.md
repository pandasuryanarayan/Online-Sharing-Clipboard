# SecureShare Pro | Encrypted Clipboard

SecureShare Pro is a simple, client-side encrypted text sharing tool designed for privacy and security. It allows users to securely share sensitive information like passwords, notes, or code snippets with others using self-destructing links, password protection, and auto-expiring content. All encryption happens locally in the browser, meaning the server (or hosting provider) never sees your plain-text data.

## Features

- **Client-Side Encryption:** Uses AES-256 encryption via CryptoJS to encrypt data in the browser.
- **Markdown Support:** Renders rich text using Marked.js.
- **Password Protection:** Option to lock encrypted clips with a custom password.
- **Expiration:** Set an expiration time for the clip (e.g., 5 minutes, 1 hour, 1 week) so that it cannot be read after the set time.
- **Burn After Reading:** Self-destructing clips that delete their content from the URL upon viewing, preventing them from being accessed again via browser history or back buttons.
- **QR Code Generation:** Easily share links via automatically generated QR codes.
- **Local History:** Keeps track of recently generated clips locally on your device for easy access.
- **Dark Mode Support:** Built-in theme toggler for light and dark modes.

## How it works

1. **Create a Clip:** Enter your text (Markdown supported), choose an expiration time, add a password (optional), and decide if it should be "Burn after reading".
2. **Generate Secure Link:** The application encrypts your text locally using AES-256. If a password is provided, it's used as the encryption key; otherwise, a default public key is used. The resulting encrypted payload (including expiry and burn settings) is encoded into a URL-safe Base64 string and appended to the URL as a query parameter (`?d=...`).
3. **Share:** You can copy the generated link, scan the QR code, or shorten the link using the built-in TinyURL shortcut to share with the recipient.
4. **Read/Unlock:** When the recipient opens the link, the application parses the encrypted payload. If a password was set, they must enter it to unlock the clip. The application decrypts the content, checks expiration and burn status, and displays the Markdown-rendered text.

## Usage

You can simply open `online-clipboard.html` in any modern web browser. No server setup is required since all logic and encryption run client-side.

You can also host it easily on static hosting platforms like GitHub Pages, Vercel, or Netlify.

## Tech Stack

- HTML5 / CSS3
- Vanilla JavaScript
- [CryptoJS](https://cryptojs.gitbook.io/docs/) (AES Encryption)
- [Marked.js](https://marked.js.org/) (Markdown Parsing)
- [QRCode.js](https://davidshimps.github.io/qrcodejs/) (QR Code Generation)

## Security Note

While SecureShare Pro provides strong client-side encryption, please be aware that "Burn after reading" is enforced locally by clearing the URL. For absolute security against sophisticated adversaries, true server-side deletion of shared secrets is required. However, for most casual sharing of passwords or notes, this client-side approach provides a highly secure and convenient mechanism without requiring a backend database.

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.
