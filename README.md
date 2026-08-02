# LeanVault

LeanVault is a lightweight, open-source Manifest V3 password-manager extension for
[Vaultwarden](https://github.com/dani-garcia/vaultwarden) and compatible Bitwarden API servers.
It is a community-built alternative for people who want a smaller browser client focused on the
core login workflow: search, site matching, fill, copy, create, edit, and save prompts.

LeanVault is not a fork of the official Bitwarden browser extension. It implements compatible
protocol behavior independently and deliberately avoids pulling the official Angular application
and its full feature surface into the browser.

> [!IMPORTANT]
> LeanVault is an unofficial independent project. It is not associated with, sponsored by,
> endorsed by, or supported by Bitwarden, Bitwarden Inc., or the Vaultwarden project. Bitwarden is
> a trademark of Bitwarden Inc. Report LeanVault bugs to this repository, not to official Bitwarden
> or Vaultwarden support channels.

> [!WARNING]
> This is unaudited security software. Test it with a non-critical account before trusting it with
> important credentials, and review the documented security boundaries before regular use.

## Why LeanVault?

Vaultwarden provides a resource-efficient, self-hosted implementation of the Bitwarden-compatible
server API. LeanVault applies the same lightweight idea to the browser client: a small extension,
limited runtime permissions, no analytics, and independently loaded cryptography only when needed.

Version **1.0.0** is LeanVault's first public MVP release and provides:

- Custom Vaultwarden server URLs, including reverse-proxy subpaths.
- PBKDF2 and Bitwarden-compatible Argon2id authentication.
- Common code-based two-step login challenges.
- Encrypted vault sync and authenticated login decryption.
- Fast vault search, field-anchored current-site suggestions, website favicons, copy, open-site,
  and iframe/open-shadow-root manual fill.
- Encrypted personal-login creation and editing with website mapping.
- A local cryptographic password generator whose preferences are shared with website fields.
- Optional website autofill, editable save/update prompts, and excluded-domain controls.
- Master-password reprompt handling and organization `ViewPassword` enforcement.
- Configurable locking: browser close, inactivity timeout, or encrypted device persistence until
  explicit lock/logout.

## Install from source

Requirements: Node.js 22+ and pnpm.

```sh
git clone https://github.com/jsjain/vaultwarden-chrome-extension.git
cd vaultwarden-chrome-extension
git checkout v1.0.0
pnpm install
pnpm verify
```

Then:

1. Open `chrome://extensions`.
2. Enable **Developer mode**.
3. Choose **Load unpacked** and select the generated `dist/` directory.
4. After each update, confirm the version shown in LeanVault **Settings**.

Every test build increments the extension version so a successful Chrome reload is visible.

See the [v1.0.0 release notes](docs/releases/v1.0.0.md) for the feature and security summary.

## Security model

- The master password is used only during login, unlock, or protected-item confirmation and is
  never persisted.
- The default unlock mode keeps keys in trusted Chrome session storage until the browser closes.
- “Keep unlocked until logout” is opt-in. It encrypts the session with AES-GCM under a
  non-extractable key held in this browser profile's IndexedDB. This is convenient but less safe on
  a shared or compromised browser profile.
- Server vault ciphertext is cached in IndexedDB; decrypted vault items remain in service-worker
  memory.
- Website integration is optional and disabled until the user grants website access.
- Favicons come from Chrome's local favicon facility, not from a third-party icon service.
- Remote HTTP servers are rejected except for loopback development.
- There is no analytics, telemetry, or remotely hosted executable code.
- URI matching is directional and fail-closed so credentials saved for a child domain are not
  exposed to its parent domain.

CodeQL, dependency review, Dependabot, and GitHub's public-repository secret scanning provide an
automated security baseline. These checks do not replace an independent security audit.

See [SECURITY.md](SECURITY.md) and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for details.

## Compatibility boundaries

The current MVP supports standard master-password accounts using Bitwarden encryption v1. It does
not yet support encryption v2/COSE accounts, organization-owned item editing, passkeys, attachments,
custom fields, multiple-URI editing, import/export, Duo, or WebAuthn two-step login.

## Contributing

Issues and pull requests are welcome. For security-sensitive reports, do not include real vault
contents, master passwords, tokens, encryption keys, or logs containing secrets. See
[SECURITY.md](SECURITY.md) before reporting a vulnerability.

## License

LeanVault is released under [GPL-3.0-only](LICENSE). The compatible protocol and referenced product
names do not imply affiliation with their respective projects or trademark owners.
