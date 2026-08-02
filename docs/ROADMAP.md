# Implementation roadmap

## Milestone 1 — server and prelogin foundation

- [x] Manifest V3 build and popup.
- [x] Optional per-origin server permission.
- [x] Environment normalization and server config verification.
- [x] Modern and legacy password-prelogin negotiation.
- [x] Defensive KDF validation.
- [x] Tests and bundle budgets.

## Milestone 2 — authenticated, read-only vault

- [x] PBKDF2 master-key derivation through Web Crypto.
- [x] Transient Argon2id offscreen/WASM context with explicit teardown.
- [x] Password grant and common code-based two-factor challenges.
- [x] Session-only unlock-key storage and lock cleanup.
- [x] Encrypted `/api/sync` persistence.
- [x] Compatible login-cipher decryption using known-answer fixtures.
- [x] Read-only vault list, search, and current-site matching.
- [x] `ViewPassword` enforcement and per-item master-password reprompt.
- [ ] WebAuthn and Duo two-step login flows.
- [ ] Encryption v2/COSE account support.

## Milestone 3 — core password manager

- [x] Personal login cipher create/update with per-item encryption keys and URI checksums.
- [ ] Folder support and cipher delete/restore.
- [x] Click-only manual autofill for top-frame username/password fields.
- [ ] Shortcut and context-menu autofill.
- [x] Standard TOTP generation without exposing seeds to the popup.
- [ ] Cards, identities, secure notes, and custom fields.
- [x] Opt-in save-login and changed-password prompts with memory-only pending capture.
- [x] Password generator.
- [x] Configurable browser-session, inactivity, and encrypted until-logout vault timeouts.
- [ ] Configurable vault timeout, clipboard timeout, and account switching.

## Milestone 4 — advanced browser integration

- [x] Lightweight matched-login picker and bounded top-frame form observation.
- [ ] SPA, iframe, shadow DOM, and HTTP downgrade handling.
- [ ] Passkey create/get bridge with RP ID and origin validation.
- [ ] Basic-auth handling and adaptive notification sync.
- [ ] Attachments, Send, import/export, organizations, and collections.

## Milestone 5 — hardening and distribution

- [ ] Differential compatibility suite against supported Vaultwarden releases.
- [ ] Automated Chrome process/heap regression tests.
- [ ] Localization and accessibility review.
- [ ] Dependency, license, SBOM, reproducibility, and trademark audit.
- [ ] Independent cryptography and browser-extension security audit.
- [ ] Chrome Web Store privacy disclosures and release automation.
