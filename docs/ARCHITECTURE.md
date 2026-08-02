# Architecture

## Runtime boundaries

LeanVault treats every browser execution context as a security and memory boundary:

1. The Manifest V3 service worker registers event listeners synchronously and dispatches to small
   feature modules.
2. The popup owns presentation only. It communicates through validated, typed messages and never
   accesses vault storage directly.
3. Manual popup fill uses a one-shot `chrome.scripting.executeScript` call after a user click.
   Optional inline integration is separately permissioned, disabled by default, and receives only
   summaries until the user selects one matched login.
4. Future page-world scripts will be tiny passkey bridges with strict origin and request validation.
5. Server ciphertext lives in IndexedDB. By default, access tokens and the account key live in
   trusted-context session storage. The opt-in “until logout” mode AES-GCM wraps that session under
   a non-extractable browser-profile key in a separate IndexedDB database. Lock removes the account
   key from both session copies; logout removes all session material.
6. Argon2id applies Bitwarden's SHA-256 email-salt preprocessing and is isolated in an offscreen
   document that exists only for one derivation request. Its
   WASM code is absent from the service-worker startup bundle.

## Current milestone

The current personal-login MVP is:

```text
popup user gesture
  -> request exact server origin permission
  -> typed runtime message
  -> background Vaultwarden client
  -> GET /api/config
  -> POST /identity/accounts/prelogin/password
       fallback: /identity/accounts/prelogin
  -> validate KDF downgrade and resource limits
  -> derive master key (Web Crypto PBKDF2 or transient Argon2id)
  -> POST /identity/connect/token
  -> unwrap user key and GET /api/sync
  -> persist only server ciphertext
  -> decrypt a minimal login model in service-worker memory
  -> enforce ViewPassword and per-item master-password reprompt
  -> search/copy/TOTP or one-shot manual fill
  -> encrypt personal cipher fields under a random item key
  -> POST/PUT /api/ciphers and resync
  -> optional site script: matched picker and explicit save/update prompt
```

Organization-item mutation remains excluded because it requires preserving organization key and
permission semantics beyond the personal-login MVP.

## Storage policy

Persistent local metadata contains the server snapshot, account email, KDF configuration, and the
server-provided encrypted user key. Encrypted sync data is stored in IndexedDB. Master passwords and
decrypted vault items are never persisted. Access tokens and the decrypted account key are normally
session-only; the explicit “until logout” option persists them only as AES-GCM ciphertext under a
non-extractable key scoped to the browser profile.

Storage layers are separated into:

- settings: small, non-secret versioned values in `chrome.storage.local`;
- encrypted vault: server ciphertext and indexes in IndexedDB;
- session secrets: narrowly scoped unlock material cleared on lock and normally at browser-session
  end, with an explicit encrypted-persistence option for a trusted browser profile;
- content state: either a one-shot injected fill function or, after explicit broad-host permission,
  a small isolated login-form observer. Submitted plaintext is held only in service-worker memory,
  expires after two minutes, and is cleared on lock/logout.

## Bundle policy

Budgets are 250 KiB for background JavaScript, 200 KiB for popup JavaScript, 96 KiB for transient
Argon2, and 48 KiB for site integration. These are ceilings, not targets. Every feature must justify
entry-bundle residency or load separately.
