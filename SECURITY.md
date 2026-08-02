# Security policy

LeanVault is pre-alpha software. Version 0.3 can authenticate, decrypt, create, and update personal
login ciphers, but it
has not received an independent security audit and is not recommended for production credentials.

## Current guarantees

- Master passwords exist only for the duration of a login or unlock request and are never written to
  persistent or session storage.
- Account email and non-secret KDF/unlock metadata are persisted locally after successful login.
- Access tokens and the decrypted account key use `chrome.storage.session`, restricted to trusted
  extension contexts, and normally disappear at browser-session end.
- Vault timeout is configurable. The default locks when the browser session ends; optional inactivity
  alarms support 15 minutes, one hour, or four hours. Explicit lock clears the account key immediately.
- The opt-in “keep unlocked until logout” mode AES-GCM encrypts the session under a non-extractable
  key stored in a browser-profile IndexedDB database. It improves convenience across browser restarts
  but weakens protection on a shared or compromised browser profile. Explicit lock persists only the
  locked session, and logout deletes the persistent session record.
- Server sync data is persisted only in its server-encrypted form in IndexedDB. The minimal decrypted
  login model is cached in the service worker and cleared on lock, logout, or worker termination.
- Remote HTTP is rejected; HTTP is allowed only for loopback development.
- Autofill rejects HTTPS-mapped credentials on downgraded HTTP pages.
- Host permission is requested for the selected server origin through an explicit user gesture.
- Server KDF parameters are checked for downgrade and resource-exhaustion values before derivation.
- Authenticated ciphertext MACs are verified before AES-CBC decryption. Unsupported encryption v2
  data is rejected.
- Argon2id uses Bitwarden's SHA-256 pre-hashed email salt and runs in a transient offscreen
  extension context that is closed after derivation.
- Login items with master-password reprompt enabled keep password, TOTP, and fill unavailable until
  the background revalidates the account key; authorization expires after 60 seconds. Organization
  `ViewPassword` restrictions are enforced during decryption.
- Broad website access is optional and disabled by default. When enabled, an isolated script detects
  login forms, offers website-matched entries, and captures a submitted credential for an explicit
  save/update decision. Pending plaintext is memory-only, expires after two minutes, and is cleared
  on lock/logout; a selected credential is sent to the page script only after a user click.
- Errors exposed to the popup do not include response bodies.
- Website icons are resolved with Chrome's local `_favicon` facility; LeanVault does not send saved
  vault URLs to a third-party favicon service.

## Reporting

Do not include real vault contents, master passwords, access tokens, encryption keys, or server
logs containing secrets in a report. Until a private reporting channel is established, create a
minimal public issue that asks the maintainers for secure contact instructions.

## Required before production use

Production use remains blocked on broader compatibility fixtures, automated browser/heap testing,
a formal threat model, dependency/SBOM review, and an independent cryptography and extension audit.
Vault writes, save/fill integration, and passkeys require separate security review before release.
