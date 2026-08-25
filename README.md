# JWT Security Inspector

A client-side JWT analyzer built with React and the browser's native **Web Crypto API**
(no server, no token/key ever leaves the browser). Built to practice detecting the two
most common real-world JWT implementation flaws, both covered in PortSwigger's Web
Security Academy JWT labs.

## What it does

- **Decodes** the header and payload of any compact JWT (`header.payload.signature`).
- **Weak-secret brute force (HS256/384/512):** tests the token's signature against a
  small wordlist of common/default secrets using `crypto.subtle` HMAC signing, and
  against a secret you supply.
- **Signature verification (RS256/384/512, ES256/384/512):** imports a PEM-encoded SPKI
  public key via `crypto.subtle.importKey` and verifies the token's signature end-to-end.
- **Algorithm-confusion forging (RS → HS):** given a token's claims and a known RSA/EC
  public key, forges an `alg: HS256` token signed with the public key material itself —
  the classic confusion attack against verifiers that trust the `alg` header and accept
  both key types. The forged token is output for testing against your own endpoint; it
  is not sent anywhere.
- Flags **`alg: none`** tokens, since many lenient parsers accept them as unauthenticated.

## Why this design

Everything runs through `SubtleCrypto` (`crypto.subtle.importKey`, `.sign`, `.verify`)
rather than a JS crypto polyfill, so the signature math is delegated to the browser's
audited crypto implementation — the same approach used by production JWT libraries.

## Running locally

```bash
npm install
npm run dev
```

## Project layout

```
src/
  App.jsx           UI + orchestration
  lib/jwt.js         base64url + JWT parsing helpers
  lib/verify.js       HMAC/RSA/EC verification, weak-secret scan, alg-confusion forge
  lib/weakSecrets.js  small example wordlist
```

## Scope / ethics note

This tool is for testing JWTs and endpoints you own or are authorized to test —
the same standard that applies to the bug bounty and lab work it was built alongside.
