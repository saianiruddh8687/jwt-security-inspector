# JWT Security Inspector

A professional, local-first JWT assessment tool built with React, Vite, and the browser's native **Web Crypto API**.

> Tokens, secrets, and public keys are processed in the browser. The application does not send analysis input to a backend.

## Features

- Decode compact JWT headers and payloads.
- Inspect security-sensitive header metadata such as `alg`, `typ`, `kid`, `jku`, `jwk`, `x5u`, and `x5c`.
- Analyze standard claims including `exp`, `iat`, `nbf`, `iss`, and `aud`.
- Detect expired tokens, future activation/issued-at values, and missing lifecycle claims.
- Verify HS256/384/512 signatures with a supplied secret.
- Test a small bundled weak-secret set for HS-family tokens.
- Verify RS256/384/512 and ES256/384/512 signatures with a PEM SPKI public key.
- Generate an RS/ES → HS algorithm-confusion test artifact for authorized endpoint testing.
- Normalize findings into severity, evidence, explanation, and remediation fields.
- Provide a deterministic security posture score.
- Responsive, semantic, keyboard-friendly UI with accessible form labels and status messaging.
- GitHub Pages deployment through GitHub Actions.

## Security model

The inspector is intentionally **client-side only**. Cryptographic operations use `crypto.subtle` where supported by the browser. The algorithm-confusion feature generates a test token locally; generating that artifact does **not** prove that any target endpoint is vulnerable.

A clean result means only that the implemented checks did not identify a finding. It is not a guarantee that the JWT or its consuming application is secure.

## Development

```bash
npm install
npm run dev
```

Create a production build with:

```bash
npm run build
```

## Architecture

```text
src/
├── App.jsx                 application orchestration
├── components/             semantic, reusable UI components
│   ├── TokenInput.jsx
│   ├── SecurityScore.jsx
│   ├── FindingCard.jsx
│   └── ClaimTable.jsx
├── lib/
│   ├── jwt.js              JWT parsing and algorithm metadata
│   ├── verify.js           browser-native cryptographic verification
│   ├── claims.js           lifecycle and standard-claim analysis
│   ├── findings.js         normalized findings and scoring
│   └── weakSecrets.js      small bundled test wordlist
└── styles/
    └── globals.css         responsive design system
```

## Deployment

The repository is configured for GitHub Pages. Vite uses the repository base path `/jwt-security-inspector/`, and the Pages workflow builds `dist/` and deploys it through GitHub Actions.

## Responsible testing

Use this tool only with tokens, applications, and endpoints you own or are explicitly authorized to test. In particular, only send generated algorithm-confusion test artifacts to authorized test targets.
