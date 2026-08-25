// Base64url helpers (RFC 7515) — no external deps, browser-native only.

export function base64UrlToBytes(b64url) {
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  const bin = atob(padded);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

export function bytesToBase64Url(bytes) {
  let bin = "";
  bytes.forEach((b) => (bin += String.fromCharCode(b)));
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function decodeJsonSegment(segment) {
  const bytes = base64UrlToBytes(segment);
  const text = new TextDecoder().decode(bytes);
  return JSON.parse(text);
}

/**
 * Splits a compact JWT into its parts and decodes header/payload.
 * Throws if the token doesn't have exactly 3 dot-separated segments.
 */
export function parseJwt(token) {
  const parts = token.trim().split(".");
  if (parts.length !== 3) {
    throw new Error("Not a valid compact JWT (expected 3 dot-separated segments)");
  }
  const [headerSeg, payloadSeg, signatureSeg] = parts;
  const header = decodeJsonSegment(headerSeg);
  const payload = decodeJsonSegment(payloadSeg);
  const signatureBytes = base64UrlToBytes(signatureSeg);

  return {
    header,
    payload,
    signatureBytes,
    signingInput: `${headerSeg}.${payloadSeg}`, // exactly what the signature was computed over
    raw: { headerSeg, payloadSeg, signatureSeg },
  };
}

export const HS_ALGS = ["HS256", "HS384", "HS512"];
export const RS_ALGS = ["RS256", "RS384", "RS512"];
export const ES_ALGS = ["ES256", "ES384", "ES512"];

export const ALG_TO_HASH = {
  HS256: "SHA-256",
  HS384: "SHA-384",
  HS512: "SHA-512",
  RS256: "SHA-256",
  RS384: "SHA-384",
  RS512: "SHA-512",
  ES256: "SHA-256",
  ES384: "SHA-384",
  ES512: "SHA-512",
};

export const ES_CURVE = {
  ES256: "P-256",
  ES384: "P-384",
  ES512: "P-521",
};
