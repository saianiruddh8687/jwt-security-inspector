const DATE_CLAIMS = new Set(["exp", "iat", "nbf"]);
const NUMERIC_DATE_CLAIMS = ["exp", "iat", "nbf"];
const MAX_RECOMMENDED_LIFETIME = 24 * 60 * 60;

function finding(id, severity, title, description, evidence, remediation) {
  return { id, severity, category: "claims", title, description, evidence, remediation };
}

export function analyzeClaims(payload, now = Math.floor(Date.now() / 1000)) {
  const findings = [];
  const claims = payload && typeof payload === "object" && !Array.isArray(payload) ? payload : {};

  for (const claim of NUMERIC_DATE_CLAIMS) {
    if (claims[claim] != null && (typeof claims[claim] !== "number" || !Number.isFinite(claims[claim]))) {
      findings.push(finding(
        `jwt.invalid-${claim}`, "high", `Invalid ${claim} claim`,
        `${claim} must be a finite NumericDate value.`,
        `${claim}=${String(claims[claim])}`,
        `Validate ${claim} as a NumericDate before accepting the token.`
      ));
    }
  }

  if (claims.exp == null) {
    findings.push(finding(
      "jwt.missing-exp", "medium", "Missing expiration claim",
      "The token has no exp claim, so its lifetime is not bounded by the token itself.",
      "exp is absent", "Issue short-lived access tokens and validate exp server-side."
    ));
  } else if (typeof claims.exp === "number" && Number.isFinite(claims.exp)) {
    if (claims.exp <= now) {
      findings.push(finding(
        "jwt.expired", "high", "Token is expired",
        "The exp claim is at or before the current time.",
        new Date(claims.exp * 1000).toISOString(),
        "Reject expired tokens and require a fresh token."
      ));
    }

    if (typeof claims.iat === "number" && Number.isFinite(claims.iat) && claims.exp > claims.iat) {
      const lifetime = claims.exp - claims.iat;
      if (lifetime > MAX_RECOMMENDED_LIFETIME) {
        findings.push(finding(
          "jwt.long-lifetime", "medium", "Long token lifetime",
          "The token lifetime exceeds the recommended 24-hour assessment threshold.",
          `${Math.round(lifetime / 3600)} hours`,
          "Prefer short-lived access tokens and use refresh-token rotation where appropriate."
        ));
      }
    }
  }

  if (typeof claims.nbf === "number" && Number.isFinite(claims.nbf) && claims.nbf > now + 60) {
    findings.push(finding(
      "jwt.not-active", "medium", "Token is not active yet",
      "The nbf claim is more than 60 seconds in the future.",
      new Date(claims.nbf * 1000).toISOString(),
      "Enforce nbf validation with a small, documented clock-skew allowance."
    ));
  }

  if (typeof claims.iat === "number" && Number.isFinite(claims.iat) && claims.iat > now + 60) {
    findings.push(finding(
      "jwt.future-iat", "medium", "Issued-at time is in the future",
      "iat is substantially ahead of the local clock.",
      new Date(claims.iat * 1000).toISOString(),
      "Validate NumericDate claims and account for bounded clock skew."
    ));
  }

  if (claims.iss == null) {
    findings.push(finding(
      "jwt.missing-iss", "low", "Missing issuer claim",
      "The token does not identify an issuer for application-level validation.",
      "iss is absent", "Require and validate iss when the application security model depends on issuer identity."
    ));
  } else if (typeof claims.iss !== "string" || !claims.iss.trim()) {
    findings.push(finding(
      "jwt.invalid-iss", "medium", "Invalid issuer claim",
      "iss should be a non-empty string when present.",
      `iss=${JSON.stringify(claims.iss)}`, "Validate issuer type and compare it against an explicit allow-list."
    ));
  }

  if (claims.aud == null) {
    findings.push(finding(
      "jwt.missing-aud", "low", "Missing audience claim",
      "The token does not identify an audience for application-level validation.",
      "aud is absent", "Require and validate aud when the token is intended for a specific service or API."
    ));
  } else if (!(typeof claims.aud === "string" || (Array.isArray(claims.aud) && claims.aud.every((value) => typeof value === "string")))) {
    findings.push(finding(
      "jwt.invalid-aud", "medium", "Invalid audience claim",
      "aud should be a string or an array of strings.",
      `aud=${JSON.stringify(claims.aud)}`, "Validate audience type and match it against an explicit allow-list."
    ));
  }

  if (claims.sub != null && typeof claims.sub !== "string") {
    findings.push(finding(
      "jwt.invalid-sub", "low", "Invalid subject claim",
      "sub should be a string when present.",
      `sub=${JSON.stringify(claims.sub)}`, "Validate claim types before using sub for authorization decisions."
    ));
  }

  if (claims.jti != null && typeof claims.jti !== "string") {
    findings.push(finding(
      "jwt.invalid-jti", "low", "Invalid JWT ID claim",
      "jti should be a string when present.",
      `jti=${JSON.stringify(claims.jti)}`, "Validate jti before using it for replay detection or token revocation."
    ));
  }

  return findings;
}

export function getClaimRows(payload) {
  return Object.entries(payload || {}).map(([name, value]) => ({
    name,
    value,
    date: DATE_CLAIMS.has(name) && typeof value === "number" ? new Date(value * 1000).toISOString() : null,
  }));
}
