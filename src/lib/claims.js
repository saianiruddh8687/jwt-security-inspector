const DATE_CLAIMS = new Set(["exp", "iat", "nbf"]);

export function analyzeClaims(payload, now = Math.floor(Date.now() / 1000)) {
  const findings = [];
  const claims = payload && typeof payload === "object" ? payload : {};

  if (claims.exp == null) {
    findings.push({
      id: "jwt.missing-exp",
      severity: "medium",
      category: "claims",
      title: "Missing expiration claim",
      description: "The token has no exp claim, so its lifetime is not bounded by the token itself.",
      evidence: "exp is absent",
      remediation: "Issue short-lived access tokens and validate exp server-side.",
    });
  } else if (typeof claims.exp !== "number") {
    findings.push({
      id: "jwt.invalid-exp",
      severity: "high",
      category: "claims",
      title: "Invalid expiration claim",
      description: "exp should be a NumericDate value.",
      evidence: `exp=${String(claims.exp)}`,
      remediation: "Validate claim types before accepting the token.",
    });
  } else if (claims.exp <= now) {
    findings.push({
      id: "jwt.expired",
      severity: "high",
      category: "claims",
      title: "Token is expired",
      description: "The exp claim is at or before the current time.",
      evidence: new Date(claims.exp * 1000).toISOString(),
      remediation: "Reject expired tokens and require a fresh token.",
    });
  }

  if (typeof claims.nbf === "number" && claims.nbf > now) {
    findings.push({
      id: "jwt.not-active",
      severity: "medium",
      category: "claims",
      title: "Token is not active yet",
      description: "The nbf claim is in the future.",
      evidence: new Date(claims.nbf * 1000).toISOString(),
      remediation: "Enforce nbf validation with a small, documented clock-skew allowance.",
    });
  }

  if (typeof claims.iat === "number" && claims.iat > now + 60) {
    findings.push({
      id: "jwt.future-iat",
      severity: "medium",
      category: "claims",
      title: "Issued-at time is in the future",
      description: "iat is substantially ahead of the local clock.",
      evidence: new Date(claims.iat * 1000).toISOString(),
      remediation: "Validate NumericDate claims and account for bounded clock skew.",
    });
  }

  for (const claim of ["iss", "aud"]) {
    if (claims[claim] == null) {
      findings.push({
        id: `jwt.missing-${claim}`,
        severity: "low",
        category: "claims",
        title: `Missing ${claim} claim`,
        description: `The token does not identify an ${claim} value for application-level validation.`,
        evidence: `${claim} is absent`,
        remediation: `Require and validate ${claim} when the application security model depends on it.`,
      });
    }
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
