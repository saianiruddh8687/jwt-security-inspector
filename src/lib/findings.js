const severityWeight = { critical: 40, high: 25, medium: 15, low: 7, info: 0 };
const SUPPORTED_ALGORITHMS = new Set(["HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]);
const REMOTE_KEY_HEADERS = ["jku", "x5u"];
const INLINE_KEY_HEADERS = ["jwk", "x5c"];

export function analyzeHeader(header) {
  const findings = [];
  const alg = typeof header?.alg === "string" ? header.alg : null;

  if (!alg) {
    findings.push({
      id: "jwt.missing-alg", severity: "critical", category: "header",
      title: "Missing signing algorithm",
      description: "The JWT header does not declare alg.",
      evidence: "alg is absent or not a string",
      remediation: "Require an explicit allow-listed algorithm during verification.",
    });
    return findings;
  }

  const normalizedAlg = alg.toUpperCase();
  if (normalizedAlg === "NONE") {
    findings.push({
      id: "jwt.none-alg", severity: "critical", category: "header",
      title: "Unsecured algorithm declared",
      description: "alg=none means the compact token carries no cryptographic signature.",
      evidence: "alg=none",
      remediation: "Reject unsecured JWTs unless an explicit, isolated protocol requires them.",
    });
  } else if (!SUPPORTED_ALGORITHMS.has(normalizedAlg)) {
    findings.push({
      id: "jwt.unsupported-algorithm", severity: "medium", category: "header",
      title: "Unsupported or unexpected algorithm",
      description: "The inspector cannot verify this algorithm and it is outside the supported allow-list.",
      evidence: `alg=${alg}`,
      remediation: "Define an explicit server-side algorithm allow-list and reject unexpected algorithms.",
    });
  }

  if (header.typ != null && (typeof header.typ !== "string" || header.typ.toUpperCase() !== "JWT")) {
    findings.push({
      id: "jwt.unexpected-typ", severity: "info", category: "header",
      title: "Non-standard typ value",
      description: "The typ header is present but is not JWT.",
      evidence: `typ=${String(header.typ)}`,
      remediation: "Treat typ as an application policy signal and validate it when required.",
    });
  }

  const remoteKeyFields = REMOTE_KEY_HEADERS.filter((key) => header[key] != null);
  if (remoteKeyFields.length) {
    findings.push({
      id: "jwt.remote-key-location", severity: "high", category: "header",
      title: "Remote key location supplied",
      description: "The header points to a remote key location that could influence verification if trusted automatically.",
      evidence: remoteKeyFields.join(", "),
      remediation: "Never fetch attacker-controlled key URLs. Use pinned trust roots and strict issuer/key policies.",
    });
  }

  const inlineKeyFields = INLINE_KEY_HEADERS.filter((key) => header[key] != null);
  if (inlineKeyFields.length) {
    findings.push({
      id: "jwt.inline-key-metadata", severity: "medium", category: "header",
      title: "Inline key metadata present",
      description: "The header embeds key material or certificate data that may influence key selection.",
      evidence: inlineKeyFields.join(", "),
      remediation: "Do not automatically trust embedded keys; bind verification keys to an established trust policy.",
    });
  }

  if (header.kid != null && (typeof header.kid !== "string" || !header.kid.trim())) {
    findings.push({
      id: "jwt.invalid-kid", severity: "low", category: "header",
      title: "Invalid key identifier",
      description: "kid should be a non-empty string when present.",
      evidence: `kid=${JSON.stringify(header.kid)}`,
      remediation: "Validate kid and resolve it only against a trusted key registry.",
    });
  }

  return findings;
}

export function buildSecurityScore(findings) {
  const penalty = findings.reduce((total, finding) => total + (severityWeight[finding.severity] || 0), 0);
  return Math.max(0, Math.min(100, 100 - penalty));
}

export function scoreLabel(score) {
  if (score >= 90) return "Low risk";
  if (score >= 70) return "Moderate risk";
  if (score >= 40) return "High risk";
  return "Critical risk";
}
