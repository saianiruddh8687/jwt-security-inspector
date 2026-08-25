const severityWeight = { critical: 40, high: 25, medium: 15, low: 7, info: 0 };

export function analyzeHeader(header) {
  const findings = [];
  const alg = header?.alg;

  if (!alg) {
    findings.push({
      id: "jwt.missing-alg",
      severity: "critical",
      category: "header",
      title: "Missing signing algorithm",
      description: "The JWT header does not declare alg.",
      evidence: "alg is absent",
      remediation: "Require an explicit allow-listed algorithm during verification.",
    });
    return findings;
  }

  if (alg.toLowerCase() === "none") {
    findings.push({
      id: "jwt.none-alg",
      severity: "critical",
      category: "header",
      title: "Unsecured algorithm declared",
      description: "alg=none means the compact token carries no cryptographic signature.",
      evidence: "alg=none",
      remediation: "Reject unsecured JWTs unless an explicit, isolated protocol requires them.",
    });
  }

  if (header.typ && header.typ.toUpperCase() !== "JWT") {
    findings.push({
      id: "jwt.unexpected-typ",
      severity: "info",
      category: "header",
      title: "Non-standard typ value",
      description: "The typ header is present but is not JWT.",
      evidence: `typ=${String(header.typ)}`,
      remediation: "Treat typ as an application policy signal and validate it when required.",
    });
  }

  if (header.jku || header.jwk || header.x5u || header.x5c || header.kid) {
    findings.push({
      id: "jwt.key-metadata",
      severity: "info",
      category: "header",
      title: "Key-selection metadata present",
      description: "The header contains fields that can influence key selection or retrieval.",
      evidence: ["kid", "jku", "jwk", "x5u", "x5c"].filter((key) => header[key] != null).join(", "),
      remediation: "Use strict allow-lists for key identifiers and never trust attacker-controlled remote key locations.",
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
