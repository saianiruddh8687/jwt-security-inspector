export function buildAssessmentReport({ analysis, score }) {
  const generatedAt = new Date().toISOString();
  return {
    reportVersion: "1.0",
    generatedAt,
    tool: {
      name: "JWT Security Inspector",
      version: "2.1",
      processing: "client-side",
    },
    assessment: {
      algorithm: analysis.alg || null,
      findingCount: analysis.findings.length,
      posture: score.label,
      score: score.value,
    },
    header: analysis.parsed.header,
    payload: analysis.parsed.payload,
    findings: analysis.findings,
    verification: {
      manualSecretValid: analysis.verification.manualSecretValid ?? null,
      weakSecretFound: Boolean(analysis.verification.weakSecretFound),
      signatureValid: analysis.verification.signatureValid ?? null,
      algorithmConfusionArtifactGenerated: Boolean(analysis.verification.algConfusion?.forgedToken),
    },
    limitations: [
      "A clean result does not prove that the token or consuming application is secure.",
      "Algorithm-confusion artifact generation does not prove target-side vulnerability.",
      "This report contains decoded token claims; store and share it according to your security policy.",
    ],
  };
}

export function downloadJsonReport(report) {
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `jwt-security-report-${report.generatedAt.replace(/[:.]/g, "-")}.json`;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}
