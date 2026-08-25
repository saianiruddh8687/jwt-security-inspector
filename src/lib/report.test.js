import { describe, expect, it } from "vitest";
import { buildAssessmentReport } from "./report";

describe("buildAssessmentReport", () => {
  it("creates a stable report envelope without including raw signing secrets", () => {
    const report = buildAssessmentReport({
      analysis: {
        alg: "HS256",
        parsed: { header: { alg: "HS256" }, payload: { sub: "123" } },
        findings: [{ id: "jwt.test", severity: "info" }],
        verification: { manualSecretValid: true, weakSecretFound: false },
      },
      score: { value: 90, label: "Low risk" },
    });

    expect(report.reportVersion).toBe("1.0");
    expect(report.assessment.score).toBe(90);
    expect(report.payload.sub).toBe("123");
    expect(JSON.stringify(report)).not.toContain("secret");
  });
});
