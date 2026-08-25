import test from "node:test";
import assert from "node:assert/strict";
import { analyzeClaims } from "./claims.js";
import { analyzeHeader, buildSecurityScore } from "./findings.js";

test("flags an unsecured algorithm as critical", () => {
  const findings = analyzeHeader({ alg: "none", typ: "JWT" });
  assert.equal(findings.some((item) => item.id === "jwt.none-alg" && item.severity === "critical"), true);
});

test("flags remote key locations as high risk", () => {
  const findings = analyzeHeader({ alg: "RS256", jku: "https://example.invalid/keys" });
  assert.equal(findings.some((item) => item.id === "jwt.remote-key-location" && item.severity === "high"), true);
});

test("detects invalid NumericDate claims", () => {
  const findings = analyzeClaims({ exp: "tomorrow", iat: "now" }, 1700000000);
  assert.equal(findings.some((item) => item.id === "jwt.invalid-exp"), true);
  assert.equal(findings.some((item) => item.id === "jwt.invalid-iat"), true);
});

test("detects long-lived tokens", () => {
  const now = 1700000000;
  const findings = analyzeClaims({ iat: now, exp: now + 3 * 24 * 60 * 60 }, now);
  assert.equal(findings.some((item) => item.id === "jwt.long-lifetime"), true);
});

test("security score is bounded", () => {
  const score = buildSecurityScore([
    { severity: "critical" },
    { severity: "high" },
    { severity: "medium" },
  ]);
  assert.equal(score >= 0 && score <= 100, true);
});
