import { useMemo, useState } from "react";
import { parseJwt, HS_ALGS, RS_ALGS, ES_ALGS } from "./lib/jwt";
import { verifyHmacToken, findWeakSecret, verifyAsymmetricToken, algorithmConfusionForge } from "./lib/verify";
import { COMMON_WEAK_SECRETS } from "./lib/weakSecrets";
import { analyzeClaims } from "./lib/claims";
import { analyzeHeader, buildSecurityScore } from "./lib/findings";
import TokenInput from "./components/TokenInput";
import SecurityScore from "./components/SecurityScore";
import FindingCard from "./components/FindingCard";
import ClaimTable from "./components/ClaimTable";
import "./styles/globals.css";

const SAMPLE_JWT =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
  "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
  "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

export default function App() {
  const [token, setToken] = useState(SAMPLE_JWT);
  const [secret, setSecret] = useState("");
  const [publicKeyPem, setPublicKeyPem] = useState("");
  const [analysis, setAnalysis] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function analyze() {
    setBusy(true);
    setError("");
    try {
      const parsed = parseJwt(token);
      const alg = parsed.header.alg;
      const findings = [...analyzeHeader(parsed.header), ...analyzeClaims(parsed.payload)];
      const verification = {};

      if (HS_ALGS.includes(alg)) {
        if (secret) verification.manualSecretValid = await verifyHmacToken(parsed, secret);
        const wordlist = secret ? [secret, ...COMMON_WEAK_SECRETS] : COMMON_WEAK_SECRETS;
        verification.weakSecretFound = await findWeakSecret(parsed, wordlist);
        if (verification.weakSecretFound) {
          findings.push({
            id: "jwt.weak-secret",
            severity: "high",
            category: "signature",
            title: "Weak HMAC secret detected",
            description: "The signature matches a secret from the bundled weak-secret test set.",
            evidence: "A candidate secret reproduced the JWT signature.",
            remediation: "Use a high-entropy, randomly generated signing key and rotate exposed keys.",
          });
        }
      } else if (RS_ALGS.includes(alg) || ES_ALGS.includes(alg)) {
        if (publicKeyPem) {
          verification.signatureValid = await verifyAsymmetricToken(parsed, publicKeyPem);
          verification.algConfusion = await algorithmConfusionForge(parsed, publicKeyPem);
        }
      } else if (alg && alg !== "none") {
        findings.push({
          id: "jwt.unrecognized-alg",
          severity: "medium",
          category: "header",
          title: "Algorithm is not in the supported set",
          description: `The inspector does not recognize ${alg} as a supported verification algorithm.`,
          evidence: `alg=${alg}`,
          remediation: "Use a documented algorithm allow-list and reject unexpected algorithms.",
        });
      }

      if (verification.signatureValid === false) {
        findings.push({
          id: "jwt.invalid-signature",
          severity: "high",
          category: "signature",
          title: "Signature verification failed",
          description: "The supplied key did not validate the JWT signature.",
          evidence: `${alg} verification returned false`,
          remediation: "Reject the token when server-side verification fails.",
        });
      }

      if (verification.algConfusion?.forgedToken) {
        findings.push({
          id: "jwt.alg-confusion-test",
          severity: "info",
          category: "signature",
          title: "Algorithm-confusion test artifact generated",
          description: "A forged RS/ES-to-HS token was generated for controlled endpoint testing. This does not prove a target is vulnerable.",
          evidence: "Forged token generated locally.",
          remediation: "On an authorized test target, enforce a fixed algorithm/key-family mapping server-side.",
        });
      }

      setAnalysis({ parsed, alg, findings, verification });
    } catch (e) {
      setAnalysis(null);
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  const score = useMemo(() => buildSecurityScore(analysis?.findings || []), [analysis]);

  return (
    <div className="app-shell">
      <header className="site-header">
        <div className="brand-mark" aria-hidden="true">JWT</div>
        <div>
          <p className="eyebrow">Security tooling</p>
          <h1>JWT Security Inspector</h1>
        </div>
        <span className="version-badge">v2</span>
      </header>

      <main>
        <section className="hero" aria-labelledby="hero-title">
          <p className="eyebrow">Local-first JWT assessment</p>
          <h2 id="hero-title">Understand what your token exposes before you trust it.</h2>
          <p>Decode claims, inspect header metadata, verify signatures, and surface actionable security findings without sending tokens or keys to a server.</p>
        </section>

        <TokenInput token={token} secret={secret} publicKeyPem={publicKeyPem} onTokenChange={setToken} onSecretChange={setSecret} onPublicKeyChange={setPublicKeyPem} onAnalyze={analyze} busy={busy} />

        {error && <div className="error-banner" role="alert"><strong>Analysis failed:</strong> {error}</div>}

        {analysis && (
          <section className="results" aria-labelledby="results-title" aria-live="polite">
            <div className="results-heading">
              <div><p className="eyebrow">Assessment</p><h2 id="results-title">Security analysis</h2></div>
              <code className="algorithm-badge">{analysis.alg || "unknown"}</code>
            </div>

            <SecurityScore score={score} count={analysis.findings.length} />

            <section className="panel" aria-labelledby="findings-title">
              <div className="panel-heading"><h3 id="findings-title">Findings</h3><span>{analysis.findings.length} detected</span></div>
              {analysis.findings.length ? (
                <div className="finding-list">{analysis.findings.map((finding) => <FindingCard key={finding.id} finding={finding} />)}</div>
              ) : (
                <div className="success-state"><strong>No findings from the current checks.</strong><span>This does not guarantee that a token is secure.</span></div>
              )}
            </section>

            <div className="results-grid">
              <section className="panel" aria-labelledby="header-title">
                <div className="panel-heading"><h3 id="header-title">Header</h3></div>
                <pre className="code-block">{JSON.stringify(analysis.parsed.header, null, 2)}</pre>
              </section>
              <section className="panel" aria-labelledby="payload-title">
                <div className="panel-heading"><h3 id="payload-title">Payload claims</h3></div>
                <ClaimTable payload={analysis.parsed.payload} />
              </section>
            </div>

            {analysis.verification.algConfusion?.forgedToken && (
              <details className="panel disclosure">
                <summary>Controlled algorithm-confusion test artifact</summary>
                <p>Use only against systems you are authorized to test. Generation alone is not a vulnerability finding.</p>
                <pre className="code-block">{analysis.verification.algConfusion.forgedToken}</pre>
              </details>
            )}
          </section>
        )}
      </main>

      <footer className="site-footer">
        <span>JWT Security Inspector</span>
        <span>All analysis is performed locally in your browser.</span>
      </footer>
    </div>
  );
}
