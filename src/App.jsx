import { useState } from "react";
import { parseJwt, HS_ALGS, RS_ALGS, ES_ALGS } from "./lib/jwt";
import {
  verifyHmacToken,
  findWeakSecret,
  verifyAsymmetricToken,
  algorithmConfusionForge,
} from "./lib/verify";
import { COMMON_WEAK_SECRETS } from "./lib/weakSecrets";

const SAMPLE_JWT =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
  "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
  "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"; // signed with "your-256-bit-secret"

export default function App() {
  const [token, setToken] = useState(SAMPLE_JWT);
  const [secret, setSecret] = useState("");
  const [publicKeyPem, setPublicKeyPem] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function analyze() {
    setError("");
    setResult(null);
    setBusy(true);
    try {
      const parsed = parseJwt(token);
      const alg = parsed.header.alg;
      const findings = { header: parsed.header, payload: parsed.payload, alg };

      if (HS_ALGS.includes(alg)) {
        if (secret) {
          findings.manualSecretValid = await verifyHmacToken(parsed, secret);
        }
        const wordlist = secret ? [secret, ...COMMON_WEAK_SECRETS] : COMMON_WEAK_SECRETS;
        findings.weakSecretFound = await findWeakSecret(parsed, wordlist);
      } else if (RS_ALGS.includes(alg) || ES_ALGS.includes(alg)) {
        if (publicKeyPem) {
          findings.signatureValid = await verifyAsymmetricToken(parsed, publicKeyPem);
          findings.algConfusion = await algorithmConfusionForge(parsed, publicKeyPem);
        }
      } else if (alg === "none") {
        findings.noneAlgWarning =
          "alg=none accepted by many lenient parsers — signature is unauthenticated.";
      } else {
        findings.unsupported = `Unrecognized/unsupported alg: ${alg}`;
      }

      setResult(findings);
    } catch (e) {
      setError(e.message || String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div style={{ maxWidth: 760, margin: "0 auto", padding: 24, fontFamily: "ui-sans-serif, system-ui" }}>
      <h1 style={{ fontSize: 22, fontWeight: 700, marginBottom: 4 }}>JWT Security Inspector</h1>
      <p style={{ color: "#666", marginTop: 0, marginBottom: 20, fontSize: 14 }}>
        Client-side JWT analysis: weak-secret brute forcing, signature verification, and
        RS/HS algorithm-confusion testing — entirely in-browser via the Web Crypto API. No
        token or key ever leaves your machine.
      </p>

      <label style={labelStyle}>JWT</label>
      <textarea
        value={token}
        onChange={(e) => setToken(e.target.value)}
        rows={4}
        style={textareaStyle}
        spellCheck={false}
      />

      <label style={labelStyle}>Known/candidate HMAC secret (optional, for HS*)</label>
      <input value={secret} onChange={(e) => setSecret(e.target.value)} style={inputStyle} />

      <label style={labelStyle}>RSA/EC public key, PEM (optional, for RS*/ES*)</label>
      <textarea
        value={publicKeyPem}
        onChange={(e) => setPublicKeyPem(e.target.value)}
        rows={5}
        style={textareaStyle}
        placeholder={"-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"}
        spellCheck={false}
      />

      <button onClick={analyze} disabled={busy} style={buttonStyle}>
        {busy ? "Analyzing…" : "Analyze"}
      </button>

      {error && <p style={{ color: "#c0392b", marginTop: 16 }}>{error}</p>}

      {result && (
        <div style={{ marginTop: 24 }}>
          <Section title="Header">
            <pre style={preStyle}>{JSON.stringify(result.header, null, 2)}</pre>
          </Section>
          <Section title="Payload">
            <pre style={preStyle}>{JSON.stringify(result.payload, null, 2)}</pre>
          </Section>
          <Section title="Findings">
            <ul style={{ paddingLeft: 18, lineHeight: 1.6 }}>
              <li>Algorithm: <code>{result.alg}</code></li>
              {"manualSecretValid" in result && (
                <li>Provided secret valid: <b>{String(result.manualSecretValid)}</b></li>
              )}
              {"weakSecretFound" in result && (
                <li>
                  Weak-secret scan:{" "}
                  <b>{result.weakSecretFound ? `MATCH — "${result.weakSecretFound}"` : "no match in wordlist"}</b>
                </li>
              )}
              {"signatureValid" in result && (
                <li>Signature valid against provided public key: <b>{String(result.signatureValid)}</b></li>
              )}
              {"algConfusion" in result && (
                <li>
                  Algorithm-confusion (RS→HS) forge: <b>{result.algConfusion.vulnerableIfMisconfigured ? "forged token generated — test against your endpoint" : "n/a"}</b>
                  {result.algConfusion.forgedToken && (
                    <pre style={preStyle}>{result.algConfusion.forgedToken}</pre>
                  )}
                </li>
              )}
              {result.noneAlgWarning && <li style={{ color: "#c0392b" }}>{result.noneAlgWarning}</li>}
              {result.unsupported && <li>{result.unsupported}</li>}
            </ul>
          </Section>
        </div>
      )}
    </div>
  );
}

function Section({ title, children }) {
  return (
    <div style={{ marginBottom: 16 }}>
      <h2 style={{ fontSize: 15, fontWeight: 600, marginBottom: 6 }}>{title}</h2>
      {children}
    </div>
  );
}

const labelStyle = { display: "block", fontSize: 13, fontWeight: 600, marginTop: 14, marginBottom: 4 };
const textareaStyle = {
  width: "100%",
  fontFamily: "ui-monospace, monospace",
  fontSize: 13,
  padding: 8,
  border: "1px solid #ccc",
  borderRadius: 6,
  boxSizing: "border-box",
};
const inputStyle = { ...textareaStyle };
const buttonStyle = {
  marginTop: 18,
  padding: "8px 18px",
  background: "#1a1a1a",
  color: "#fff",
  border: "none",
  borderRadius: 6,
  cursor: "pointer",
  fontSize: 14,
};
const preStyle = {
  background: "#f6f6f6",
  padding: 10,
  borderRadius: 6,
  fontSize: 12,
  overflowX: "auto",
};
