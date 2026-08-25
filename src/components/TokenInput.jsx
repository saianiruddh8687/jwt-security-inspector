export default function TokenInput({ token, secret, publicKeyPem, onTokenChange, onSecretChange, onPublicKeyChange, onAnalyze, busy }) {
  return (
    <form className="input-panel" onSubmit={(event) => { event.preventDefault(); onAnalyze(); }}>
      <div className="section-heading">
        <div>
          <p className="eyebrow">Input</p>
          <h2>Inspect a compact JWT</h2>
        </div>
        <span className="privacy-badge">● Client-side only</span>
      </div>

      <label htmlFor="jwt-token">JWT</label>
      <textarea id="jwt-token" value={token} onChange={(e) => onTokenChange(e.target.value)} rows={5} spellCheck={false} autoComplete="off" aria-describedby="jwt-help" />
      <p id="jwt-help" className="field-help">Paste a three-segment JWS/JWT. Analysis and cryptographic operations run locally in your browser.</p>

      <div className="input-grid">
        <div>
          <label htmlFor="hmac-secret">HMAC secret <span>(optional)</span></label>
          <input id="hmac-secret" type="password" value={secret} onChange={(e) => onSecretChange(e.target.value)} autoComplete="off" />
        </div>
        <div>
          <label htmlFor="public-key">Public key PEM <span>(optional)</span></label>
          <textarea id="public-key" value={publicKeyPem} onChange={(e) => onPublicKeyChange(e.target.value)} rows={4} placeholder="-----BEGIN PUBLIC KEY-----" spellCheck={false} />
        </div>
      </div>

      <button className="primary-button" type="submit" disabled={busy} aria-busy={busy}>
        {busy ? "Analyzing…" : "Analyze JWT"}
      </button>
    </form>
  );
}
