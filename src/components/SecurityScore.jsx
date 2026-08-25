import { scoreLabel } from "../lib/findings";

export default function SecurityScore({ score, count }) {
  return (
    <section className="score-card" aria-label="Security posture">
      <div>
        <p className="eyebrow">Security posture</p>
        <div className="score-value">{score}<span>/100</span></div>
        <p className="score-label">{scoreLabel(score)}</p>
      </div>
      <div className="score-meta">
        <strong>{count}</strong>
        <span>finding{count === 1 ? "" : "s"}</span>
      </div>
    </section>
  );
}
