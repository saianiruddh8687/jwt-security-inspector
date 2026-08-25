export default function FindingCard({ finding }) {
  return (
    <article className={`finding finding--${finding.severity}`}>
      <div className="finding__topline">
        <span className="severity">{finding.severity}</span>
        <span className="finding__category">{finding.category}</span>
      </div>
      <h3>{finding.title}</h3>
      <p>{finding.description}</p>
      <div className="finding__detail"><strong>Evidence:</strong> {finding.evidence}</div>
      <div className="finding__detail"><strong>Remediation:</strong> {finding.remediation}</div>
    </article>
  );
}
