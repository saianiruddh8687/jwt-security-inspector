import { useState } from "react";
import { buildAssessmentReport, downloadJsonReport } from "../lib/report";

export default function AssessmentActions({ analysis, score }) {
  const [status, setStatus] = useState("");

  function exportReport() {
    downloadJsonReport(buildAssessmentReport({ analysis, score }));
    setStatus("JSON report downloaded.");
  }

  function printReport() {
    window.print();
    setStatus("Print dialog opened.");
  }

  return (
    <div className="assessment-actions" aria-label="Assessment actions">
      <button type="button" className="secondary-button" onClick={exportReport}>Export JSON report</button>
      <button type="button" className="secondary-button" onClick={printReport}>Print report</button>
      <span className="sr-only" role="status" aria-live="polite">{status}</span>
    </div>
  );
}
