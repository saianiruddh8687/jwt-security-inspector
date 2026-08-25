import { getClaimRows } from "../lib/claims";

export default function ClaimTable({ payload }) {
  const rows = getClaimRows(payload);

  return (
    <div className="table-wrap">
      <table>
        <caption className="sr-only">JWT payload claims</caption>
        <thead>
          <tr><th scope="col">Claim</th><th scope="col">Value</th><th scope="col">Interpreted</th></tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.name}>
              <th scope="row"><code>{row.name}</code></th>
              <td><code>{typeof row.value === "object" ? JSON.stringify(row.value) : String(row.value)}</code></td>
              <td>{row.date || "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
