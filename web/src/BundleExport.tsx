import { useState } from 'react';
import { validate, type Schemas } from './contract';

type Props = { endpoint: string; label?: string };

/** Local evidence bundle export. Raw bytes are opt-in and only ever written to a local file. */
export default function BundleExport({ endpoint, label = 'Export evidence bundle' }: Props) {
  const [raw, setRaw] = useState(false), [busy, setBusy] = useState(false), [error, setError] = useState('');
  const [result, setResult] = useState<Schemas['BundleResult'] | null>(null);
  async function run() {
    setBusy(true); setError(''); setResult(null);
    try {
      const response = await fetch(endpoint, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ include_raw: raw }) });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(typeof body.detail === 'string' ? body.detail : 'Export failed');
      const checked = validate('BundleResult', body);
      if (!checked.ok) throw new Error('Export response did not match the contract: ' + checked.errors[0]);
      setResult(checked.value);
    } catch (e) { setError(String(e instanceof Error ? e.message : e)); } finally { setBusy(false); }
  }
  return <div className="bundle-export" data-testid="bundle-export">
    <label><input type="checkbox" checked={raw} onChange={e => setRaw(e.target.checked)} /> Include raw bytes (local file only; never sent to a model)</label>
    <button onClick={() => void run()} disabled={busy}>{busy ? 'Writing…' : label}</button>
    {error && <p className="error" role="alert">{error}</p>}
    {result && <p className="notice" data-testid="bundle-result"><strong>{result.verification}</strong> · {result.raw_included}/{result.captures} captures with raw bytes · <code>{result.path}</code>
      {result.verification !== 'VERIFIED' && <><br />{result.raw_included === 0 ? 'Metadata only: independent hash and disassembly verification is unavailable.' : 'Incomplete or failed: see the verifier output.'}</>}
      <br />Verify offline: <code>uv run python scripts/verify_bundle.py {result.path}</code></p>}
  </div>;
}
