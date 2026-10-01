import { useEffect, useMemo, useState } from 'react';
import ErrorBoundary from './ErrorBoundary';
import { KNOWN_OPERATIONS, validate, validateAdvice, validateList, type Schemas } from './contract';
import './workbench.css';

// Types come from the generated backend contract (npm run types); nothing here restates them.
type Plan = Schemas['AttackPlan'];
type Advice = Schemas['DebuggerAdvice'];
type PatchPreview = Schemas['PatchPreview'];
type Props = { targetId: string; targetBackend: string; modelId: string };

const hex = (value: number | null | undefined) => (value == null ? '—' : '0x' + value.toString(16).padStart(8, '0'));

class ContractError extends Error {}

async function fetchJson(path: string, init: RequestInit = {}): Promise<unknown> {
  const response = await fetch(path, { ...init, headers: { 'Content-Type': 'application/json', ...init.headers } });
  if (!response.ok) {
    const body = await response.json().catch(() => ({ detail: 'Request failed' }));
    throw new Error(typeof body.detail === 'string' ? body.detail : 'Request failed');
  }
  return response.json();
}

function contractFailure(what: string, errors: string[]) {
  return new ContractError(`The ${what} response did not match the backend contract and was not displayed. ${errors.join('; ')}`);
}

function AdviceView({ advice }: { advice: Advice }) {
  return <div className="advice" data-testid="advice">
    <h3>{advice.summary}</h3>
    <div className="hypothesis"><strong>Hypothesis</strong><p>{advice.hypothesis}</p></div>
    <h3>Evidence observations</h3><ul>{(advice.observations ?? []).map((item, i) => <li key={i}>{item}</li>)}</ul>
    <h3>Proposed typed actions</h3>
    {(advice.actions ?? []).map((item, index) => {
      const known = KNOWN_OPERATIONS.includes(String(item.operation));
      return <article key={index} data-testid="advice-action" className={known ? '' : 'unrecognized'}>
        <div><strong>{String(item.operation).replaceAll('_', ' ')}</strong>
          <span>{!known ? 'UNRECOGNIZED · not executable' : item.requires_approval ? 'HITL required' : 'read-only'}</span></div>
        <p>{item.rationale}</p>
        {(item.address != null || item.length != null || item.count != null) &&
          <code>{[item.address != null && hex(item.address), item.length != null && item.length + ' bytes', item.count != null && '× ' + item.count].filter(Boolean).join(' · ')}</code>}
      </article>;
    })}
    <h3>Limitations</h3><ul>{(advice.limitations ?? []).map((item, i) => <li key={i}>{item}</li>)}</ul>
  </div>;
}

export default function Workbench({ targetId, targetBackend, modelId }: Props) {
  const [plans, setPlans] = useState<Plan[]>([]), [planId, setPlanId] = useState(''), [objective, setObjective] = useState('Explain the captured control flow and recommend the next evidence-backed debugger action.');
  const [advice, setAdvice] = useState<Advice | null>(null), [preview, setPreview] = useState<PatchPreview | null>(null), [busy, setBusy] = useState(false);
  const [error, setError] = useState(''), [adviceError, setAdviceError] = useState(''), [patchError, setPatchError] = useState('');
  const [address, setAddress] = useState('0x402f0400'), [original, setOriginal] = useState('00000000'), [replacement, setReplacement] = useState('0000a0e1'), [mode, setMode] = useState<'arm' | 'thumb'>('arm');
  useEffect(() => {
    void fetchJson('/api/attack-lab/plans').then(raw => {
      const { valid, rejected } = validateList('AttackPlan', raw);
      setPlans(valid);
      if (rejected.length) setError(`${rejected.length} retained plan(s) failed contract validation and are hidden: ${rejected[0]}`);
      const withEvidence = valid.find(item => item.captures.length);
      if (withEvidence) {
        setPlanId(withEvidence.plan_id ?? "");
        setAddress(hex(withEvidence.captures[0].base_address));
        setMode(withEvidence.captures[0].evidence.instruction_mode === 'thumb' ? 'thumb' : 'arm');
      }
    }).catch(e => setError(String(e instanceof Error ? e.message : e)));
  }, []);
  const plan = useMemo(() => plans.find(item => item.plan_id === planId) || null, [plans, planId]);
  const capture = plan?.captures.at(-1), registers = plan?.registers.at(-1);
  async function askAgent() {
    if (!plan) return;
    setBusy(true); setAdviceError('');
    try {
      const raw = await fetchJson('/api/debugger/advice', { method: 'POST', body: JSON.stringify({ plan_id: plan.plan_id, objective }) });
      const checked = validateAdvice(raw);
      if (!checked.ok) throw contractFailure('debugger advice', checked.errors);
      setAdvice(checked.value);
    } catch (e) { setAdvice(null); setAdviceError(String(e instanceof Error ? e.message : e)); } finally { setBusy(false); }
  }
  async function buildPreview() {
    if (!plan) return;
    setBusy(true); setPatchError('');
    try {
      const raw = await fetchJson('/api/workbench/patch-preview', { method: 'POST', body: JSON.stringify({ plan_id: plan.plan_id, address: Number.parseInt(address, 0), original_hex: original.replaceAll(' ', ''), replacement_hex: replacement.replaceAll(' ', ''), instruction_mode: mode }) });
      const checked = validate('PatchPreview', raw);
      if (!checked.ok) throw contractFailure('patch preview', checked.errors);
      setPreview(checked.value);
    } catch (e) { setPreview(null); setPatchError(String(e instanceof Error ? e.message : e)); } finally { setBusy(false); }
  }
  return <main className="workbench">
    <section className="workbench-hero"><div><span className="eyebrow">AUTHORIZED LAB / EVIDENCE-FIRST DEVELOPMENT</span><h1>AI Firmware Workbench</h1><p>Inspect physical JTAG evidence, ask the model for typed debugger actions, and validate byte patches offline before any hardware change.</p></div><div className="workbench-context"><span>{targetBackend.toUpperCase()} TARGET</span><span>{modelId}</span><small>{targetId}</small></div></section>
    {error && <div className="error" role="alert">{error}<button onClick={() => setError('')}>Dismiss</button></div>}
    <section className="panel artifact-select"><label>JTAG evidence plan<select value={planId} onChange={e => { setPlanId(e.target.value); setAdvice(null); setPreview(null); setAdviceError(''); setPatchError(''); }}><option value="">Select a plan with captured evidence</option>{plans.map(item => <option value={item.plan_id} key={item.plan_id}>{item.module_id} · {item.status} · {item.captures.length} captures</option>)}</select></label><div><span className="status-pill">{capture ? 'EVIDENCE LINKED' : 'NO CAPTURE'}</span><span className="status-pill offline">LIVE WRITES DISABLED</span></div></section>
    <div className="workbench-grid">
      <section className="panel evidence-code"><span className="eyebrow">01 / PHYSICAL EVIDENCE</span><h2>Memory and disassembly</h2>
        <ErrorBoundary label="Evidence view" resetKey={planId}>
          {!capture ? <div className="empty">Complete a real JTAG snapshot probe, then reopen this page.</div> : <><div className="capture-meta"><span>{hex(capture.base_address)}–{hex(capture.base_address + capture.returned_length)}</span><span>{capture.returned_length} bytes</span><span>{capture.evidence.instruction_mode.toUpperCase()} · {capture.evidence.endianness}</span><span>{capture.target_state}</span></div><small>SHA-256 {capture.content_hash}</small>{capture.evidence.approved_hex ? <pre className="hex-view">{capture.evidence.approved_hex}</pre> : <div className="withheld">{capture.evidence.withheld_reason || 'Raw hardware bytes remain at the trusted edge.'}</div>}<h3>Decoded instructions</h3>{capture.evidence.instructions?.length ? <div className="instruction-table">{capture.evidence.instructions.map(item => <div key={item.address}><code>{hex(item.address)}</code><strong>{item.mnemonic}</strong><span>{item.operands}</span></div>)}</div> : <p className="muted">No instructions decoded. Verify execution mode and capture boundaries.</p>}<h3>Registers</h3><div className="workbench-registers">{Object.entries(registers?.values || {}).map(([name, value]) => <div key={name}><span>{name}</span><code>{hex(value)}</code></div>)}</div></>}
        </ErrorBoundary></section>
      <section className="panel agent-panel"><span className="eyebrow">02 / MODEL CODING AGENT</span><h2>Debugger guidance</h2><label>Objective<textarea value={objective} maxLength={500} onChange={e => setObjective(e.target.value)} /></label><button className="primary" disabled={busy || !capture || objective.trim().length < 3} onClick={() => void askAgent()}>{busy ? 'Working…' : 'Ask debugger agent'}</button><p className="muted">The model returns schema-valid proposals only. It cannot emit or execute raw GDB, OpenOCD, shell, or write commands.</p>
        {adviceError && <div className="error" role="alert" data-testid="advice-error">{adviceError}<button onClick={() => setAdviceError('')}>Dismiss</button></div>}
        <ErrorBoundary label="Debugger guidance" resetKey={advice}>{advice && <AdviceView advice={advice} />}</ErrorBoundary></section>
      <section className="panel patch-panel"><span className="eyebrow">03 / IMMUTABLE PATCH DRAFT</span><h2>Binary patch preview</h2><p className="muted">Draft an equal-length change covered by the selected capture. Previewing never writes to hardware.</p><label>Runtime address<input value={address} onChange={e => setAddress(e.target.value)} /></label><label>Instruction mode<select value={mode} onChange={e => setMode(e.target.value as 'arm' | 'thumb')}><option value="arm">ARM / A32</option><option value="thumb">Thumb</option></select></label><label>Expected original bytes<input className="mono" value={original} onChange={e => setOriginal(e.target.value)} /></label><label>Replacement bytes<input className="mono" value={replacement} onChange={e => setReplacement(e.target.value)} /></label><button className="primary" disabled={busy || !capture} onClick={() => void buildPreview()}>Validate offline patch</button>
        {patchError && <div className="error" role="alert">{patchError}<button onClick={() => setPatchError('')}>Dismiss</button></div>}
        <ErrorBoundary label="Patch preview" resetKey={preview}>{preview && <div className="patch-preview"><div className="patch-verdict"><strong>OFFLINE PREVIEW VERIFIED</strong><span>Hardware unchanged</span></div><p>{hex(preview.address)} · {preview.length} bytes · {preview.instruction_mode}</p><div className="patch-diff"><div><small>BEFORE</small><code>{preview.original_hex}</code>{preview.original_instructions.map(item => <span key={item.address}>{item.mnemonic} {item.operands}</span>)}</div><div><small>AFTER</small><code>{preview.replacement_hex}</code>{preview.replacement_instructions.map(item => <span key={item.address}>{item.mnemonic} {item.operands}</span>)}</div></div><ul>{preview.warnings.map((item, i) => <li key={i}>{item}</li>)}</ul></div>}</ErrorBoundary></section>
    </div>
    <section className="panel roadmap"><span className="eyebrow">04 / TOOLCHAIN ADAPTERS</span><div><article><strong>Capstone</strong><span>Active · immediate ARM/Thumb decoding</span></article><article><strong>Ghidra Headless</strong><span>Next · functions, xrefs, CFG and pseudocode</span></article><article><strong>GDB/MI</strong><span>Next · typed breakpoints and bounded stepping</span></article><article><strong>Volatile patch executor</strong><span>Locked · snapshot, read-back and rollback required</span></article></div></section>
  </main>;
}
