import type { components } from './api';

type Readiness = components['schemas']['Readiness'];
type Props = { readiness: Readiness; ageSeconds: number; stale: boolean };

const yn = (v: boolean | null | undefined, yes = 'yes', no = 'no') => (v == null ? 'unknown' : v ? yes : no);

/** Shows each status layer separately. Unknown stays unknown; nothing here computes readiness. */
export default function ReadinessPanel({ readiness: r, ageSeconds, stale }: Props) {
  const verdict = r.edge === 'unreachable' ? 'EDGE UNREACHABLE'
    : r.edge === 'incompatible' ? 'INCOMPATIBLE EDGE'
    : stale ? 'STATUS STALE'
    : r.live_ready ? 'LIVE OPERATIONS READY'
    : r.run_ready ? (r.target_backend === 'openocd' ? 'READY' : 'READY · NON-LIVE BACKEND')
    : 'BLOCKED';
  const tone = r.edge !== 'ok' || stale ? 'bad' : r.run_ready ? 'good' : 'warn';
  const layers: [string, string][] = [
    ['Application', r.edge === 'ok' ? 'ok' : r.edge],
    ['Debugger reachable', yn(r.debugger?.reachable)],
    ['OpenOCD version', r.debugger?.applicable === false ? 'not applicable' : (r.debugger?.version ?? 'unknown') + (r.debugger ? ' · compatible: ' + yn(r.debugger.version_ok) : '')],
    ['Target communication', r.target?.communication ?? 'unknown'],
    ['Execution state', r.target?.execution_state ?? 'unknown'],
    ['Snapshots armed', yn(r.snapshots_armed)],
    ['Recovery required', yn(r.recovery_required, 'YES', 'no')],
    ['Status schema', r.schema_version == null ? 'none / unsupported' : 'v' + r.schema_version],
  ];
  return <section className={'readiness-panel ' + tone} aria-label="Layered readiness" data-testid="readiness-panel">
    <div className="readiness-head"><strong data-testid="readiness-verdict">{verdict}</strong>
      <small>observed {ageSeconds.toFixed(0)}s ago{stale ? ' · older than the freshness limit' : ''}</small></div>
    <div className="layers">{layers.map(([name, value]) => <div key={name} data-testid={'layer-' + name.toLowerCase().replaceAll(' ', '-')}><span>{name}</span><code>{value}</code></div>)}</div>
    {r.read_prerequisite && <p className="muted">{r.read_prerequisite}</p>}
    {r.blockers.length > 0 && <ul className="blockers" data-testid="readiness-blockers">{r.blockers.map(b => <li key={b.code}><code>{b.code}</code> {b.message}</li>)}</ul>}
    <p className="muted builds">Edge build <code>{r.edge_build?.build_id ?? 'unknown'}</code>{r.edge_source_drift ? ' — source on disk has changed since it started; restart to load it' : ''} · Orchestrator build <code>{r.orchestrator_build.build_id}</code>{r.orchestrator_source_drift ? ' — source on disk has changed since it started' : ''}</p>
  </section>;
}
