import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import type { components } from './api';
import './style.css';
type Run = components['schemas']['RunState'];
type Profile = components['schemas']['TargetProfile'];
type Config = {profile:Profile;target:{state:string;target_backend:string;recovery_required:boolean};inference_backend:string;model_id:string};
const hex=(n:number)=>'0x'+n.toString(16).padStart(8,'0');
async function api<T>(path:string,init:RequestInit={}):Promise<T>{
  const res=await fetch(path,{...init,headers:{'Content-Type':'application/json',...init.headers}});
  if(!res.ok){const body=await res.json().catch(()=>({detail:'Connection failed'}));throw new Error(body.detail||'Request failed');}
  return res.json();
}
function App(){
  const [config,setConfig]=useState<Config|null>(null),[run,setRun]=useState<Run|null>(null);
  const [password,setPassword]=useState(''),[error,setError]=useState(''),[signed,setSigned]=useState(false);
  const [purpose,setPurpose]=useState('bootloader inspection'),[scope,setScope]=useState<string[]>([]);
  const [busy,setBusy]=useState(false),[selected,setSelected]=useState(0),[timeline,setTimeline]=useState<Record<string,unknown>[]>([]);
  const [budget,setBudget]=useState(16384),[streamState,setStreamState]=useState('idle');
  const active=!!run&&['running','queued'].includes(run.status);
  async function load(){try{const c=await api<Config>('/api/config');setConfig(c);setSigned(true);setScope(c.profile.regions.filter(r=>r.approved).map(r=>r.name));setError('');}catch(e){setError(String(e));}}
  useEffect(()=>{void load();},[]);
  useEffect(()=>{
    if(!run?.run_id)return;
    const id=run.run_id;
    const source=new EventSource('/api/runs/'+id+'/events');
    setStreamState('connecting');
    const refresh=()=>api<Run>('/api/runs/'+id).then(setRun).catch(e=>setError(String(e)));
    source.onopen=()=>setStreamState('connected');
    source.onmessage=e=>{const event=JSON.parse(e.data);setTimeline(old=>old.some(x=>x.id===event.id)?old:[...old,event]);void refresh();};
    source.addEventListener('done',()=>{source.close();setStreamState('complete');void refresh();});
    source.onerror=()=>{setStreamState('disconnected / retrying');void refresh();};
    return ()=>source.close();
  },[run?.run_id]);
  async function login(e:React.FormEvent){e.preventDefault();setBusy(true);try{await api('/api/login',{method:'POST',body:JSON.stringify({password})});setPassword('');await load();}catch(e){setError(String(e));}finally{setBusy(false);}}
  async function start(){if(!config)return;setBusy(true);setError('');setTimeline([]);setSelected(0);try{
    const r=await api<Run>('/api/runs',{method:'POST',body:JSON.stringify({target_id:config.profile.target_id,purpose,region_names:scope,byte_budget:budget})});setRun(r);
  }catch(e){setError(String(e));}finally{setBusy(false);}}
  async function cancel(){if(run)try{await api('/api/runs/'+run.run_id+'/cancel',{method:'POST'});}catch(e){setError(String(e));}}
  const capture=run?.captures[selected];
  const registers=run?.registers[selected];
  const evidence=capture?.evidence;
  const byteRows=evidence?.approved_hex?.match(/.{1,32}/g)||[];
  return <div className="shell">
    <header><a className="brand" href="/"><span className="chip">S</span><div>SiliconSentinel<small>JTAGent / EMBEDDED EVIDENCE CONSOLE</small></div></a><span className="version">LAB WORKSPACE · v0.1</span></header>
    {!signed?<main className="login"><span className="eyebrow">OPERATOR ACCESS</span><h1>Inspect with evidence.</h1><p>Sign in with the password printed by the local launcher.</p><form onSubmit={login}><label>Operator password<input type="password" value={password} onChange={e=>setPassword(e.target.value)} autoComplete="current-password"/></label><button disabled={busy}>Sign in</button></form>{error&&<p role="alert" className="error">{error}</p>}</main>:
    <><section className="intro"><div><span className="eyebrow">AUTHORIZED LAB / CPU & MEMORY INSPECTION</span><h1>From bytes to bounded findings.</h1><p>Collect a scoped snapshot. Decode locally. Follow the evidence.</p></div><div className="modebox"><span className="badge">{config?.target.target_backend.toUpperCase()} TARGET</span><span className="badge">{config?.inference_backend.toUpperCase()} ANALYSIS</span><small>{config?.target.target_backend==='mock'?'Synthetic target data · no physical board connected':config?.profile.provenance}</small></div></section>
    {error&&<div className="error" role="alert">{error}<button onClick={()=>void load()}>Reconnect</button></div>}
    <main className="layout"><aside className="panel scope"><span className="eyebrow">01 / INVESTIGATION</span><h2>Audit scope</h2>
      <label>Target profile<select disabled={active}><option>{config?.profile.target_id}</option></select></label>
      <label>Investigation<select value={purpose} disabled={active} onChange={e=>setPurpose(e.target.value)}>{['bootloader inspection','firmware triage','crash investigation'].map(p=><option key={p}>{p}</option>)}</select></label>
      <label>Memory budget<select value={budget} disabled={active} onChange={e=>setBudget(+e.target.value)}><option value={256}>256 bytes</option><option value={4096}>4 KiB</option><option value={16384}>16 KiB</option></select></label>
      <div className="limits">12 captures · 4 analysis iterations<br/>120-second deadline · 256-byte initial reads</div>
      <h3>Configured regions</h3><p className="muted">Ends exclusive. These ranges are configured, not discovered.</p>
      {config?.profile.regions.map(r=><label className={'region '+(!r.approved?'excluded':'')} key={r.name}><input type="checkbox" checked={scope.includes(r.name)} disabled={active||!r.approved} onChange={e=>setScope(s=>e.target.checked?[...s,r.name]:s.filter(n=>n!==r.name))}/><span>{r.name}<small>{hex(r.start)}–{hex(r.end)}<br/>{!r.approved?'Excluded':run?.captures.some(c=>c.base_address>=r.start&&c.base_address<r.end)?'Inspected capture available':'Configured / not inspected'}</small></span></label>)}
      <button className="primary" onClick={()=>void start()} disabled={busy||active||!scope.length||!config}>Start audit</button>
      <button className="secondary" onClick={()=>void cancel()} disabled={!active}>Cancel audit</button>
      <p className="muted">Snapshots restore execution locally. Live independent halt/step and writes are disabled.</p>
    </aside><div className="workspace"><div className="stats"><div><small>RUN STATE</small><strong>{run?.status||'Ready'}</strong></div><div><small>BYTES REQUESTED</small><strong>{run?.bytes_requested||0}<em> / {budget}</em></strong></div><div><small>EVIDENCE CAPTURES</small><strong>{run?.captures.length||0}</strong></div><div><small>EVENT STREAM</small><strong className="small-value">{streamState}</strong></div></div>
      <section className="panel"><div className="section-head"><div><span className="eyebrow">02 / CAPTURED EVIDENCE</span><h2>Memory inspector</h2></div><select aria-label="Evidence capture" value={selected} onChange={e=>setSelected(+e.target.value)}>{run?.captures.map((c,i)=><option key={c.evidence_id} value={i}>{hex(c.base_address)} · generation {c.generation}</option>)}</select></div>
      {!capture?<div className="empty">No evidence collected. Start an audit to inspect approved memory.</div>:<>
      <div className="metadata">{capture.source_mode} · {capture.address_space} · {capture.returned_length}/{capture.requested_length} bytes · {capture.timestamp}<br/>{evidence?.decoder} · {evidence?.instruction_mode} · {evidence?.endianness} · {capture.target_state} at capture<br/>SHA256 {capture.content_hash}</div>
      <div className="inspect-grid"><div><h3>Hex / ASCII</h3>{byteRows.length?<pre>{byteRows.map((row,i)=>hex(capture.base_address+i*16)+'  '+(row.match(/../g)||[]).join(' ').padEnd(47)+'  '+(row.match(/../g)||[]).map(x=>{const b=parseInt(x,16);return b>=32&&b<=126?String.fromCharCode(b):'.';}).join('')).join('\n')}</pre>:<p className="notice">{evidence?.withheld_reason||'No approved bytes returned'}</p>}
      <h3>Attributed strings</h3>{evidence?.strings.length?evidence.strings.map((s,i)=><div className="string" key={i}><code>{hex(s.address)}</code><span>{s.text}</span></div>):<p className="muted">No printable strings in this capture.</p>}</div>
      <div><h3>Decoded instructions</h3>{evidence?.instructions.length?<pre>{evidence.instructions.map(i=>hex(i.address)+'  '+i.mnemonic+' '+i.operands).join('\n')}</pre>:<p className="muted">Data region or instructions withheld; no code claim.</p>}<h3>Registers</h3><small>{registers?.timestamp||'No register capture'}</small><div className="registers">{Object.entries(registers?.values||{}).map(([k,v])=><div key={k}><span>{k}</span><code>{hex(v)}</code></div>)}</div></div></div>
      <p className="muted">{capture.consistency}. Captured generations describe historical evidence.</p></>}
      </section>
      <section className="panel"><div className="section-head"><div><span className="eyebrow">03 / VERIFIED REFERENCES</span><h2>Findings</h2></div><div className="exports">{run&&<><a href={'/api/runs/'+run.run_id+'/report.md'}>Export Markdown</a><a href={'/api/runs/'+run.run_id+'/report.json'}>Export JSON</a></>}</div></div>
      {!run?.findings.length?<div className="empty">{active?'Collection and analysis in progress…':'No findings yet. An empty result is not a security certification.'}</div>:run.findings.map((f,i)=><article className="finding" key={i}><div><span className="badge">{f.status}</span><small>{f.severity} severity · {f.confidence} confidence</small></div><h3>{f.title}</h3><p>{f.explanation}</p><div className="evidence-links">{f.evidence_ids.map(id=><button key={id} onClick={()=>{const index=run.captures.findIndex(c=>c.evidence_id===id);if(index>=0)setSelected(index);}}>Evidence {id.slice(0,8)}</button>)}</div><p className="muted">{f.limitations.join(' ')}</p><p><b>Next verification:</b> {f.suggested_verification}</p></article>)}
      {run?.termination_reason&&<p className="notice">Termination: {run.termination_reason} · {run.elapsed_ms.toFixed(0)} ms{run.errors.length?' · '+run.errors.join('; '):''}</p>}
      </section>
    </div><aside className="panel timeline"><span className="eyebrow">LIVE / ACTION LOG</span><h2>Investigation timeline</h2><p className="muted">Concise actions and results, with policy decisions.</p>{!timeline.length?<p className="empty">Waiting for an audit.</p>:timeline.map((e,i)=><div className="event" key={i}><small>{String(e.time).slice(11,23)}</small><strong>{String(e.node)}</strong><p>{String(e.message)}</p></div>)}
    {run&&!active&&<button className="secondary" onClick={async()=>{try{await api('/api/runs/'+run.run_id,{method:'DELETE'});setRun(null);setTimeline([]);}catch(e){setError(String(e));}}}>Delete run from memory</button>}
    </aside></main><footer>Evidence remains in process memory for up to one hour. Exports are operator-managed. Provider retention: unverified.</footer></>}
  </div>;
}
createRoot(document.getElementById('root')!).render(<App/>);
