import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import type { components } from './api';
import AttackLab from './AttackLab';
import Workbench from './Workbench';
import BundleExport from './BundleExport';
import ErrorBoundary from './ErrorBoundary';
import ReadinessPanel from './ReadinessPanel';
import { validate } from './contract';
import './style.css';
import './enhancements.css';
type Run = components['schemas']['RunState'];
type Profile = components['schemas']['TargetProfile'];
type UartMode='observe'|'interrupt'|'credential_check';
type UartResult={status:string;mode:UartMode;port:string;baud:number;transcript_hash:string;transcript_bytes:number;transcript_excerpt:string;uboot_version?:string;kernel_version?:string;boot_observed:boolean;autoboot_interrupt_window:boolean;uboot_prompt_obtained:boolean;default_credentials_advertised:boolean;configured_login_attempted:boolean;configured_login_succeeded:boolean;root_without_additional_prompt:boolean;observations:string[];errors:string[]};
type RunSummary={run_id:string;created_at:string;status:string;purpose:string;target_backend:string;inference_backend:string;model_id:string;capture_count:number;bytes_requested:number;elapsed_ms:number;termination_reason?:string};
type Dependency={id:string;label:string;status:string;detail:string;latency_ms:number;checked_at:string};
type Readiness=components['schemas']['Readiness'];
type Config = {profile:Profile|null;target:{state:string|null;target_backend:string|null;recovery_required:boolean|null};readiness:Readiness;uart:{enabled:boolean;port?:string;baud?:number};inference_backend:string;model_id:string;dependencies:Dependency[];pricing:{input_usd_per_million:number|null;output_usd_per_million:number|null};attack_lab:{live_jtag_enabled:boolean}};
// An orchestrator that predates the readiness contract sends no `readiness`. Treat that as an explicit,
// blocked state (never as ready) so retained evidence stays reviewable while live controls stay disabled.
function withReadiness(c:Config):Config{
  if((c as Partial<Config>).readiness)return c;
  const blocker={code:'orchestrator_legacy_config',message:'The orchestrator predates the readiness contract; restart it on current code.'};
  return {...c,readiness:{checked_at:new Date().toISOString(),edge:'incompatible',compatible:false,incompatibilities:[blocker],run_ready:false,live_ready:false,blockers:[blocker],stale:false,
    orchestrator_build:{component:'orchestrator',version:'unknown',source_fingerprint:'unknown',build_id:'unknown (legacy orchestrator)',process_started_at:'unknown',pid:0,python:'unknown'},orchestrator_source_drift:false} as Readiness};
}
const hex=(n:number)=>'0x'+n.toString(16).padStart(8,'0');
async function api<T>(path:string,init:RequestInit={}):Promise<T>{
  const res=await fetch(path,{...init,headers:{'Content-Type':'application/json',...init.headers}});
  if(!res.ok){const body=await res.json().catch(()=>({detail:'Connection failed'}));throw new Error(body.detail||'Request failed');}
  return res.json();
}
function App(){
  const [config,setConfig]=useState<Config|null>(null),[run,setRun]=useState<Run|null>(null);
  const [history,setHistory]=useState<RunSummary[]>([]),[pendingDelete,setPendingDelete]=useState(false);
  const [password,setPassword]=useState(''),[error,setError]=useState(''),[signed,setSigned]=useState(false);
  const [purpose,setPurpose]=useState('bootloader inspection'),[scope,setScope]=useState<string[]>([]);
  const [busy,setBusy]=useState(false),[selected,setSelected]=useState(0),[timeline,setTimeline]=useState<Record<string,unknown>[]>([]);
  const [budget,setBudget]=useState(16384),[streamState,setStreamState]=useState('idle');
  const [uartMode,setUartMode]=useState<UartMode>('observe'),[uartResult,setUartResult]=useState<UartResult|null>(null),[uartState,setUartState]=useState('idle');
  const [uartBusy,setUartBusy]=useState(false),[uartRemaining,setUartRemaining]=useState(0);
  const [page,setPage]=useState<'workspace'|'attack'|'workbench'>('workspace');
  const [readinessAt,setReadinessAt]=useState(0),[now,setNow]=useState(Date.now());
  const active=!!run&&['running','queued'].includes(run.status);
  async function refreshHistory(){setHistory(await api<RunSummary[]>('/api/runs'));}
  async function load(){try{const [raw,h]=await Promise.all([api<Config>('/api/config'),api<RunSummary[]>('/api/runs')]);const c=withReadiness(raw);const checked=validate('Readiness',c.readiness);if(!checked.ok)throw new Error('Readiness did not match the backend contract: '+checked.errors[0]);setConfig(c);setReadinessAt(Date.now());setHistory(h);setSigned(true);setScope(c.profile?c.profile.regions.filter(r=>r.approved).map(r=>r.name):[]);setError('');}catch(e){setError(String(e));}}
  async function refreshConfig(){try{const c=withReadiness(await api<Config>('/api/config'));const checked=validate('Readiness',c.readiness);if(checked.ok){setConfig(c);setReadinessAt(Date.now());}}catch{/* the age counter marks this status stale */}}
  useEffect(()=>{void load();},[]);
  useEffect(()=>{const timer=window.setInterval(()=>setNow(Date.now()),1000);return()=>window.clearInterval(timer);},[]);
  useEffect(()=>{if(!signed||active||busy)return;let inflight=false;const timer=window.setInterval(async()=>{if(inflight)return;inflight=true;try{await refreshConfig();}finally{inflight=false;}},5000);return()=>window.clearInterval(timer);},[signed,active,busy]);
  useEffect(()=>{
    if(!run?.run_id)return;
    const id=run.run_id;
    const source=new EventSource('/api/runs/'+id+'/events');
    setStreamState('connecting');
    const refresh=()=>api<Run>('/api/runs/'+id).then(setRun).catch(e=>setError(String(e)));
    source.onopen=()=>setStreamState('connected');
    source.onmessage=e=>{const event=JSON.parse(e.data);setTimeline(old=>old.some(x=>x.id===event.id)?old:[...old,event]);void refresh();};
    source.addEventListener('done',()=>{source.close();setStreamState('complete');void refresh();void refreshHistory();});
    source.onerror=()=>{setStreamState('disconnected / retrying');void refresh();};
    return ()=>source.close();
  },[run?.run_id]);
  async function login(e:React.FormEvent){e.preventDefault();setBusy(true);try{await api('/api/login',{method:'POST',body:JSON.stringify({password})});setPassword('');await load();}catch(e){setError(String(e));}finally{setBusy(false);}}
  async function logout(){setBusy(true);try{await api('/api/logout',{method:'POST'});setSigned(false);setConfig(null);setRun(null);setHistory([]);setTimeline([]);setUartResult(null);setUartState('idle');setStreamState('idle');setError('');}catch(e){setError(String(e));}finally{setBusy(false);}}
  async function start(){if(!config||!config.profile)return;setBusy(true);setError('');setTimeline([]);setSelected(0);try{
    const r=await api<Run>('/api/runs',{method:'POST',body:JSON.stringify({target_id:config.profile.target_id,purpose,region_names:scope,byte_budget:budget})});setRun(r);void refreshHistory();
  }catch(e){setError(String(e));}finally{setBusy(false);}}
  async function cancel(){if(run)try{await api('/api/runs/'+run.run_id+'/cancel',{method:'POST'});}catch(e){setError(String(e));}}
  async function openRun(id:string){try{const loaded=await api<Run>('/api/runs/'+id);setRun(loaded);setTimeline(loaded.events as Record<string,unknown>[]);setSelected(0);setStreamState(['running','queued'].includes(loaded.status)?'connecting':'complete');setError('');}catch(e){setError(String(e));}}
  async function startUart(){setUartBusy(true);setError('');setUartResult(null);setUartRemaining(uartMode==='credential_check'?0:90);setUartState(uartMode==='credential_check'?'checking configured account':'armed — power-cycle the board within 90 seconds');try{const result=await api<UartResult>('/api/uart/audit',{method:'POST',body:JSON.stringify({mode:uartMode,timeout_seconds:90})});setUartResult(result);setUartState(result.status);}catch(e){setError(String(e));setUartState('failed');}finally{setUartBusy(false);setUartRemaining(0);}}
  async function deleteRun(){if(!run)return;try{await api('/api/runs/'+run.run_id,{method:'DELETE'});setRun(null);setTimeline([]);setPendingDelete(false);await refreshHistory();}catch(e){setError(String(e));}}
  useEffect(()=>{if(!uartBusy||uartMode==='credential_check'||uartRemaining<=0)return;const timer=window.setInterval(()=>setUartRemaining(value=>Math.max(0,value-1)),1000);return()=>window.clearInterval(timer);},[uartBusy,uartMode,uartRemaining]);
  const ageSeconds=Math.max(0,(now-readinessAt)/1000),stale=ageSeconds>15;
  const runReady=!!config&&config.readiness.run_ready&&!stale,liveReady=!!config&&config.readiness.live_ready&&!stale;
  const offline=signed&&!!config&&!config.profile;
  const capture=run?.captures[selected];
  const registers=run?.registers[selected];
  const evidence=capture?.evidence;
  const byteRows=evidence?.approved_hex?.match(/.{1,32}/g)||[];
  const authorizedBytes=config?.profile?.regions.filter(r=>r.approved&&scope.includes(r.name)).reduce((sum,r)=>sum+r.end-r.start,0)||0;
  const acceptedFindings=run?.findings.filter(f=>f.status!=='rejected')||[];
  const rejectedFindings=run?.findings.filter(f=>f.status==='rejected')||[];
  const tokenUsage=(run?.provider_usage||[]).reduce<{input:number;output:number;total:number}>((sum,u)=>{const input=Number(u.prompt_tokens)||0,output=Number(u.completion_tokens)||0,total=Number(u.total_tokens)||input+output;return {input:sum.input+input,output:sum.output+output,total:sum.total+total}},{input:0,output:0,total:0});
  const estimatedCost=config&&config.pricing.input_usd_per_million!==null&&config.pricing.output_usd_per_million!==null?(tokenUsage.input*config.pricing.input_usd_per_million+tokenUsage.output*config.pricing.output_usd_per_million)/1_000_000:null;
  const terminationHelp=run?.termination_reason==='invalid_proposal'?'The model requested an address outside the approved range. The policy gate blocked it.':run?.termination_reason==='dependency_failure'?'A local target or inference dependency failed. Check readiness, then retry.':run?.termination_reason==='deadline_exceeded'?'The bounded run deadline expired before completion.':run?.termination_reason==='operator_cancelled'?'The operator cancelled this run; collected evidence remains available.':'';
  return <div className="shell">
    <header><a className="brand" href="/"><span className="chip">S</span><div>SiliconSentinel<small>JTAGent / EMBEDDED EVIDENCE CONSOLE</small></div></a><div className="header-actions">{signed&&<nav className="app-nav" aria-label="Workspace"><button className={page==='workspace'?'active':''} onClick={()=>setPage('workspace')}>Investigation</button><button className={page==='attack'?'active':''} onClick={()=>setPage('attack')}>Attack Lab</button><button className={page==='workbench'?'active':''} onClick={()=>setPage('workbench')}>AI Workbench</button></nav>}<span className="version">LAB WORKSPACE · v0.1</span>{signed&&<button onClick={()=>void logout()} disabled={busy}>Sign out</button>}</div></header>
    {!signed?<main className="login"><span className="eyebrow">OPERATOR ACCESS</span><h1>Inspect with evidence.</h1><p>Sign in with the password printed by the local launcher.</p><form onSubmit={login}><label>Operator password<input type="password" value={password} onChange={e=>setPassword(e.target.value)} autoComplete="current-password"/></label><button disabled={busy}>Sign in</button></form>{error&&<p role="alert" className="error">{error}</p>}</main>:
    <>{offline&&config?<main className="panel offline" role="alert" data-testid="edge-offline"><h2>Edge service unavailable</h2><p>The orchestrator cannot read the target profile, so audits and hardware controls are disabled. Locally exported evidence bundles remain on disk and verifiable offline.</p><ReadinessPanel readiness={config.readiness} ageSeconds={ageSeconds} stale={stale}/><button onClick={()=>void load()}>Reconnect</button></main>:page==='attack'&&config?.profile?<AttackLab targetId={config.profile.target_id} targetBackend={config.target.target_backend??'unknown'} modelId={config.model_id} liveJtagEnabled={config.attack_lab.live_jtag_enabled} liveReady={liveReady} liveBlockers={config.readiness.blockers.map(b=>b.code)}/>:page==='workbench'&&config?.profile?<ErrorBoundary label="AI Workbench"><Workbench targetId={config.profile.target_id} targetBackend={config.target.target_backend??'unknown'} modelId={config.model_id}/></ErrorBoundary>:<><section className="intro"><div><span className="eyebrow">AUTHORIZED LAB / CPU & MEMORY INSPECTION</span><h1>From bytes to bounded findings.</h1><p>Collect a scoped snapshot. Decode locally. Follow the evidence.</p></div><div className="modebox"><span className="badge">{(config?.target.target_backend??'unknown').toUpperCase()} TARGET</span><span className="badge">{config?.inference_backend.toUpperCase()} ANALYSIS</span><small>{config?.target.target_backend==='mock'?'Synthetic target data · no physical board connected':config?.profile?.provenance}</small></div></section>
    {config&&<ReadinessPanel readiness={config.readiness} ageSeconds={ageSeconds} stale={stale}/>}
    <section className="readiness" aria-label="Dependency readiness">{config?.dependencies.map(d=><div className={'dependency '+d.status} key={d.id}><span>{d.label}</span><strong>{d.status}</strong><small>{d.detail}<br/>{d.latency_ms.toFixed(1)} ms · {d.checked_at.slice(11,19)} UTC</small></div>)}</section>
    <div className="mobile-status"><span>{run?.status||'ready'}</span><span>{run?.captures.length||0} captures</span><span>{streamState}</span>{active&&<button onClick={()=>void cancel()}>Cancel</button>}</div>
    {error&&<div className="error" role="alert">{error}<button onClick={()=>void load()}>Reconnect</button></div>}
    <main className="layout"><aside className="panel scope"><span className="eyebrow">01 / INVESTIGATION</span><h2>Audit scope</h2>
      <label>Target profile<select disabled={active}><option>{config?.profile?.target_id}</option></select></label>
      <label>Investigation<select value={purpose} disabled={active} onChange={e=>setPurpose(e.target.value)}>{['bootloader inspection','firmware triage','crash investigation'].map(p=><option key={p}>{p}</option>)}</select></label>
      <label>Memory budget<select value={budget} disabled={active} onChange={e=>setBudget(+e.target.value)}><option value={256}>256 bytes</option><option value={4096}>4 KiB</option><option value={16384}>16 KiB</option></select></label>
      <div className="limits">12 captures · 4 analysis iterations<br/>120-second deadline · 256-byte initial reads<br/>Budget: {budget} bytes · Currently authorized: {authorizedBytes} bytes</div>
      <h3>Configured regions</h3><p className="muted">Ends exclusive. These ranges are configured, not discovered.</p>
      {config?.profile?.regions.map(r=><label className={'region '+(!r.approved?'excluded':'')} key={r.name}><input type="checkbox" checked={scope.includes(r.name)} disabled={active||!r.approved} onChange={e=>setScope(s=>e.target.checked?[...s,r.name]:s.filter(n=>n!==r.name))}/><span>{r.name}<small>{hex(r.start)}–{hex(r.end)}<br/>{!r.approved?'Excluded':run?.captures.some(c=>c.base_address>=r.start&&c.base_address<r.end)?'Inspected capture available':'Configured / not inspected'}</small></span></label>)}
      <div className="memory-map" aria-label="Configured memory map">{config?.profile?.regions.map(r=><div key={r.name}><span>{r.name}</span><div className={'memory-track '+(!r.approved?'excluded':scope.includes(r.name)?'approved':'configured')}><i className={run?.captures.some(c=>c.base_address>=r.start&&c.base_address<r.end)?'inspected':''}/></div><small>{r.end-r.start} bytes · {!r.approved?'excluded':scope.includes(r.name)?'approved':'not selected'}</small></div>)}</div>
      <button className="primary" onClick={()=>void start()} disabled={busy||uartBusy||active||!scope.length||!config||!runReady}>Start audit</button>
      {config&&!runReady&&<p className="notice" role="status" data-testid="start-blocked">Audit blocked: {stale?'status is stale; ':''}{config.readiness.blockers.map(b=>b.code).join(', ')||'readiness not established'}. Evidence review and offline tools remain available.</p>}
      <button className="secondary" onClick={()=>void cancel()} disabled={!active}>Cancel audit</button>
      <p className="muted">Snapshots restore execution locally. Live independent halt/step and writes are disabled.</p>
      <h3>UART security audit</h3>
      {!config?.uart.enabled?<p className="muted">UART audit is disabled at the edge.</p>:<><label>Fixed audit mode<select value={uartMode} disabled={uartBusy} onChange={e=>{setUartMode(e.target.value as UartMode);setUartState('idle');setUartResult(null)}}><option value="observe">Observe boot only</option><option value="interrupt">Interrupt U-Boot once</option><option value="credential_check">Validate configured account</option></select></label><p className="muted">{uartMode==='credential_check'?'No power cycle required. Uses only the fixed configured identity checks.':'Arm first, then physically power-cycle the board. No software reset or power relay is configured.'}</p><button className="secondary" onClick={()=>void startUart()} disabled={uartBusy||active}>Arm UART audit</button><p className="muted">{config.uart.port} · {config.uart.baud} 8N1<br/>{uartState}{uartRemaining>0?' · '+uartRemaining+'s remaining':''}</p><ol className="uart-steps">{(uartMode==='credential_check'?['Armed','Login prompt','Identity checks','Logged out']:['Armed','Boot detected',uartMode==='interrupt'?'U-Boot interrupted':'Boot captured','Complete']).map((step,index)=>{const reached=uartResult?(index===0||index===1&&uartResult.boot_observed||index===2&&(uartResult.uboot_prompt_obtained||uartMode==='observe'&&uartResult.boot_observed)||index===3&&uartResult.status==='completed'):uartBusy&&index===0;return <li className={reached?'reached':''} key={step}>{step}</li>})}</ol>{uartResult?.errors.includes('no_uart_data_received')&&<button className="secondary" onClick={()=>void startUart()}>Retry and power-cycle</button>}</>}
      <h3>Run history</h3><div className="run-history">{history.length?history.map(item=><button className={run?.run_id===item.run_id?'selected':''} key={item.run_id} onClick={()=>void openRun(item.run_id)}><span>{item.purpose}</span><strong>{item.status}</strong><small>{item.created_at.slice(0,19).replace('T',' ')} · {item.capture_count} captures · {item.elapsed_ms.toFixed(0)} ms</small></button>):<p className="muted">No retained runs.</p>}</div>
    </aside><div className="workspace"><div className="stats"><div><small>RUN STATE</small><strong>{run?.status||'Ready'}</strong></div><div><small>BYTES REQUESTED</small><strong>{run?.bytes_requested||0}<em> / {budget}</em></strong></div><div><small>EVIDENCE CAPTURES</small><strong>{run?.captures.length||0}</strong></div><div><small>EVENT STREAM</small><strong className="small-value">{streamState}</strong></div></div>
      <section className="panel"><div className="section-head"><div><span className="eyebrow">02 / CAPTURED EVIDENCE</span><h2>Memory inspector</h2></div><select aria-label="Evidence capture" value={selected} onChange={e=>setSelected(+e.target.value)}>{run?.captures.map((c,i)=><option key={c.evidence_id} value={i}>{hex(c.base_address)} · generation {c.generation}</option>)}</select></div>
      {!capture?<div className="empty">No evidence collected. Start an audit to inspect approved memory.</div>:<>
      <div className="metadata">{capture.source_mode} · {capture.address_space} · {capture.returned_length}/{capture.requested_length} bytes · {capture.timestamp}<br/>{evidence?.decoder} · {evidence?.instruction_mode} · {evidence?.endianness} · {capture.target_state} at capture<br/>SHA256 {capture.content_hash}</div>
      <div className="inspect-grid"><div><h3>Hex / ASCII</h3>{byteRows.length?<pre>{byteRows.map((row,i)=>hex(capture.base_address+i*16)+'  '+(row.match(/../g)||[]).join(' ').padEnd(47)+'  '+(row.match(/../g)||[]).map(x=>{const b=parseInt(x,16);return b>=32&&b<=126?String.fromCharCode(b):'.';}).join('')).join('\n')}</pre>:<p className="notice">{evidence?.withheld_reason||'No approved bytes returned'}</p>}
      <h3>Attributed strings</h3>{evidence?.strings.length?evidence.strings.map((s,i)=><div className="string" key={i}><code>{hex(s.address)}</code><span>{s.text}</span></div>):<p className="muted">No printable strings in this capture.</p>}</div>
      <div><h3>Decoded instructions</h3>{evidence?.instructions.length?<pre>{evidence.instructions.map(i=>hex(i.address)+'  '+i.mnemonic+' '+i.operands).join('\n')}</pre>:<p className="muted">Data region or instructions withheld; no code claim.</p>}<h3>Registers</h3><small>{registers?.timestamp||'No register capture'}</small><div className="registers">{Object.entries(registers?.values||{}).map(([k,v])=><div key={k}><span>{k}</span><code>{hex(v)}</code></div>)}</div></div></div>
      <p className="muted">{capture.consistency}. Captured generations describe historical evidence.</p></>}
      </section>
      <section className="panel"><div className="section-head"><div><span className="eyebrow">03 / VERIFIED REFERENCES</span><h2>Findings</h2></div><div className="exports">{run&&<><a href={'/api/runs/'+run.run_id+'/report.md'}>Export Markdown</a><a href={'/api/runs/'+run.run_id+'/report.json'}>Export JSON</a>{!active&&<BundleExport endpoint={'/api/runs/'+run.run_id+'/bundle'}/>}</>}</div></div>
      {run&&<div className="usage"><div><small>INPUT TOKENS</small><strong>{tokenUsage.input.toLocaleString()}</strong></div><div><small>OUTPUT TOKENS</small><strong>{tokenUsage.output.toLocaleString()}</strong></div><div><small>TOTAL TOKENS</small><strong>{tokenUsage.total.toLocaleString()}</strong></div><div><small>ESTIMATED COST</small><strong>{estimatedCost===null?'Rate not set':'$'+estimatedCost.toFixed(4)}</strong></div></div>}
      {!acceptedFindings.length?<div className="empty">{active?'Collection and analysis in progress…':'No accepted findings yet. An empty result is not a security certification.'}</div>:acceptedFindings.map((f,i)=><article className="finding" key={i}><div><span className="badge">{f.status}</span><small>{f.severity} severity · {f.confidence} confidence</small></div><h3>{f.title}</h3><p>{f.explanation}</p><div className="evidence-links">{f.evidence_ids.map(id=><button key={id} onClick={()=>{const index=run!.captures.findIndex(c=>c.evidence_id===id);if(index>=0)setSelected(index);}}>Evidence {id.slice(0,8)}</button>)}</div><p className="muted">{f.limitations.join(' ')}</p><p><b>Next verification:</b> {f.suggested_verification}</p></article>)}
      {rejectedFindings.length>0&&<div className="rejected-findings"><h3>Rejected by evidence verifier</h3><p className="muted">These model claims are retained for auditability but are not presented as findings.</p>{rejectedFindings.map((f,i)=><article className="finding rejected" key={i}><div><span className="badge">rejected</span><small>{f.severity} severity · {f.confidence} confidence</small></div><h3>{f.title}</h3><p>{f.explanation}</p><p className="muted">{f.limitations.join(' ')}</p></article>)}</div>}
      {run?.termination_reason&&<p className="notice">Termination: {run.termination_reason} · {run.elapsed_ms.toFixed(0)} ms{run.errors.length?' · '+run.errors.join('; '):''}</p>}
      {terminationHelp&&<div className="failure-help"><strong>What happened</strong><p>{terminationHelp}</p>{['dependency_failure','deadline_exceeded'].includes(run?.termination_reason||'')&&<button className="secondary" onClick={()=>void start()} disabled={busy||active||!runReady}>Retry audit</button>}</div>}
      </section>
      <section className="panel"><span className="eyebrow">04 / LOCAL UART EVIDENCE</span><h2>Boot and console assessment</h2>{!uartResult?<div className="empty">{uartMode==='credential_check'?'Run the fixed configured-account check; no reboot is required.':'Arm the listener, then physically power-cycle the board during its 90-second window.'}</div>:<><div className="metadata">{uartResult.status} · {uartResult.mode} · {uartResult.port} at {uartResult.baud} baud · {uartResult.transcript_bytes} bytes<br/>SHA256 {uartResult.transcript_hash}</div><h3>Observations</h3>{uartResult.observations.length?<ul>{uartResult.observations.map((o,i)=><li key={i}>{o}</li>)}</ul>:<p className="muted">No configured exposure observed.</p>}<div className="registers"><div><span>Boot observed</span><code>{String(uartResult.boot_observed)}</code></div><div><span>U-Boot prompt</span><code>{String(uartResult.uboot_prompt_obtained)}</code></div><div><span>Login succeeded</span><code>{String(uartResult.configured_login_succeeded)}</code></div><div><span>Root without prompt</span><code>{String(uartResult.root_without_additional_prompt)}</code></div></div><h3>Redacted transcript excerpt</h3><pre>{uartResult.transcript_excerpt}</pre>{uartResult.errors.length>0&&<p className="notice">{uartResult.errors.join('; ')}</p>}</>}
      </section>
    </div><aside className="panel timeline"><span className="eyebrow">LIVE / ACTION LOG</span><h2>Investigation timeline</h2><p className="muted">Concise actions and results, with policy decisions.</p>{!timeline.length?<p className="empty">Waiting for an audit.</p>:timeline.map((e,i)=><div className="event" key={i}><small>{String(e.time).slice(11,23)}</small><strong>{String(e.node)}</strong><p>{String(e.message)}</p></div>)}
    {run&&!active&&<button className="secondary danger" onClick={()=>setPendingDelete(true)}>Delete run from memory</button>}
    </aside></main><footer>Evidence remains in process memory for up to one hour. Exports are operator-managed. Provider retention: unverified.</footer>
    {pendingDelete&&run&&<div className="modal-backdrop"><div className="confirm-dialog" role="dialog" aria-modal="true" aria-labelledby="delete-title"><span className="eyebrow">DESTRUCTIVE ACTION</span><h2 id="delete-title">Delete in-memory evidence?</h2><p>Run <code>{run.run_id}</code> and its captures will be removed from this process. Export first if you need to preserve the evidence.</p><div><button className="secondary" onClick={()=>setPendingDelete(false)}>Keep run</button><button className="danger" onClick={()=>void deleteRun()}>Delete permanently</button></div></div></div>}</>}</>}
  </div>;
}
createRoot(document.getElementById('root')!).render(<App/>);
