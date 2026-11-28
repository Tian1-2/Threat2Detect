'use strict';

const data = window.demoData;
const app = document.querySelector('#app');
const dialog = document.querySelector('#dialog');
const icons = {
  report:'<path d="M8 3h8m-7 0v7l-5 8a2 2 0 0 0 2 3h12a2 2 0 0 0 2-3l-5-8V3M7 15h10"/>',
  activity:'<rect x="9" y="3" width="6" height="5" rx="1"/><rect x="2" y="16" width="6" height="5" rx="1"/><rect x="16" y="16" width="6" height="5" rx="1"/><path d="M12 8v4m-7 4v-4h14v4"/>',
  data:'<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v14a8 3 0 0 0 16 0V5M4 12a8 3 0 0 0 16 0"/>',
  file:'<path d="M6 3h8l4 4v14H6zM14 3v5h4M9 12h6m-6 4h6"/>',
  folder:'<path d="M3 6h7l2 2h9v12H3z"/>',
  play:'<path d="m7 4 14 8-14 8z"/>',
  download:'<path d="M12 3v12m-4-4 4 4 4-4M4 15v5h16v-5"/>',
  warning:'<path d="m12 3 10 18H2zM12 9v5m0 3v1"/>',
  layers:'<path d="m12 3 9 5-9 5-9-5zM3 12l9 5 9-5M3 16l9 5 9-5"/>',
  settings:'<circle cx="12" cy="12" r="3"/><path d="m9 3-1 3-3 1-2 4 2 2v4l4 3 3-1 3 1 4-3v-4l2-2-2-4-3-1-1-3z"/>'
};
const icon = name => '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'+icons[name]+'</svg>';
const escape = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const e = escape;
const fmt = value => value == null ? '—' : new Intl.NumberFormat('en-US').format(value);
const includes = (query, ...values) => values.flat(Infinity).some(value => String(value ?? '').toLowerCase().includes(query.trim().toLowerCase()));
const badge = (label, tone='') => '<span class="badge '+tone+'">'+e(label)+'</span>';
const button = (label, action, value='', tone='', glyph='') => '<button type="button" class="button '+tone+'" data-action="'+action+'" data-value="'+e(value)+'">'+(glyph?icon(glyph):'')+e(label)+'</button>';
const link = (label, action, value='') => '<button type="button" class="link" data-action="'+action+'" data-value="'+e(value)+'">'+e(label)+'</button>';
const option = (value, label, selection) => '<option value="'+e(value)+'" '+(String(value)===String(selection)?'selected':'')+'>'+e(label)+'</option>';
const select = (key, label, options, value) => '<select class="field" data-field="'+key+'" aria-label="'+label+'">'+options.map(([v,l])=>option(v,l,value)).join('')+'</select>';
const input = (key, label, value) => '<input type="search" class="field" data-field="'+key+'" aria-label="'+label+'" placeholder="'+label+'" value="'+e(value)+'">';
const empty = label => '<div class="empty">'+e(label)+'</div>';
const kv = rows => '<dl class="kv">'+rows.map(([k,v])=>'<dt>'+e(k)+'</dt><dd>'+e(v ?? '—')+'</dd>').join('')+'</dl>';
const table = (headers, rows) => '<div class="table-wrap"><table class="table"><thead><tr>'+headers.map(h=>'<th scope="col">'+e(h)+'</th>').join('')+'</tr></thead><tbody>'+rows.join('')+'</tbody></table></div>';
const row = (cells, current=false) => '<tr'+(current?' class="selected"':'')+'>'+cells.map(c=>'<td>'+c+'</td>').join('')+'</tr>';
const raw = (obj, label='Raw JSON') => '<details><summary>'+e(label)+'</summary><pre>'+e(JSON.stringify(obj,null,2))+'</pre></details>';
const statusLabels = {
  hit:'Matched',miss:'No match',not_tested:'Not tested',unsupported_rule:'Unsupported syntax',incompatible_logsource:'Incompatible log source',
  draft:'Needs review',confirmed:'Confirmed',disputed:'Disputed',insufficient_evidence:'Insufficient evidence',
  matches_procedure:'Procedure matches',partially_matches:'Partial match',does_not_match:'Procedure does not match',insufficient_detail:'Insufficient detail',
  observed:'Observed',attempted:'Attempted',inferred:'Inferred',unclear:'Unclear',
  completed_with_review:'Run complete · Review required',partial_with_review:'Partially complete · Review required',budget_exhausted:'Budget exhausted',controller_error:'Controller error'
};
const status = key => statusLabels[key] ?? key ?? '—';
const tools = {analyze_report:'Extract report behaviors',read_context:'Read source context',search_rules:'Find candidate rules',check_telemetry:'Check logs and fields',assess_candidate:'Assess rule conditions',test_rule:'Test rule on samples',request_review:'Request human review',generate_rule:'Generate candidate rule',finish:'Finish run'};
const caseNames = {'AA25-266A':'CISA incident response','AA23-319A':'Rhysida ransomware'};
const routes = ['reports','activity','data','settings'];
const state = {view:'reports',caseId:data.reports[0].id,reportSearch:'',source:data.log_sources[0].id,eventType:'10',dataTab:'fields',fieldSearch:'',cases:{}};
const firstState = () => ({search:'',tech:'',review:'',page:1,pageSize:10,selected:null,tool:'',activityBehavior:'',step:null});
const current = () => state.cases[state.caseId] ??= firstState();
const getReport = () => data.reports.find(report=>report.id===state.caseId);
const getRun = () => data.runs.find(run=>run.report_id===state.caseId);
const shortId = id => id?.split('-').at(-1) ?? '';
const draftsKey = 'threat2detect-review-drafts';
let drafts = {};
try { drafts = JSON.parse(localStorage.getItem(draftsKey) ?? '{}') ?? {}; } catch {}
const draftKey = id => [state.caseId,getRun()?.id ?? 'handoff',id].join('/');
function route(view, caseId=state.caseId) {
  const next = '#'+view+(['reports','activity'].includes(view)?'/'+caseId:'');
  if (location.hash === next) render();
  else location.hash = next;
}
function readRoute() {
  const [view, caseId] = location.hash.slice(1).split('/');
  state.view = routes.includes(view) ? view : 'reports';
  if (data.reports.some(report=>report.id===caseId)) state.caseId=caseId;
  render();
}
function sidebar() {
  const list = data.reports.filter(report=>includes(state.reportSearch,report.id,report.title,caseNames[report.id]));
  return '<aside class="sidebar"><div class="brand"><span class="mark" aria-hidden="true"></span>Threat2Detect</div><h2>Reports</h2>'+
    input('reportSearch','Search reports',state.reportSearch)+'<div class="group">Development cases '+badge(data.reports.length)+'</div>'+
    (list.map(report=>'<button class="case '+(state.caseId===report.id?'active':'')+'" data-action="case" data-value="'+e(report.id)+'" aria-pressed="'+(state.caseId===report.id)+'"><strong>'+e(report.id)+'</strong><span>'+e(caseNames[report.id] ?? report.title)+'</span><small>'+(data.runs.some(run=>run.report_id===report.id)?'Demo run available':'No runs yet')+'</small></button>').join('')||empty('No matching reports'))+
    '<div class="sealed">Held-out evaluation</div><div class="sidebar-foot muted">Local workspace</div></aside>';
}
function header(report, run) {
  const activity = state.view==='activity';
  const reportView = state.view==='reports'||activity;
  const attack = data.knowledge_assets.find(x=>x.type==='attack');
  const sigma = data.knowledge_assets.find(x=>x.type==='sigma');
  const title = {reports:report.id,activity:'Agent Activity / '+report.id,data:'Data Sources',settings:'Settings'}[state.view];
  const subtitle = reportView?report.title:state.view==='data'?'Log sources, available fields, and catalog versions':'Local demo workspace';
  const actions = reportView
    ? button(activity?'Export trace':'Export report','export','','','download')+button('Run analysis','run','','primary','play')
    : state.view==='data'?button('Connect data source','connect','','primary'):'';
  return '<header class="header">'+(!reportView?'<div class="brand"><span class="mark" aria-hidden="true"></span>Threat2Detect</div>':'')+'<h1>'+e(title)+'</h1><span class="sub" title="'+e(subtitle)+'">'+e(subtitle)+'</span><div class="actions">'+actions+'</div></header>'+
    (reportView?'<div class="meta"><span>'+iconInline('folder')+' Local demo</span><span>Offline Sysmon samples</span><span>ATT&CK v'+e(attack?.version)+'</span><span>Sigma '+e(sigma?.commit?.slice(0,8))+'</span>'+link('View data sources','nav','data')+'</div>':'');
}
function iconInline(name) { return '<span style="display:inline-block;width:16px;vertical-align:middle">'+icon(name)+'</span>'; }
function notice(content, extra='', neutral=false) {
  return '<div class="notice '+(neutral?'neutral':'')+'"><span>'+(neutral?'':icon('warning'))+content+'</span>'+extra+'</div>';
}
function items(bundle) { return bundle?.items ?? []; }
function behaviorResults(run,id) {
  const candidates=items(run?.candidates).filter(x=>x.behavior_id===id);
  const ids=new Set(candidates.map(x=>x.candidate_id));
  return {candidates,coverage:items(run?.coverage).filter(x=>ids.has(x.candidate_id)),tests:items(run?.rule_tests).filter(x=>ids.has(x.candidate_id))};
}
function reportPage(report,run) {
  const s=current();
  const {behaviors,mappings}=report.handoff;
  const pendingIds=new Set((run?.result.review_queue??[]).map(x=>x.behavior_id));
  const filtered=behaviors.filter(b=>{
    const ids=mappings.filter(x=>x.behavior_id===b.behavior_id).map(x=>x.technique_id);
    return includes(s.search,b.behavior_id,b.action,b.object,b.evidence.quote,ids) &&
      (!s.tech||ids.includes(s.tech)) &&
      (!s.review||(s.review==='pending'?pendingIds.has(b.behavior_id):
        s.review==='analyzed'?behaviorResults(run,b.behavior_id).coverage.length>0:b.review_status===s.review));
  });
  const pages=Math.max(1,Math.ceil(filtered.length/s.pageSize));
  s.page=Math.min(s.page,pages);
  const offset=(s.page-1)*s.pageSize;
  const visible=filtered.slice(offset,offset+s.pageSize);
  const selected=visible.find(b=>b.behavior_id===s.selected) ?? visible[0];
  if (selected) s.selected=selected.behavior_id;
  const rows=visible.map(b=>{
    const id=b.behavior_id;
    const ids=mappings.filter(x=>x.behavior_id===id).map(x=>x.technique_id);
    const {coverage,tests}=behaviorResults(run,id);
    const testLabels=[...new Set(tests.map(x=>status(x.status)))];
    const title=b.evidence.quote.length<=38 ? b.evidence.quote : b.action;
    return row([
      '<button class="row-button" data-action="behavior" data-value="'+e(id)+'" aria-pressed="'+(id===selected?.behavior_id)+'"><span class="row-id">'+e(shortId(id))+'</span>'+e(title)+'</button>',
      ids.length ? ids.slice(0,2).map(x=>badge(x,'tech')).join(' ')+(ids.length>2?' '+badge('+'+(ids.length-2)):'') : '—',
      pendingIds.has(id)?badge('Needs review','warn'):coverage.length?badge('Analyzed'):badge('Not analyzed'),
      testLabels.length===1?badge(testLabels[0],tests.every(x=>x.status==='hit')?'good':''):testLabels.length?badge('View details'):badge('Not tested')
    ],id===selected?.behavior_id);
  });
  const controls='<div class="filters">'+input('search','Search behaviors, commands, or techniques',s.search)+
    select('tech','Filter by technique',[['','All techniques'],...[...new Set(mappings.map(x=>x.technique_id))].sort().map(x=>[x,x])],s.tech)+
    select('review','Filter by status',[['','All statuses'],['pending','Pending review items'],['analyzed','Analyzed'],['confirmed','Annotation confirmed'],['draft','Annotation needs review'],['insufficient_evidence','Insufficient evidence'],['disputed','Disputed']],s.review)+'</div>';
  const pagination=filtered.length?'<div class="pagination"><span class="count">'+(offset+1)+'–'+(offset+visible.length)+' / '+filtered.length+'</span>'+
    Array.from({length:pages},(_,i)=>button(i+1,'page',i+1,i+1===s.page?'primary':'')).join('')+
    select('pageSize','Rows per page',[[8,'8 per page'],[10,'10 per page'],[20,'20 per page']],s.pageSize)+'</div>':'';
  const unprocessed=run?.result.unselected_behavior_ids?.length ?? 0;
  return (run?notice(e(status(run.result.workflow_status))+' · '+pendingIds.size+' pending review'+(unprocessed?' · '+unprocessed+' outside run scope':''),
    link(s.review==='pending'?'Show all':'Show pending reviews','pending')):notice('No Agent runs for this report.','',true))+
    '<div class="split"><section><h2 class="section-title">Behaviors and Technique Mappings <small>('+behaviors.length+')</small></h2>'+controls+
    (rows.length?table(['Behavior','ATT&CK','Rule applicability','Sample test'],rows)+pagination:empty('No matching behaviors'))+
    '</section><aside class="detail" aria-label="Behavior details">'+(selected?behaviorDetail(selected,mappings,run):empty('Select a behavior to view its details'))+'</aside></div>';
}
function behaviorDetail(b,mappings,run) {
  const id=b.behavior_id, ev=b.evidence;
  const {candidates,coverage,tests}=behaviorResults(run,id);
  const mapped=mappings.filter(x=>x.behavior_id===id);
  const conditions=(label,values)=>values?.length?'<p><strong>'+label+'</strong></p><ul class="list">'+values.map(x=>'<li>'+e(x)+'</li>').join('')+'</ul>':'';
  return '<h2>'+e(shortId(id)+' · '+b.action)+'</h2><p class="muted">'+e(b.object)+'</p><p>'+badge(status(b.fact_status))+' '+badge(status(b.review_status),b.review_status==='confirmed'?'good':'warn')+'</p>'+
    '<section><h3>'+icon('file')+'Source Evidence</h3><blockquote class="quote">'+e(ev.quote)+'</blockquote><small>'+
    (ev.pdf_page?'Report page '+e(ev.pdf_page)+' · ':'')+'Characters '+e(ev.char_start)+'–'+e(ev.char_end)+'</small></section>'+
    '<section><h3>'+icon('layers')+'ATT&CK Mappings</h3>'+
    (mapped.map(x=>'<p>'+badge(x.technique_id,'tech')+' '+e(x.technique_name)+' '+badge(status(x.review_status))+'</p><p class="muted">'+e(x.rationale)+'</p>').join('')||'<p class="muted">No mappings yet</p>')+'</section>'+
    '<section><h3>'+icon('activity')+'Sigma Conditions</h3>'+
    (candidates.map(c=>{
      const assessment=coverage.find(x=>x.candidate_id===c.candidate_id);
      return '<p><strong>'+e(c.title)+'</strong></p><p>'+badge(assessment?status(assessment.decision):'Not analyzed','tech')+
      (assessment?' '+badge(status(assessment.review_status),assessment.review_status==='draft'?'warn':''):'')+'</p>'+
      (assessment?'<details><summary>View conditions and rationale</summary>'+conditions('Supporting conditions',assessment.supporting_conditions)+
      conditions('Missing conditions',assessment.missing_conditions)+conditions('Unknown conditions',assessment.unknown_conditions)+'<p>'+e(assessment.explanation)+'</p></details>':'')+
      '<details><summary>Rule source</summary>'+kv([['Rule ID',c.rule_id],['File',c.rule_path],['SHA-256',c.rule_sha256],['Version',run.candidates.ruleset_commit]])+'</details>';
    }).join('')||'<p class="muted">No candidate rules</p>')+'</section>'+
    '<section><h3>'+icon('data')+'Log Samples</h3>'+
    (tests.map(x=>'<p>'+badge(status(x.status),x.status==='hit'?'good':'')+' '+e(x.dataset_id)+'</p>'+
      kv([['Evaluated',x.events_evaluated],['Skipped',x.events_skipped],['Matched events',x.matched_event_uids.join(', ')||'—'],['Executor',x.engine_version]])+
      (x.unsupported_features?.length?'<p>'+e(x.unsupported_features.join(', '))+'</p>':'')).join('')||'<p class="muted">Not tested</p>')+
    '<p class="muted">Rule applicability and sample matches are measured separately.</p></section>'+
    (run?.trace.some(x=>x.action?.behavior_id===id)?link('View related Agent activity','related',id):'')+
    button(drafts[draftKey(id)]?'Edit review draft':'Review this behavior','review',id,'primary full');
}

function observationLabel(step) {
  const x=step.observation ?? {};
  if (step.error) return ['Execution error','warn'];
  const results={
    read_context:['Context loaded','good'],search_rules:[(x.candidate_ids?.length??0)+' candidates',''],
    check_telemetry:[fmt(x.compatible_events)+' compatible events',''],
    assess_candidate:[status(x.review_status),'warn'],test_rule:[status(x.status),x.status==='hit'?'good':''],
    request_review:['Needs review','warn'],finish:[status(x.status),'']
  };
  return results[step.action?.tool] ?? ['Recorded',''];
}
function activityPage(report,run) {
  if (!run) return empty('No Agent runs for this report.');
  const s=current();
  const result=run.result;
  const steps=run.trace.filter(x=>(!s.tool||x.action?.tool===s.tool)&&(!s.activityBehavior||x.action?.behavior_id===s.activityBehavior));
  const selected=steps.find(x=>x.step===s.step)??steps[0];
  const filters='<div class="filters">'+select('activityBehavior','Filter by behavior',
    [['','All behaviors'],...report.handoff.behaviors.map(b=>[b.behavior_id,shortId(b.behavior_id)+' · '+b.action])],s.activityBehavior)+
    select('tool','Filter by tool',[['','All tools'],...[...new Set(run.trace.map(x=>x.action?.tool).filter(Boolean))].map(x=>[x,tools[x]??x])],s.tool)+'</div>';
  return notice(e(status(result.workflow_status)),e(fmt(result.steps_used)+' steps / '+fmt(result.model_calls_used)+' model calls'))+
    '<div class="split"><section><h2 class="section-title">Agent Execution Trace</h2>'+filters+
    (steps.length?'<ol class="timeline">'+steps.map(x=>{
      const t=x.action?.tool;
      return '<li><button class="step '+(x===selected?'active':'')+'" data-action="step" data-value="'+e(x.step)+'" aria-pressed="'+(x===selected)+'"><span class="step-num">'+e(String(x.step).padStart(2,'0'))+'</span><strong>'+e(tools[t]??t??'Controller step')+'</strong>'+badge(t??'Unknown','tech')+badge(...observationLabel(x))+'</button></li>';
    }).join('')+'</ol>':empty('No matching steps'))+'</section><aside class="detail" aria-label="Step details">'+
    (selected?'<h2>'+e(tools[selected.action?.tool]??'Controller step')+'</h2><p class="muted">Step '+e(selected.step)+' · '+e(shortId(selected.action?.behavior_id)||'Current run')+'</p>'+
      '<section><h3>Tool Results</h3><p>'+badge(...observationLabel(selected))+'</p>'+
      (selected.error?'<p>'+e(selected.error)+'</p>':'')+raw(selected.observation??{},'View tool output')+
      (selected.decision?.reason?'<details><summary>Model rationale · Unverified</summary><p>'+e(selected.decision.reason)+'</p></details>':'')+'</section>':'')+
    '<section><h3>Run Budget</h3>'+
    [['Model calls',result.model_calls_used,result.budgets?.model_calls],['Controller steps',result.steps_used,result.budgets?.steps]].map(([label,used,max])=>
      '<div class="meter">'+label+' <strong>'+e(used)+' / '+e(max??'—')+'</strong>'+(max?'<progress aria-label="'+label+'" value="'+e(used)+'" max="'+e(max)+'"></progress>':'')+'</div>').join('')+
    '<p class="muted">'+e(result.unselected_behavior_ids?.length??0)+' outside run scope · '+e(result.pending_behavior_ids?.length??0)+' pending</p></section>'+
    '<section><h3>Human Review Items</h3>'+((result.review_queue??[]).map(x=>'<p>'+badge(shortId(x.behavior_id),'warn')+' '+e(x.reason)+'</p>').join('')||'<p class="muted">No review items</p>')+'</section></aside></div>';
}
function sourceField(location) {
  return location?.replace(/^Message 内 /, 'Message: ');
}
function dataPage() {
  const source=data.log_sources.find(x=>x.id===state.source);
  const events=source.event_types;
  if (!events.some(x=>String(x.event_id)===state.eventType)) state.eventType=String(events[0]?.event_id??'');
  const fields=(source.field_catalogues[state.eventType]??[]).filter(x=>includes(state.fieldSearch,x.name,x.standard_name,sourceField(x.raw_location)));
  const typeNames={'1':'Process creation','10':'Process access','11':'File creation'};
  const typeSelect=select('eventType','Event type',events.map(x=>[x.event_id,'Event ID '+x.event_id+' · '+(typeNames[x.event_id]??'Sysmon')]),state.eventType);
  const assets='<div class="asset-grid">'+data.knowledge_assets.map(x=>'<button class="asset" data-action="asset" data-value="'+e(x.id)+'">'+
    icon(x.type==='attack'?'layers':'file')+'<strong>'+e(x.type==='attack'?'ATT&CK Enterprise v'+x.version:'SigmaHQ '+x.commit.slice(0,8))+'</strong><span class="muted">View pinned version</span></button>').join('')+'</div>';
  const sources=table(['Data source','Connection','Log type','Time range','Status'],data.log_sources.map(x=>row([
    '<button class="row-button" data-action="source" data-value="'+e(x.id)+'" aria-pressed="'+(state.source===x.id)+'">'+e(x.name)+'</button>',
    'Offline sample','Windows Sysmon',e(x.time_range?.start?.slice(0,10)??'Unknown'),
    badge(x.status==='readable'?'Readable':x.status,x.status==='readable'?'good':'')
  ],state.source===x.id)));
  const tabs='<div class="tabs" aria-label="Log data views">'+[['fields','Field catalog'],['events','Event samples'],['limits','Compatibility and gaps']].map(([id,label])=>
    '<button class="tab '+(state.dataTab===id?'active':'')+'" data-action="dataTab" data-value="'+id+'" aria-pressed="'+(state.dataTab===id)+'">'+label+'</button>').join('')+'</div>';
  let content;
  if (state.dataTab==='fields') {
    content=fields.length?table(['Source field','Normalized field','Type','Sample value','Availability'],fields.map(x=>row([
      e(sourceField(x.raw_location)),e(x.standard_name),badge(x.type,'tech'),'<div class="sample-cell">'+e(x.sample_preview?.replaceAll('脱敏示例', '[redacted sample]')??'—')+'</div>',
      x.nonempty_count==null?badge('Not measured'):badge(x.nonempty_count===0?'No nonempty values':x.nonempty_count<x.total_events?'Missing in some events':'Observed',x.nonempty_count===x.total_events?'good':'warn')+
      ' <small title="Nonempty events / total events of this type">'+fmt(x.nonempty_count)+' / '+fmt(x.total_events)+'</small>'
    ]))):empty('No matching fields');
  } else if (state.dataTab==='events') {
    const samples=source.sample_events.filter(x=>String(x.event_code)===state.eventType);
    content=samples.length? samples.map(x=>'<section>'+kv([['Event ID',x.event_uid],['Collected at',x.timestamp_raw],['Channel',x.channel],['Source location',x.raw_ref]])+'</section>').join(''):empty('No loaded samples for this event type');
  } else {
    content=kv([['Source',source.source_path],['Start time',source.time_range?.start],['End time',source.time_range?.end],['Normalized data hash',source.normalized_sha256]])+
      '<p class="muted">The field catalog describes these samples. Field requirements depend on the rule branch. Live log sources are disconnected.</p>';
  }
  return '<section class="data-section"><h2 class="section-title">Knowledge Base and Rules</h2>'+assets+'</section>'+
    '<section class="data-section"><h2 class="section-title">Log Sources</h2>'+sources+'</section>'+
    '<section><div class="data-head"><div><h2 class="section-title">'+e(source.name)+' · Log Details</h2><span class="muted">'+fmt(source.record_count)+' normalized events · Parse errors '+fmt(source.parse_error_count)+'</span></div>'+
    '<div class="filters">'+(state.dataTab==='fields'?input('fieldSearch','Search fields',state.fieldSearch):'')+typeSelect+'</div></div>'+tabs+content+'</section>'+
    '<p class="muted">Public simulation logs come from a separate source from the original incident logs.</p>';
}
function render() {
  const focused=document.activeElement;
  const field=focused?.dataset?.field;
  const selection=field&&focused.tagName==='INPUT'?[focused.selectionStart,focused.selectionEnd]:null;
  const report=getReport(),run=getRun();
  const nav=[['reports','Reports','report'],['activity','Activity','activity'],['data','Data Sources','data'],['settings','Settings','settings']];
  const wide=['data','settings'].includes(state.view);
  const pages={reports:reportPage,activity:activityPage,data:dataPage,settings:()=>empty('The local demo needs no configuration.')};
  app.innerHTML='<div class="shell '+(wide?'wide':'')+'"><nav class="rail" aria-label="Main navigation">'+nav.map(([id,label,glyph])=>
    (id==='settings'?'<span class="spacer"></span>':'')+'<button class="nav '+(state.view===id?'active':'')+'" data-action="nav" data-value="'+id+'" '+(state.view===id?'aria-current="page"':'')+'>'+icon(glyph)+e(label)+'</button>').join('')+
    '</nav>'+(!wide?sidebar():'')+'<main class="main">'+header(report,run)+'<div class="content">'+pages[state.view](report,run)+'</div></main></div>';
  if (field) {
    const next=app.querySelector('[data-field="'+field+'"]');
    next?.focus({preventScroll:true});
    if (next&&selection) next.setSelectionRange(...selection);
  }
}
function showDialog(title, body, actions='') {
  dialog.innerHTML='<h2 id="dialog-title">'+e(title)+'</h2>'+body+'<div class="dialog-actions">'+button('Close','close')+actions+'</div>';
  dialog.showModal();
}
function download(filename, value) {
  const url=URL.createObjectURL(new Blob([JSON.stringify(value,null,2)+'\n'],{type:'application/json'}));
  const a=document.createElement('a');
  a.href=url;
  a.download=filename;
  a.click();
  setTimeout(()=>URL.revokeObjectURL(url),1000);
}
const fieldUpdate = event => {
  const key=event.target.dataset.field;
  if (!key) return;
  const s=current();
  if (['reportSearch','fieldSearch','eventType'].includes(key)) state[key]=event.target.value;
  else {
    s[key]=key==='pageSize'?Number(event.target.value):event.target.value;
    if (['search','tech','review','pageSize'].includes(key)) s.page=1;
  }
  render();
};
app.addEventListener('input', event=>{if(event.target.tagName==='INPUT') fieldUpdate(event);});
app.addEventListener('change', event=>{if(event.target.tagName==='SELECT') fieldUpdate(event);});
document.addEventListener('click',event=>{
  const control=event.target.closest('[data-action]');
  if (!control) return;
  const {action,value}=control.dataset;
  const s=current(),run=getRun();
  switch(action) {
    case 'nav': if(value==='activity') s.activityBehavior=''; route(value); return;
    case 'case': route(state.view,value); return;
    case 'pending': s.review=s.review==='pending'?'':'pending';s.page=1;break;
    case 'behavior': s.selected=value;break;
    case 'page': s.page=Number(value);break;
    case 'related': s.activityBehavior=value;s.tool='';route('activity');return;
    case 'step': s.step=Number(value);break;
    case 'source': state.source=value;state.fieldSearch='';break;
    case 'dataTab': state.dataTab=value;break;
    case 'close': dialog.close();return;
    case 'asset': {
      const asset=data.knowledge_assets.find(x=>x.id===value);
      showDialog('Pinned Knowledge Version',kv([['Path',asset.path],['Version',asset.version??asset.commit],['SHA-256',asset.sha256],['Mode','Pinned version · Read-only']]));
      return;
    }
    case 'run':
      showDialog('Run analysis','<p>The local demo is disconnected from the analysis service.</p>',
        run?(state.view==='activity'?'':button('View demo run','showRun','','primary')):'');
      return;
    case 'showRun': dialog.close();s.activityBehavior='';s.tool='';route('activity');return;
    case 'connect': showDialog('Connect data source','<p>You can browse the offline log samples. Live connections require a backend service.</p>');return;
    case 'export':
      if(state.view==='activity') {
        if(run) download(state.caseId+'-trace.json',run.trace);
        else showDialog('Export trace','<p>This report has no Agent trace to export.</p>');
      } else download(state.caseId+'-report.json',{handoff:getReport().handoff,result:run?.result??null,coverage:run?.coverage??null,rule_tests:run?.rule_tests??null});
      return;
    case 'review': {
      const draft=drafts[draftKey(value)];
      showDialog('Review behavior '+shortId(value),'<label>Notes<textarea id="review-note" class="field" placeholder="Record your assessment of the evidence, mapping, or rule conditions">'+e(draft?.note)+'</textarea></label><p id="draft-state" class="muted" role="status">Drafts stay in this browser and can be exported as JSON.</p>',
        button('Export draft','exportDraft',value)+button('Save draft','saveDraft',value,'primary'));
      return;
    }
    case 'saveDraft':
    case 'exportDraft': {
      const draft={case_id:state.caseId,run_id:run?.id??null,behavior_id:value,review_status:'draft',note:dialog.querySelector('#review-note').value};
      if(action==='exportDraft') download(value+'-review-draft.json',draft);
      else {
        drafts[draftKey(value)]=draft;
        try {
          localStorage.setItem(draftsKey,JSON.stringify(drafts));
          dialog.querySelector('#draft-state').textContent='Saved in this browser.';
        } catch {
          dialog.querySelector('#draft-state').textContent='The browser could not save this draft. You can still export it.';
        }
        render();
      }
      return;
    }
    default: return;
  }
  render();
});
window.addEventListener('hashchange',readRoute);
readRoute();
