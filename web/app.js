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
const fmt = value => value == null ? '—' : new Intl.NumberFormat('zh-CN').format(value);
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
const raw = (obj, label='原始 JSON') => '<details><summary>'+e(label)+'</summary><pre>'+e(JSON.stringify(obj,null,2))+'</pre></details>';
const statusLabels = {
  hit:'命中',miss:'未命中',not_tested:'未测试',unsupported_rule:'语法未支持',incompatible_logsource:'日志源不兼容',
  draft:'待复核',confirmed:'已确认',disputed:'有争议',insufficient_evidence:'证据不足',
  matches_procedure:'做法适用',partially_matches:'部分适用',does_not_match:'做法不适用',insufficient_detail:'信息不足',
  observed:'已观察',attempted:'尝试',inferred:'推测',unclear:'不明确',
  completed_with_review:'本轮结束 · 待复核',partial_with_review:'部分完成 · 待复核',budget_exhausted:'预算耗尽',controller_error:'主控异常'
};
const status = key => statusLabels[key] ?? key ?? '—';
const tools = {analyze_report:'提取报告行为',read_context:'读取原文上下文',search_rules:'检索候选规则',check_telemetry:'核对日志与字段',assess_candidate:'分析规则条件',test_rule:'执行样例规则',request_review:'记录人工复核事项',generate_rule:'生成候选规则',finish:'结束本轮处理'};
const caseNames = {'AA25-266A':'CISA 事件响应','AA23-319A':'Rhysida 勒索软件'};
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
  return '<aside class="sidebar"><div class="brand"><span class="mark" aria-hidden="true"></span>Threat2Detect</div><h2>报告</h2>'+
    input('reportSearch','搜索报告',state.reportSearch)+'<div class="group">开发案例 '+badge(data.reports.length)+'</div>'+
    (list.map(report=>'<button class="case '+(state.caseId===report.id?'active':'')+'" data-action="case" data-value="'+e(report.id)+'" aria-pressed="'+(state.caseId===report.id)+'"><strong>'+e(report.id)+'</strong><span>'+e(caseNames[report.id] ?? report.title)+'</span><small>'+(data.runs.some(run=>run.report_id===report.id)?'有演示运行':'暂无运行')+'</small></button>').join('')||empty('没有匹配的报告'))+
    '<div class="sealed">▣　封存测试</div><div class="sidebar-foot muted">本地工作区</div></aside>';
}
function header(report, run) {
  const activity = state.view==='activity';
  const reportView = state.view==='reports'||activity;
  const attack = data.knowledge_assets.find(x=>x.type==='attack');
  const sigma = data.knowledge_assets.find(x=>x.type==='sigma');
  const title = {reports:report.id,activity:'Agent 活动 / '+report.id,data:'数据接入',settings:'设置'}[state.view];
  const subtitle = reportView?report.title:state.view==='data'?'日志源、可用字段与知识版本':'本地演示工作区';
  const actions = reportView
    ? button(activity?'导出轨迹':'导出报告','export','','','download')+button('运行分析','run','','primary','play')
    : state.view==='data'?button('接入数据源','connect','','primary'):'';
  return '<header class="header">'+(!reportView?'<div class="brand"><span class="mark" aria-hidden="true"></span>Threat2Detect</div>':'')+'<h1>'+e(title)+'</h1><span class="sub" title="'+e(subtitle)+'">'+e(subtitle)+'</span><div class="actions">'+actions+'</div></header>'+
    (reportView?'<div class="meta"><span>'+iconInline('folder')+' 本地演示</span><span>离线 Sysmon 样本</span><span>ATT&CK v'+e(attack?.version)+'</span><span>Sigma '+e(sigma?.commit?.slice(0,8))+'</span>'+link('查看数据接入','nav','data')+'</div>':'');
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
      pendingIds.has(id)?badge('待复核','warn'):coverage.length?badge('已分析'):badge('未分析'),
      testLabels.length===1?badge(testLabels[0],tests.every(x=>x.status==='hit')?'good':''):testLabels.length?badge('查看详情'):badge('未测试')
    ],id===selected?.behavior_id);
  });
  const controls='<div class="filters">'+input('search','搜索行为、命令或技术',s.search)+
    select('tech','筛选技术',[['','全部技术'],...[...new Set(mappings.map(x=>x.technique_id))].sort().map(x=>[x,x])],s.tech)+
    select('review','筛选状态',[['','全部状态'],['pending','待复核事项'],['analyzed','已分析'],['confirmed','标注已确认'],['draft','标注待复核'],['insufficient_evidence','证据不足'],['disputed','有争议']],s.review)+'</div>';
  const pagination=filtered.length?'<div class="pagination"><span class="count">'+(offset+1)+'–'+(offset+visible.length)+' / '+filtered.length+'</span>'+
    Array.from({length:pages},(_,i)=>button(i+1,'page',i+1,i+1===s.page?'primary':'')).join('')+
    select('pageSize','每页条数',[[8,'8 条/页'],[10,'10 条/页'],[20,'20 条/页']],s.pageSize)+'</div>':'';
  const unprocessed=run?.result.unselected_behavior_ids?.length ?? 0;
  return (run?notice(e(status(run.result.workflow_status))+' · '+pendingIds.size+' 条待复核'+(unprocessed?' · '+unprocessed+' 条未选中':''),
    link(s.review==='pending'?'显示全部':'只看待复核','pending')):notice('此报告暂无 Agent 运行记录。','',true))+
    '<div class="split"><section><h2 class="section-title">行为与技术映射 <small>共 '+behaviors.length+' 条</small></h2>'+controls+
    (rows.length?table(['行为','ATT&CK','规则适用性','样例验证'],rows)+pagination:empty('没有符合条件的行为'))+
    '</section><aside class="detail" aria-label="行为详情">'+(selected?behaviorDetail(selected,mappings,run):empty('选择行为查看详情'))+'</aside></div>';
}
function behaviorDetail(b,mappings,run) {
  const id=b.behavior_id, ev=b.evidence;
  const {candidates,coverage,tests}=behaviorResults(run,id);
  const mapped=mappings.filter(x=>x.behavior_id===id);
  const conditions=(label,values)=>values?.length?'<p><strong>'+label+'</strong></p><ul class="list">'+values.map(x=>'<li>'+e(x)+'</li>').join('')+'</ul>':'';
  return '<h2>'+e(shortId(id)+' · '+b.action)+'</h2><p class="muted">'+e(b.object)+'</p><p>'+badge(status(b.fact_status))+' '+badge(status(b.review_status),b.review_status==='confirmed'?'good':'warn')+'</p>'+
    '<section><h3>'+icon('file')+'原文证据</h3><blockquote class="quote">'+e(ev.quote)+'</blockquote><small>'+
    (ev.pdf_page?'报告第 '+e(ev.pdf_page)+' 页 · ':'')+'字符 '+e(ev.char_start)+'–'+e(ev.char_end)+'</small></section>'+
    '<section><h3>'+icon('layers')+'ATT&CK 映射</h3>'+
    (mapped.map(x=>'<p>'+badge(x.technique_id,'tech')+' '+e(x.technique_name)+' '+badge(status(x.review_status))+'</p><p class="muted">'+e(x.rationale)+'</p>').join('')||'<p class="muted">尚未映射</p>')+'</section>'+
    '<section><h3>'+icon('activity')+'Sigma 条件</h3>'+
    (candidates.map(c=>{
      const assessment=coverage.find(x=>x.candidate_id===c.candidate_id);
      return '<p><strong>'+e(c.title)+'</strong></p><p>'+badge(assessment?status(assessment.decision):'未分析','tech')+
      (assessment?' '+badge(status(assessment.review_status),assessment.review_status==='draft'?'warn':''):'')+'</p>'+
      (assessment?'<details><summary>查看条件与理由</summary>'+conditions('支持条件',assessment.supporting_conditions)+
      conditions('缺失条件',assessment.missing_conditions)+conditions('未知条件',assessment.unknown_conditions)+'<p>'+e(assessment.explanation)+'</p></details>':'')+
      '<details><summary>规则来源</summary>'+kv([['规则 ID',c.rule_id],['文件',c.rule_path],['SHA-256',c.rule_sha256],['版本',run.candidates.ruleset_commit]])+'</details>';
    }).join('')||'<p class="muted">暂无候选规则</p>')+'</section>'+
    '<section><h3>'+icon('data')+'日志样例</h3>'+
    (tests.map(x=>'<p>'+badge(status(x.status),x.status==='hit'?'good':'')+' '+e(x.dataset_id)+'</p>'+
      kv([['已求值',x.events_evaluated],['跳过',x.events_skipped],['命中事件',x.matched_event_uids.join('、')||'—'],['执行器',x.engine_version]])+
      (x.unsupported_features?.length?'<p>'+e(x.unsupported_features.join('、'))+'</p>':'')).join('')||'<p class="muted">未测试</p>')+
    '<p class="muted">规则适用性与样例命中分别记录。</p></section>'+
    (run?.trace.some(x=>x.action?.behavior_id===id)?link('查看相关 Agent 活动','related',id):'')+
    button(drafts[draftKey(id)]?'编辑复核草稿':'复核此行为','review',id,'primary full');
}

function observationLabel(step) {
  const x=step.observation ?? {};
  if (step.error) return ['执行异常','warn'];
  const results={
    read_context:['已读取','good'],search_rules:[(x.candidate_ids?.length??0)+' 条候选',''],
    check_telemetry:[fmt(x.compatible_events)+' 条兼容事件',''],
    assess_candidate:[status(x.review_status),'warn'],test_rule:[status(x.status),x.status==='hit'?'good':''],
    request_review:['待复核','warn'],finish:[status(x.status),'']
  };
  return results[step.action?.tool] ?? ['已记录',''];
}
function activityPage(report,run) {
  if (!run) return empty('此报告暂无 Agent 运行记录。');
  const s=current();
  const result=run.result;
  const steps=run.trace.filter(x=>(!s.tool||x.action?.tool===s.tool)&&(!s.activityBehavior||x.action?.behavior_id===s.activityBehavior));
  const selected=steps.find(x=>x.step===s.step)??steps[0];
  const filters='<div class="filters">'+select('activityBehavior','筛选行为',
    [['','全部行为'],...report.handoff.behaviors.map(b=>[b.behavior_id,shortId(b.behavior_id)+' · '+b.action])],s.activityBehavior)+
    select('tool','筛选工具',[['','全部工具'],...[...new Set(run.trace.map(x=>x.action?.tool).filter(Boolean))].map(x=>[x,tools[x]??x])],s.tool)+'</div>';
  return notice(e(status(result.workflow_status)),e(fmt(result.steps_used)+' 步 / '+fmt(result.model_calls_used)+' 次模型调用'))+
    '<div class="split"><section><h2 class="section-title">Agent 执行轨迹</h2>'+filters+
    (steps.length?'<ol class="timeline">'+steps.map(x=>{
      const t=x.action?.tool;
      return '<li><button class="step '+(x===selected?'active':'')+'" data-action="step" data-value="'+e(x.step)+'" aria-pressed="'+(x===selected)+'"><span class="step-num">'+e(String(x.step).padStart(2,'0'))+'</span><strong>'+e(tools[t]??t??'主控步骤')+'</strong>'+badge(t??'未知','tech')+badge(...observationLabel(x))+'</button></li>';
    }).join('')+'</ol>':empty('没有符合条件的步骤'))+'</section><aside class="detail" aria-label="步骤详情">'+
    (selected?'<h2>'+e(tools[selected.action?.tool]??'主控步骤')+'</h2><p class="muted">第 '+e(selected.step)+' 步 · '+e(shortId(selected.action?.behavior_id)||'本轮运行')+'</p>'+
      '<section><h3>工具结果</h3><p>'+badge(...observationLabel(selected))+'</p>'+
      (selected.error?'<p>'+e(selected.error)+'</p>':'')+raw(selected.observation??{},'查看工具输出')+
      (selected.decision?.reason?'<details><summary>模型理由摘要 · 未核验</summary><p>'+e(selected.decision.reason)+'</p></details>':'')+'</section>':'')+
    '<section><h3>本次预算</h3>'+
    [['模型调用',result.model_calls_used,result.budgets?.model_calls],['主控步数',result.steps_used,result.budgets?.steps]].map(([label,used,max])=>
      '<div class="meter">'+label+' <strong>'+e(used)+' / '+e(max??'—')+'</strong>'+(max?'<progress aria-label="'+label+'" value="'+e(used)+'" max="'+e(max)+'"></progress>':'')+'</div>').join('')+
    '<p class="muted">'+e(result.unselected_behavior_ids?.length??0)+' 条未选中 · '+e(result.pending_behavior_ids?.length??0)+' 条待处理</p></section>'+
    '<section><h3>人工复核事项</h3>'+((result.review_queue??[]).map(x=>'<p>'+badge(shortId(x.behavior_id),'warn')+' '+e(x.reason)+'</p>').join('')||'<p class="muted">无记录</p>')+'</section></aside></div>';
}
function dataPage() {
  const source=data.log_sources.find(x=>x.id===state.source);
  const events=source.event_types;
  if (!events.some(x=>String(x.event_id)===state.eventType)) state.eventType=String(events[0]?.event_id??'');
  const fields=(source.field_catalogues[state.eventType]??[]).filter(x=>includes(state.fieldSearch,x.name,x.standard_name,x.raw_location));
  const typeNames={'1':'进程创建','10':'进程访问','11':'文件创建'};
  const typeSelect=select('eventType','事件类型',events.map(x=>[x.event_id,'Event ID '+x.event_id+' · '+(typeNames[x.event_id]??'Sysmon')]),state.eventType);
  const assets='<div class="asset-grid">'+data.knowledge_assets.map(x=>'<button class="asset" data-action="asset" data-value="'+e(x.id)+'">'+
    icon(x.type==='attack'?'layers':'file')+'<strong>'+e(x.type==='attack'?'ATT&CK Enterprise v'+x.version:'SigmaHQ '+x.commit.slice(0,8))+'</strong><span class="muted">查看固定版本</span></button>').join('')+'</div>';
  const sources=table(['数据源','接入方式','日志类型','时间范围','状态'],data.log_sources.map(x=>row([
    '<button class="row-button" data-action="source" data-value="'+e(x.id)+'" aria-pressed="'+(state.source===x.id)+'">'+e(x.name)+'</button>',
    '离线样本','Windows Sysmon',e(x.time_range?.start?.slice(0,10)??'未知'),
    badge(x.status==='readable'?'可读取':x.status,x.status==='readable'?'good':'')
  ],state.source===x.id)));
  const tabs='<div class="tabs" aria-label="日志数据视图">'+[['fields','字段目录'],['events','事件样例'],['limits','适配与缺口']].map(([id,label])=>
    '<button class="tab '+(state.dataTab===id?'active':'')+'" data-action="dataTab" data-value="'+id+'" aria-pressed="'+(state.dataTab===id)+'">'+label+'</button>').join('')+'</div>';
  let content;
  if (state.dataTab==='fields') {
    content=fields.length?table(['原始字段','标准字段','类型','样例值','可用情况'],fields.map(x=>row([
      e(x.raw_location),e(x.standard_name),badge(x.type,'tech'),'<div class="sample-cell">'+e(x.sample_preview??'—')+'</div>',
      x.nonempty_count==null?badge('尚未统计'):badge(x.nonempty_count===0?'未观测非空值':x.nonempty_count<x.total_events?'部分事件缺失':'已观测',x.nonempty_count===x.total_events?'good':'warn')+
      ' <small title="非空事件 / 当前类型事件">'+fmt(x.nonempty_count)+' / '+fmt(x.total_events)+'</small>'
    ]))):empty('没有匹配的字段');
  } else if (state.dataTab==='events') {
    const samples=source.sample_events.filter(x=>String(x.event_code)===state.eventType);
    content=samples.length? samples.map(x=>'<section>'+kv([['事件 ID',x.event_uid],['采集时间',x.timestamp_raw],['频道',x.channel],['原始位置',x.raw_ref]])+'</section>').join(''):empty('当前事件类型暂无已加载样例');
  } else {
    content=kv([['来源',source.source_path],['开始时间',source.time_range?.start],['结束时间',source.time_range?.end],['标准化摘要',source.normalized_sha256]])+
      '<p class="muted">字段目录来自当前样本统计。规则字段是否齐全，仍需按实际逻辑分支核对。在线日志平台尚未接入。</p>';
  }
  return '<section class="data-section"><h2 class="section-title">知识与规则库</h2>'+assets+'</section>'+
    '<section class="data-section"><h2 class="section-title">日志数据源</h2>'+sources+'</section>'+
    '<section><div class="data-head"><div><h2 class="section-title">'+e(source.name)+' · 日志详情</h2><span class="muted">'+fmt(source.record_count)+' 条标准化事件 · 解析错误 '+fmt(source.parse_error_count)+'</span></div>'+
    '<div class="filters">'+(state.dataTab==='fields'?input('fieldSearch','搜索字段',state.fieldSearch):'')+typeSelect+'</div></div>'+tabs+content+'</section>'+
    '<p class="muted">公开模拟日志与报告现场日志来自不同来源。</p>';
}
function render() {
  const focused=document.activeElement;
  const field=focused?.dataset?.field;
  const selection=field&&focused.tagName==='INPUT'?[focused.selectionStart,focused.selectionEnd]:null;
  const report=getReport(),run=getRun();
  const nav=[['reports','报告','report'],['activity','活动','activity'],['data','数据接入','data'],['settings','设置','settings']];
  const wide=['data','settings'].includes(state.view);
  const pages={reports:reportPage,activity:activityPage,data:dataPage,settings:()=>empty('本地演示无需配置。')};
  app.innerHTML='<div class="shell '+(wide?'wide':'')+'"><nav class="rail" aria-label="全局导航">'+nav.map(([id,label,glyph])=>
    (id==='settings'?'<span class="spacer"></span>':'')+'<button class="nav '+(state.view===id?'active':'')+'" data-action="nav" data-value="'+id+'" '+(state.view===id?'aria-current="page"':'')+'>'+icon(glyph)+e(label)+'</button>').join('')+
    '</nav>'+(!wide?sidebar():'')+'<main class="main">'+header(report,run)+'<div class="content">'+pages[state.view](report,run)+'</div></main></div>';
  if (field) {
    const next=app.querySelector('[data-field="'+field+'"]');
    next?.focus({preventScroll:true});
    if (next&&selection) next.setSelectionRange(...selection);
  }
}
function showDialog(title, body, actions='') {
  dialog.innerHTML='<h2 id="dialog-title">'+e(title)+'</h2>'+body+'<div class="dialog-actions">'+button('关闭','close')+actions+'</div>';
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
      showDialog('固定知识版本',kv([['路径',asset.path],['版本',asset.version??asset.commit],['SHA-256',asset.sha256],['模式','固定版本 · 只读']]));
      return;
    }
    case 'run':
      showDialog('运行分析','<p>当前是本地演示，尚未连接分析服务。</p>',
        run?(state.view==='activity'?'':button('查看演示运行','showRun','','primary')):'');
      return;
    case 'showRun': dialog.close();s.activityBehavior='';s.tool='';route('activity');return;
    case 'connect': showDialog('接入数据源','<p>当前可以查看仓库提供的离线日志样本。在线数据接入需要后端服务。</p>');return;
    case 'export':
      if(state.view==='activity') {
        if(run) download(state.caseId+'-trace.json',run.trace);
        else showDialog('导出轨迹','<p>此报告暂无可导出的 Agent 轨迹。</p>');
      } else download(state.caseId+'-report.json',{handoff:getReport().handoff,result:run?.result??null,coverage:run?.coverage??null,rule_tests:run?.rule_tests??null});
      return;
    case 'review': {
      const draft=drafts[draftKey(value)];
      showDialog('复核行为 '+shortId(value),'<label>备注<textarea id="review-note" class="field" placeholder="记录你对证据、映射或规则条件的判断">'+e(draft?.note)+'</textarea></label><p id="draft-state" class="muted" role="status">草稿保存在当前浏览器，可导出为 JSON。</p>',
        button('导出草稿','exportDraft',value)+button('保存草稿','saveDraft',value,'primary'));
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
          dialog.querySelector('#draft-state').textContent='已保存到当前浏览器。';
        } catch {
          dialog.querySelector('#draft-state').textContent='浏览器无法保存。你可以导出当前草稿。';
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
