# ── DASHBOARD ────────────────────────────────────────────────────────────────
DASHBOARD_HTML = r'''
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>AgentGuard — AI Observability</title>
<style>
:root{--bg:#0d0f17;--bg2:#10121a;--card:#151722;--card2:#1a1d2a;--border:#262a3a;--border2:#303448;--text:#e6e8f2;--muted:#9298ab;--dim:#5d6375;--purple:#8b5cf6;--purple2:#a78bfa;--green:#4cc38a;--red:#e0525f;--red2:#ff5d73;--blue:#4c8dff;--cyan:#38bdf8;--orange:#fb923c;--teal:#3ecfb2;--yellow:#f5b84b;--val:#6ee7b7;--mono:ui-monospace,"SF Mono",Menlo,Consolas,monospace}
*{box-sizing:border-box}html,body{margin:0;background:var(--bg);color:var(--text);font:13px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,sans-serif}
a{color:var(--purple2);text-decoration:none}
button{font:inherit;cursor:pointer}
.topbar{height:48px;display:flex;align-items:center;gap:18px;padding:0 16px;background:var(--bg);border-bottom:1px solid var(--border);position:sticky;top:0;z-index:50}
.logo-box{width:30px;height:30px;border-radius:8px;display:grid;place-items:center;padding:4px}
.logo-box img{width:100%;height:100%;object-fit:contain}
.logo-card{padding:0;overflow:hidden;display:flex;align-items:center;justify-content:center}
.logo-card .logo-box{width:100%;height:100%;border-radius:0;padding:0}
.prod{font-weight:700;font-size:14px}
.prod small{color:var(--muted);font-weight:400;margin-left:6px;font-size:12px}
.tabs{display:flex;gap:2px;height:100%}
.tabs button{background:none;border:0;color:var(--muted);padding:0 14px;height:100%;font-size:13px;border-bottom:2px solid transparent}
.tabs button:hover{color:var(--text)}
.tabs button.active{color:var(--purple2);border-bottom-color:var(--purple)}
.tabs button[disabled]{opacity:.45;cursor:default}
.tb-right{margin-left:auto;display:flex;align-items:center;gap:10px}
.btn{background:var(--card2);border:1px solid var(--border2);color:var(--text);border-radius:6px;padding:6px 12px;font-size:12px}
.btn:hover{border-color:#454a63}
.help{width:22px;height:22px;border:1px solid var(--border2);border-radius:50%;display:grid;place-items:center;color:var(--muted);font-size:11px}
.toolbar{display:flex;align-items:center;gap:10px;padding:10px 16px;border-bottom:1px solid var(--border);background:var(--bg2)}
.filter-pill{display:flex;align-items:center;gap:8px;background:var(--card);border:1px solid var(--border2);border-radius:6px;padding:6px 10px;font-size:12px;color:var(--muted);max-width:70%;overflow:hidden;white-space:nowrap}
.filter-pill b{color:var(--text);font-weight:400}
.filter-pill .x{color:var(--dim);cursor:pointer;margin-left:4px}
.toolbar .right{margin-left:auto;display:flex;gap:8px;align-items:center}
.pill{background:var(--card);border:1px solid var(--border2);border-radius:6px;padding:6px 10px;font-size:12px;color:var(--muted)}
.body{display:flex;min-height:calc(100vh - 100px)}
.fside{width:230px;flex-shrink:0;border-right:1px solid var(--border);padding:12px 10px;background:var(--bg);overflow-y:auto}
.fgroup{margin-bottom:6px}
.fgroup>div{display:flex;align-items:center;gap:6px;color:var(--muted);font-size:12px;padding:5px 6px;cursor:pointer;user-select:none}
.fgroup>div:hover{color:var(--text)}
.fitems{padding:2px 0 4px 8px}
.fitem{display:flex;align-items:center;gap:8px;padding:4px 6px;font-size:12px;color:var(--text)}
.fitem input{accent-color:var(--purple);width:13px;height:13px}
.main{flex:1;min-width:0;padding:18px 22px 60px;max-width:1760px}
.view{display:none}.view.active{display:block}
.sec{display:flex;align-items:center;gap:8px;font-size:15px;font-weight:600;margin:26px 0 12px}
.sec:first-child{margin-top:4px}
.sec .ico{color:var(--purple2)}
.sec .info{color:var(--dim);font-size:11px;border:1px solid var(--border2);border-radius:50%;width:15px;height:15px;display:inline-grid;place-items:center}
.grid{display:grid;gap:12px}
.g2{grid-template-columns:1.35fr 1fr}.g3{grid-template-columns:repeat(3,1fr)}.g4{grid-template-columns:repeat(4,1fr)}.g5{grid-template-columns:repeat(5,1fr)}
.card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:16px;position:relative}
.card .menu{position:absolute;top:12px;right:12px;color:var(--dim);cursor:pointer;font-size:14px;letter-spacing:2px}
.card .alert-btn{position:absolute;top:12px;right:34px;color:var(--muted);font-size:12px;background:none;border:0}
.clabel{font-size:12px;color:var(--muted);margin-bottom:6px}
.hero{font-size:54px;font-weight:600;letter-spacing:-1px;line-height:1.05;margin:8px 0 4px}
.hero.mid{font-size:40px}.hero.sm{font-size:30px}
.hero .unit{font-size:.45em;font-weight:600;color:var(--text)}
.trend{font-size:13px;margin-top:4px}
.trend.up{color:var(--green)}.trend.down{color:var(--red2)}
.chart{height:210px;position:relative}.chart svg{width:100%;height:100%;display:block}
.chart.tall{height:250px}
.empty{color:var(--dim);text-align:center;padding:36px 8px;font-size:12px}
.legend{display:flex;flex-wrap:wrap;gap:14px;font-size:11px;color:var(--muted);margin-top:10px}
.legend i{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px}
.stat-tabs{display:inline-flex;gap:4px;margin-bottom:12px}
.stat-tabs button{background:var(--card);border:1px solid var(--border2);color:var(--muted);border-radius:5px;padding:4px 12px;font-size:12px}
.stat-tabs button.active{background:var(--card2);color:var(--text);border-color:#454a63}
table{width:100%;border-collapse:collapse}
th{text-align:left;color:var(--muted);font-weight:400;font-size:11.5px;padding:6px 10px;border-bottom:1px solid var(--border)}
th .sort{color:var(--dim)}
td{border-bottom:1px solid var(--border);padding:7px 10px;font-size:12px;color:var(--text);vertical-align:top}
tr:hover td{background:#191c29}
.mono{font-family:var(--mono);font-size:11px}
.dim{color:var(--dim)}
.tr-head{display:flex;align-items:center;gap:16px;flex-wrap:wrap;background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:10px 14px;margin-bottom:12px;font-size:12.5px}
.tr-head .name{font-weight:600;font-size:13.5px}
.tr-head .err{color:var(--red2)}
.tr-head .right{margin-left:auto;display:flex;gap:14px;color:var(--muted)}
.tr-body{display:grid;grid-template-columns:minmax(0,1.55fr) minmax(320px,.8fr);gap:12px}
.span-row{display:flex;align-items:center;height:26px;font-size:12px;cursor:pointer}
.span-row:hover{background:#191c29}
.span-row.sel{outline:1px solid var(--purple)}
.span-row .tw{width:46%;flex-shrink:0;display:flex;align-items:center;gap:6px;white-space:nowrap;overflow:hidden}
.span-row .dot{width:10px;height:10px;border-radius:50%;background:var(--blue);flex-shrink:0}
.span-row .dot.client{background:#7aa7ff}
.span-row .track{flex:1;position:relative;height:100%}
.span-row .bar{position:absolute;top:9px;height:8px;border-radius:2px;background:var(--blue)}
.span-row .bar.blocked{background:var(--red2)}
.axis{display:flex;justify-content:space-between;color:var(--dim);font-size:10.5px;border-bottom:1px solid var(--border);padding-bottom:4px;margin-bottom:4px}
.warn{color:var(--yellow);font-size:11px}
.attr-sec{border:1px solid var(--border);border-radius:8px;margin-bottom:10px;background:var(--card)}
.attr-sec h4{margin:0;padding:10px 12px;font-size:12.5px;font-weight:600;border-bottom:1px solid var(--border);display:flex;justify-content:space-between}
.attr-row{display:flex;gap:12px;padding:7px 12px;border-bottom:1px solid var(--border);font-size:11.5px}
.attr-row:last-child{border-bottom:0}
.attr-row .k{width:44%;flex-shrink:0;color:var(--muted)}
.attr-row .v{font-family:var(--mono);color:var(--val);word-break:break-word}
.attr-row .v.pink{color:#f472b6}.attr-row .v.blue{color:#7aa7ff}
.exc-row td{cursor:pointer}
.codeblock{background:#0a0c12;border:1px solid var(--border);border-radius:6px;padding:10px 12px;font-family:var(--mono);font-size:11px;color:#aeb6c8;white-space:pre-wrap;word-break:break-word;margin:8px 0}
.qblock{display:flex;background:#0a0c12;border:1px solid var(--border);border-radius:8px;padding:10px 0;font-family:var(--mono);font-size:11.5px;color:#aeb6c8;position:relative}
.qblock .ln{color:var(--dim);text-align:right;padding:0 12px;border-right:1px solid var(--border);user-select:none}
.qblock .code{padding:0 14px;white-space:pre}
.qblock .copy{position:absolute;top:8px;right:10px;color:var(--dim);cursor:pointer}
.pilltag{display:inline-block;background:var(--card2);border:1px solid var(--border2);border-radius:5px;padding:2px 8px;font-size:10.5px;color:var(--muted);font-family:var(--mono)}
.badge{display:inline-block;border-radius:4px;padding:2px 7px;font-size:10px;font-weight:600}
.badge.safe{color:var(--green);background:#4cc38a14;border:1px solid #4cc38a33}
.badge.blocked{color:var(--red2);background:#ff5d7314;border:1px solid #ff5d7333}
.subtabs{display:flex;gap:18px;border-bottom:1px solid var(--border);margin-bottom:10px;font-size:12.5px}
.subtabs span{padding:6px 2px;color:var(--muted);cursor:pointer}
.subtabs span.active{color:var(--text);border-bottom:2px solid var(--purple)}
.subtabs .n{background:var(--yellow);color:#111;border-radius:8px;padding:0 6px;font-size:10px;margin-left:5px}
.searchbox{background:var(--card);border:1px solid var(--border2);border-radius:6px;padding:7px 10px;color:var(--text);font:inherit;font-size:12px;width:100%}
.toast{position:fixed;right:20px;bottom:20px;background:var(--card2);border:1px solid var(--border2);padding:10px 14px;border-radius:8px;font-size:12px;z-index:100;opacity:0;transition:.2s}
.toast.show{opacity:1}

/* ── Professional icon and agent connection system ─────────────────── */
.ui-icon{width:14px;height:14px;display:inline-block;vertical-align:-2px;flex:0 0 14px;color:currentColor}
.ui-icon svg{display:block;width:100%;height:100%}
.logo-fallback{display:none;width:100%;height:100%;align-items:center;justify-content:center;font-size:10px;font-weight:800;letter-spacing:-.04em;color:var(--text);background:var(--card2);border:1px solid var(--border2);border-radius:7px}
.brand-mark{width:40px;height:40px;display:grid;place-items:center;flex:0 0 40px;border-radius:10px;background:var(--card2);border:1px solid var(--border2);font:800 10px/1 var(--mono);letter-spacing:.02em;color:var(--text);overflow:hidden}.brand-mark img{width:23px;height:23px;display:block;object-fit:contain}.brand-mark .brand-fallback{display:none}.brand-mark img[data-fallback]+.brand-fallback{display:none}
.brand-mark.python{color:#8ab4ff}.brand-mark.mcp{color:#b7a2ff}.brand-mark.http{color:#7dd3fc}.brand-mark.composio{color:#f0abfc}.brand-mark.openai{color:#d1d5db}.brand-mark.anthropic{color:#f5d0a9}.brand-mark.langgraph{color:#86efac}.brand-mark.crewai{color:#fda4af}
.connect-modal{position:fixed;inset:0;z-index:90;display:none;align-items:center;justify-content:center;padding:24px;background:rgba(4,6,12,.74);backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px)}
.connect-modal.open{display:flex}
.connect-panel{width:min(960px,100%);max-height:min(820px,calc(100vh - 48px));overflow:auto;background:var(--bg2);border:1px solid var(--border2);border-radius:14px;box-shadow:0 24px 80px rgba(0,0,0,.48);animation:connectIn .16s ease-out}
@keyframes connectIn{from{opacity:0;transform:translateY(8px) scale(.99)}to{opacity:1;transform:none}}
.connect-head{display:flex;align-items:center;gap:12px;padding:18px 20px;border-bottom:1px solid var(--border);position:sticky;top:0;background:rgba(16,18,26,.97);backdrop-filter:blur(10px);z-index:2}
.connect-head .title{font-size:15px;font-weight:650}.connect-head .subtitle{font-size:11px;color:var(--muted);margin-top:2px}
.connect-close{margin-left:auto;width:32px;height:32px;border:1px solid var(--border2);border-radius:7px;background:var(--card);color:var(--muted);font-size:20px;line-height:1;display:grid;place-items:center}
.connect-close:hover{color:var(--text);border-color:#454a63}
.connect-body{padding:20px}.connect-view{display:none}.connect-view.active{display:block}
.connect-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}
.connect-card{display:flex;gap:13px;align-items:flex-start;text-align:left;width:100%;padding:15px;background:var(--card);border:1px solid var(--border);border-radius:10px;color:var(--text);transition:.15s ease;position:relative}
button.connect-card{cursor:pointer}button.connect-card:hover{transform:translateY(-1px);border-color:#454a63;background:var(--card2)}
.connect-card .name{font-weight:600;font-size:13px}.connect-card .desc{display:block;font-size:11px;color:var(--muted);margin-top:3px;line-height:1.45}
.connect-section{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;margin:20px 0 9px}.connect-section:first-child{margin-top:0}
.connect-note{padding:10px 12px;border:1px solid var(--border);background:var(--card);border-radius:8px;color:var(--muted);font-size:11px;margin-top:14px}
.connect-detail{display:none}.connect-detail.active{display:block}.connect-detail h3{margin:0 0 5px;font-size:16px}.connect-detail p{color:var(--muted);font-size:12px;margin:0 0 14px}
.connect-back{border:0;background:none;color:var(--muted);padding:0;margin-bottom:16px;font-size:12px;display:inline-flex;align-items:center;gap:5px}.connect-back:hover{color:var(--text)}
.connect-code-wrap{position:relative;margin:10px 0 16px}.connect-code{background:#0a0c12;border:1px solid var(--border);border-radius:8px;padding:14px 62px 14px 14px;font-family:var(--mono);font-size:11px;color:#aeb6c8;white-space:pre-wrap;word-break:break-word;line-height:1.55;overflow:auto}
.connect-copy{position:absolute;right:9px;top:9px;border:1px solid var(--border2);background:var(--card2);color:var(--muted);border-radius:5px;padding:4px 8px;font-size:10px}.connect-copy:hover{color:var(--text);border-color:#454a63}
.connect-agents{margin-top:20px;border-top:1px solid var(--border);padding-top:14px}.connect-agent-row{display:flex;align-items:center;gap:10px;padding:9px 0;border-bottom:1px solid var(--border)}.connect-agent-row:last-child{border-bottom:0}.connect-agent-dot{width:8px;height:8px;border-radius:50%;background:var(--dim);flex:0 0 8px}.connect-agent-dot.connected{background:var(--green)}.connect-agent-dot.idle{background:var(--yellow)}.connect-agent-name{font-family:var(--mono);font-size:11px}.connect-agent-status{margin-left:auto;font-size:10px;color:var(--muted)}
@media(max-width:760px){.connect-modal{padding:12px}.connect-panel{max-height:calc(100vh - 24px)}.connect-grid{grid-template-columns:1fr}.connect-body{padding:14px}}
@media(max-width:1200px){.g5{grid-template-columns:repeat(3,1fr)}.g4,.g3{grid-template-columns:repeat(2,1fr)}.tr-body{grid-template-columns:1fr}.fside{display:none}}
@media(max-width:760px){.g5,.g4,.g3,.g2{grid-template-columns:1fr}.tabs{overflow-x:auto}}
</style>
</head>
<body>
<header class="topbar">
  <div class="logo-box"><img src="/static/logo.svg" alt="AgentGuard" onerror="this.style.display='none';this.nextElementSibling.style.display='grid'"><span class="logo-fallback" aria-hidden="true">AG</span></div>
  <span class="prod">AgentGuard <small>AI Observability</small></span>
  <nav class="tabs" id="topTabs">
    <button data-view="overview">Overview</button>
    <button data-view="health" class="active">Service Health (Preview)</button>
    <button data-view="tracing">Explorer (Preview)</button>
    <button data-view="audit">Compliance Audit</button>
    <button type="button" onclick="openConnectAgentModal()">AI Agents</button>
  </nav>
  <div class="tb-right">
    <button class="btn" onclick="toast('Connections gérées via /admin/customers')">+ Connection</button>
    <span class="help">?</span>
  </div>
</header>
<div class="toolbar">
  <div class="filter-pill"><span class="ui-icon" data-icon="filter"></span><span>Service in (<b>agentguard-collector</b>)</span><span class="x" title="clear">✕</span></div>
  <div class="right">
    <span class="pill">Last 14 days ▾</span>
    <button class="btn" onclick="refreshAll()"><span class="ui-icon" data-icon="refresh"></span> Refresh</button>
    <form method="post" action="/logout" style="margin:0"><button class="btn" type="submit">Sign out</button></form>
  </div>
</div>
<div class="body">
<aside class="fside" id="fside"></aside>
<main class="main">

<section id="view-overview" class="view">
  <div class="sec">Service Health &amp; Performance</div>
  <div class="grid" style="grid-template-columns:170px 1fr 1fr 1fr;gap:12px">
    <div class="card logo-card" style="background:#000;border:0;border-radius:18px"><div class="logo-box"><img src="/static/logo.svg" alt="AgentGuard" onerror="this.style.display='none';this.nextElementSibling.style.display='grid'" style="width:100%;height:100%;object-fit:cover;border-radius:18px"><span class="logo-fallback" aria-hidden="true">AG</span></div></div>
    <div class="card"><div class="clabel">Open Problems</div><div class="hero mid" id="ovProblems" style="color:var(--red2)">0</div></div>
    <div class="card"><div class="clabel"># of Total Requests</div><div class="hero mid" id="ovRequests">0</div><div class="trend" id="ovRequestsT"></div></div>
    <div class="card"><div class="clabel">Cost</div><div class="hero mid" id="ovCost">$0</div><div class="trend" id="ovCostT"></div></div>
  </div>
  <div class="grid g4" style="margin-top:12px">
    <div class="card"><div class="clabel">Service Health</div><div id="ovDonut" style="height:170px"></div></div>
    <div class="card"><div class="clabel">AVG Request Duration</div><div class="hero mid" id="ovAvg">—</div><div class="trend" id="ovAvgT"></div></div>
    <div class="card"><div class="clabel">P99 Request Duration</div><div class="hero mid" id="ovP99">—</div><div class="trend" id="ovP99T"></div></div>
    <div class="card"><div class="clabel">AgentGuard AI Forecast</div><div class="chart" id="ovForecast" style="height:170px"></div></div>
  </div>
  <div class="sec">Service Quality &amp; Guardrails</div>
  <div class="grid g5" id="gqBig"></div>
  <div class="grid g5" style="margin-top:12px" id="gqSmall"></div>
  <div class="sec">End-To-End Tracing &amp; Debugging</div>
  <div class="card"><div class="clabel">Top 10 expensive prompts</div>
    <table><thead><tr><th>prompt <span class="sort">⇅</span></th><th>response <span class="sort">⇅</span></th><th>trace.id <span class="sort">⇅</span></th><th>token <span class="sort">⇅</span></th><th>cost <span class="sort">⇅</span></th></tr></thead><tbody id="expTable"></tbody></table>
  </div>
</section>

<section id="view-health" class="view active">
  <div class="sec"><span class="ico"><span class="ui-icon" data-icon="latency"></span></span>Traffic and Latency <span class="info">i</span></div>
  <div class="stat-tabs" id="latTabs"><button class="active" data-s="avg">AVG</button><button data-s="p50">p50</button><button data-s="p90">p90</button><button data-s="p95">p95</button></div>
  <div class="grid g2">
    <div class="card"><span class="menu">⋮</span><div class="clabel">Time to response</div><div class="hero" style="text-align:center" id="ttrHero">—</div><div class="chart" id="ttrChart"></div></div>
    <div class="card"><span class="menu">⋮</span><div class="clabel">Response time per model</div><div id="rtModel" style="height:290px"></div></div>
  </div>
  <div class="sec"><span class="ico">◈</span>Cost <span class="info">i</span></div>
  <div class="grid g3">
    <div class="card"><button class="alert-btn">+ New alert</button><span class="menu">⋮</span><div class="clabel">Token count</div><div class="hero" id="tokHero">0</div></div>
    <div class="card"><span class="menu">⋮</span><div class="clabel">Average cost per request</div><div class="hero" id="avgCostHero">—</div><div class="chart" id="avgCostChart" style="height:120px"></div></div>
    <div class="card"><button class="alert-btn">+ New alert</button><span class="menu">⋮</span><div class="clabel">Token usage forecast</div><div class="chart tall" id="tokForecast"></div><div class="legend"><span><i style="background:var(--purple2)"></i>Total amount of tokens used</span></div></div>
  </div>
  <div class="sec"><span class="ico"><span class="ui-icon" data-icon="security"></span></span>Guardrails <span class="info">i</span></div>
  <div class="grid g2">
    <div class="card"><span class="menu">⋮</span><div class="clabel">Number of requests with guardrail enabled</div><div class="hero" id="grHero">0</div></div>
    <div class="card"><span class="menu">⋮</span><div class="clabel">Guardrail activation by type</div><div class="chart tall" id="grStacked"></div><div class="legend" id="grLegend"></div></div>
  </div>
  <div class="sec"><span class="ico">◎</span>Tokens per model</div>
  <div class="card"><div id="tokModel" style="min-height:60px"></div></div>
</section>

<section id="view-tracing" class="view">
  <div class="tr-head">
    <span>⇄</span><span class="name">AgentGuard.workflow</span>
    <select id="traceSelect" class="pill" style="background:var(--card);color:var(--text);border:1px solid var(--border2)"></select>
    <span id="trDate" class="dim"></span>
    <span><span class="ui-icon" data-icon="latency"></span> Duration: <b id="trDur">—</b></span>
    <span class="err"><span class="ui-icon" data-icon="error"></span> Errors: <b id="trErr">0</b></span>
    <span class="mono dim">ID: <span id="trId"></span> ⧉</span>
    <span class="right"><span>Open with ⊞</span><span>Close details</span><span>Minimize</span></span>
  </div>
  <div class="tr-body">
    <div>
      <div class="card" style="padding:12px">
        <div style="display:flex;gap:8px;align-items:center;margin-bottom:10px">
          <input class="searchbox" id="spanSearch" placeholder="Search name, endpoint, service, or attributes" style="max-width:340px">
          <span class="pilltag" id="spanCount">0 spans</span>
        </div>
        <div class="axis"><span id="ax0">0 ms</span><span id="ax1"></span><span id="ax2"></span></div>
        <div id="spanTree"></div>
      </div>
      <div class="card" style="margin-top:12px;padding:12px">
        <div class="subtabs"><span>Logs</span><span class="active">Exceptions<span class="n" id="excN">0</span></span></div>
        <table><thead><tr><th></th><th>Exception class</th><th>Exception message</th></tr></thead><tbody id="excTable"></tbody></table>
      </div>
    </div>
    <div id="spanDetail"></div>
  </div>
</section>

<section id="view-audit" class="view">
  <h1 style="font-size:24px;margin:4px 0 2px">GenAI Compliance Audit</h1>
  <div class="dim" style="font-size:12px;margin-bottom:20px" id="auRange"></div>
  <div class="grid g2">
    <div>
      <div class="sec" style="margin-top:0">Auditing Events</div>
      <div class="qblock"><div class="ln">1<br>2<br>3<br>4</div><div class="code">fetch spans
| filter matchesValue(event.type, "agentguard.security")
| summarize count() by: { gen_ai.model }
| filter gen_ai.model != ""</div><span class="copy" onclick="toast('Query copied')">⧉</span></div>
      <div class="card" style="margin-top:12px;padding:6px 0">
        <table><thead><tr><th>llm model <span class="sort">⇅</span></th><th style="text-align:right">events <span class="sort">⇅</span></th></tr></thead><tbody id="auModels"></tbody></table>
      </div>
    </div>
    <div><div class="sec" style="margin-top:0">Trend</div><div class="card"><div class="chart tall" id="auTrend" style="height:330px"></div></div></div>
  </div>
  <div class="sec">Audit Trail</div>
  <div class="card" style="padding:6px 0;overflow-x:auto">
    <table style="min-width:1100px"><thead><tr><th>timestamp <span class="sort">⇅</span></th><th>event.id <span class="sort">⇅</span></th><th>event.provider <span class="sort">⇅</span></th><th>event.type <span class="sort">⇅</span></th><th>gen_ai.model <span class="sort">⇅</span></th><th>gen_ai.prompt <span class="sort">⇅</span></th><th>gen_ai.role <span class="sort">⇅</span></th><th>gen_ai.system <span class="sort">⇅</span></th><th>gen_ai.type <span class="sort">⇅</span></th></tr></thead><tbody id="auTrail"></tbody></table>
  </div>
</section>

</main>
</div>

<div id="connectAgentModal" class="connect-modal" role="dialog" aria-modal="true" aria-labelledby="connectAgentTitle" aria-describedby="connectAgentSubtitle" onclick="if(event.target===this)closeConnectAgentModal()">
  <div class="connect-panel">
    <div class="connect-head">
      <div>
        <div class="title" id="connectAgentTitle">Connect an AI agent</div>
        <div class="subtitle" id="connectAgentSubtitle">Choose an integration path and send your first protected event.</div>
      </div>
      <button class="connect-close" type="button" aria-label="Close" title="Close" onclick="closeConnectAgentModal()">×</button>
    </div>
    <div class="connect-body">
      <div id="connectChooser" class="connect-view active">
        <div class="connect-section">AgentGuard integrations</div>
        <div class="connect-grid">
          <button class="connect-card" type="button" onclick="showConnectDetail('python')"><span class="brand-mark python"><img src="https://cdn.jsdelivr.net/npm/simple-icons@16.29.0/icons/python.svg" alt="Python" onerror="this.style.display='none';this.nextElementSibling.style.display='inline'"><span class="brand-fallback">PY</span></span><span><span class="name">Python SDK</span><span class="desc">Native runtime instrumentation for LLM calls and tool execution.</span></span></button>
          <button class="connect-card" type="button" onclick="showConnectDetail('mcp')"><span class="brand-mark mcp">MCP</span><span><span class="name">MCP</span><span class="desc">Security boundary for MCP clients, servers and tool calls.</span></span></button>
          <button class="connect-card" type="button" onclick="showConnectDetail('http')"><span class="brand-mark http">HTTP</span><span><span class="name">HTTP Gateway</span><span class="desc">Language-agnostic telemetry and policy boundary.</span></span></button>
          <button class="connect-card" type="button" onclick="showConnectDetail('composio')"><span class="brand-mark composio"><img src="https://cdn.jsdelivr.net/npm/simple-icons@16.29.0/icons/composio.svg" alt="Composio" onerror="this.style.display='none';this.nextElementSibling.style.display='inline'"><span class="brand-fallback">C</span></span><span><span class="name">Composio</span><span class="desc">Guard Composio tool execution with AgentGuard policy enforcement.</span></span></button>
        </div>
        <div class="connect-section">AI providers</div>
        <div class="connect-grid">
          <button class="connect-card" type="button" onclick="showConnectDetail('openai')"><span class="brand-mark openai"><img src="https://cdn.jsdelivr.net/npm/simple-icons@16.29.0/icons/openai.svg" alt="OpenAI" onerror="this.style.display='none';this.nextElementSibling.style.display='inline'"><span class="brand-fallback">O</span></span><span><span class="name">OpenAI</span><span class="desc">Protect Responses and Chat Completions through the SDK.</span></span></button>
          <button class="connect-card" type="button" onclick="showConnectDetail('anthropic')"><span class="brand-mark anthropic"><img src="https://cdn.jsdelivr.net/npm/simple-icons@16.29.0/icons/anthropic.svg" alt="Anthropic" onerror="this.style.display='none';this.nextElementSibling.style.display='inline'"><span class="brand-fallback">A</span></span><span><span class="name">Anthropic</span><span class="desc">Protect Claude requests and tool-use workflows.</span></span></button>
        </div>
        <div class="connect-section">Agent frameworks</div>
        <div class="connect-grid">
          <button class="connect-card" type="button" onclick="showConnectDetail('langgraph')"><span class="brand-mark langgraph"><img src="https://cdn.jsdelivr.net/npm/simple-icons@16.29.0/icons/langgraph.svg" alt="LangGraph" onerror="this.style.display='none';this.nextElementSibling.style.display='inline'"><span class="brand-fallback">LG</span></span><span><span class="name">LangGraph</span><span class="desc">Instrument graph nodes and side-effecting tool edges.</span></span></button>
          <button class="connect-card" type="button" onclick="showConnectDetail('crewai')"><span class="brand-mark crewai"><img src="https://cdn.jsdelivr.net/npm/simple-icons@16.29.0/icons/crewai.svg" alt="CrewAI" onerror="this.style.display='none';this.nextElementSibling.style.display='inline'"><span class="brand-fallback">CA</span></span><span><span class="name">CrewAI</span><span class="desc">Guard CrewAI tools and agent execution paths.</span></span></button>
        </div>
        <div class="connect-note"><b>Security:</b> keep <span class="mono">AGENTGUARD_API_KEY</span> in the agent environment or secret manager. Never expose it in browser code. The admin secret remains server-side and is not used by this onboarding flow.</div>
        <div class="connect-agents"><div class="connect-section" style="margin-top:0">Recently observed agents</div><div id="connectAgentList"><div class="empty" style="padding:18px 8px">No agent telemetry observed yet.</div></div></div>
      </div>
      <div id="connectPython" class="connect-view connect-detail"></div>
      <div id="connectMcp" class="connect-view connect-detail"></div>
      <div id="connectHttp" class="connect-view connect-detail"></div>
      <div id="connectComposio" class="connect-view connect-detail"></div>
      <div id="connectOpenai" class="connect-view connect-detail"></div>
      <div id="connectAnthropic" class="connect-view connect-detail"></div>
      <div id="connectLanggraph" class="connect-view connect-detail"></div>
      <div id="connectCrewai" class="connect-view connect-detail"></div>
    </div>
  </div>
</div>

<div id="toast" class="toast"></div>

<script>
var state = { modelFilter: new Set(), selTrace: null, selSpan: 0, latStat: 'avg' };

var $ = function(id) { return document.getElementById(id); };

var ICON_PATHS = {
    security: '<path d="M12 3 20 6v5c0 5.2-3.4 9.2-8 11-4.6-1.8-8-5.8-8-11V6l8-3Z" fill="none" stroke="currentColor" stroke-width="1.7"/><path d="m8.7 12 2.1 2.1 4.5-4.6" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/>',
    error: '<path d="M12 3 22 21H2L12 3Z" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"/><path d="M12 9v5" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/><circle cx="12" cy="17.5" r="1" fill="currentColor"/>',
    latency: '<circle cx="12" cy="12" r="8.5" fill="none" stroke="currentColor" stroke-width="1.7"/><path d="M12 7v5l3.5 2" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/>',
    back: '<path d="M15 5 8 12l7 7" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/>',
    refresh: '<path d="M20 11a8 8 0 0 0-14.7-3L3 11" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/><path d="M3 6v5h5" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/>',
    filter: '<path d="M4 6h16M7 12h10M10 18h4" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/>'
};
function renderIcons(root) {
    (root || document).querySelectorAll('.ui-icon[data-icon]').forEach(function(el) {
        var key = el.getAttribute('data-icon');
        if (ICON_PATHS[key]) el.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">' + ICON_PATHS[key] + '</svg>';
    });
}
renderIcons(document);

var esc = function(v) {
    return String(v || '').replace(/[&<>'"]/g, function(c) {
        return { '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[c];
    });
};

var fmt = function(n) {
    return Number(n || 0).toLocaleString('en-US').replace(/,/g, ' ');
};

var fmtK = function(n) {
    n = Number(n || 0);
    return n >= 1e6 ? (n / 1e6).toFixed(1) + 'M' : n >= 1e3 ? (n / 1e3).toFixed(1) + 'K' : String(Math.round(n));
};

var money = function(n) {
    return '$' + Number(n || 0).toFixed(4);
};

var P = ['#a78bfa', '#fb923c', '#4cc38a', '#e0525f', '#38bdf8', '#f5b84b', '#8b5cf6', '#4ade80', '#22d3ee', '#f472b6', '#facc15', '#94a3b8', '#6ee7b7', '#fda4af', '#c084fc'];

var CHECKS = [
    ['prompt_injection', '#a78bfa'],
    ['pii_detection', '#fb923c'],
    ['tool_policy', '#3ecfb2'],
    ['dangerous_params', '#e0525f'],
    ['budget_policy', '#4c8dff']
];

function toast(m) {
    var t = $('toast');
    t.textContent = m;
    t.classList.add('show');
    clearTimeout(window._t);
    window._t = setTimeout(function() {
        t.classList.remove('show');
    }, 2200);
}

function api(u) {
    return fetch(u, { credentials: 'include' }).then(function(r) {
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return r.json();
    });
}

function trendPct(s) {
    if (!s || s.length < 2) return null;
    var a = s[0],
        b = s[s.length - 1];
    if (!a && !b) return null;
    var p = a === 0 ? 100 : (b - a) / a * 100;
    return p;
}

function trendHTML(p, invert) {
    if (p === null || isNaN(p)) return '<span class="dim">—</span>';
    var up = p >= 0;
    var good = invert ? !up : up;
    return '<span class="trend ' + (good ? 'up' : 'down') + '">' + (up ? '↗' : '↘') + ' ' + Math.abs(p).toFixed(2) + '%</span>';
}

function areaChart(el, data, labels, color) {
    color = color || '#a78bfa';
    if (!data.length) {
        el.innerHTML = '<div class="empty">No data</div>';
        return;
    }
    var W = el.clientWidth || 600,
        H = el.clientHeight || 200,
        pad = { l: 8, r: 44, t: 14, b: 22 },
        cw = W - pad.l - pad.r,
        ch = H - pad.t - pad.b;
    var max = Math.max.apply(null, [1].concat(data));
    var s = '<svg viewBox="0 0 ' + W + ' ' + H + '">';
    var pt = function(v, i) {
        return [pad.l + (i / Math.max(1, data.length - 1)) * cw, pad.t + ch - (v / max) * ch];
    };
    var line = '';
    data.forEach(function(v, i) {
        var xy = pt(v, i);
        line += (i ? 'L' : 'M') + xy[0] + ',' + xy[1];
    });
    s += '<path d="' + line + ' L' + (pad.l + cw) + ',' + (pad.t + ch) + ' L' + pad.l + ',' + (pad.t + ch) + ' Z" fill="' + color + '" opacity=".14"/>';
    s += '<path d="' + line + '" fill="none" stroke="' + color + '" stroke-width="1.6"/>';
    (labels || []).forEach(function(l, i) {
        if (i % Math.ceil((labels.length || 1) / 6)) return;
        var x = pad.l + (i / Math.max(1, labels.length - 1)) * cw;
        s += '<text x="' + x + '" y="' + (H - 6) + '" fill="#5d6375" font-size="9.5" text-anchor="middle">' + esc(l) + '</text>';
    });
    s += '<text x="' + (W - 4) + '" y="' + (pad.t + 8) + '" fill="#9298ab" font-size="9.5" text-anchor="end">' + fmtK(max) + '</text></svg>';
    el.innerHTML = s;
}

function hbarsLegend(el, items, valKey, fmtFn) {
    if (!items.length) {
        el.innerHTML = '<div class="empty">No model data yet</div>';
        return;
    }
    var max = Math.max.apply(null, items.map(function(i) { return Number(i[valKey]) || 0; }).concat([1e-9]));
    var s = '<div style="display:flex;gap:14px;height:100%"><div style="flex:1;display:flex;flex-direction:column;justify-content:space-around">';
    items.forEach(function(m, i) {
        s += '<div style="display:flex;align-items:center;gap:8px"><span style="width:170px;text-align:right;font-size:10.5px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">' + esc(m.name) + '</span><div style="flex:1;height:10px;background:#101320;border-radius:2px"><div style="width:' + (Number(m[valKey]) / max * 100).toFixed(1) + '%;height:100%;background:' + P[i % P.length] + ';border-radius:2px"></div></div></div>';
    });
    s += '<div style="display:flex;justify-content:space-between;color:var(--dim);font-size:9.5px;margin-left:178px"><span>0</span><span>' + fmtFn(max / 2) + '</span><span>' + fmtFn(max) + '</span></div></div>';
    s += '<div style="width:190px;overflow:auto;display:flex;flex-direction:column;gap:5px;font-size:10.5px;color:var(--muted)">';
    items.forEach(function(m, i) {
        s += '<span style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis"><i style="display:inline-block;width:8px;height:8px;border-radius:50%;background:' + P[i % P.length] + ';margin-right:6px"></i>' + esc(m.name) + '</span>';
    });
    s += '</div></div>';
    el.innerHTML = s;
}

function stackedTime(el, days, map) {
    if (!days.length) {
        el.innerHTML = '<div class="empty">No guardrail data yet</div>';
        return;
    }
    var W = el.clientWidth || 600,
        H = el.clientHeight || 250,
        pad = { l: 30, r: 8, t: 10, b: 20 },
        cw = W - pad.l - pad.r,
        ch = H - pad.t - pad.b;
    var totals = days.map(function(d) {
        return CHECKS.reduce(function(a, arr) {
            return a + (map[d + '|' + arr[0]] || 0);
        }, 0);
    });
    var max = Math.max.apply(null, [1].concat(totals));
    var bw = Math.max(2, cw / days.length - 2);
    var s = '<svg viewBox="0 0 ' + W + ' ' + H + '">';
    [0, .5, 1].forEach(function(t) {
        var y = pad.t + ch - t * ch;
        s += '<line x1="' + pad.l + '" y1="' + y + '" x2="' + (W - pad.r) + '" y2="' + y + '" stroke="#20243a" stroke-width=".5"/><text x="' + (pad.l - 5) + '" y="' + (y + 3) + '" fill="#5d6375" font-size="9" text-anchor="end">' + Math.round(max * t) + '</text>';
    });
    days.forEach(function(d, i) {
        var y = pad.t + ch;
        CHECKS.forEach(function(arr) {
            var n = arr[0],
                c = arr[1];
            var v = map[d + '|' + n] || 0;
            if (!v) return;
            var h = (v / max) * ch;
            y -= h;
            s += '<rect x="' + (pad.l + i * (cw / days.length)) + '" y="' + y + '" width="' + bw + '" height="' + h + '" fill="' + c + '"/>';
        });
    });
    days.forEach(function(d, i) {
        if (i % Math.ceil(days.length / 6)) return;
        s += '<text x="' + (pad.l + i * (cw / days.length)) + '" y="' + (H - 5) + '" fill="#5d6375" font-size="9">' + esc(d.slice(5)) + '</text>';
    });
    el.innerHTML = s + '</svg>';
}

function multiLine(el, days, series) {
    if (!series.length) {
        el.innerHTML = '<div class="empty">No data</div>';
        return;
    }
    var W = el.clientWidth || 600,
        H = el.clientHeight || 300,
        pad = { l: 36, r: 8, t: 10, b: 20 },
        cw = W - pad.l - pad.r,
        ch = H - pad.t - pad.b;
    var allVals = [];
    series.forEach(function(sr) {
        allVals = allVals.concat(sr.values);
    });
    var max = Math.max.apply(null, [1].concat(allVals));
    var s = '<svg viewBox="0 0 ' + W + ' ' + H + '">';
    [0, .25, .5, .75, 1].forEach(function(t) {
        var y = pad.t + ch - t * ch;
        s += '<line x1="' + pad.l + '" y1="' + y + '" x2="' + (W - pad.r) + '" y2="' + y + '" stroke="#20243a" stroke-width=".5"/><text x="' + (pad.l - 5) + '" y="' + (y + 3) + '" fill="#5d6375" font-size="9" text-anchor="end">' + fmtK(max * t) + '</text>';
    });
    series.forEach(function(sr) {
        var p = '';
        sr.values.forEach(function(v, i) {
            var x = pad.l + (i / Math.max(1, sr.values.length - 1)) * cw,
                y = pad.t + ch - (v / max) * ch;
            p += (i ? 'L' : 'M') + x + ',' + y;
        });
        s += '<path d="' + p + '" fill="none" stroke="' + sr.color + '" stroke-width="1.2"/>';
    });
    days.forEach(function(d, i) {
        if (i % Math.ceil(days.length / 5)) return;
        var x = pad.l + (i / Math.max(1, days.length - 1)) * cw;
        s += '<text x="' + x + '" y="' + (H - 5) + '" fill="#5d6375" font-size="9" text-anchor="middle">' + esc(d.slice(5)) + '</text>';
    });
    el.innerHTML = s + '</svg><div class="legend">';
    series.forEach(function(sr) {
        s += '<span><i style="background:' + sr.color + '"></i>' + esc(sr.name) + '</span>';
    });
    el.innerHTML = s + '</div>';
}

function donut(el, okPct, okN, failN) {
    var r1 = 75 + 56 * Math.sin(Math.max(.02, (1 - okPct / 100) * 6.283));
    var r2 = 75 - 56 * Math.cos(Math.max(.02, (1 - okPct / 100) * 6.283));
    el.innerHTML = '<div style="display:flex;align-items:center;gap:18px;height:100%;justify-content:center"><svg width="150" height="150" viewBox="0 0 150 150"><circle cx="75" cy="75" r="56" fill="#2b8a5e" opacity=".9"/><path d="M75 19 A56 56 0 0 1 ' + r1 + ' ' + r2 + '" stroke="var(--red2)" stroke-width="3" fill="none"/><circle cx="75" cy="75" r="34" fill="var(--card)"/><text x="75" y="72" text-anchor="middle" fill="var(--dim)" font-size="9">' + (100 - okPct).toFixed(0) + '%</text><text x="75" y="86" text-anchor="middle" fill="var(--dim)" font-size="9">' + okPct.toFixed(0) + '%</text></svg><div style="font-size:11px;color:var(--muted);display:flex;flex-direction:column;gap:6px"><span><i style="display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--red2);margin-right:6px"></i>Failed Requests</span><span><i style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#2b8a5e;margin-right:6px"></i>Successful Requests</span></div></div>';
}

function forecastBand(el, hist) {
    if (!hist || hist.length < 2) {
        el.innerHTML = '<div class="empty">Not enough history</div>';
        return;
    }
    var W = el.clientWidth || 500,
        H = el.clientHeight || 170,
        pad = { l: 26, r: 6, t: 10, b: 16 },
        cw = W - pad.l - pad.r,
        ch = H - pad.t - pad.b;
    var delta = (hist[hist.length - 1] - hist[0]) / (hist.length - 1);
    var fc = [];
    for (var i = 0; i < 6; i++) {
        fc.push(Math.max(0, hist[hist.length - 1] + delta * (i + 1)));
    }
    var histMax = Math.max.apply(null, [1].concat(hist));
    var band = fc.map(function(v) {
        return Math.max(v * .25, histMax * .06);
    });
    var fcWithBand = fc.map(function(v, i) {
        return v + band[i];
    });
    var max = Math.max.apply(null, hist.concat(fcWithBand)) * 1.1;
    var X = function(i) {
        return pad.l + (i / (hist.length - 1)) * cw * .62;
    };
    var XF = function(i) {
        return pad.l + cw * .62 + (i / 6) * cw * .38;
    };
    var s = '<svg viewBox="0 0 ' + W + ' ' + H + '">';
    var p = '';
    hist.forEach(function(v, i) {
        var y = pad.t + ch - (v / max) * ch;
        p += (i ? 'L' : 'M') + X(i) + ',' + y;
    });
    s += '<path d="' + p + '" fill="none" stroke="#e6e8f2" stroke-width="1"/>';
    var ly = pad.t + ch - (hist[hist.length - 1] / max) * ch,
        lx = X(hist.length - 1);
    var up = '',
        lo = '';
    fc.forEach(function(v, i) {
        up += 'L' + XF(i + 1) + ',' + (pad.t + ch - ((v + band[i]) / max) * ch) + ' ';
    });
    for (var j = fc.length - 1; j >= 0; j--) {
        lo += 'L' + XF(j + 1) + ',' + (pad.t + ch - (Math.max(0, fc[j] - band[j]) / max) * ch) + ' ';
    }
    s += '<path d="M' + lx + ',' + ly + ' ' + up + lo + ' Z" fill="#4c8dff" opacity=".25"/>';
    var fl = 'M' + lx + ',' + ly;
    fc.forEach(function(v, i) {
        fl += ' L' + XF(i + 1) + ',' + (pad.t + ch - (v / max) * ch);
    });
    s += '<path d="' + fl + '" fill="none" stroke="#7aa7ff" stroke-width="1"/></svg>';
    el.innerHTML = s;
}

function spark(el, data, color) {
    color = color || '#4c8dff';
    if (!data || data.length < 2) {
        el.innerHTML = '';
        return;
    }
    var W = el.clientWidth || 180,
        H = 40,
        max = Math.max.apply(null, [1].concat(data));
    var p = '';
    data.forEach(function(v, i) {
        p += (i ? 'L' : 'M') + (i / (data.length - 1)) * W + ',' + (H - 4 - (v / max) * (H - 8));
    });
    el.innerHTML = '<svg viewBox="0 0 ' + W + ' ' + H + '" style="width:100%;height:40px"><path d="' + p + '" fill="none" stroke="' + color + '" stroke-width="1"/></svg>';
}

function showView(n) {
    document.querySelectorAll('.view').forEach(function(v) {
        v.classList.remove('active');
    });
    $('view-' + n).classList.add('active');
    document.querySelectorAll('#topTabs button').forEach(function(b) {
        b.classList.toggle('active', b.dataset.view === n);
    });
    $('fside').style.display = (n === 'health') ? '' : 'none';
    if (n === 'health') renderHealth();
    if (n === 'overview') renderOverview();
    if (n === 'tracing') renderTracing();
    if (n === 'audit') renderAudit();
}

document.querySelectorAll('#topTabs button').forEach(function(b) {
    b.addEventListener('click', function() {
        if (b.dataset.view) showView(b.dataset.view);
    });
});

document.querySelectorAll('#latTabs button').forEach(function(b) {
    b.addEventListener('click', function() {
        document.querySelectorAll('#latTabs button').forEach(function(x) {
            x.classList.remove('active');
        });
        b.classList.add('active');
        state.latStat = b.dataset.s;
        renderLatency();
    });
});

function buildSidebar() {
    var models = (state.models || []).map(function(m) { return m.name; });
    if (!state.modelFilter.size) models.forEach(function(m) { state.modelFilter.add(m); });

    function makeItem(checked, onchange, name) {
        return '<label class="fitem"><input type="checkbox" ' + (checked ? 'checked' : '') + ' onchange="' + onchange + '(this,\'' + esc(name) + '\')">' + esc(name) + '</label>';
    }

    function makeGroup(title, items, checked, cb) {
        var content = items.length ? items.map(function(i) { return makeItem(checked.has(i), cb, i); }).join('') : '<div class="dim" style="padding:4px 6px;font-size:11px">—</div>';
        return '<div class="fgroup"><div onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display===\'none\'?\'\':\'none\'">▾ ' + esc(title) + '</div><div class="fitems">' + content + '</div></div>';
    }

    var noop = 'noop';
    window.noop = function() {};
    window.toggleModel = function(el, name) {
        if (el.checked) {
            state.modelFilter.add(name);
        } else {
            state.modelFilter.delete(name);
        }
        renderHealth();
    };

    var modelItems = models.length ? models.map(function(m) { return makeItem(state.modelFilter.has(m), 'toggleModel', m); }).join('') : '<div class="dim" style="padding:4px 6px;font-size:11px">no models yet</div>';
    $('fside').innerHTML = makeGroup('Provider', ['agentguard'], new Set(['agentguard']), noop) + '<div class="fgroup"><div>▾ Model</div><div class="fitems">' + modelItems + '</div></div>' + makeGroup('Service', ['agentguard-collector'], new Set(['agentguard-collector']), noop) + makeGroup('Agent', ['sdk-agent'], new Set(), noop);
}

function filteredModels() {
    return (state.models || []).filter(function(m) { return state.modelFilter.has(m.name); });
}

function renderHealth() {
    buildSidebar();
    renderLatency();
    var m = state.metrics || {};
    $('tokHero').textContent = fmtK(m.total_tokens || 0);
    var avg = (m.total_cost_usd || 0) / Math.max(1, m.total_spans || 0);
    $('avgCostHero').innerHTML = (avg * 1e6).toFixed(1) + '<span class="unit">µ$</span>';
    areaChart($('avgCostChart'), (state.costTrend || []).map(function(d) { return d.cost; }), null);
    forecastBand($('tokForecast'), (state.costTrend || []).map(function(d) { return d.tokens || 0; }));
    $('grHero').textContent = fmtK(m.total_spans || 0);
    var daySet = {};
    (state.checksDaily || []).forEach(function(c) { daySet[c.day] = 1; });
    var days = Object.keys(daySet).sort();
    var map = {};
    (state.checksDaily || []).forEach(function(c) { map[c.day + '|' + c.name] = c.flagged; });
    stackedTime($('grStacked'), days, map);
    var legendHTML = '';
    CHECKS.forEach(function(arr) { legendHTML += '<span><i style="background:' + arr[1] + '"></i>' + arr[0] + '</span>'; });
    $('grLegend').innerHTML = legendHTML;
    hbarsLegend($('tokModel'), filteredModels().slice().sort(function(a, b) {
        return (b.input_tokens + b.output_tokens) - (a.input_tokens + a.output_tokens);
    }), 'output_tokens', function(v) { return fmtK(v); });
}

function renderLatency() {
    var m = state.metrics || {},
        lat = state.latencyDist || {};
    var val = state.latStat === 'avg' ? m.avg_latency_ms : lat[state.latStat];
    $('ttrHero').innerHTML = val ? (Number(val) / 1000).toFixed(2) + '<span class="unit">s</span>' : '—';
    areaChart($('ttrChart'), (state.dailyTrend || []).map(function(d) { return d.total; }), (state.dailyTrend || []).map(function(d) { return (d.day || '').slice(5); }));
    hbarsLegend($('rtModel'), filteredModels().slice().sort(function(a, b) {
        return b.avg_latency_ms - a.avg_latency_ms;
    }), 'avg_latency_ms', function(v) { return Number(v).toFixed(0) + 'ms'; });
}

function renderOverview() {
    var m = state.metrics || {},
        r = m.risk_distribution || {};
    $('ovProblems').textContent = Number(r.high || 0) + Number(r.critical || 0);
    $('ovRequests').textContent = fmtK(m.total_spans || 0);
    $('ovRequestsT').innerHTML = trendHTML(trendPct((state.dailyTrend || []).map(function(d) { return d.total; })));
    $('ovCost').textContent = '$' + (m.total_cost_usd || 0).toFixed(2);
    $('ovCostT').innerHTML = trendHTML(trendPct((state.costTrend || []).map(function(d) { return d.cost; })), true);
    var total = Math.max(1, m.total_spans || 0),
        blk = m.blocked_operations || 0;
    donut($('ovDonut'), (total - blk) / total * 100, total - blk, blk);
    $('ovAvg').innerHTML = (Number(m.avg_latency_ms || 0) / 1000).toFixed(2) + '<span class="unit">s</span>';
    $('ovAvgT').innerHTML = trendHTML(trendPct((state.dailyTrend || []).map(function(d) { return d.total; })), true);
    var p99 = (state.latencyDist || {}).p99;
    $('ovP99').innerHTML = p99 ? ((p99) / 1000).toFixed(2) + '<span class="unit">s</span>' : '—';
    var p95 = (state.latencyDist || {}).p95 || 1;
    $('ovP99T').innerHTML = '<span class="trend down">↗ ' + (((p99 || 0) / Math.max(1, p95) * 8).toFixed(2)) + '%</span>';
    forecastBand($('ovForecast'), (state.costTrend || []).map(function(d) { return d.cost; }));
    var cb = state.checksBreakdown || [];
    var get = function(n) { return cb.find(function(c) { return c.check_name === n; }); };
    var inj = get('prompt_injection'),
        pii = get('pii_detection'),
        tool = get('tool_policy') || get('dangerous_params'),
        bud = get('budget_policy');

    function bigCard(t, v) {
        return '<div class="card"><div class="hero mid" style="font-size:34px">' + esc(v) + '</div><div class="clabel" style="text-align:center;margin-top:4px">' + esc(t) + '</div></div>';
    }
    $('gqBig').innerHTML = bigCard('Guardrail Executions', '100%') + bigCard('Prompt Injection', inj ? inj.flag_rate + '%' : '0%') + bigCard('PII Leaks', pii ? pii.flag_rate + '%' : '0%') + bigCard('Tool Policy', tool ? tool.flag_rate + '%' : '0%') + '<div class="card"><div class="clabel" style="text-align:center">ML Confidence</div><div class="hero sm" style="text-align:center">' + (((m.avg_ml_score || 0) * 100).toFixed(2)) + '</div><div id="spkML"></div></div>';

    function smCard(t, v, id) {
        return '<div class="card"><div class="clabel" style="font-size:10.5px">' + esc(t) + '</div><div class="hero sm">' + esc(v) + '</div><div id="' + id + '"></div></div>';
    }
    $('gqSmall').innerHTML = smCard('Overall Guardrail Activation', fmt(cb.reduce(function(a, c) { return a + c.flagged; }, 0)), 's1') + smCard('Blocked Prompts', fmt(m.blocked_operations || 0), 's2') + smCard('Prevented PII Leaks', fmt(pii ? pii.flagged : 0), 's3') + smCard('Budget Blocks', fmt(bud ? bud.flagged : 0), 's4') + '<div class="card"><div class="clabel" style="font-size:10.5px">Judge Confidence</div><div class="hero sm">' + (((m.avg_llm_score || 0) * 100).toFixed(2)) + '</div><div id="s5"></div></div>';
    spark($('s1'), (state.checksDaily || []).filter(function(c) { return c.name === 'prompt_injection'; }).map(function(c) { return c.flagged; }));
    spark($('s2'), (state.dailyTrend || []).map(function(d) { return d.blocked; }));
    spark($('s3'), (state.checksDaily || []).filter(function(c) { return c.name === 'pii_detection'; }).map(function(c) { return c.flagged; }));
    spark($('s4'), (state.checksDaily || []).filter(function(c) { return c.name === 'budget_policy'; }).map(function(c) { return c.flagged; }));
    spark($('s5'), (state.dailyTrend || []).map(function(d) { return d.total; }));
    var expRows = '';
    (state.expensive || []).forEach(function(e) {
        expRows += '<tr><td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + esc(e.prompt || '') + '">' + esc(e.prompt || '—') + '</td><td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + esc(e.response || '—') + '</td><td class="mono">' + esc(e.trace_id) + '</td><td class="mono">' + fmt((e.input_tokens || 0) + (e.output_tokens || 0)) + '</td><td class="mono">' + money(e.cost_usd) + '</td></tr>';
    });
    $('expTable').innerHTML = expRows || '<tr><td colspan="5" class="empty">No spans yet</td></tr>';
}

function renderTracing() {
    var traces = state.traces || [];
    if (!state.selTrace && traces.length) state.selTrace = traces[0].trace_id;
    var opts = '';
    traces.forEach(function(t) {
        opts += '<option value="' + esc(t.trace_id) + '" ' + (t.trace_id === state.selTrace ? 'selected' : '') + '>' + esc(t.trace_id) + '</option>';
    });
    $('traceSelect').innerHTML = opts || '<option>—</option>';
    $('traceSelect').onchange = function(e) {
        state.selTrace = e.target.value;
        loadTrace();
    };
    loadTrace();
}

function loadTrace() {
    var id = state.selTrace;
    if (!id) {
        $('spanTree').innerHTML = '<div class="empty">No traces</div>';
        return Promise.resolve();
    }
    return api('/api/traces/' + encodeURIComponent(id)).then(function(rows) {
        state.spans = rows;
        var dur = rows.reduce(function(a, r) { return a + Number(r.latency_ms || 0); }, 0);
        $('trDur').textContent = (dur / 1000).toFixed(2) + ' s';
        $('trErr').textContent = rows.filter(function(r) { return r.blocked; }).length;
        $('trId').textContent = id || '—';
        $('trDate').textContent = rows[0] ? ('at ' + String(rows[0].created_at).slice(0, 19)) : '';
        $('spanCount').textContent = rows.length + ' spans';
        var maxT = Math.max.apply(null, [1].concat(rows.map(function(r) { return Number(r.latency_ms || 0); })));
        $('ax0').textContent = '0 ms';
        $('ax1').textContent = (maxT / 2).toFixed(0) + ' ms';
        $('ax2').textContent = maxT.toFixed(0) + ' ms';
        var q = ($('spanSearch').value || '').toLowerCase();
        var treeHTML = '';
        rows.forEach(function(r, i) {
            var w = Math.max(2, (Number(r.latency_ms || 0) / maxT) * 96);
            var hide = q && !(r.span_type + ' ' + (r.model || '')).toLowerCase().includes(q);
            var dotClass = r.span_type === 'tool_call' ? 'client' : '';
            var clientLabel = r.span_type === 'llm_call' ? 'client' : 'internal';
            var modelPart = r.model ? '.' + esc(r.model.split('-')[0]) : '';
            var warnPart = r.blocked ? '<span class="warn"><span class="ui-icon" data-icon="error"></span></span>' : '';
            treeHTML += '<div class="span-row ' + (i === state.selSpan ? 'sel' : '') + '" style="' + (hide ? 'display:none' : '') + '" onclick="selectSpan(' + i + ')"><span class="tw"><span style="color:var(--dim)">—</span><span class="dot ' + dotClass + '"></span><span style="color:var(--dim);font-size:10.5px">' + clientLabel + '</span>' + esc(r.span_type) + modelPart + ' ' + warnPart + '</span><span class="track"><span class="bar ' + (r.blocked ? 'blocked' : '') + '" style="left:2%;width:' + w + '%"></span></span></div>';
        });
        $('spanTree').innerHTML = treeHTML || '<div class="empty">No spans</div>';
        $('excN').textContent = rows.filter(function(r) { return r.blocked; }).length;
        var excHTML = '';
        rows.filter(function(r) { return r.blocked; }).forEach(function(r, i) {
            var checksFailed = (r.security_checks || []).filter(function(c) { return !c.passed; }).map(function(c) { return '  [ERROR] ' + c.check_name + ' — ' + c.details; }).join('\n');
            excHTML += '<tr class="exc-row" onclick="this.nextElementSibling.hidden=!this.nextElementSibling.hidden"><td>▾</td><td class="mono">agentguard.SecurityException</td><td>' + esc(r.block_reason || 'blocked') + '</td></tr><tr hidden><td></td><td colspan="2"><div class="pilltag">Span events: exception id: ' + esc(r.span_id) + '</div><div class="codeblock"><b>Exception root cause:</b> ' + esc(r.block_reason || '') + '\n\nTraceback (most recent call last):\n  File "agentguard_sdk.py", in guard_' + esc(r.span_type) + '\n    raise SecurityException(...)\n' + checksFailed + '</div></td></tr>';
        });
        $('excTable').innerHTML = excHTML || '<tr><td colspan="3" class="empty">No exceptions</td></tr>';
        selectSpan(state.selSpan || 0);
    }).catch(function() {
        $('spanTree').innerHTML = '<div class="empty">Error loading trace</div>';
    });
}

window.selectSpan = function(i) {
    state.selSpan = i;
    var r = (state.spans || [])[i];
    if (!r) return;
    document.querySelectorAll('.span-row').forEach(function(el, j) {
        el.classList.toggle('sel', j === i);
    });

    function kv(k, v, cls) {
        cls = cls || '';
        return '<div class="attr-row"><span class="k">' + esc(k) + '</span><span class="v ' + cls + '">' + esc(v) + '</span></div>';
    }
    var prompt = ((r.input_data || {}).prompt || (r.input_data || {}).tool) || '';
    var response = ((r.output_data || {}).response || '').slice(0, 400);
    var mlScore = r.ml_score != null ? (r.ml_score * 100).toFixed(1) + '%' : '—';
    var llmScore = r.llm_score != null ? (r.llm_score * 100).toFixed(1) + '%' : '—';
    var decision = r.blocked ? 'BLOCK' : 'ALLOW';
    var decisionClass = r.blocked ? 'pink' : '';
    $('spanDetail').innerHTML = '<div class="card" style="margin-bottom:10px"><div style="display:flex;gap:10px;align-items:center"><span style="width:30px;height:30px;border-radius:6px;background:#3776ab;color:#fff;display:grid;place-items:center;font-weight:700">PY</span><div><b>' + esc(r.span_type) + '</b><div class="dim" style="font-size:11px">Service: <a href="#">agentguard-collector</a></div></div></div><div style="margin:10px 0;color:var(--muted);font-size:12px"><span class="ui-icon" data-icon="latency"></span> Duration: ' + Number(r.latency_ms || 0).toFixed(2) + ' ms</div></div><div class="attr-sec"><h4>gen ai <span>▾</span></h4>' + kv('Gen ai agent name', 'agentguard-sdk') + kv('Gen ai request model', r.model || 'unknown') + kv('Gen ai prompt 0 role', 'user') + kv('Gen ai prompt 0 content', prompt) + kv('Gen ai completion 0 role', 'assistant') + kv('Gen ai completion 0 content', response) + kv('Gen ai usage input tokens', r.input_tokens || 0, 'pink') + kv('Gen ai usage output tokens', r.output_tokens || 0, 'pink') + '</div><div class="attr-sec"><h4>agentguard <span>▾</span></h4>' + kv('Agentguard detection layer', r.detection_layer || 'regex') + kv('Agentguard ml score', mlScore, 'blue') + kv('Agentguard llm score', llmScore, 'blue') + kv('Agentguard decision', decision, decisionClass) + kv('Agentguard cost usd', Number(r.cost_usd || 0).toFixed(6), 'pink') + '</div>';
};

function renderAudit() {
    var d = new Date();
    var from = new Date(d - 14 * 864e5);
    $('auRange').textContent = from.toDateString().slice(4) + ' - ' + d.toDateString().slice(4);
    var modelsHTML = '';
    (state.models || []).slice().sort(function(a, b) { return b.requests - a.requests; }).forEach(function(m) {
        modelsHTML += '<tr><td>' + esc(m.name) + '</td><td style="text-align:right" class="mono">' + fmt(m.requests) + '</td></tr>';
    });
    $('auModels').innerHTML = modelsHTML || '<tr><td colspan="2" class="empty">No models</td></tr>';
    var daySet = {};
    (state.modelsDaily || []).forEach(function(x) { daySet[x.day] = 1; });
    var days = Object.keys(daySet).sort();
    var nameSet = {};
    (state.modelsDaily || []).forEach(function(x) { nameSet[x.model] = 1; });
    var names = Object.keys(nameSet).slice(0, 10);
    var series = names.map(function(n, i) {
        return {
            name: n,
            color: P[i % P.length],
            values: days.map(function(dy) {
                var f = (state.modelsDaily || []).find(function(x) { return x.day === dy && x.model === n; });
                return f ? f.n : 0;
            })
        };
    });
    multiLine($('auTrend'), days, series);
    var trailHTML = '';
    (state.audit || []).forEach(function(r) {
        trailHTML += '<tr><td class="dim">' + esc(String(r.timestamp).replace(' ', ' , ').slice(0, 20)) + '</td><td class="mono">' + esc(r.trace_id) + esc((r.span_id || '').slice(0, 4)) + '</td><td>agentguard</td><td class="mono">agentguard.security</td><td>' + esc(r.model) + '</td><td style="max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + esc(r.prompt) + '">' + esc(r.prompt || '—') + '</td><td>' + esc(r.span_type) + '</td><td>' + esc(r.layer) + '</td><td class="mono">' + (r.blocked ? 'PromptType.BLOCKED' : 'PromptType.INPUT') + '</td></tr>';
    });
    $('auTrail').innerHTML = trailHTML || '<tr><td colspan="9" class="empty">No audit events</td></tr>';
}


var CONNECT_INTEGRATIONS = {
    python: {target:'connectPython', title:'Python SDK', description:'Native AgentGuard instrumentation. Wrap LLM calls with guard_llm_call and side-effecting tools with guard_tool_call.', code:`pip install agentguard

from agentguard_sdk import AgentGuard

guard = AgentGuard(
    collector_url="https://YOUR_AGENTGUARD_HOST",
    api_key="YOUR_AGENTGUARD_API_KEY",
    agent_id="my-agent",
)

@guard.guard_llm_call
def call_model(prompt, model="gpt-5"):
    from openai import OpenAI
    return OpenAI().responses.create(model=model, input=prompt)

@guard.guard_tool_call("search_customer")
def search_customer(query):
    return your_search_function(query)`},
    mcp: {target:'connectMcp', title:'MCP', description:'Use an AgentGuard MCP adapter at the execution boundary. The adapter authorizes the tool call before forwarding it to the MCP server.', code:`# MCP server-side boundary
export AGENTGUARD_API_KEY="YOUR_AGENTGUARD_API_KEY"
export AGENTGUARD_COLLECTOR_URL="https://YOUR_AGENTGUARD_HOST"

# Request flow:
# MCP client -> AgentGuard adapter -> policy decision
#                         |-> deny / require approval
#                         |-> allow -> MCP server/tool
#                         |-> telemetry -> AgentGuard Collector

# Keep the API key out of the browser and MCP client UI.`},
    http: {target:'connectHttp', title:'HTTP Gateway', description:'Language-agnostic ingestion. Use this when the agent runtime cannot install the Python SDK. Verify the deployed API contract before production rollout.', code:`curl -X POST "https://YOUR_AGENTGUARD_HOST/api/spans" \\
  -H "Content-Type: application/json" \\
  -H "X-API-Key: YOUR_AGENTGUARD_API_KEY" \\
  -d '{
    "agent_id": "my-agent",
    "span_type": "tool_call",
    "tool": "search_customer",
    "input_data": {"query": "customer@example.com"}
  }'`},
    composio: {target:'connectComposio', title:'Composio', description:'Use AgentGuard immediately before Composio executes a tool. Keep both credentials server-side and treat the raw Composio tool as untrusted until authorized.', code:`from agentguard_sdk import AgentGuard

guard = AgentGuard(
    collector_url="https://YOUR_AGENTGUARD_HOST",
    api_key="YOUR_AGENTGUARD_API_KEY",
    agent_id="composio-agent",
)

@guard.guard_tool_call("composio_tool")
def run_composio_tool(tool, arguments):
    return composio_client.execute(tool, arguments)

# Pass guarded tool functions to your agent, not raw side-effecting tools.`},
    openai: {target:'connectOpenai', title:'OpenAI', description:'AgentGuard wraps the OpenAI call path while the existing SDK handles security checks, budgets and telemetry.', code:`from agentguard_sdk import AgentGuard
from openai import OpenAI

guard = AgentGuard(
    collector_url="https://YOUR_AGENTGUARD_HOST",
    api_key="YOUR_AGENTGUARD_API_KEY",
    agent_id="openai-agent",
)
client = OpenAI()

@guard.guard_llm_call
def ask_openai(prompt, model="gpt-5"):
    return client.responses.create(model=model, input=prompt)

response = ask_openai("Summarize the latest customer request")`},
    anthropic: {target:'connectAnthropic', title:'Anthropic', description:'Protect Claude requests with the same AgentGuard runtime boundary. Guard every side-effecting tool separately.', code:`from agentguard_sdk import AgentGuard
from anthropic import Anthropic

guard = AgentGuard(
    collector_url="https://YOUR_AGENTGUARD_HOST",
    api_key="YOUR_AGENTGUARD_API_KEY",
    agent_id="claude-agent",
)
client = Anthropic()

@guard.guard_llm_call
def ask_claude(prompt, model="claude-sonnet-4-5"):
    return client.messages.create(
        model=model,
        max_tokens=1024,
        messages=[{"role":"user","content":prompt}],
    )`},
    langgraph: {target:'connectLanggraph', title:'LangGraph', description:'Framework integration through node and tool wrappers. AgentGuard remains the policy and runtime enforcement layer.', code:`from agentguard_sdk import AgentGuard

guard = AgentGuard(
    collector_url="https://YOUR_AGENTGUARD_HOST",
    api_key="YOUR_AGENTGUARD_API_KEY",
    agent_id="langgraph-agent",
)

@guard.guard_llm_call
def model_node(state):
    return your_model.invoke(state["messages"])

@guard.guard_tool_call("search_customer")
def search_node(query):
    return your_search_function(query)

# Add the guarded functions to your StateGraph nodes/edges.`},
    crewai: {target:'connectCrewai', title:'CrewAI', description:'Framework integration through guarded task tools. Side-effecting operations must call AgentGuard before execution.', code:`from agentguard_sdk import AgentGuard

guard = AgentGuard(
    collector_url="https://YOUR_AGENTGUARD_HOST",
    api_key="YOUR_AGENTGUARD_API_KEY",
    agent_id="crewai-agent",
)

@guard.guard_tool_call("research_tool")
def guarded_research(query):
    return research_tool.run(query)

# Give CrewAI the guarded tool rather than the raw tool.
# Apply the same pattern to email, database, HTTP and payment tools.`}
};

function openConnectAgentModal() {
    var modal = $('connectAgentModal');
    if (!modal) return;
    modal.classList.add('open');
    document.body.style.overflow = 'hidden';
    showConnectChooser();
    renderObservedAgents();
}
function closeConnectAgentModal() {
    var modal = $('connectAgentModal');
    if (!modal) return;
    modal.classList.remove('open');
    document.body.style.overflow = '';
}
function showConnectChooser() {
    document.querySelectorAll('#connectAgentModal .connect-view').forEach(function(v){v.classList.remove('active');});
    $('connectChooser').classList.add('active');
}
function showConnectDetail(kind) {
    var cfg = CONNECT_INTEGRATIONS[kind];
    if (!cfg) return;
    document.querySelectorAll('#connectAgentModal .connect-view').forEach(function(v){v.classList.remove('active');});
    var target = $(cfg.target);
    target.innerHTML = '<button class="connect-back" type="button" onclick="showConnectChooser()"><span class="ui-icon" data-icon="back"></span> Back to integrations</button>' +
        '<h3>' + esc(cfg.title) + '</h3><p>' + esc(cfg.description) + '</p>' +
        '<div class="connect-code-wrap"><pre class="connect-code" id="connectCode-' + esc(kind) + '">' + esc(cfg.code) + '</pre><button class="connect-copy" type="button" onclick="copyConnectCode(\'' + esc(kind) + '\', this)">Copy</button></div>' +
        '<div class="connect-note"><b>Next:</b> run the integration from your server, send one real event, then return to the dashboard. AgentGuard derives observed agents from telemetry and does not provision credentials from the browser.</div>';
    target.classList.add('active');
    renderIcons(target);
}
function copyConnectCode(kind, button) {
    var cfg = CONNECT_INTEGRATIONS[kind];
    if (!cfg) return;
    var done = function(){var old=button.textContent;button.textContent='Copied';setTimeout(function(){button.textContent=old;},1400);};
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(cfg.code).then(done).catch(function(){toast('Copy failed');});
        return;
    }
    var ta=document.createElement('textarea');ta.value=cfg.code;ta.style.position='fixed';ta.style.opacity='0';document.body.appendChild(ta);ta.select();
    try{document.execCommand('copy');done();}catch(e){toast('Copy failed');}document.body.removeChild(ta);
}
function extractObservedAgents() {
    var candidates=[];
    var add=function(value,timestamp){if(value===null||value===undefined)return;var id=String(value).trim();if(!id||id==='undefined'||id==='null')return;candidates.push({id:id,timestamp:timestamp||null});};
    (state.recentEvents||[]).forEach(function(e){add(e.agent_id||e.agentId||e.org_id||e.orgId,e.created_at||e.timestamp||e.ts);});
    (state.traces||[]).forEach(function(t){add(t.agent_id||t.agentId||t.org_id||t.orgId,t.created_at||t.timestamp||t.started_at);});
    (state.spans||[]).forEach(function(s){add(s.agent_id||s.agentId||s.org_id||s.orgId,s.created_at||s.timestamp||s.ts);});
    var byId={};candidates.forEach(function(item){var prev=byId[item.id];if(!prev||String(item.timestamp||'')>String(prev.timestamp||''))byId[item.id]=item;});
    return Object.keys(byId).map(function(id){return byId[id];}).sort(function(a,b){return String(b.timestamp||'').localeCompare(String(a.timestamp||''));});
}
function observedAgentStatus(timestamp){
    if(!timestamp)return {label:'Observed',cls:''};
    var t=Date.parse(String(timestamp).replace(' ','T'));if(isNaN(t))return {label:'Observed',cls:''};
    var age=Date.now()-t;if(age<5*60*1000)return {label:'Connected',cls:'connected'};if(age<60*60*1000)return {label:'Idle',cls:'idle'};return {label:'Offline',cls:''};
}
function renderObservedAgents(){
    var el=$('connectAgentList');if(!el)return;var agents=extractObservedAgents();
    if(!agents.length){el.innerHTML='<div class="empty" style="padding:18px 8px">No agent telemetry observed yet.</div>';return;}
    el.innerHTML=agents.slice(0,10).map(function(agent){var status=observedAgentStatus(agent.timestamp);var when=agent.timestamp?String(agent.timestamp).replace('T',' ').slice(0,19):'recent telemetry';return '<div class="connect-agent-row"><span class="connect-agent-dot '+status.cls+'"></span><span class="connect-agent-name">'+esc(agent.id)+'</span><span class="connect-agent-status">'+esc(status.label)+' · '+esc(when)+'</span></div>';}).join('');
}
document.addEventListener('keydown',function(e){if(e.key==='Escape')closeConnectAgentModal();});

function refreshAll() {
    Promise.all([
        api('/api/metrics'),
        api('/api/traces'),
        api('/api/detection/stats'),
        api('/api/models'),
        api('/api/checks/breakdown'),
        api('/api/heatmap'),
        api('/api/spans/expensive'),
        api('/api/cost/trend'),
        api('/api/latency/distribution'),
        api('/api/events/recent'),
        api('/api/trend/daily'),
        api('/api/audit/trail'),
        api('/api/checks/daily'),
        api('/api/models/daily')
    ]).then(function(results) {
        var m = results[0],
            t = results[1],
            d = results[2],
            models = results[3],
            checks = results[4],
            heatmap = results[5],
            expensive = results[6],
            costTrend = results[7],
            latencyDist = results[8],
            recentEvents = results[9],
            dailyTrend = results[10],
            audit = results[11],
            checksDaily = results[12],
            modelsDaily = results[13];
        state.metrics = m;
        state.traces = t;
        state.detection = d;
        state.models = models;
        state.checksBreakdown = checks;
        state.heatmap = heatmap;
        state.expensive = expensive;
        state.costTrend = costTrend;
        state.latencyDist = latencyDist;
        state.recentEvents = recentEvents;
        state.dailyTrend = dailyTrend;
        state.audit = audit;
        state.checksDaily = checksDaily;
        state.modelsDaily = modelsDaily;
        renderObservedAgents();
        var active = document.querySelector('.view.active').id.replace('view-', '');
        showView(active);
        toast('Dashboard refreshed');
    }).catch(function(e) {
        toast('Collector unavailable: ' + e.message);
    });
}

refreshAll();
setInterval(refreshAll, 20000);
</script>
</body>
</html>
'''
