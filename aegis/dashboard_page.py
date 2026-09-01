"""Dashboard page markup — modern security-operations UI.

Separated from dashboard.py so the interface can evolve without touching
server logic. All element IDs and JS function names are a stable contract:
the server-side tests and the /api/* handlers depend on them.

Design language: ops-console dark — deep space background, cyan/emerald
accents, glassy cards, pill badges, live pulse. Everything renders on first
paint; the 3s refresh only swaps data.
"""

PAGE = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Aegis Workbench</title>
<style>
:root{
  --bg:#05070c; --panel:#0b111c; --panel2:#0e1624; --line:rgba(94,164,255,.14);
  --txt:#dbe7f5; --dim:#7d92ad; --cyan:#22d3ee; --green:#34d399;
  --red:#f87171; --orange:#fb923c; --yellow:#fbbf24; --blue:#60a5fa;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--txt);
  font-family:"Inter","Segoe UI",system-ui,sans-serif;
  background-image:radial-gradient(ellipse 60% 40% at 15% -5%,rgba(34,211,238,.07),transparent),
    radial-gradient(ellipse 50% 35% at 90% 0%,rgba(52,211,153,.05),transparent);}
header{position:sticky;top:0;z-index:10;display:flex;align-items:center;gap:1rem;
  padding:.8rem 1.6rem;background:rgba(5,7,12,.85);backdrop-filter:blur(10px);
  border-bottom:1px solid var(--line)}
.logo{font-size:1.15rem;font-weight:800;letter-spacing:.18em;
  background:linear-gradient(90deg,var(--cyan),var(--green));
  -webkit-background-clip:text;background-clip:text;color:transparent}
.logo small{color:var(--dim);-webkit-text-fill-color:var(--dim);
  font-weight:500;letter-spacing:.08em;font-size:.7rem;margin-left:.5rem}
.live{margin-left:auto;display:flex;align-items:center;gap:.45rem;
  font-size:.7rem;letter-spacing:.14em;color:var(--green);text-transform:uppercase}
.dot{width:8px;height:8px;border-radius:50%;background:var(--green);
  box-shadow:0 0 8px var(--green);animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.35}}
.wrap{max-width:1400px;margin:0 auto;padding:1.4rem 1.6rem 3rem}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem;margin-bottom:1.4rem}
.stat{background:linear-gradient(180deg,var(--panel2),var(--panel));
  border:1px solid var(--line);border-radius:12px;padding:.9rem 1.1rem}
.stat .n{font-size:1.6rem;font-weight:800;font-family:"JetBrains Mono",ui-monospace,monospace}
.stat .l{font-size:.62rem;letter-spacing:.16em;text-transform:uppercase;color:var(--dim)}
.stat.c-cyan .n{color:var(--cyan)} .stat.c-red .n{color:var(--red)}
.stat.c-green .n{color:var(--green)} .stat.c-blue .n{color:var(--blue)}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:1.1rem}
@media(max-width:900px){.grid,.stats{grid-template-columns:1fr}}
.card{background:linear-gradient(180deg,var(--panel2),var(--panel));
  border:1px solid var(--line);border-radius:12px;padding:1.1rem 1.25rem;
  transition:border-color .2s}
.card:hover{border-color:rgba(94,164,255,.3)}
.card.full{margin-top:1.1rem}
h2{font-size:.68rem;letter-spacing:.18em;text-transform:uppercase;color:var(--dim);
  margin:0 0 .8rem;padding-bottom:.5rem;border-bottom:1px solid var(--line);
  font-weight:700}
.card h2 + div{min-height:1rem}
table{border-collapse:collapse;width:100%;font-size:.8rem}
td,th{padding:.3rem .55rem;text-align:left;border-bottom:1px solid rgba(94,164,255,.08)}
th{color:var(--dim);font-size:.66rem;letter-spacing:.1em;text-transform:uppercase}
.mono{font-family:"JetBrains Mono",ui-monospace,Consolas,monospace;
  font-size:.75rem;color:#9db3cc}
.pill{display:inline-block;padding:.08rem .5rem;border-radius:999px;
  font-size:.62rem;font-weight:700;letter-spacing:.08em;vertical-align:middle}
.sev-critical{color:#fecaca;background:rgba(248,113,113,.14);border:1px solid rgba(248,113,113,.35)}
.sev-high{color:#fed7aa;background:rgba(251,146,60,.12);border:1px solid rgba(251,146,60,.3)}
.sev-medium{color:#fde68a;background:rgba(251,191,36,.1);border:1px solid rgba(251,191,36,.28)}
.sev-low{color:#bae6fd;background:rgba(96,165,250,.1);border:1px solid rgba(96,165,250,.28)}
.sev-info{color:var(--dim);background:rgba(125,146,173,.08);border:1px solid rgba(125,146,173,.25)}
.ok{color:var(--green)} .fail{color:var(--red)}
a{color:var(--cyan);text-decoration:none} a:hover{text-decoration:underline}
input,select{background:#070d17;border:1px solid var(--line);color:var(--txt);
  border-radius:8px;padding:.5rem .7rem;font-size:.82rem;outline:none;
  transition:border-color .15s,box-shadow .15s}
input:focus,select:focus{border-color:var(--cyan);
  box-shadow:0 0 0 3px rgba(34,211,238,.12)}
button{background:linear-gradient(90deg,rgba(34,211,238,.18),rgba(52,211,153,.18));
  border:1px solid rgba(34,211,238,.4);color:var(--cyan);border-radius:8px;
  padding:.5rem 1.1rem;font-size:.78rem;font-weight:700;letter-spacing:.08em;
  text-transform:uppercase;cursor:pointer;transition:all .15s}
button:hover{border-color:var(--cyan);box-shadow:0 0 14px rgba(34,211,238,.25);
  color:#a5f3fc}
form{display:flex;gap:.6rem;flex-wrap:wrap;align-items:center}
pre{white-space:pre-wrap;background:#04080f;border:1px solid var(--line);
  border-radius:8px;padding:.8rem;max-height:26rem;overflow:auto;
  font-family:"JetBrains Mono",ui-monospace,monospace;font-size:.75rem;color:#9db3cc}
.chip{display:inline-block;background:rgba(34,211,238,.06);
  border:1px solid rgba(34,211,238,.2);border-radius:6px;
  padding:.1rem .5rem;margin:.14rem;font-size:.72rem;color:#a5c4e4}
.row{padding:.28rem 0;border-bottom:1px solid rgba(94,164,255,.06)}
.row:last-child{border-bottom:none}
.tgt-host{font-weight:600}
.status{font-size:.66rem;letter-spacing:.1em;text-transform:uppercase;
  color:var(--yellow);margin-left:.5rem}
.runbtn{color:var(--green);font-size:.7rem;white-space:nowrap;font-weight:700}
.stopbtn{color:var(--red);font-weight:700}
.loglink{font-size:.68rem;color:var(--dim)}
.loglink:hover{color:var(--cyan)}
footer{margin-top:2.5rem;text-align:center;font-size:.66rem;color:#3d4f68;
  letter-spacing:.12em;text-transform:uppercase}
</style></head><body>
<header>
  <div class="logo">AEGIS<small>WORKBENCH · live engagement</small></div>
  <div class="live"><span class="dot"></span>live</div>
</header>
<div class="wrap">

<div class="stats">
  <div class="stat c-cyan"><div class="n" id="stat-targets">0</div><div class="l">Targets</div></div>
  <div class="stat c-red"><div class="n" id="stat-findings">0</div><div class="l">Findings</div></div>
  <div class="stat c-green"><div class="n" id="stat-loot">0</div><div class="l">Loot items</div></div>
  <div class="stat c-blue"><div class="n" id="stat-missions">0</div><div class="l">Missions running</div></div>
</div>

<div class="grid">
<div class="card"><h2>◈ Targets</h2><div id="targets"></div></div>
<div class="card"><h2>◈ ATT&CK Coverage</h2><div id="attack"></div></div>
<div class="card"><h2>◈ Findings</h2><div id="findings"></div></div>
<div class="card"><h2>◈ Loot Vault</h2><div id="loot"></div></div>
</div>

<div class="card full"><h2>◈ Mission Control</h2>
<form onsubmit="launch(event)">
<input id="mhost" placeholder="in-scope target host" required>
<select id="mmode"><option>scan</option><option>attack</option><option>mission</option></select>
<button type="submit">Launch ▸</button></form>
<div id="missions" class="mono" style="margin-top:.7rem"></div></div>

<div class="card full"><h2>◈ Add to Scope</h2>
<form onsubmit="addScope(event)">
<input id="shost" placeholder="IP / host / CIDR" required>
<input id="snetwork" placeholder="network / room label (e.g. THM-Attacks)">
<button type="submit">Authorize</button></form>
<div id="scopemsg" class="mono" style="margin-top:.5rem"></div>
<div class="mono" style="margin-top:.3rem;opacity:.7">Adds to authorization.json (audited) and registers the target.</div></div>

<div class="card full"><h2>◈ Playbook Knowledge Base</h2>
<form onsubmit="addKb(event)">
<select id="kbgroup"><option value="version_hints">version exploit</option>
<option value="service_hints">service playbook</option>
<option value="port_hints">port fallback</option></select>
<input id="kbpattern" placeholder="regex on service string, or port (e.g. 6379)" required style="flex:1;min-width:220px">
<input id="kbhint" placeholder="attack hint — use TARGET as host placeholder" required style="flex:1.2;min-width:240px">
<button type="submit">Add rule</button></form>
<div id="kbmsg" class="mono" style="margin-top:.5rem"></div>
<div id="kbrules" class="mono" style="margin-top:.5rem"></div></div>

<div class="card full"><h2>◈ Recent Activity</h2>
<div id="actions"></div></div>

<div class="card full"><h2>◈ Target Command Center</h2>
<div id="detail">click a target above to explore everything known about it</div></div>

<div class="card full"><h2>◈ Action Log</h2>
<pre id="logview">press [log] on any action in the command center</pre></div>

<footer>Aegis Workbench · authorized security testing only · every action is audit-chained</footer>
</div>
<script>
const TOK = new URLSearchParams(location.search).get('token');
const REVEALED = {};  // loot id -> revealed value; survives the 3s refresh
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,
  c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function sevPill(s){return `<span class="pill sev-${s}">${s.toUpperCase()}</span>`;}
async function launch(e){
  e.preventDefault();
  await fetch('/api/mission/start?token='+TOK, {method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({host: mhost.value, mode: mmode.value})});
}
async function addScope(e){
  e.preventDefault();
  const r = await fetch('/api/scope/add?token='+TOK, {method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({host: shost.value, network: snetwork.value})});
  const j = await r.json();
  document.getElementById('scopemsg').textContent =
    j.added ? '✔ authorized: '+shost.value : '✘ '+(j.error||'failed');
}
async function addKb(e){
  e.preventDefault();
  const r = await fetch('/api/playbook/add?token='+TOK, {method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({group: kbgroup.value, pattern: kbpattern.value,
                          hint: kbhint.value})});
  const j = await r.json();
  document.getElementById('kbmsg').textContent =
    j.added ? '✔ rule added — live for the next planning step'
            : '✘ '+(j.error||'failed');
  if (j.added){ kbpattern.value=''; kbhint.value=''; }
  loadKb();
}
async function kbAction(op, i){
  await fetch('/api/playbook/'+op+'?token='+TOK, {method:'POST',
    headers:{'Content-Type':'application/json'}, body: JSON.stringify({index:i})});
  loadKb();
}
async function loadKb(){
  try {
    const j = await (await fetch('/api/playbook?token='+TOK)).json();
    const b = j.bundled, c = j.custom;
    const custom = (c.version_hints||[]).map(r=>['version',...r])
      .concat((c.service_hints||[]).map(r=>['service',...r]))
      .concat(Object.entries(c.port_hints||{}).map(([k,v])=>['port',k,v]));
    const drafts = (c.drafts||[]);
    document.getElementById('kbrules').innerHTML =
      `<div class="row">${b.version_hints} version + ${b.service_hints} service + `+
      `${b.port_hints} port rules bundled — custom rules fire first, hot-reloaded</div>` +
      (drafts.length ? '<div class="row" style="color:var(--yellow)">⏳ learned drafts — review before they go live:</div>' +
        drafts.map((d,i)=>`<div class="row">✎ <b>${d.group}</b> <span class="mono">${esc(d.pattern)}</span> → ${esc(d.hint)}
          <a href="#" onclick="kbAction('promote',${i});return false" style="color:var(--green)">promote</a>
          <a href="#" onclick="kbAction('dismiss',${i});return false" style="color:var(--red)">dismiss</a></div>`).join('') : '') +
      (custom.map(r=>`<div class="row">· <b>${r[0]}</b> <span class="mono">${esc(r[1])}</span> → ${esc(r[2])}</div>`).join('') ||
       '<div class="row">no live custom rules yet</div>');
  } catch(e){ /* transient */ }
}
async function stopMission(id){
  await fetch('/api/mission/stop?token='+TOK, {method:'POST',
    headers:{'Content-Type':'application/json'}, body: JSON.stringify({id})});
}
async function revealLoot(id){
  try {
    const r = await fetch('/api/loot?id='+id+'&reveal=1&token='+TOK);
    const j = await r.json();
    REVEALED[id] = j.error ? '⚠ '+j.error
                           : (j.value || j.file_path || '(no value stored)');
  } catch(e) { REVEALED[id] = '⚠ reveal failed: '+e; }
  refresh();
}
function lootLine(l){
  const shown = REVEALED[l.id] !== undefined ? REVEALED[l.id] : (l.value||'');
  const link = REVEALED[l.id] !== undefined ? '' :
    ` <a href="#" onclick="revealLoot(${l.id});return false" class="loglink">reveal</a>`;
  return `<div class="row"><span class="pill sev-info">${esc(l.kind)}</span> ${esc(l.title)} <span class="mono">${esc(shown)}</span>${link}</div>`;
}
// ---- Target Command Center --------------------------------------------------
let SEL = null;
let LAST_DETAIL = null;  // last /api/target payload (hint commands live here)
async function selectTarget(id){ SEL = id; await loadDetail(); }
async function loadDetail(){
  if (SEL == null) return;
  try {
    const d = await (await fetch('/api/target?id='+SEL+'&token='+TOK)).json();
    if (d.error){ document.getElementById('detail').textContent = d.error; return; }
    LAST_DETAIL = d;
    renderDetail(d);
  } catch(e){ /* transient — next refresh retries */ }
}
async function runHint(hi, ci, el){
  const d = LAST_DETAIL; if (!d) return;
  const cmd = ((d.hint_commands||[])[hi]||[])[ci]; if (!cmd) return;
  el.textContent = '⏳'; el.style.pointerEvents = 'none';
  try {
    const r = await fetch('/api/run?token='+TOK, {method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({host: d.target.host, command: cmd})});
    const j = await r.json();
    el.textContent = j.started ? '✔ started' : '✘ '+(j.error||'failed');
  } catch(e){ el.textContent = '✘ '+e; }
  setTimeout(refresh, 800);
}
async function showLog(id){
  const r = await fetch('/api/action/log?id='+id+'&token='+TOK);
  document.getElementById('logview').textContent = await r.text();
  document.getElementById('logview').scrollIntoView({behavior:'smooth'});
}
function renderDetail(d){
  const t = d.target;
  const svc  = d.intel.filter(i=>i.kind==='service');
  const web  = d.intel.filter(i=>i.kind==='web');
  const os   = d.intel.filter(i=>i.kind==='os');
  const tech = d.intel.filter(i=>i.kind==='tech');
  let h = `<div><b style="font-size:1.05rem">${esc(t.host)}</b>
    <span class="status">${esc(t.status)}</span>
    <span class="mono">${esc(t.description||'')}</span></div>`;
  if (d.hints && d.hints.length) {
    h += '<h2 style="margin-top:1rem">Playbook recommendations</h2>' + d.hints.map((x,hi)=>{
      const cmds = (d.hint_commands||[])[hi]||[];
      const btns = cmds.map((c,ci)=>
        ` <a href="#" onclick="runHint(${hi},${ci},this);return false"
           title="${esc(c)}" class="runbtn">▶ run</a>`
      ).join('');
      return `<div class="row mono">▸ ${esc(x)}${btns}</div>`;
    }).join('');
  }
  h += '<h2 style="margin-top:1rem">Infrastructure</h2>';
  h += svc.length
    ? '<table><tr><th>port</th><th>service / version</th></tr>' +
      svc.map(s=>`<tr><td class="mono">${esc(s.key)}</td><td>${esc(s.value)}</td></tr>`).join('') +
      '</table>'
    : '<div class="mono">no services identified yet</div>';
  h += '<div style="margin-top:.5rem">' +
       web.map(w=>`<span class="chip">🌐 ${esc(w.key)}: ${esc(w.value)}</span>`).join('') +
       os.map(w=>`<span class="chip">🖥 ${esc(w.value)}</span>`).join('') +
       tech.map(w=>`<span class="chip">⚙ ${esc(w.value)}</span>`).join('') + '</div>';
  h += '<h2 style="margin-top:1rem">Findings</h2>' + (d.findings.map(f=>
    `<div class="row">${sevPill(f.severity)} ${esc(f.title)}</div>`
    ).join('') || '<div class="mono">none</div>');
  h += '<h2 style="margin-top:1rem">Loot</h2>' + (d.loot.map(lootLine).join('') || '<div class="mono">none</div>');
  h += '<h2 style="margin-top:1rem">Attempts</h2>' + (d.attempts.map(a=>
    `<div class="row mono"><span class="${a.success?'ok':'fail'}">${a.success?'✔':'✘'}</span> `+
    `${esc(a.technique)}${a.vector?' via '+esc(a.vector):''} — ${esc((a.result||'').slice(0,140))}</div>`
    ).join('') || '<div class="mono">none</div>');
  h += '<h2 style="margin-top:1rem">Actions</h2>' + (d.actions.map(a=>
    `<div class="row mono">[${a.ts}] ${esc(a.command)} —
     <span class="${a.exit_code==0?'ok':'fail'}">${a.status}${a.exit_code?' (exit '+a.exit_code+')':''}</span>
     <a href="#" onclick="showLog(${a.id});return false" class="loglink">log</a></div>` +
    (a.error ? `<div class="fail mono" style="white-space:pre-wrap;margin:0 0 .4rem 1rem">${esc(a.error)}</div>` : '')
    ).join('') || '<div class="mono">none</div>');
  document.getElementById('detail').innerHTML = h;
}
async function refresh(){
  const s = await (await fetch('/api/state?token='+TOK)).json();
  document.getElementById('stat-targets').textContent = s.targets.length;
  document.getElementById('stat-findings').textContent = s.findings.length;
  document.getElementById('stat-loot').textContent = s.loot.length;
  document.getElementById('stat-missions').textContent =
    Object.values(s.missions||{}).filter(m=>m.status==='running').length;
  document.getElementById('targets').innerHTML = s.targets.map(t =>
    `<div class="row"><b class="tgt-host"><a href="#" onclick="selectTarget(${t.id});return false">${esc(t.host)}</a></b>
     <span class="status">${esc(t.status)}</span></div>`).join('') || 'none';
  document.getElementById('attack').innerHTML =
    '<table>' + s.attack.map(a =>
      `<tr><td>${esc(a.tactic)}</td><td class="mono">${a.tried}</td><td class="mono ok">${a.succeeded}</td></tr>`
    ).join('') + '</table>';
  document.getElementById('findings').innerHTML = s.findings.map(f =>
    `<div class="row">${sevPill(f.severity)} ${esc(f.title)}
     <span class="mono">${esc(f.host||'')}</span></div>`).join('') || 'none yet';
  document.getElementById('loot').innerHTML = s.loot.map(lootLine).join('') || 'none yet';
  document.getElementById('actions').innerHTML = s.actions.map(a =>
    `<div class="row mono">[${a.ts}] <b>${esc(a.agent)}</b> ${esc(a.command)}
     — <span class="${a.exit_code==0?'ok':'fail'}">${a.status}${
       a.exit_code ? ' (exit '+a.exit_code+')' : ''}</span></div>` +
    (a.error ? `<div class="fail mono" style="white-space:pre-wrap;margin:0 0 .5rem 1rem">${esc(a.error)}</div>` : '')
  ).join('') || 'none yet';
  document.getElementById('missions').innerHTML = Object.entries(s.missions||{})
    .map(([id,m]) => `<div class="row mono">mission ${id}: <b>${esc(m.mode)}</b> ${esc(m.host)} — ${esc(m.status)}` +
      (m.status==='running' ?
       ` <a href="#" onclick="stopMission(${id});return false" class="stopbtn">■ stop</a>` : '') + `</div>`)
    .join('') || 'no missions yet';
  if (SEL != null) loadDetail();
  loadKb();
}
refresh(); setInterval(refresh, 3000);
</script></body></html>"""
