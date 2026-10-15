// Capability token (C4b): when the server runs as an authZ'd API it injects the
// operator Grant here, and this wrapper attaches it to every same-origin API/ICS
// request. Empty (household mode) = no header, unchanged behavior.
(function(){const f=window.fetch.bind(window);window.fetch=(u,o)=>{o=o||{};const s=typeof u==='string'?u:(u&&u.url)||'';if(__CAP__&&(s.indexOf('/api/')===0||s.indexOf('/ics/')===0)){o.headers=Object.assign({},o.headers||{},{'Authorization':'Bearer '+__CAP__});}return f(u,o);};})();
const $=s=>document.querySelector(s);
const TABS=['chat','calendar','adddata','week','tasks','activity','directory','security','prompts','sampling','models','runtime','skills','retrieval','rag','grammar','policies','budgets','eval'];
// esc makes a value safe as HTML text AND inside a double- or single-quoted attribute
// (textContent->innerHTML leaves quotes alone, which broke every attribute that carried one).
const esc=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
// jsarg quotes a value as a JavaScript string literal for an inline onclick="fn(...)" handler.
// The HTML parser decodes entities BEFORE the JS parser runs, so esc() alone cannot protect a
// JS string: a title like "Chancellor's Day" ended the literal and the click was a SyntaxError
// (nothing sent, nothing saved). JSON-quote first, then entity-escape for the attribute.
const jsarg=s=>esc(JSON.stringify(String(s==null?'':s)));
const when=e=>e.all_day?((e.due||e.start)+' · all day'):((e.start||e.due)+(e.end?(' – '+e.end.slice(11)):''));
// descLine renders an item's source-context description (the email words it came from),
// so a cryptic title is understandable. Skipped when it just repeats the title.
function descLine(e){
  const n=((e.notes||'')+'').trim();
  if(!n||n.toLowerCase()===((e.title||'')+'').toLowerCase().trim())return '';
  return '<div class="mut" style="font-size:13px;margin-top:3px;font-style:italic">“'+esc(n)+'”</div>';
}
// Theme: a manual light/dark toggle that overrides the OS preference (persisted).
function effectiveDark(){const dt=document.documentElement.dataset.theme;if(dt)return dt==='dark';return window.matchMedia&&matchMedia('(prefers-color-scheme:dark)').matches;}
function themeBtnText(){const b=$('#themeToggle');if(b)b.textContent=effectiveDark()?'☀️ Light mode':'🌙 Dark mode';}
function applyTheme(t){document.documentElement.dataset.theme=t;try{localStorage.setItem('theme',t);}catch(e){}themeBtnText();}
function toggleTheme(){applyTheme(effectiveDark()?'light':'dark');}
themeBtnText();
document.querySelectorAll('nav button').forEach(b=>b.onclick=()=>{
  document.querySelectorAll('nav button').forEach(x=>x.classList.toggle('active',x===b));
  TABS.forEach(t=>$('#'+t).classList.toggle('hide',t!==b.dataset.tab));
  const t=b.dataset.tab;
  if(t==='chat'){const q=$('#chatq');if(q)q.focus();loadMiniCal();loadChatHistory();}
  if(t==='calendar'){loadEvents();loadDeadlines();setView('month');}
  if(t==='adddata') loadAddData();
  if(t==='week'){loadWeekStrip();loadProfile();}
  if(t==='tasks'){loadTasks();loadReview();}
  if(t==='directory') loadDirectory();
  if(t==='activity') setActView('plain');
  if(t==='security'){loadKill();loadMCP();loadBundles();}
  if(t==='prompts') loadPrompts();
  if(t==='sampling') loadSampling();
  if(t==='models'){loadModels();loadModelCatalog();loadFrontier();}
  if(t==='runtime') loadRuntime();
  if(t==='rag') loadRAG();
  if(t==='skills') loadSkills();
  if(t==='retrieval') loadRetrieval();
  if(t==='grammar') loadGrammar();
  if(t==='budgets') loadBudgets();
  if(t==='policies') loadPolicies();
  if(t==='eval') loadEval();
});
// --- App / Studio surface split: 1 view, 1 job ---
// App = consumer (zero control knobs); Studio = operator (the tuning/governance plane).
const SURFACES={
  app:['chat','calendar','adddata','week','tasks','directory'],
  studio:['security','prompts','sampling','models','runtime','skills','retrieval','rag','grammar','policies','budgets','eval','activity']
};
(function(){
  const vis=(SURFACES[SURFACE]||TABS);
  document.querySelectorAll('nav button').forEach(b=>{ if(vis.indexOf(b.dataset.tab)<0) b.style.display='none'; });
  TABS.forEach(t=>{ if(vis.indexOf(t)<0){ const el=$('#'+t); if(el) el.classList.add('hide'); }});
  // hide a group label if no visible button follows it (until the next label)
  const nav=document.querySelector('nav'); let grp=null, seen=false;
  [...nav.children].forEach(el=>{
    if(el.classList&&el.classList.contains('grp')){ if(grp&&!seen) grp.style.display='none'; grp=el; seen=false; }
    else if(el.tagName==='BUTTON' && el.style.display!=='none'){ seen=true; }
  });
  if(grp&&!seen) grp.style.display='none';
  const sw=$('#surfaceSwitch');
  if(sw){ if(SURFACE==='studio'){ sw.textContent='🏠 Back to App'; sw.href='/'; } else { sw.textContent='⚙ Studio'; sw.href='/studio'; } }
  const first=document.querySelector('nav button[data-tab="'+vis[0]+'"]');
  if(first) first.click(); // land on this surface's first tab
})();
// A directory, not a raw address dump: real Name · Role entries first (from the
// profile teachers today), then the scraped addresses grouped so a school address
// isn't mixed in with a personal one. Addresses are shown as plain text, never
// clickable links — they came from untrusted email and we don't action them here.
function isSchoolAddr(e){const d=(e.split('@')[1]||'').toLowerCase();return /(^|\.)schools\.|\.gov$|\.edu$|nycps|\.org$/.test(d);}
function addrRow(e){return '<div class="ev"><div><span class="mut">'+esc(e)+'</span></div></div>';}
async function loadDirectory(){
  const c=$('#directoryList');if(!c)return;const d=await getJSON('/api/directory');
  const ppl=d.people||[];const em=d.emails||[];
  if(!ppl.length&&!em.length){c.innerHTML='<p class="mut">No contacts yet — add your child’s teacher in My Week, or drop a school email in Add Data.</p>';return;}
  let h='';
  if(ppl.length) h+='<h3>People</h3>'+ppl.map(p=>'<div class="ev"><div><b>'+esc(p.name)+'</b> <span class="kind">'+esc(p.role)+'</span></div></div>').join('');
  const school=em.filter(isSchoolAddr),other=em.filter(e=>!isSchoolAddr(e));
  if(school.length) h+='<h3>School contacts</h3>'+school.map(addrRow).join('');
  if(other.length) h+='<h3>Other addresses seen</h3><p class="mut" style="margin:4px 0 8px">Scraped from your emails; may be personal — not an official directory.</p>'+other.map(addrRow).join('');
  c.innerHTML=h;
}
function chatFeedbackHTML(turnId,rating){
  if(!turnId)return '';
  const on=x=>rating===x?' on':'';
  return '<div class="fb" data-turn="'+turnId+'">'+
    '<button class="thumb'+on('up')+'" title="good" onclick="rateChat('+turnId+',\'up\',this)">👍</button>'+
    '<button class="thumb'+on('neutral')+'" title="ok" onclick="rateChat('+turnId+',\'neutral\',this)">😐</button>'+
    '<button class="thumb'+on('down')+'" title="bad" onclick="rateChat('+turnId+',\'down\',this)">👎</button></div>';
}
function chatMetaHTML(r){
  const bits=[];
  if(r.model)bits.push('model '+esc(r.model));
  if(r.prompt_tokens)bits.push(r.prompt_tokens+' ctx + '+(r.completion_tokens||0)+' out tok');
  if(r.retrieval)bits.push(r.retrieval.indexOf('unavailable')>=0?'<span style="color:var(--bad)">'+esc(r.retrieval)+'</span>':esc(r.retrieval));
  return bits.length?'<div class="meta mut">'+bits.join(' · ')+'</div>':'';
}
function assistantHTML(r,unsafe){
  const src=(r.sources&&r.sources.length)?'<div class="src">sources: '+r.sources.map(esc).join(', ')+'</div>':'';
  const warn=unsafe?'<div class="src" style="color:var(--bad)">⚠ controls off — retrieved text spliced in raw (injection can hijack)</div>':'';
  return '<div class="msg a">'+esc(r.answer||'(no answer)')+warn+src+chatMetaHTML(r)+chatFeedbackHTML(r.turn_id,r.rating)+'</div>';
}
function updateChatStatus(r){
  const el=$('#chatStatus');if(!el)return;
  if(!r||(!r.model&&!r.prompt_tokens)){el.textContent='';return;}
  let s=r.model?('model: '+r.model):'';
  if(r.context_limit){const pct=Math.round(100*(r.prompt_tokens||0)/r.context_limit);s+=(s?'  ·  ':'')+'context '+(r.prompt_tokens||0)+' / '+r.context_limit+' ('+pct+'%)';}
  else if(r.prompt_tokens){s+=(s?'  ·  ':'')+r.prompt_tokens+' ctx + '+(r.completion_tokens||0)+' out tokens';}
  el.textContent=s;
}
async function loadChatHistory(){
  const log=$('#chatlog');if(!log)return;
  const d=await getJSON('/api/chat/history');const turns=d.turns||[];
  log.innerHTML='';let last=null;
  turns.forEach(t=>{
    if(t.role==='user')log.insertAdjacentHTML('beforeend','<div class="msg u">'+esc(t.content)+'</div>');
    else{log.insertAdjacentHTML('beforeend',assistantHTML({answer:t.content,sources:t.sources,model:t.model,prompt_tokens:t.prompt_tokens,completion_tokens:t.completion_tokens,turn_id:t.id,rating:t.rating},!!t.unsafe));last={model:t.model,prompt_tokens:t.prompt_tokens,completion_tokens:t.completion_tokens};}
  });
  updateChatStatus(last);
  log.scrollTop=log.scrollHeight;
}
async function rateChat(turnId,rating,btn){
  const wrap=btn.closest('.fb');
  // Send a snippet of the rated answer so Studio shows WHAT was rated (the tuning signal).
  const msg=btn.closest('.msg');
  const label=msg?(msg.textContent||'').trim().slice(0,140):'';
  const r=await postJSON('/api/chat/feedback',{turn_id:turnId,rating:rating,label:label});
  if(r.ok&&wrap){wrap.querySelectorAll('.thumb').forEach(b=>b.classList.remove('on'));btn.classList.add('on');}
}
async function clearChat(){
  if(!confirm('Clear the conversation history?'))return;
  const r=await postJSON('/api/chat/clear',{});
  if(r.ok){const log=$('#chatlog');if(log)log.innerHTML='';updateChatStatus(null);}
}
async function sendChat(){
  const inp=$('#chatq');const q=(inp.value||'').trim();if(!q)return;const log=$('#chatlog');
  const unsafe=$('#chatUnsafe')&&$('#chatUnsafe').checked;
  log.insertAdjacentHTML('beforeend','<div class="msg u">'+esc(q)+'</div>');inp.value='';
  log.insertAdjacentHTML('beforeend','<div class="msg a" id="pending"><span class="mut">thinking…</span></div>');log.scrollTop=log.scrollHeight;
  let r;try{r=await (await postJSON('/api/chat',{question:q,unsafe:unsafe})).json();}catch(e){r={answer:'error'};}
  const p=document.getElementById('pending');if(p)p.remove();
  log.insertAdjacentHTML('beforeend',assistantHTML(r,unsafe));
  updateChatStatus(r);
  log.scrollTop=log.scrollHeight;
}
document.addEventListener('keydown',e=>{if(e.key==='Enter'&&document.activeElement&&document.activeElement.id==='chatq')sendChat();});
async function doEnrich(){
  const u=$('#enrichURL').value.trim();const c=$('#enrichOut');if(!u){return;}
  // phase 1: request the HITL challenge
  let r=await (await postJSON('/api/enrich',{url:u})).json();
  if(r.confirm_required){
    if(!confirm('Fetch into the knowledge base?\n'+(r.evidence||[]).join('\n'))){c.textContent='cancelled';return;}
    r=await (await postJSON('/api/enrich',{url:u,nonce:r.nonce,confirm:true})).json();
  }
  if(r.refused){c.innerHTML='<span class="kind warn">refused</span> '+esc(r.refused);return;}
  if(r.ok){c.innerHTML='indexed '+r.bytes+' bytes from <b>'+esc(r.url)+'</b><br><span class="mut">'+esc(r.preview||'')+'</span>';}
}
async function loadKill(){const d=await getJSON('/api/safety');const p=$('#klevel');if(p){p.textContent=d.level;p.className='pill '+(d.level==='none'?'pass':'fail');}}
async function setKill(l){await postJSON('/api/killswitch',{level:l});loadKill();loadMCP();}
async function loadMCP(){
  const c=$('#mcp');if(!c)return;const d=await getJSON('/api/mcp');const s=d.servers||[];
  if(!s.length){c.innerHTML='<p class="mut">no servers</p>';return;}
  c.innerHTML=s.map(m=>{
    const ok=m.status==='pinned';
    const act=(m.status==='rug-pull'||m.status==='unapproved')?(' <button class="ghost" onclick="approveMCP('+jsarg(m.name)+')">Approve</button>'):'';
    const drift=(m.current&&m.current!==m.pinned)?(' → now '+esc(m.current)):'';
    const tag=m.registered?' <span class="kind">registered</span>':' <span class="kind">built-in</span>';
    const url=m.url?'<br><span class="mut">'+esc(m.url)+'</span>':'';
    // Invoke buttons only on an approved registered server.
    let invoke='';
    if(m.registered&&ok){invoke='<div style="margin-top:4px">'+(m.tools||[]).map(t=>'<button class="ghost" onclick="invokeMCP('+jsarg(m.name)+','+jsarg(t)+',this)">▶ '+esc(t)+'</button>').join(' ')+'</div>';}
    const del=m.registered?(' <button class="ghost" onclick="deleteMCP('+jsarg(m.name)+')">Delete</button>'):'';
    return '<div class="ev"><div style="width:100%"><b>'+esc(m.name)+'</b>'+tag+' <span class="pill '+(ok?'pass':'fail')+'">'+esc(m.status)+'</span>'+act+del+url+
      '<br><span class="mut">tools: '+esc((m.tools||[]).join(', ')||'—')+'</span>'+
      '<br><span class="mut">pin '+esc(m.pinned||'—')+drift+'</span>'+invoke+
      '<div class="mcpOut mut" style="margin-top:6px"></div></div></div>';
  }).join('');
}
async function approveMCP(name){await postJSON('/api/mcp/approve',{server:name});loadMCP();}
async function registerMCP(){
  const name=$('#mcpNewName').value.trim(),url=$('#mcpNewURL').value.trim(),msg=$('#mcpNewMsg');
  const tools=$('#mcpNewTools').value.split(',').map(x=>x.trim()).filter(Boolean);
  if(!name||!url||!tools.length){if(msg)msg.textContent='name, url and at least one tool required';return;}
  const resp=await postJSON('/api/mcp/register',{name:name,url:url,tools:tools});
  if(resp.ok){if(msg)msg.textContent='registered — Approve it above to pin the manifest';$('#mcpNewName').value='';$('#mcpNewURL').value='';$('#mcpNewTools').value='';loadMCP();}
  else{if(msg)msg.textContent=(await resp.text())||'failed';}
}
async function deleteMCP(name){if(!confirm('Delete server "'+name+'"?'))return;await postJSON('/api/mcp/delete',{server:name});loadMCP();}
async function invokeMCP(server,tool,btn){
  const out=btn.closest('.ev').querySelector('.mcpOut');out.textContent='calling '+tool+'…';
  const r=await (await postJSON('/api/mcp/call',{server:server,tool:tool})).json();
  if(r.ok){out.innerHTML='<pre>'+esc((r.output||'(empty)').slice(0,600))+'</pre>';}
  else{out.innerHTML='<span class="warn">refused: '+esc(r.refused||'error')+'</span>';}
}
async function loadBundles(){
  const c=$('#bundleList');if(!c)return;const d=await getJSON('/api/bundles');const bs=d.bundles||[];
  if(!bs.length){c.innerHTML='<p class="mut">no snapshots yet</p>';return;}
  c.innerHTML=bs.map(b=>'<div class="ev"><div><b>'+esc(b.label)+'</b> <span class="mut">'+esc(b.at)+'</span> <button class="ghost" onclick="applyBundle('+jsarg(b.label)+')">Roll back to this</button></div></div>').join('');
}
async function saveBundle(){
  const l=$('#bundleLabel').value.trim();if(!l)return;
  await postJSON('/api/bundles/save',{label:l});$('#bundleLabel').value='';loadBundles();
}
async function applyBundle(label){
  if(!confirm('Roll the ENTIRE governed plane (prompts + sampling + policies) back to "'+label+'"?'))return;
  await postJSON('/api/bundles/apply',{label:label});loadBundles();
}
async function loadPrompts(){
  const c=$('#promptList');if(!c)return;const d=await getJSON('/api/prompts');const ps=d.prompts||[];
  if(!ps.length){c.innerHTML='<p class="mut">no prompts registered</p>';return;}
  c.innerHTML=ps.map(p=>{
    const governed=p.version>0;
    return '<div class="ev"><div><b>'+esc(p.name)+'</b> <span class="pill '+(governed?'pass':'')+'">v'+p.version+'</span> <span class="mut">'+esc(p.hash)+'</span>'+
      '<br><textarea id="pt_'+esc(p.name)+'" rows="5" style="width:100%;margin-top:6px">'+esc(p.text)+'</textarea>'+
      '<div style="margin-top:6px"><button class="ghost" onclick="testPrompt('+jsarg(p.name)+')">Test (shadow eval)</button> '+
      '<button class="go" onclick="activatePrompt('+jsarg(p.name)+')">Activate new version</button>'+
      (governed?(' <button class="ghost" onclick="resetPrompt('+jsarg(p.name)+')">Reset to default</button>'):'')+
      '<div id="pttest_'+esc(p.name)+'" class="mut" style="margin-top:4px"></div></div></div></div>';
  }).join('');
}
async function activatePrompt(name){
  const ta=$('#pt_'+name);if(!ta)return;
  await postJSON('/api/prompts/activate',{name:name,text:ta.value});loadPrompts();
}
async function resetPrompt(name){await postJSON('/api/prompts/reset',{name:name});loadPrompts();}
async function loadSampling(){
  const c=$('#samplingList');if(!c)return;const d=await getJSON('/api/sampling');const ss=d.sampling||[];
  if(!ss.length){c.innerHTML='<p class="mut">no models registered</p>';return;}
  c.innerHTML=ss.map(s=>{const cf=s.config||{};const governed=s.version>0;
    return '<div class="ev"><div><b>'+esc(s.name)+'</b> <span class="pill '+(governed?'pass':'')+'">v'+s.version+'</span> <span class="mut">'+esc(s.hash)+'</span>'+
      '<div style="margin-top:6px">temp <input id="st_'+esc(s.name)+'" type="number" step="0.1" value="'+(cf.temperature||0)+'" style="width:70px"> '+
      'max tokens <input id="sm_'+esc(s.name)+'" type="number" value="'+(cf.max_tokens||0)+'" style="width:90px"> '+
      'seed <input id="ss_'+esc(s.name)+'" type="number" value="'+(cf.seed||0)+'" style="width:90px"></div>'+
      '<div style="margin-top:6px"><button class="go" onclick="activateSampling('+jsarg(s.name)+')">Activate</button>'+
      (governed?(' <button class="ghost" onclick="resetSampling('+jsarg(s.name)+')">Reset to default</button>'):'')+'</div></div></div>';
  }).join('');
}
async function activateSampling(name){
  const cfg={temperature:parseFloat($('#st_'+name).value)||0,max_tokens:parseInt($('#sm_'+name).value)||0,seed:parseInt($('#ss_'+name).value)||0};
  await postJSON('/api/sampling/activate',{name:name,config:cfg});loadSampling();
}
async function resetSampling(name){await postJSON('/api/sampling/reset',{name:name});loadSampling();}
let __CAT__=[];
// options for a role's model <select>: every catalog name, plus the current binding
// if it is not (any longer) in the catalog, so a stale binding stays visible.
function modelOpts(cur){
  let o=__CAT__.map(e=>'<option'+(e.name===cur?' selected':'')+'>'+esc(e.name)+'</option>').join('');
  if(!__CAT__.some(e=>e.name===cur)) o+='<option selected>'+esc(cur)+'</option>';
  return o;
}
async function loadModels(){
  const c=$('#modelsList');if(!c)return;
  const [d,cd]=await Promise.all([getJSON('/api/models'),getJSON('/api/modelcatalog')]);
  const ms=d.models||[]; __CAT__=cd.catalog||[];
  if(!ms.length){c.innerHTML='<p class="mut">no roles registered</p>';return;}
  c.innerHTML=ms.map(m=>{const governed=m.version>0;
    return '<div class="ev"><div><b>'+esc(m.name)+'</b> <span class="pill '+(governed?'pass':'')+'">v'+m.version+'</span> <span class="mut">'+esc(m.hash)+'</span>'+
      '<div style="margin-top:6px">model <select id="md_'+esc(m.name)+'">'+modelOpts(m.model)+'</select></div>'+
      '<div style="margin-top:6px"><button class="go" onclick="activateModel('+jsarg(m.name)+')">Bind</button>'+
      (governed?(' <button class="ghost" onclick="resetModel('+jsarg(m.name)+')">Reset to default</button>'):'')+'</div></div></div>';
  }).join('');
}
async function activateModel(name){await postJSON('/api/models/activate',{name:name,model:$('#md_'+name).value});loadModels();}
async function resetModel(name){await postJSON('/api/models/reset',{name:name});loadModels();}
async function loadModelCatalog(){
  const c=$('#modelCatalog');if(!c)return;const d=await getJSON('/api/modelcatalog');const cat=d.catalog||[];__CAT__=cat;
  if(!cat.length){c.innerHTML='<p class="mut">catalog empty</p>';return;}
  c.innerHTML=cat.map(m=>{
    const pin=m.pinned?'<span class="pill pass">SHA pinned</span>':'<span class="pill">magic-verify only</span>';
    const kind=m.kind==='embedding'?' <span class="pill">embedding</span>':'';
    return '<div class="ev"><div><b>'+esc(m.name)+'</b> '+pin+kind+' <span class="mut">:'+m.port+' · ctx '+m.ctx+' · '+esc(m.host)+'</span>'+
      '<div class="mut" style="margin-top:4px">'+esc(m.file)+'</div>'+
      '<div class="mut" style="margin-top:2px;word-break:break-all">'+esc(m.url)+'</div>'+
      '<div style="margin-top:6px"><button class="ghost" onclick="downloadModel('+jsarg(m.name)+',this)">Download</button> '+
      '<button class="ghost" onclick="editModel('+jsarg(m.name)+')">Edit</button> '+
      '<button class="ghost" onclick="delModel('+jsarg(m.name)+')">Delete</button>'+
      ' <span class="dlOut mut"></span></div></div></div>';
  }).join('');
}
async function downloadModel(name,btn){
  const out=btn.closest('.ev').querySelector('.dlOut');
  btn.disabled=true;out.textContent='downloading + verifying…';
  const r=await (await postJSON('/api/modelcatalog/download',{name:name})).json();
  btn.disabled=false;
  if(r.ok){out.innerHTML='<span class="pill pass">downloaded + verified</span>';loadRuntime&&null;}
  else{out.innerHTML='<span class="pill fail">'+esc(r.error||'failed')+'</span>';}
}
function editModel(name){const m=__CAT__.find(e=>e.name===name);if(!m)return;
  $('#mc_name').value=m.name;$('#mc_file').value=m.file;$('#mc_url').value=m.url;
  $('#mc_sha').value=m.sha256||'';$('#mc_port').value=m.port||'';$('#mc_ctx').value=m.ctx||'';$('#mc_kind').value=m.kind||'';
  $('#mcMsg').textContent='editing '+name;}
async function saveModel(){
  const body={name:$('#mc_name').value.trim(),file:$('#mc_file').value.trim(),url:$('#mc_url').value.trim(),
    sha256:$('#mc_sha').value.trim(),port:parseInt($('#mc_port').value)||0,ctx:parseInt($('#mc_ctx').value)||0,kind:$('#mc_kind').value};
  if(!body.name||!body.url||!body.file){$('#mcMsg').textContent='name, url and file are required';return;}
  const r=await postJSON('/api/modelcatalog/upsert',body);
  if(r.ok){$('#mcMsg').textContent='saved ✓';['mc_name','mc_file','mc_url','mc_sha','mc_port','mc_ctx'].forEach(id=>$('#'+id).value='');$('#mc_kind').value='';loadModelCatalog();loadModels();}
  else{$('#mcMsg').textContent='error: '+(await r.text());}
}
async function delModel(name){
  if(!confirm('Delete model "'+name+'" from the catalog?'))return;
  const r=await postJSON('/api/modelcatalog/delete',{name:name});
  if(r.ok){loadModelCatalog();loadModels();}
  else{alert(await r.text());}
}
async function loadFrontier(){
  const c=$('#frontierList');if(!c)return;const d=await getJSON('/api/frontier');const fs=d.frontier||[];
  if(!fs.length){c.innerHTML='<p class="mut">no frontier bindings — all subjects are on-host</p>';return;}
  c.innerHTML=fs.map(f=>{
    const key=f.key_ref?('key <code>'+esc(f.key_ref)+'</code> <span class="pill '+(f.key_set?'pass':'fail')+'">'+(f.key_set?'set':'unset')+'</span>'):'<span class="pill">no key</span>';
    return '<div class="ev"><div><b>'+esc(f.subject)+'</b> <span class="pill warn">frontier-bound</span> '+key+
      '<div class="mut" style="margin-top:2px;word-break:break-all">'+esc(f.endpoint)+'</div></div>'+
      '<div><button class="ghost" onclick="delFrontier('+jsarg(f.subject)+')">Delete</button></div></div>';
  }).join('');
}
async function saveFrontier(){
  const body={subject:$('#fr_subject').value.trim(),endpoint:$('#fr_endpoint').value.trim(),key_ref:$('#fr_keyref').value.trim()};
  if(!body.subject||!body.endpoint){$('#frMsg').textContent='subject and endpoint are required';return;}
  const r=await postJSON('/api/frontier/upsert',body);
  if(r.ok){$('#frMsg').textContent='saved ✓';['fr_subject','fr_endpoint','fr_keyref'].forEach(id=>$('#'+id).value='');loadFrontier();}
  else{$('#frMsg').textContent='error: '+(await r.text());}
}
async function delFrontier(subject){
  if(!confirm('Remove frontier binding for "'+subject+'"?'))return;
  const r=await postJSON('/api/frontier/delete',{subject:subject});
  if(r.ok)loadFrontier();else alert(await r.text());
}
function ragStatsText(s){return s?('corpus: '+s.docs+' docs → '+s.chunks+' chunks · mode '+esc(s.mode)):'';}
async function loadRAG(){
  const c=$('#ragStats');const d=await getJSON('/api/rag');const cfg=d.config||{};
  const chSel=$('#rag_chunker');if(chSel){chSel.innerHTML=(d.chunkers||[]).map(n=>'<option'+(n===cfg.chunker?' selected':'')+'>'+esc(n)+'</option>').join('');}
  const emSel=$('#rag_embedder');if(emSel){emSel.innerHTML=(d.embedders||[]).map(n=>'<option'+(n===cfg.embedder?' selected':'')+'>'+esc(n)+'</option>').join('');}
  if($('#rag_mode'))$('#rag_mode').value=cfg.mode||'fts';
  if($('#rag_size'))$('#rag_size').value=cfg.chunk_size||'';
  if($('#rag_overlap'))$('#rag_overlap').value=cfg.chunk_overlap||'';
  if(c)c.textContent=ragStatsText(d.stats);
}
function ragConfigFromForm(){return{mode:$('#rag_mode').value,chunker:$('#rag_chunker').value,embedder:$('#rag_embedder').value,chunk_size:parseInt($('#rag_size').value)||0,chunk_overlap:parseInt($('#rag_overlap').value)||0};}
async function saveRAG(){
  $('#ragMsg').textContent='saving + reindexing (semantic boots a model, can take a bit)…';
  const r=await postJSON('/api/rag/save',ragConfigFromForm());
  if(r.ok){const j=await r.json();$('#ragMsg').textContent='saved ✓';$('#ragStats').textContent=ragStatsText(j.stats);}
  else{$('#ragMsg').textContent='error: '+(await r.text());}
}
async function reindexRAG(){
  $('#ragMsg').textContent='reindexing…';
  const r=await postJSON('/api/rag/reindex',{});
  if(r.ok){const j=await r.json();$('#ragMsg').textContent='reindexed ✓';$('#ragStats').textContent=ragStatsText(j.stats);}
  else{$('#ragMsg').textContent='error: '+(await r.text());}
}
async function loadRuntime(){
  const c=$('#runtimeOut');if(!c)return;const d=await getJSON('/api/runtime');const gw=d.gateway||{};
  const gwPill=gw.up?'<span class="pill pass">up</span>':'<span class="pill fail">down</span>';
  let html='';
  const id=d.identity||{};
  if(id.ephemeral) html+='<div class="ev"><div><b>agent identity</b> <span class="pill fail">ephemeral</span> <span class="mut">throwaway key — signed .ics will not verify across restarts</span></div></div>';
  html+='<div class="ev"><div><b>gateway</b> '+gwPill+' <span class="mut">'+esc(gw.url||'')+'</span></div></div>';
  if(d.sandbox){const sb=d.sandbox;const sbPill=sb.up?'<span class="pill pass">up</span>':'<span class="pill fail">down</span>';html+='<div class="ev"><div><b>sandbox (MicroVM)</b> '+sbPill+' <span class="mut">'+esc(sb.url||'')+(sb.up?'':' — enrich needs launchvm')+'</span></div></div>';}
  if(d.control&&d.control.available){const run=d.control.running,managed=d.control.managed;
    const label=run?(managed?'running':'running (reused gateway)'):'stopped';
    let ctl;
    if(!run)ctl='<button class="go" onclick="startModels(this)">Start</button>';
    else if(managed)ctl='<button class="ghost" onclick="stopModels(this)">Stop</button>';
    else ctl='<span class="mut">external — not managed by this instance</span>';
    html+='<div class="ev"><div><b>model stack</b> <span class="pill '+(run?'pass':'')+'">'+label+'</span></div>'+
      '<div>'+ctl+' <span class="ctlOut mut"></span></div></div>';}
  html+='<div class="mut" style="margin:10px 0 4px">model servers <span style="opacity:.7">(assets: '+esc(d.assets_dir||'')+')</span></div>';
  (d.models||[]).forEach(m=>{
    const file=m.present?(m.valid_gguf?'<span class="pill pass">file ok</span>':'<span class="pill fail">file invalid</span>'):'<span class="pill fail">file missing</span>';
    const port=m.port_open?'<span class="pill pass">:'+m.port+' serving</span>':'<span class="pill">:'+m.port+' down</span>';
    html+='<div class="ev"><div><b>'+esc(m.name)+'</b> '+file+' '+port+' <span class="mut">'+esc(m.file)+'</span></div></div>';
  });
  if(!d.models||!d.models.length) html+='<p class="mut">no models in catalog</p>';
  c.innerHTML=html;
}
async function startModels(btn){const o=btn.closest('.ev').querySelector('.ctlOut');btn.disabled=true;o.textContent='starting…';
  const r=await (await postJSON('/api/runtime/start',{})).json();
  if(r.ok)loadRuntime();else{btn.disabled=false;o.innerHTML='<span class="pill fail">'+esc(r.error||'failed')+'</span>';}}
async function stopModels(btn){const o=btn.closest('.ev').querySelector('.ctlOut');btn.disabled=true;o.textContent='stopping…';
  const r=await (await postJSON('/api/runtime/stop',{})).json();
  if(r.ok)loadRuntime();else{btn.disabled=false;o.innerHTML='<span class="pill fail">'+esc(r.error||'failed')+'</span>';}}
async function loadSkills(){
  const c=$('#skillList');if(!c)return;const d=await getJSON('/api/skills');const cat=d.catalog||[];
  // Author form: offer the agent's allow-set as the tool choices.
  const tw=$('#skNewTools');
  if(tw){const tools=d.allowed_tools||[];tw.innerHTML='required tools: '+(tools.length?tools.map(t=>'<label style="margin-right:12px"><input type="checkbox" class="skTool" value="'+esc(t)+'"> '+esc(t)+'</label>').join(''):'<span class="mut">none available</span>');}
  if(!cat.length){c.innerHTML='<p class="mut">no skills in the catalog</p>';}
  else c.innerHTML=cat.map(s=>{
    const trust=s.signer_trusted?'<span class="pill pass">signed · trusted</span>':'<span class="pill fail">untrusted signer</span>';
    const appr=s.approved?'<span class="pill pass">approved</span>':'<span class="pill">unapproved</span>';
    const active=(s.approved&&s.signer_trusted)?' <span class="pill pass">shaping Chat</span>':'';
    const tag=s.authored?' <span class="kind">authored</span>':'';
    let act;
    if(s.approved) act='<button class="ghost" onclick="revokeSkill('+jsarg(s.name)+')">Revoke approval</button>';
    else if(s.signer_trusted) act='<button class="go" onclick="approveSkill('+jsarg(s.name)+')">Approve this version</button>';
    else act='<span class="mut">cannot approve — untrusted signer</span>';
    if(s.authored) act+=' <button class="ghost" onclick="deleteSkill('+jsarg(s.name)+')">Delete</button>';
    return '<div class="ev"><div><b>'+esc(s.name)+'</b> <span class="mut">v'+s.version+' · '+esc(s.hash)+'</span>'+tag+
      '<div style="margin-top:4px">'+trust+' '+appr+active+'</div>'+
      '<div style="margin-top:6px">'+act+'</div></div></div>';
  }).join('');
  const sel=$('#skillLoadName');if(sel){sel.innerHTML=cat.map(s=>'<option value="'+esc(s.name)+'">'+esc(s.name)+'</option>').join('');}
}
async function approveSkill(name){await postJSON('/api/skills/approve',{name:name});loadSkills();}
async function revokeSkill(name){await postJSON('/api/skills/reset',{name:name});loadSkills();}
async function authorSkill(){
  const name=$('#skNewName').value.trim(),instr=$('#skNewInstr').value.trim(),msg=$('#skNewMsg');
  const tools=[...document.querySelectorAll('.skTool:checked')].map(x=>x.value);
  if(!name||!instr){if(msg)msg.textContent='name and instructions required';return;}
  const resp=await postJSON('/api/skills/author',{name:name,instructions:instr,tools:tools});
  if(resp.ok){if(msg)msg.textContent='created — Approve it above to activate';$('#skNewName').value='';$('#skNewInstr').value='';document.querySelectorAll('.skTool:checked').forEach(x=>x.checked=false);loadSkills();}
  else{if(msg)msg.textContent=(await resp.text())||'failed';}
}
async function deleteSkill(name){if(!confirm('Delete skill "'+name+'"? It will stop shaping the agent.'))return;await postJSON('/api/skills/delete',{name:name});loadSkills();}
async function loadSkill(){
  const name=$('#skillLoadName').value;const unsafe=$('#skillUnsafe').checked;
  const r=await postJSON('/api/skills/load',{name:name,unsafe:unsafe});
  const out=$('#skillLoadOut');
  if(r.loaded){out.textContent=(r.unsafe?'⚠ CONTROLS OFF — loaded unchecked:\n\n':'✓ loaded (gate passed):\n\n')+(r.instructions||'');}
  else{out.textContent='⛔ '+(r.reason||'refused');}
}
async function loadRetrieval(){
  const c=$('#retrievalList');if(!c)return;const d=await getJSON('/api/retrieval');const rs=d.retrieval||[];
  if(!rs.length){c.innerHTML='<p class="mut">no corpora registered</p>';return;}
  c.innerHTML=rs.map(s=>{const cf=s.config||{};const governed=s.version>0;
    return '<div class="ev"><div><b>'+esc(s.name)+'</b> <span class="pill '+(governed?'pass':'')+'">v'+s.version+'</span> <span class="mut">'+esc(s.hash)+'</span>'+
      '<div style="margin-top:6px">top-k <input id="rk_'+esc(s.name)+'" type="number" value="'+(cf.k||0)+'" style="width:80px"> '+
      'context tokens <input id="rc_'+esc(s.name)+'" type="number" value="'+(cf.context_tokens||0)+'" style="width:100px"> <span class="mut">0 = auto (≈window/3)</span></div>'+
      '<div style="margin-top:6px"><button class="go" onclick="activateRetrieval('+jsarg(s.name)+')">Activate</button>'+
      (governed?(' <button class="ghost" onclick="resetRetrieval('+jsarg(s.name)+')">Reset to default</button>'):'')+'</div></div></div>';
  }).join('');
}
async function activateRetrieval(name){await postJSON('/api/retrieval/activate',{name:name,config:{k:parseInt($('#rk_'+name).value)||0,context_tokens:parseInt($('#rc_'+name).value)||0}});loadRetrieval();}
async function resetRetrieval(name){await postJSON('/api/retrieval/reset',{name:name});loadRetrieval();}
async function loadGrammar(){
  const c=$('#grammarList');if(!c)return;const d=await getJSON('/api/grammar');const gs=d.grammars||[];
  if(!gs.length){c.innerHTML='<p class="mut">no grammars registered</p>';return;}
  c.innerHTML=gs.map(g=>{const governed=g.version>0;
    return '<div class="ev"><div><b>'+esc(g.name)+'</b> <span class="pill '+(governed?'pass':'')+'">v'+g.version+'</span> <span class="mut">'+esc(g.hash)+'</span>'+
      '<div style="margin-top:6px"><textarea id="gt_'+esc(g.name)+'" rows="5" style="width:100%;font-family:monospace;font-size:12px">'+esc(g.text)+'</textarea></div>'+
      '<div style="margin-top:6px"><button class="go" onclick="activateGrammar('+jsarg(g.name)+')">Activate</button>'+
      (governed?(' <button class="ghost" onclick="resetGrammar('+jsarg(g.name)+')">Reset to default</button>'):'')+'</div></div></div>';
  }).join('');
}
async function activateGrammar(name){await postJSON('/api/grammar/activate',{name:name,text:$('#gt_'+name).value});loadGrammar();}
async function resetGrammar(name){await postJSON('/api/grammar/reset',{name:name});loadGrammar();}
async function loadBudgets(){
  const c=$('#budgetList');if(!c)return;const d=await getJSON('/api/budgets');const bs=d.budgets||[];
  if(!bs.length){c.innerHTML='<p class="mut">no budgets registered</p>';return;}
  c.innerHTML=bs.map(b=>{const cf=b.config||{};const governed=b.version>0;
    const key=cf.key_ref?(' · key <code>'+esc(cf.key_ref)+'</code> <span class="pill '+(b.key_set?'pass':'fail')+'">'+(b.key_set?'set':'unset')+'</span>'):'';
    return '<div class="ev"><div><b>'+esc(b.name)+'</b> <span class="pill '+(governed?'pass':'')+'">v'+b.version+'</span>'+key+
      '<div style="margin-top:6px">rate/min <input id="br_'+esc(b.name)+'" type="number" value="'+(cf.rate_per_min||0)+'" style="width:80px"> '+
      'concurrency <input id="bc_'+esc(b.name)+'" type="number" value="'+(cf.max_concurrency||0)+'" style="width:80px"> '+
      '<span class="pill pass">enforced here</span></div>'+
      '<div style="margin-top:6px">max tokens <input id="bt_'+esc(b.name)+'" type="number" value="'+(cf.max_tokens||0)+'" style="width:90px"> '+
      'spend $ <input id="bs_'+esc(b.name)+'" type="number" step="0.01" value="'+(cf.spend_cap_usd||0)+'" style="width:90px"> '+
      '<span class="pill" title="enforced by the gouncer gateway on model calls, not by this console">gateway-side</span></div>'+
      '<div style="margin-top:6px"><button class="go" onclick="activateBudget('+jsarg(b.name)+','+jsarg(cf.key_ref||'')+')">Activate</button>'+
      (governed?(' <button class="ghost" onclick="resetBudget('+jsarg(b.name)+')">Reset to default</button>'):'')+'</div></div></div>';
  }).join('');
}
async function activateBudget(name,keyRef){
  const cfg={rate_per_min:parseInt($('#br_'+name).value)||0,max_tokens:parseInt($('#bt_'+name).value)||0,max_concurrency:parseInt($('#bc_'+name).value)||0,spend_cap_usd:parseFloat($('#bs_'+name).value)||0,key_ref:keyRef};
  await postJSON('/api/budgets/activate',{name:name,config:cfg});loadBudgets();
}
async function resetBudget(name){await postJSON('/api/budgets/reset',{name:name});loadBudgets();}
async function loadPolicies(){
  const c=$('#policyList');if(!c)return;const d=await getJSON('/api/policies');const ps=d.policies||[];
  if(!ps.length){c.innerHTML='<p class="mut">no policies registered</p>';return;}
  c.innerHTML=ps.map(p=>{
    const governed=p.version>0;
    return '<div class="ev"><div><b>'+esc(p.name)+'</b> <span class="pill '+(governed?'pass':'')+'">v'+p.version+'</span> <span class="mut">'+esc(p.hash)+' · '+(p.items||[]).length+' entries</span>'+
      '<br><textarea id="pol_'+esc(p.name)+'" rows="5" style="width:100%;margin-top:6px" placeholder="one entry per line">'+esc((p.items||[]).join('\n'))+'</textarea>'+
      '<div style="margin-top:6px"><button class="go" onclick="activatePolicy('+jsarg(p.name)+')">Activate new version</button>'+
      (governed?(' <button class="ghost" onclick="resetPolicy('+jsarg(p.name)+')">Reset to default</button>'):'')+'</div></div></div>';
  }).join('');
}
async function activatePolicy(name){
  const ta=$('#pol_'+name);if(!ta)return;
  const items=ta.value.split('\n').map(s=>s.trim()).filter(Boolean);
  await postJSON('/api/policies/activate',{name:name,items:items});loadPolicies();
}
async function resetPolicy(name){await postJSON('/api/policies/reset',{name:name});loadPolicies();}
// 7-day strip (Mon–Sun): one chip per day with a count; click a day for its detail.
let __WEEKSTART__=null;
async function loadWeekStrip(start){
  const c=$('#weekStrip');if(!c)return;
  const d=await getJSON('/api/week'+(start?('?start='+encodeURIComponent(start)):''));
  __WEEKSTART__=d.start;const days=d.days||[];
  const rng=$('#weekRange');if(rng&&days.length)rng.textContent=days[0].date+' – '+days[6].date;
  c.innerHTML=days.map(x=>{
    const cnt=x.count?('<span class="cnt">'+x.count+'</span>'):'<span class="mut">–</span>';
    const todayTag=x.today?' · today':'';
    return '<div class="chip day" data-date="'+esc(x.date)+'" onclick="selectDay('+jsarg(x.date)+',this)">'+
      '<b>'+esc(x.weekday)+'</b><span class="mut">'+esc(x.date.slice(5))+todayTag+'</span>'+cnt+'</div>';
  }).join('');
  const sel=days.find(x=>x.today)||days[0];
  if(sel)selectDay(sel.date,c.querySelector('[data-date="'+sel.date+'"]'));
}
function selectDay(date,btn){
  document.querySelectorAll('#weekStrip .chip.day').forEach(b=>b.classList.toggle('sel',b===btn));
  loadWeek(date);
}
function shiftWeek(delta){
  const base=__WEEKSTART__?new Date(__WEEKSTART__+'T00:00:00'):new Date();
  base.setDate(base.getDate()+delta);
  loadWeekStrip(base.toISOString().slice(0,10));
}
async function loadWeek(day){
  const c=$('#timeline');if(!c)return;const d=await getJSON('/api/timeline?day='+day);
  const w=$('#weekDay');if(w)w.innerHTML=esc((d.weekday||'')+' '+(d.day||''))+(d.half_day?' <span class="pill fail">half day</span>':'');
  let html='';
  const anchors=d.anchors||[];
  if(anchors.length) html+='<h3>Daily</h3>'+anchors.map(a=>'<div class="ev"><div><b>'+esc(a.child)+'</b> '+esc(a.label)+' <span class="mut">'+esc(a.time)+'</span></div></div>').join('');
  const items=d.items||[];
  html+='<h3>On this day</h3>';
  if(!items.length) html+='<p class="mut">nothing extracted for this day</p>';
  else html+=items.map(e=>'<div class="ev"><div><b>'+esc(e.title)+'</b>'+(e.kind&&e.kind!=='event'?' <span class="kind">'+esc(e.kind)+'</span>':'')+'<br><span class="mut">'+esc(when(e))+(e.location?(' · '+esc(e.location)):'')+'</span>'+descLine(e)+'</div></div>').join('');
  c.innerHTML=html;
}
// Child profile is edited as a plain form (no raw JSON): one card per child with the
// anchors (arrival/lunch/dismissal) that drive My Week. Host-only config, never an email.
let __PROFILE__=[];
async function loadProfile(){
  const host=$('#profileForm');if(!host)return;
  const p=await getJSON('/api/profile');
  __PROFILE__=(p&&Array.isArray(p.children))?p.children:[];
  renderProfile();
}
function childCard(i,c){
  const F=(f,label,ph)=>'<div style="flex:1;min-width:120px"><label class="mut">'+label+'</label><br><input data-f="'+f+'" style="width:100%" value="'+esc(c[f]||'')+'" placeholder="'+esc(ph||'')+'"></div>';
  const row=inner=>'<div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:8px">'+inner+'</div>';
  const half=(c.half_days||[]).join(', ');
  return '<div class="pf-child card" style="margin-top:8px;padding:12px">'+
    '<div style="display:flex;justify-content:space-between;align-items:center"><b>'+esc(c.name||('Child '+(i+1)))+'</b> <button class="ghost" onclick="removeChild('+i+')">Remove</button></div>'+
    row(F('name','Name','e.g. Ada')+F('grade','Grade','e.g. 3')+F('class','Class','e.g. 3B'))+
    row(F('teacher','Teacher','e.g. Ms. Rivera')+F('school','School',''))+
    row(F('in','Arrival','e.g. 8:15')+F('lunch','Lunch','e.g. 10:55')+F('out','Dismissal','e.g. 2:30'))+
    '<div style="margin-top:8px"><label class="mut">Notes</label><br><input data-f="notes" style="width:100%" value="'+esc(c.notes||'')+'" placeholder="allergies, bus, after-school…"></div>'+
    row('<div style="flex:2;min-width:160px"><label class="mut">Half days (optional, ISO dates, comma-separated)</label><br><input data-f="half_days" style="width:100%" value="'+esc(half)+'" placeholder="2026-11-26, 2026-12-24"></div>'+
      '<div style="flex:1;min-width:120px"><label class="mut">Half-day dismissal</label><br><input data-f="half_day_out" style="width:100%" value="'+esc(c.half_day_out||'')+'" placeholder="e.g. 11:30"></div>')+
    '</div>';
}
function renderProfile(){
  const host=$('#profileForm');if(!host)return;
  host.innerHTML=__PROFILE__.length?__PROFILE__.map((c,i)=>childCard(i,c)).join(''):'<p class="mut">No children yet — add one so My Week can show arrival, lunch and dismissal.</p>';
}
// Read the current inputs back into __PROFILE__ so add/remove/save don't lose edits.
function syncProfile(){
  const cards=document.querySelectorAll('#profileForm .pf-child');
  if(!cards.length)return;
  __PROFILE__=Array.from(cards).map(el=>{
    const c={};
    el.querySelectorAll('input[data-f]').forEach(inp=>{
      const f=inp.dataset.f,v=inp.value.trim();
      if(f==='half_days'){if(v)c.half_days=v.split(',').map(s=>s.trim()).filter(Boolean);}
      else if(v)c[f]=v;
    });
    return c;
  });
}
function addChild(){syncProfile();__PROFILE__.push({});renderProfile();}
function removeChild(i){syncProfile();__PROFILE__.splice(i,1);renderProfile();}
async function saveProfile(){
  const m=$('#profileMsg');
  syncProfile();
  __PROFILE__=__PROFILE__.filter(c=>c.name||c.grade||c.teacher||c.in||c.out||c.notes);
  const r=await postJSON('/api/profile/save',{children:__PROFILE__});
  if(m)m.textContent=r.ok?'saved ✓':'save failed';
  renderProfile();loadWeek('today');
}
async function loadFlywheel(){
  const c=$('#flywheel');if(!c)return;const d=await getJSON('/api/flywheel');
  if(d.accepts===undefined){c.textContent='';return;}
  const total=(d.accepts||0)+(d.rejects||0);
  let h='<b>Data flywheel</b> — thumbs &amp; accept/reject from real use: '+(d.accepts||0)+' 👍 · '+(d.rejects||0)+' 👎'+(total?(' · '+Math.round((d.accept_rate||0)*100)+'% positive'):'')+
    '<div class="mut" style="margin-top:4px">Signal, not auto-training: use the 👎 examples below to tune the governed <b>prompt / retrieval / sampling</b> knobs and promote failures into the eval set, then re-run eval. (Weight fine-tuning on this sparse household signal would overfit.)</div>';
  const rec=d.recent||[];
  if(rec.length){
    h+='<div style="margin-top:8px">';
    rec.slice(0,12).forEach(f=>{const ic=f.decision==='accept'?'👍':(f.decision==='reject'?'👎':'😐');
      const lab=(f.label||'').slice(0,90);
      const promote=f.decision==='reject'?' <button class="ghost" title="make this a durable regression case" onclick="promoteCase('+jsarg(f.source)+','+jsarg(lab)+')">Promote to eval case</button>':'';
      h+='<div class="ev" style="padding:6px 0"><div><span class="kind">'+esc(f.source)+'</span> '+ic+' <span class="mut">'+esc(lab)+'</span></div><div>'+promote+'</div></div>';});
    h+='</div>';
  }
  c.innerHTML=h;
}
async function promoteCase(source,label){
  const note=prompt('Expected behavior for this case (what SHOULD happen):','');
  if(note===null)return;
  const r=await (await postJSON('/api/eval/cases/promote',{source,label,note})).json();
  if(r.ok)loadEvalCases();
}
async function loadEvalCases(){
  const c=$('#evalCases');if(!c)return;const d=await getJSON('/api/eval/cases');const cs=d.cases||[];
  if(!cs.length){c.innerHTML='<p class="mut">no promoted cases — 👎 something, then "Promote to eval case" to track the regression here</p>';return;}
  c.innerHTML='<b>Promoted regression cases</b> <span class="mut">— failures to re-check on every prompt/model/retrieval change</span>'+
    cs.map(x=>'<div class="ev" style="padding:6px 0"><div><span class="kind">'+esc(x.source)+'</span> <b>'+esc(x.label)+'</b>'+(x.note?('<br><span class="mut">expected: '+esc(x.note)+'</span>'):'')+'</div>'+
      '<div><button class="ghost" onclick="delEvalCase('+x.id+')">Resolve</button></div></div>').join('');
}
async function delEvalCase(id){
  const r=await (await postJSON('/api/eval/cases/delete',{id})).json();
  if(r.ok)loadEvalCases();
}
async function loadEval(){
  loadFlywheel();loadEvalCases();
  const c=$('#evalHistory');if(!c)return;const d=await getJSON('/api/eval');const h=d.history||[];
  if(!h.length){c.innerHTML='<p class="mut">no eval scores yet — click Run eval now (needs the model path up), or run cmd/livecheck</p>';return;}
  c.innerHTML='<table><thead><tr><th>label</th><th>F1</th><th>when</th></tr></thead><tbody>'+
    h.map(e=>'<tr><td>'+esc(e.label)+'</td><td><span class="pill '+(e.f1>=0.87?'pass':'fail')+'">'+e.f1.toFixed(2)+'</span></td><td class="mut">'+esc(e.at||'')+'</td></tr>').join('')+'</tbody></table>';
}
async function runEval(){
  const m=$('#evalMode');if(m)m.textContent='running…';
  const r=await (await fetch('/api/eval/run',{method:'POST'})).json();
  if(m)m.textContent=r.mode||'';loadEval();
}
async function testPrompt(name){
  const ta=$('#pt_'+name);if(!ta)return;const out=$('#pttest_'+name);if(out)out.textContent='testing…';
  const r=await (await fetch('/api/prompts/test',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:name,text:ta.value})})).json();
  if(!out)return;
  if(r.note){out.innerHTML='<span class="mut">'+esc(r.note)+'</span>';return;}
  out.innerHTML='candidate F1 <b>'+(r.f1||0).toFixed(2)+'</b> vs baseline '+(r.baseline||0).toFixed(2)+
    ' · ADD '+(r.asr_pass?'holds':'BROKEN')+' · gate <span class="pill '+(r.gate_ok?'pass':'fail')+'">'+(r.gate_ok?'PASS':'FAIL')+'</span> <span class="mut">('+esc(r.mode||'')+')</span>';
}

async function getJSON(u){try{return await (await fetch(u)).json();}catch(e){return {};}}

async function loadDeadlines(){
  const d=await getJSON('/api/items');
  const c=$('#deadlines');c.innerHTML='';
  const dated=(d.items||[]).filter(i=>(i.due||i.start));
  if(!dated.length){c.innerHTML='<span class="mut">nothing scheduled yet</span>';return;}
  dated.slice(0,8).forEach(i=>{const el=document.createElement('div');el.className='chip';
    el.innerHTML='<b>'+esc((i.due||i.start).slice(0,10))+'</b>'+esc(i.title.slice(0,40));c.appendChild(el);});
}
async function loadAddData(){
  const d=await getJSON('/api/events');
  if(d.inbox) $('#inbox').innerHTML='📥 Drop <b>.txt</b> emails here: <code>'+esc(d.inbox)+'</code>';
}
async function loadEvents(){
  const d=await getJSON('/api/events');
  if(d.inbox && $('#inbox')) $('#inbox').innerHTML='📥 Drop <b>.txt</b> emails here: <code>'+esc(d.inbox)+'</code>';
  const c=$('#events'); c.innerHTML='';
  const evs=(d.events||[]).filter(e=>(e.kind||'event')==='event');
  if(!evs.length){c.innerHTML='<p class="mut">no meetings yet — add one above or drop an email in Add Data</p>';return;}
  evs.forEach(e=>{const div=document.createElement('div');div.className='ev';
    const del=e.key?' <button class="ghost" title="remove from calendar" onclick="deleteEvent('+jsarg(e.key)+',this)">Delete</button>':'';
    div.innerHTML='<div style="min-width:0"><b>'+esc(e.title)+'</b>'+(e.signed?' <span class="kind" title="signed by this agent, unaltered">✓ signed</span>':'')+'<br><span class="mut">'+esc(when(e))+(e.location?(' · '+esc(e.location)):'')+'</span>'+descLine(e)+'</div>'+
      '<div>'+(e.has_reminder?'<span class="bell">🔔</span>':'')+'<a class="go" href="/ics/'+encodeURIComponent(e.file)+'" download>Accept .ics</a>'+del+'</div>';
    c.appendChild(div);});
}
async function deleteEvent(key,btn){
  if(!confirm('Remove this event from your calendar?'))return;
  btn.disabled=true;const r=await (await postJSON('/api/events/delete',{key})).json();
  if(r.ok){loadEvents();loadDeadlines();}else{btn.disabled=false;btn.textContent='err';}
}
// Add a calendar event from scratch (not from an email) — the household "add event".
function openCreateModal(){
  const ov=document.createElement('div');
  ov.style.cssText='position:fixed;inset:0;background:rgba(0,0,0,.6);display:flex;align-items:center;justify-content:center;z-index:1000';
  ov.innerHTML='<div style="background:var(--panel,#1a1a1a);border:1px solid var(--line,#333);border-radius:12px;padding:20px;width:min(440px,92vw)">'+
    '<b>Add a calendar event</b>'+
    '<div style="margin-top:12px"><label class="mut">Title</label><br><input id="ce_title" style="width:100%" placeholder="e.g. Dentist appointment"></div>'+
    '<div style="margin-top:10px;display:flex;gap:10px"><div style="flex:1"><label class="mut">Date</label><br><input id="ce_date" type="date" style="width:100%"></div>'+
    '<div style="flex:1"><label class="mut">Time</label><br><input id="ce_time" type="time" style="width:100%"></div></div>'+
    '<div style="margin-top:8px"><label class="mut"><input id="ce_allday" type="checkbox"> all-day</label></div>'+
    '<div style="margin-top:10px"><label class="mut">Location</label><br><input id="ce_loc" style="width:100%"></div>'+
    '<div style="margin-top:16px;display:flex;gap:8px;justify-content:flex-end"><button class="ghost" id="ce_cancel">Cancel</button><button class="go" id="ce_save">Add event</button></div>'+
    '<div id="ce_msg" class="mut" style="margin-top:8px"></div></div>';
  document.body.appendChild(ov);
  const close=()=>ov.remove();
  ov.addEventListener('click',e=>{if(e.target===ov)close();});
  $('#ce_cancel').onclick=close;
  $('#ce_save').onclick=async()=>{
    const allday=$('#ce_allday').checked,date=$('#ce_date').value,time=$('#ce_time').value;
    if(!$('#ce_title').value.trim()||!date){$('#ce_msg').textContent='title and date are required';return;}
    let start=date;if(date&&time&&!allday)start=date+'T'+time+':00';
    const r=await (await postJSON('/api/events/create',{title:$('#ce_title').value.trim(),start,location:$('#ce_loc').value.trim(),all_day:allday||!time})).json();
    if(r.ok){close();loadEvents();loadDeadlines();}else{$('#ce_msg').textContent='error';}
  };
}
async function postJSON(url,body){return fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});}
// Download the calendar (events + dated reminders) as .ics. Uses fetch (not a bare link) so
// the capability header rides along, then triggers a client-side file download.
function triggerICSDownload(blob){
  const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='family-calendar.ics';
  document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(a.href),2000);
}
// Download only events not exported before, and mark them so the next download skips them —
// no duplicates when you import into your real calendar.
async function downloadNewICS(){
  const msg=$('#icsMsg');if(msg)msg.textContent='preparing…';
  try{
    const r=await postJSON('/api/calendar/export',{});
    if(!r.ok){if(msg)msg.textContent='export failed';return;}
    const n=parseInt(r.headers.get('X-New-Count')||'0',10);
    if(n===0){if(msg)msg.textContent='nothing new since your last export ✓';return;}
    triggerICSDownload(await r.blob());
    if(msg)msg.textContent='exported '+n+' new event'+(n===1?'':'s')+' — import into your calendar';
  }catch(e){if(msg)msg.textContent='export failed';}
}
// Re-export everything (clears the "already exported" memory) — for switching calendars.
async function exportAllICS(){
  if(!confirm('Re-export EVERYTHING, including items you already exported? Use this if you switched calendars.'))return;
  await postJSON('/api/calendar/reset-exported',{});
  downloadNewICS();
}
async function rejectItem(file,index,btn){btn.disabled=true;const r=await postJSON('/api/reject',{file,index});if(r.ok){btn.textContent='rejected ✓';loadReview();}else{btn.textContent='err';btn.disabled=false;alert('Could not reject that: '+(await r.text().catch(()=>r.status)));}}
async function accept(file,index,btn){
  const p1=await postJSON('/api/accept',{file,index}); // phase 1: evidence + nonce
  if(!p1.ok){btn.textContent='refused';alert('Could not add that: '+(await p1.text().catch(()=>p1.status)));return;}
  const d=await p1.json();
  if(!d.confirm_required){btn.textContent='error';return;}
  if(!confirm(d.summary+'\n'+(d.evidence||[]).join('\n')+'\n\n(approval '+d.nonce.slice(0,6)+') — Confirm?')) return;
  btn.disabled=true;btn.textContent='…';
  const r=await postJSON('/api/accept',{file,index,nonce:d.nonce,confirm:true}); // phase 2
  if(r.ok){btn.textContent='added ✓';loadDeadlines();loadEvents();loadReview();}else{btn.textContent='refused';btn.disabled=false;alert('Could not add that: '+(await r.text().catch(()=>r.status)));}
}
// Edit-before-accept: a modal pre-filled from the extracted event; Save & add writes the
// EDITED event through the same HITL-confirmed accept (the human touch on extraction).
function openEditModal(file,index){
  const it=__ITEMS__[file+'|'+index];if(!it)return;
  const iso=(it.start||it.due||'');
  const date=iso.slice(0,10);
  const time=(iso.length>=16&&!it.all_day)?iso.slice(11,16):'';
  const ov=document.createElement('div');
  ov.style.cssText='position:fixed;inset:0;background:rgba(0,0,0,.6);display:flex;align-items:center;justify-content:center;z-index:1000';
  ov.innerHTML='<div style="background:var(--panel,#1a1a1a);border:1px solid var(--line,#333);border-radius:12px;padding:20px;width:min(440px,92vw);max-height:90vh;overflow:auto">'+
    '<b>Edit event before adding</b>'+
    '<div style="margin-top:12px"><label class="mut">Title</label><br><input id="ed_title" style="width:100%" value="'+esc(it.title||'')+'"></div>'+
    '<div style="margin-top:10px;display:flex;gap:10px"><div style="flex:1"><label class="mut">Date</label><br><input id="ed_date" type="date" style="width:100%" value="'+esc(date)+'"></div>'+
    '<div style="flex:1"><label class="mut">Time</label><br><input id="ed_time" type="time" style="width:100%" value="'+esc(time)+'"></div></div>'+
    '<div style="margin-top:8px"><label class="mut"><input id="ed_allday" type="checkbox"'+(it.all_day?' checked':'')+'> all-day</label></div>'+
    '<div style="margin-top:10px"><label class="mut">Location</label><br><input id="ed_loc" style="width:100%" value="'+esc(it.location||'')+'"></div>'+
    '<div style="margin-top:16px;display:flex;gap:8px;justify-content:flex-end">'+
    '<button class="ghost" id="ed_cancel">Cancel</button><button class="go" id="ed_save">Save &amp; add</button></div>'+
    '<div id="ed_msg" class="mut" style="margin-top:8px"></div></div>';
  document.body.appendChild(ov);
  const close=()=>ov.remove();
  ov.addEventListener('click',e=>{if(e.target===ov)close();});
  $('#ed_cancel').onclick=close;
  $('#ed_save').onclick=async()=>{
    const allday=$('#ed_allday').checked;
    const date=$('#ed_date').value,time=$('#ed_time').value;
    let start=date;
    if(date&&time&&!allday)start=date+'T'+time+':00';
    const edit={title:$('#ed_title').value.trim(),start:start,location:$('#ed_loc').value.trim(),all_day:allday};
    $('#ed_msg').textContent='confirming…';
    const p1=await postJSON('/api/accept',{file,index,edit}); // phase 1 (evidence reflects edits)
    if(!p1.ok){$('#ed_msg').textContent='refused: '+(await p1.text().catch(()=>p1.status));return;}
    const d=await p1.json();
    if(!d.confirm_required){$('#ed_msg').textContent='error';return;}
    if(!confirm(d.summary+'\n'+(d.evidence||[]).join('\n')+'\n\n(approval '+d.nonce.slice(0,6)+') — Confirm?')){$('#ed_msg').textContent='';return;}
    const r=await postJSON('/api/accept',{file,index,edit,nonce:d.nonce,confirm:true}); // phase 2
    if(r.ok){close();loadTasks();loadReview();loadEvents();loadDeadlines&&loadDeadlines();}else{$('#ed_msg').textContent='refused: '+(await r.text().catch(()=>r.status));}
  };
}
const __ITEMS__={}; // file|index -> item, for the edit modal
function itemRow(i){
  __ITEMS__[i.file+'|'+i.index]=i;
  const div=document.createElement('div');div.className='ev';
  // Tasks and heads-ups are NOT calendar events: "Add this" writes an .ics, which is
  // the wrong verb for a to-do or an FYI. The accept-to-calendar flow lives on events
  // (Calendar tab). Here the vocabulary is task-shaped: done / dismiss / snooze,
  // keyed by the item's stable fingerprint so it survives a projection rebuild (C2).
  let btn='';
  if(i.key){const k=jsarg(i.key),done=(i.kind==='heads_up')?'✓ Got it':'✓ Done';
    btn='<button class="ghost" title="handled" onclick="setItemStatus('+k+',\'done\')">'+done+'</button>'+
    ' <button class="ghost" title="remove it from your list (you can restore it under Show removed)" onclick="setItemStatus('+k+',\'dismissed\')">Remove</button>'+
    ' <button class="ghost" title="remind me later" onclick="snoozeItem('+k+')">Snooze</button>';}
  const badge=i.status&&i.status!=='active'?' <span class="kind warn">'+esc(i.status)+(i.snooze_until?' → '+esc(i.snooze_until):'')+'</span>':'';
  div.innerHTML='<div><span class="kind">'+esc(i.kind||'item')+'</span>'+badge+' <b>'+esc(i.title)+'</b>'+descLine(i)+'<br><span class="mut">'+esc((i.due||i.start)?when(i):'no date')+'</span></div><div>'+btn+'</div>';
  return div;
}
async function setItemStatus(key,status,snooze){
  const r=await postJSON('/api/items/status',{key:key,status:status,snooze_until:snooze||''});
  if(!r.ok)alert('Could not save that: '+(await r.text().catch(()=>r.status)));
  loadTasks();
}
function snoozeItem(key){
  const d=new Date();d.setDate(d.getDate()+7);
  const def=d.toISOString().slice(0,10);
  const until=prompt('Snooze until (YYYY-MM-DD):',def);
  if(until)setItemStatus(key,'snoozed',until);
}
// Removed and done rows are only hidden (every row is a projection of an email's
// summary), so they can be shown and restored. Restore clears the status overlay.
let __showRemoved=false;
async function toggleRemoved(){__showRemoved=!__showRemoved;loadTasks();}
async function restoreItem(key){const r=await postJSON('/api/items/status',{key:key,status:'active'});if(!r.ok)alert('Could not restore that: '+(await r.text().catch(()=>r.status)));loadTasks();}
async function loadRemoved(){
  const host=$('#removedList');if(!host)return;
  if(!__showRemoved){host.innerHTML='';$('#removedToggle').textContent='Show removed';return;}
  $('#removedToggle').textContent='Hide removed';
  const d=await getJSON('/api/items?all=1');const xs=(d.items||[]).filter(i=>i.status==='done'||i.status==='dismissed'||i.status==='snoozed');
  if(!xs.length){host.innerHTML='<p class="mut">nothing removed, done or snoozed</p>';return;}
  host.innerHTML='';xs.forEach(i=>{const div=document.createElement('div');div.className='ev';
    div.innerHTML='<div><span class="kind">'+esc(i.kind||'item')+'</span> <span class="kind warn">'+esc(i.status)+(i.snooze_until?' → '+esc(i.snooze_until):'')+'</span> <b>'+esc(i.title)+'</b><br><span class="mut">'+esc((i.due||i.start)?when(i):'no date')+'</span></div>'+
      '<div><button class="ghost" title="put it back on the list" onclick="restoreItem('+jsarg(i.key)+')">Restore</button></div>';
    host.appendChild(div);});
}
async function loadTasks(){
  loadRemoved();
  const d=await getJSON('/api/items');const items=d.items||[];
  const fill=(id,kind)=>{const c=$('#'+id);c.innerHTML='';const xs=items.filter(i=>(i.kind||'event')===kind);
    if(!xs.length){c.innerHTML='<p class="mut">none</p>';return;}xs.forEach(i=>c.appendChild(itemRow(i)));};
  fill('taskList','task');fill('headsList','heads_up');
  // actions: show the URL as text; fetching is gated (A6), never auto-opened.
  const ac=$('#actionList');ac.innerHTML='';const acts=items.filter(i=>(i.kind||'')==='action');
  if(!acts.length){ac.innerHTML='<p class="mut">none</p>';}
  acts.forEach(i=>{const div=document.createElement('div');div.className='ev';
    div.innerHTML='<div style="width:100%"><b>'+esc(i.title)+'</b><br><span class="mut">'+esc(i.url||'')+'</span>'+
      '<br><span class="warn" style="font-size:12px">fetched in the sandbox, only if the host is allow-listed</span>'+
      '<div class="actionOut mut" style="margin-top:6px"></div></div>'+
      '<div><button class="ghost" onclick="doAction('+jsarg(i.file)+','+i.index+',this)">Check &amp; fetch</button></div>';
    ac.appendChild(div);});
  loadSummaries(items);
}
async function doAction(file,index,btn){
  const out=btn.closest('.ev').querySelector('.actionOut');
  const c=await (await postJSON('/api/action',{file,index})).json(); // phase 1
  if(!c.confirm_required){out.textContent='error';return;}
  if(!confirm(c.summary+'\n'+(c.evidence||[]).join('\n')+'\n\n(approval '+c.nonce.slice(0,6)+') — Fetch this link in the sandbox?')) return;
  btn.disabled=true;btn.textContent='…';
  const d=await (await postJSON('/api/action',{file,index,nonce:c.nonce,confirm:true})).json(); // phase 2
  btn.disabled=false;btn.textContent='Check & fetch';
  if(d.refused){out.innerHTML='<span class="warn">refused: '+esc(d.refused)+'</span>';}
  else if(d.ok){out.innerHTML='<pre>'+esc((d.result||'').slice(0,600))+'</pre>';}
  else{out.textContent='error';}
}
async function loadSummaries(items){
  const files=[...new Set(items.map(i=>i.file).filter(Boolean))];
  const c=$('#summaries');c.innerHTML='';
  if(!files.length){c.innerHTML='<p class="mut">nothing processed yet</p>';return;}
  for(const f of files){const s=await getJSON('/api/summary?file='+encodeURIComponent(f));
    const div=document.createElement('div');div.className='ev';
    const digest=(s.tools&&s.tools.digest)||'';const contacts=(s.tools&&s.tools.contacts)||'';
    div.innerHTML='<div style="width:100%"><b>'+esc(s.source||f)+'</b>'+
      (s.doc_type?' <span class="kind'+(s.doc_type==='reference'?' warn':'')+'">'+esc(s.doc_type)+'</span>':'')+
      (digest?'<pre class="mut" style="margin-top:6px">'+esc(digest)+'</pre>':'')+
      (contacts?'<div class="mut" style="margin-top:6px">✉️ '+esc(contacts.replace(/\n/g,', '))+'</div>':'')+'</div>';
    c.appendChild(div);}
}
async function loadReview(){
  const d=await getJSON('/api/review');const c=$('#reviewList');if(!c)return;c.innerHTML='';
  const card=$('#reviewCard');const xs=d.items||[];
  if(card)card.classList.toggle('hide',!xs.length); // the "Needs your OK" card shows only when there's something to confirm
  if(!xs.length)return;
  // Batch controls: tick rows, then add or reject them together. Adding still goes
  // through the per-item HITL gate; the evidence for every ticked row is shown in ONE
  // confirm, then each approval is confirmed with its own single-use nonce.
  const bar=document.createElement('div');bar.className='ev';bar.id='reviewBatch';
  bar.innerHTML='<div><label class="mut"><input type="checkbox" id="rvAll" onclick="reviewSelectAll(this.checked)"> select all</label> <span id="rvCount" class="mut"></span></div>'+
    '<div><button class="go" onclick="acceptSelected(this)">Add selected</button> <button class="ghost" onclick="rejectSelected(this)">Not real (selected)</button></div>';
  c.appendChild(bar);
  xs.forEach(i=>{if(i.file&&i.index>=0)__ITEMS__[i.file+'|'+i.index]=i;
    const div=document.createElement('div');div.className='ev';
    const why=(i.warnings&&i.warnings.join(', '))||('confidence '+Math.round((i.confidence||0)*100)+'%');
    const lbl=(i.title||'').slice(0,60);
    let act='';
    const tick=(i.file&&i.index>=0)?'<input type="checkbox" class="rvSel" data-file="'+esc(i.file)+'" data-index="'+i.index+'" onclick="reviewCount()" style="margin-right:8px"> ':'';
    if(i.file&&i.index>=0){act='<button class="ghost" onclick="accept('+jsarg(i.file)+','+i.index+',this)">Add this</button> '+
      '<button class="ghost" onclick="openEditModal('+jsarg(i.file)+','+i.index+')">Edit &amp; add</button> '+
      '<button class="ghost" title="wrong extraction: remove it and record that it was wrong" onclick="rejectItem('+jsarg(i.file)+','+i.index+',this)">Not real</button> ';}
    act+=feedbackBtns('review',lbl);
    div.innerHTML='<div>'+tick+'<b>'+esc(i.title)+'</b>'+descLine(i)+'<br><span class="warn" style="font-size:13px">'+esc(why)+'</span></div><div>'+act+'</div>';
    c.appendChild(div);});
  reviewCount();
}
function reviewSelected(){return [...document.querySelectorAll('.rvSel:checked')].map(x=>({file:x.dataset.file,index:parseInt(x.dataset.index,10)}));}
function reviewSelectAll(on){document.querySelectorAll('.rvSel').forEach(x=>x.checked=on);reviewCount();}
function reviewCount(){const n=reviewSelected().length,el=$('#rvCount');if(el)el.textContent=n?n+' selected':'';}
// Add every ticked row: phase 1 for each (evidence + nonce), one confirm listing all of
// it, then phase 2 for each. A row that fails is reported and left in the queue.
async function acceptSelected(btn){
  const sel=reviewSelected();if(!sel.length){alert('Tick the rows to add first.');return;}
  btn.disabled=true;btn.textContent='…';
  const pending=[],failed=[];
  for(const it of sel){
    const r=await postJSON('/api/accept',{file:it.file,index:it.index});
    if(!r.ok){failed.push((__ITEMS__[it.file+'|'+it.index]||{}).title+': '+(await r.text().catch(()=>r.status)));continue;}
    const d=await r.json();if(!d.confirm_required){failed.push((__ITEMS__[it.file+'|'+it.index]||{}).title+': no approval challenge');continue;}
    pending.push({it,d});
  }
  if(pending.length){
    const lines=pending.map(p=>'• '+p.d.summary+' ('+(p.d.evidence||[]).join('; ')+')');
    const shown=lines.slice(0,12).join('\n')+(lines.length>12?'\n… and '+(lines.length-12)+' more':'');
    if(!confirm('Add '+pending.length+' item(s) to your calendar?\n\n'+shown+'\n\nConfirm all?')){btn.disabled=false;btn.textContent='Add selected';return;}
    for(const p of pending){
      const r=await postJSON('/api/accept',{file:p.it.file,index:p.it.index,nonce:p.d.nonce,confirm:true});
      if(!r.ok)failed.push((__ITEMS__[p.it.file+'|'+p.it.index]||{}).title+': '+(await r.text().catch(()=>r.status)));
    }
  }
  if(failed.length)alert('Not added:\n'+failed.join('\n'));
  loadReview();loadEvents();loadDeadlines();
}
async function rejectSelected(btn){
  const sel=reviewSelected();if(!sel.length){alert('Tick the rows first.');return;}
  if(!confirm('Mark '+sel.length+' item(s) as not real? They leave this list.'))return;
  btn.disabled=true;
  const failed=[];
  for(const it of sel){const r=await postJSON('/api/reject',{file:it.file,index:it.index});if(!r.ok)failed.push((__ITEMS__[it.file+'|'+it.index]||{}).title);}
  if(failed.length)alert('Could not reject:\n'+failed.join('\n'));
  loadReview();
}
function feedbackBtns(source,label){
  const s=jsarg(source),l=jsarg(label);
  return '<span class="fb">'+
    '<button class="ghost" title="good" onclick="sendFeedback('+s+','+l+',\'up\',this)">👍</button>'+
    '<button class="ghost" title="meh" onclick="sendFeedback('+s+','+l+',\'neutral\',this)">😐</button>'+
    '<button class="ghost" title="bad" onclick="sendFeedback('+s+','+l+',\'down\',this)">👎</button></span>';
}
async function sendFeedback(source,label,rating,btn){
  const r=await (await postJSON('/api/feedback',{source,label,rating})).json();
  if(r.ok&&btn){const row=btn.closest('.fb');if(row)row.querySelectorAll('button').forEach(b=>b.style.opacity=b===btn?'1':'.35');}
}
// Activity has two views of the SAME tamper-evident log: Plain (friendly feed) and Detailed
// (the raw tool-call stream, with clickable traces to replay a full timeline).
function setActView(v){
  const plain=v!=='detail';
  const f=$('#feed'),cl=$('#commandList'),rc=$('#replayCard');
  if(f)f.classList.toggle('hide',!plain);
  if(cl)cl.classList.toggle('hide',plain);
  if(rc&&plain)rc.classList.add('hide');
  const pb=$('#actPlain'),db=$('#actDetail');
  if(pb)pb.classList.toggle('active',plain);if(db)db.classList.toggle('active',!plain);
  if(plain)loadActivity();else loadCommands();
}
async function loadActivity(){
  const d=await getJSON('/api/activity');const c=$('#feed');if(!c)return;c.innerHTML='';
  const xs=d.activity||[];if(!xs.length){c.innerHTML='<p class="mut">no activity logged yet</p>';return;}
  xs.forEach(a=>{const div=document.createElement('div');
    div.innerHTML='<time>'+esc((a.ts||'').slice(11,19))+'</time>'+esc(a.text);c.appendChild(div);});
}
// Commands: the raw tool-call stream (operator twin of Activity). Shows the exact command
// (argv/URL), the allow/block decision, and the sandbox outcome — never the output content.
async function loadCommands(){
  const c=$('#commandList');if(!c)return;const d=await getJSON('/api/commands');const xs=d.commands||[];
  if(!xs.length){c.innerHTML='<p class="mut">no tool calls yet — the agent runs commands &amp; fetches through the sandbox; they appear here as it does.</p>';return;}
  c.innerHTML=xs.map(x=>{
    const icon=x.decision==='block'?'⛔':(x.kind==='exec'?'🖥️':'🌐');
    const dec=x.decision==='block'
      ?('<span class="pill fail">block</span>'+(x.reason?' <span class="mut">'+esc(x.reason)+'</span>':''))
      :('<span class="pill pass">allow</span>'+(x.outcome?' → <span class="mut">'+esc(x.outcome)+'</span>':''));
    const t=esc((x.ts||'').slice(11,19));
    const tr=x.trace?'<span class="trace" title="replay this trace" onclick="replay('+jsarg(x.trace)+')">trace '+esc(x.trace.slice(0,8))+'</span>':'';
    return '<div class="ev"><div style="width:100%">'+icon+' <span class="kind">'+esc(x.kind)+'</span> <code>'+esc(x.command||'—')+'</code>'+
      '<br><span class="mut">'+dec+' · '+tr+' · '+t+'</span></div></div>';
  }).join('');
}

// --- month view (A7) ---
let curMonth=null, monthItems={};
const todayStr=()=>new Date().toISOString().slice(0,10);
const pad=n=>String(n).padStart(2,'0');
const dateStr=(y,m,d)=>{const dt=new Date(y,m,d);return dt.getFullYear()+'-'+pad(dt.getMonth()+1)+'-'+pad(dt.getDate());};
function setView(v){
  $('#vList').classList.toggle('active',v==='list');$('#vMonth').classList.toggle('active',v==='month');
  $('#events').classList.toggle('hide',v!=='list');$('#monthView').classList.toggle('hide',v!=='month');
  if(v==='month') loadMonth();
}
async function loadMonth(){
  const d=await getJSON('/api/items');monthItems={};
  (d.items||[]).forEach(i=>{const k=(i.due||i.start||'').slice(0,10);if(k)(monthItems[k]=monthItems[k]||[]).push(i);});
  if(!curMonth){const ds=Object.keys(monthItems).sort();const pick=ds.find(x=>x>=todayStr())||ds[0]||todayStr();
    const [y,m]=pick.split('-');curMonth=new Date(+y,+m-1,1);}
  renderMonth();
}
function dayCell(y,m,d,other){
  const ds=dateStr(y,m,d);const items=monthItems[ds]||[];
  let inner='<div class="daynum">'+d+'</div>';
  items.slice(0,3).forEach(i=>inner+='<span class="it k-'+(i.kind||'event')+'">'+esc(i.title)+'</span>');
  if(items.length>3)inner+='<span class="mut" style="font-size:11px">+'+(items.length-3)+' more</span>';
  return '<div class="day'+(other?' other':'')+(ds===todayStr()?' today':'')+'" onclick="showDay('+jsarg(ds)+')">'+inner+'</div>';
}
function renderMonth(){
  const y=curMonth.getFullYear(),m=curMonth.getMonth();
  const name=curMonth.toLocaleString('en',{month:'long',year:'numeric'});
  let h='<div class="mhead"><button class="ghost" onclick="shiftMonth(-1)">‹</button><b>'+name+'</b><button class="ghost" onclick="shiftMonth(1)">›</button></div><div class="grid">';
  ['Mon','Tue','Wed','Thu','Fri','Sat','Sun'].forEach(x=>h+='<div class="dow">'+x+'</div>');
  const startDow=(new Date(y,m,1).getDay()+6)%7, days=new Date(y,m+1,0).getDate(), prev=new Date(y,m,0).getDate();
  for(let i=0;i<startDow;i++) h+=dayCell(y,m-1,prev-startDow+1+i,true);
  for(let d=1;d<=days;d++) h+=dayCell(y,m,d,false);
  const trail=(7-(startDow+days)%7)%7;
  for(let i=1;i<=trail;i++) h+=dayCell(y,m+1,i,true);
  h+='</div><div id="dayDetail"></div>';
  $('#monthView').innerHTML=h;
}
function shiftMonth(n){curMonth=new Date(curMonth.getFullYear(),curMonth.getMonth()+n,1);renderMonth();}
function showDay(ds){const items=monthItems[ds]||[];const c=$('#dayDetail');
  if(!items.length){c.innerHTML='<p class="mut" style="margin-top:12px">'+esc(ds)+' — nothing</p>';return;}
  c.innerHTML='<h3>'+esc(ds)+'</h3>'+items.map(i=>'<div class="ev"><div><span class="kind">'+esc(i.kind||'event')+'</span> <b>'+esc(i.title)+'</b>'+(i.location?(' <span class="mut">· '+esc(i.location)+'</span>'):'')+descLine(i)+'</div></div>').join('');
}
// Mini calendar on the Chat tab: a compact month glance sharing monthItems. It is
// the trusted PROJECTION of the extracted calendar (untrusted email → extract +
// sanitize → .ics → here); it renders event titles already sanitized upstream.
let miniMonth=null;
async function loadMiniCal(){
  const c=$('#miniCal');if(!c)return;
  const d=await getJSON('/api/items');monthItems={};
  (d.items||[]).forEach(i=>{const k=(i.due||i.start||'').slice(0,10);if(k)(monthItems[k]=monthItems[k]||[]).push(i);});
  if(!miniMonth)miniMonth=new Date();
  renderMiniCal();
}
function miniCell(y,m,d,other){
  const ds=dateStr(y,m,d);const n=(monthItems[ds]||[]).length;
  const dot=n?'<span class="mdot">'+(n>1?n:'●')+'</span>':'';
  return '<div class="mday'+(other?' other':'')+(ds===todayStr()?' today':'')+(n?' has':'')+'" onclick="jumpDay('+jsarg(ds)+')">'+d+dot+'</div>';
}
function renderMiniCal(){
  const c=$('#miniCal');if(!c)return;
  const y=miniMonth.getFullYear(),m=miniMonth.getMonth();
  const name=new Date(y,m,1).toLocaleString('en',{month:'short',year:'numeric'});
  let h='<div class="mhead"><button class="ghost" onclick="miniShift(-1)">‹</button><b>'+name+'</b><button class="ghost" onclick="miniShift(1)">›</button></div><div class="grid mini">';
  ['M','T','W','T','F','S','S'].forEach(x=>h+='<div class="dow">'+x+'</div>');
  const sd=(new Date(y,m,1).getDay()+6)%7,dd=new Date(y,m+1,0).getDate(),pv=new Date(y,m,0).getDate();
  for(let i=0;i<sd;i++)h+=miniCell(y,m-1,pv-sd+1+i,true);
  for(let d=1;d<=dd;d++)h+=miniCell(y,m,d,false);
  const tr=(7-(sd+dd)%7)%7;for(let i=1;i<=tr;i++)h+=miniCell(y,m+1,i,true);
  h+='</div>';c.innerHTML=h;
}
function miniShift(n){miniMonth=new Date(miniMonth.getFullYear(),miniMonth.getMonth()+n,1);renderMiniCal();}
function jumpDay(ds){const p=ds.split('-');curMonth=new Date(+p[0],+p[1]-1,1);document.querySelector('nav button[data-tab="calendar"]').click();setView('month');}

const dz=$('#dropzone');
dz.addEventListener('dragover',e=>{e.preventDefault();dz.classList.add('over');});
dz.addEventListener('dragleave',()=>dz.classList.remove('over'));
dz.addEventListener('drop',e=>{e.preventDefault();dz.classList.remove('over');if(e.dataTransfer.files[0])upload(e.dataTransfer.files[0]);});
$('#file').addEventListener('change',e=>{if(e.target.files[0])upload(e.target.files[0]);});
async function upload(f){const fd=new FormData();fd.append('email',f);await postDrop(fd,f.name);}
async function dropText(){const t=$('#paste').value;if(!t.trim())return;const fd=new FormData();fd.append('text',t);await postDrop(fd,'pasted email');$('#paste').value='';}
async function postDrop(fd,label){$('#dropmsg').textContent='processing '+label+'…';const out=$('#dropResult');if(out)out.innerHTML='';
  const r=await fetch('/api/drop',{method:'POST',body:fd});
  if(!r.ok){$('#dropmsg').textContent='error: '+(await r.text());return;}
  const d=await r.json().catch(()=>({}));
  $('#dropmsg').textContent='queued, extracting…';
  watchDrop(d.file||'');}
// The agent processes a drop in the background (the model runs); poll for its summary
// sidecar and show what came out, so a paste never ends on "queued" with no answer.
async function watchDrop(file){
  const out=$('#dropResult');const stem=file.replace(/\.[^.]+$/,'');
  if(!stem){$('#dropmsg').textContent='queued (no file name returned); check Tasks in a moment';loadEvents();loadDeadlines();return;}
  const sidecar=stem+'.summary.json';const started=Date.now();const max=180000;
  const tick=async()=>{
    const r=await fetch('/api/summary?file='+encodeURIComponent(sidecar));
    if(r.ok){const s=await r.json();renderDropResult(s,Date.now()-started);$('#dropmsg').textContent='done';loadEvents();loadDeadlines();return;}
    if(Date.now()-started>max){$('#dropmsg').textContent='still processing after 3 minutes; the model may be busy. Check Tasks and Calendar later.';return;}
    $('#dropmsg').textContent='extracting… '+Math.round((Date.now()-started)/1000)+'s';
    setTimeout(tick,2000);};
  setTimeout(tick,1500);
}
function renderDropResult(s,ms){
  const out=$('#dropResult');if(!out)return;
  const items=s.items||[],review=s.needs_review||[],contacts=s.contacts||[];
  const kinds={};items.forEach(i=>{const k=i.kind||'event';kinds[k]=(kinds[k]||0)+1;});
  const counts=Object.keys(kinds).map(k=>kinds[k]+' '+k+(kinds[k]>1?'s':'')).join(', ')||'nothing';
  const rows=items.map(i=>{const when=(i.due||i.start)?when_(i):'no date';
    return '<div class="ev"><div><span class="kind">'+esc(i.kind||'event')+'</span> <b>'+esc(i.title||'')+'</b><br><span class="mut">'+esc(when)+(i.location?' · '+esc(i.location):'')+'</span>'+
      ((i.warnings||[]).length?'<br><span class="warn" style="font-size:12px">'+esc(i.warnings.join(', '))+'</span>':'')+'</div></div>';}).join('');
  out.innerHTML='<div class="mut" style="margin-bottom:6px">Extracted '+esc(counts)+' in '+Math.round(ms/1000)+'s'+(review.length?', '+review.length+' need your OK':'')+(contacts.length?', '+contacts.length+' contact(s)':'')+
    '. <a href="#" onclick="document.querySelector(\'nav button[data-tab=tasks]\').click();return false;">Open Tasks</a> · <a href="#" onclick="document.querySelector(\'nav button[data-tab=calendar]\').click();return false;">Open Calendar</a></div>'+rows;
}
function when_(i){const iso=i.due||i.start||'';if(i.all_day||iso.length<=10)return iso.slice(0,10);return iso.slice(0,10)+' '+iso.slice(11,16)+(i.end?'–'+i.end.slice(11,16):'');}
loadEvents();loadDeadlines();setView('month');

async function runScorecard(){
  $('#verdict').textContent=' running…';
  const d=await getJSON('/api/scorecard');
  const tb=$('#score tbody'); tb.innerHTML='';
  (d.results||[]).forEach(r=>{const tr=tb.insertRow();
    tr.insertCell().textContent=r.name; tr.insertCell().textContent=r.technique;
    tr.insertCell().textContent=r.before.toFixed(0)+'%'; tr.insertCell().textContent=r.after.toFixed(0)+'%';
    const c=tr.insertCell(); c.innerHTML='<span class="pill '+(r.pass?'pass':'fail')+'">'+(r.pass?'ok':'FAIL')+'</span>';});
  $('#score').classList.remove('hide');
  $('#verdict').innerHTML=d.all_pass?' <span class="pill pass">all defenses hold</span>':' <span class="pill fail">regression!</span>';
}
async function replay(id){
  const d=await getJSON('/api/incident?trace='+id);
  $('#replayCard').classList.remove('hide');
  $('#replay').textContent=(d.timeline||[]).map(e=>e.ts+'  '+e.service+'  '+e.span+'/'+e.event).join('\n');
}
