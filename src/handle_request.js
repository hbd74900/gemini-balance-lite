import { handleVerification } from './verify_keys.js';
import openai from './openai.mjs';

const splitKeys = (value) => (value || '').split(',').map(k => k.trim()).filter(k => k);
const pickRandom = (items) => items[Math.floor(Math.random() * items.length)];

const getHeaderValue = (request, names) => {
  for (const name of names) {
    const value = request.headers.get(name);
    if (value) {
      return value;
    }
  }
  return '';
};

const getEnvValue = (env, name) => {
  if (!env) {
    return '';
  }
  if (typeof env.get === 'function') {
    return env.get(name) || '';
  }
  return env[name] || '';
};

const jsonResponse = (data, status = 200) => new Response(JSON.stringify(data), {
  status,
  headers: { 'Content-Type': 'application/json' }
});

const resolveAccessKey = (request) => {
  const auth = request.headers.get('Authorization');
  if (auth?.toLowerCase().startsWith('bearer ')) {
    return auth.slice(7).trim();
  }
  return getHeaderValue(request, ['x-proxy-key', 'x-goog-api-key']);
};

const isAdminRequest = (request, env = {}) => {
  const adminToken = getEnvValue(env, 'ADMIN_TOKEN');
  if (!adminToken) {
    return false;
  }
  const url = new URL(request.url);
  const auth = request.headers.get('Authorization');
  const bearer = auth?.toLowerCase().startsWith('bearer ') ? auth.slice(7).trim() : '';
  return bearer === adminToken || request.headers.get('x-admin-token') === adminToken || url.searchParams.get('token') === adminToken;
};

const nextUtcMidnight = () => {
  const now = new Date();
  return Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1);
};

const createKeyId = async (key) => {
  const data = new TextEncoder().encode(key);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('').slice(0, 16);
};

const maskKey = (key) => {
  if (!key) {
    return '';
  }
  if (key.length <= 12) {
    return `${key.slice(0, 3)}...${key.slice(-3)}`;
  }
  return `${key.slice(0, 6)}...${key.slice(-6)}`;
};

const getKeyStore = (env = {}) => env.GEMINI_KEYS_KV || null;

const readJsonStore = async (env = {}, storeKey, fallback = []) => {
  const store = getKeyStore(env);
  if (!store) {
    return null;
  }
  const value = await store.get(storeKey, 'json');
  return Array.isArray(value) ? value : fallback;
};

const writeJsonStore = async (env = {}, storeKey, value = []) => {
  const store = getKeyStore(env);
  if (!store) {
    return false;
  }
  await store.put(storeKey, JSON.stringify(value));
  return true;
};

const readStoredKeys = (env = {}) => readJsonStore(env, 'keys', []);
const writeStoredKeys = (env = {}, keys = []) => writeJsonStore(env, 'keys', keys);
const readProxyKeys = (env = {}) => readJsonStore(env, 'proxy_keys', []);
const writeProxyKeys = (env = {}, keys = []) => writeJsonStore(env, 'proxy_keys', keys);

const publicKey = (item) => ({
  id: item.id,
  name: item.name || '',
  maskedKey: maskKey(item.key),
  status: item.status || 'available',
  disabled: !!item.disabled,
  requestCount: item.requestCount || 0,
  successCount: item.successCount || 0,
  failCount: item.failCount || 0,
  lastStatus: item.lastStatus || 0,
  lastError: item.lastError || '',
  lastUsedAt: item.lastUsedAt || '',
  lastCheckedAt: item.lastCheckedAt || '',
  last429At: item.last429At || '',
  rateLimitedUntil: item.rateLimitedUntil || 0
});

const publicProxyKey = (item) => ({
  id: item.id,
  name: item.name || '',
  maskedKey: maskKey(item.key),
  disabled: !!item.disabled,
  requestCount: item.requestCount || 0,
  lastUsedAt: item.lastUsedAt || ''
});

const isKeyAvailable = (item, now = Date.now()) => {
  if (item.disabled) {
    return false;
  }
  if (item.status === 'invalid') {
    return false;
  }
  if (item.status === 'rate_limited' && item.rateLimitedUntil && item.rateLimitedUntil > now) {
    return false;
  }
  return true;
};

const validateProxyAccess = async (request, env = {}) => {
  const accessKey = resolveAccessKey(request);
  const proxyKeys = await readProxyKeys(env);
  if (proxyKeys) {
    const index = proxyKeys.findIndex(item => item.key === accessKey && !item.disabled);
    if (index === -1) {
      return { error: jsonResponse({ error: 'Invalid proxy API key.' }, 401) };
    }
    proxyKeys[index].requestCount = (proxyKeys[index].requestCount || 0) + 1;
    proxyKeys[index].lastUsedAt = new Date().toISOString();
    await writeProxyKeys(env, proxyKeys);
    return { ok: true };
  }
  const allowedAccessKeys = splitKeys(getEnvValue(env, 'PROXY_API_KEYS') || getEnvValue(env, 'PROXY_API_KEY'));
  if (allowedAccessKeys.length > 0 && !allowedAccessKeys.includes(accessKey)) {
    return { error: jsonResponse({ error: 'Invalid proxy API key.' }, 401) };
  }
  if (allowedAccessKeys.length === 0 && !accessKey) {
    return { error: jsonResponse({ error: 'Missing proxy API key.' }, 401) };
  }
  return { ok: true };
};

const updateKeyAfterResponse = async (env, selected, response) => {
  if (!selected?.id || !selected.fromStore) {
    return;
  }
  const keys = await readStoredKeys(env);
  if (!keys) {
    return;
  }
  const index = keys.findIndex(item => item.id === selected.id);
  if (index === -1) {
    return;
  }
  const now = new Date().toISOString();
  const item = keys[index];
  item.requestCount = (item.requestCount || 0) + 1;
  item.lastStatus = response.status;
  item.lastUsedAt = now;
  item.lastCheckedAt = now;
  if (response.status >= 200 && response.status < 300) {
    item.status = 'available';
    item.successCount = (item.successCount || 0) + 1;
    item.lastError = '';
    item.rateLimitedUntil = 0;
  } else if (response.status === 429) {
    item.status = 'rate_limited';
    item.failCount = (item.failCount || 0) + 1;
    item.last429At = now;
    item.rateLimitedUntil = nextUtcMidnight();
    item.lastError = 'Daily quota or rate limit reached';
  } else if (response.status === 400 || response.status === 401 || response.status === 403) {
    item.status = 'invalid';
    item.failCount = (item.failCount || 0) + 1;
    item.lastError = `HTTP ${response.status}`;
  } else if (response.status >= 500) {
    item.failCount = (item.failCount || 0) + 1;
    item.lastError = `HTTP ${response.status}`;
  }
  keys[index] = item;
  await writeStoredKeys(env, keys);
};

const selectUpstreamKey = async (request, env = {}) => {
  const access = await validateProxyAccess(request, env);
  if (access.error) {
    return access;
  }

  const storedKeys = await readStoredKeys(env);
  if (storedKeys) {
    const availableKeys = storedKeys.filter(item => isKeyAvailable(item));
    if (availableKeys.length > 0) {
      const selected = pickRandom(availableKeys);
      return { id: selected.id, key: selected.key, fromEnv: false, fromStore: true };
    }
    return { error: jsonResponse({ error: 'No available Gemini API key.' }, 503) };
  }

  const upstreamKeys = splitKeys(getEnvValue(env, 'GEMINI_API_KEYS'));
  if (upstreamKeys.length > 0) {
    return { key: pickRandom(upstreamKeys), fromEnv: true, fromStore: false };
  }

  const requestKeys = splitKeys(getHeaderValue(request, ['x-goog-api-key']));
  if (requestKeys.length === 0) {
    return { error: jsonResponse({ error: 'Missing x-goog-api-key header.' }, 400) };
  }

  return { key: pickRandom(requestKeys), fromEnv: false, fromStore: false };
};

const adminHtml = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Gemini Key 管理</title>
<style>
:root{color-scheme:light;--ink:#201b16;--muted:#756a5f;--line:#dfd2c0;--green:#157347;--red:#b42318;--amber:#a15c00}body{margin:0;background:radial-gradient(circle at 10% 0,#ffe2b8,transparent 30%),linear-gradient(135deg,#f8ead4,#eef1e5 58%,#e5eef6);font-family:Georgia,'Times New Roman',serif;color:var(--ink)}main{max-width:1120px;margin:38px auto;padding:0 18px}.hero{display:flex;justify-content:space-between;gap:18px;align-items:end;margin-bottom:22px}h1{font-size:42px;margin:0;letter-spacing:-.04em}.sub{color:var(--muted);margin-top:8px}.card{background:rgba(255,250,241,.88);border:1px solid var(--line);box-shadow:0 24px 70px rgba(75,53,28,.13);border-radius:26px;padding:20px;backdrop-filter:blur(12px);margin-bottom:16px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px}label{display:block;font-size:13px;color:var(--muted);margin-bottom:7px}input,textarea{box-sizing:border-box;width:100%;border:1px solid var(--line);border-radius:14px;background:#fffdf8;color:var(--ink);padding:12px 13px;font:14px ui-monospace,SFMono-Regular,Consolas,monospace}textarea{min-height:112px;resize:vertical}.actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:12px}button{border:0;border-radius:999px;background:var(--ink);color:#fff;padding:11px 16px;font-weight:700;cursor:pointer}button.secondary{background:#e6d7c1;color:var(--ink)}button.danger{background:var(--red)}.toolbar{display:flex;justify-content:space-between;gap:12px;align-items:center;margin:18px 0 10px}.pill{display:inline-flex;align-items:center;border-radius:999px;padding:6px 10px;font-size:12px;font-weight:700}.available{background:#ddf3e6;color:var(--green)}.rate_limited{background:#fff0cf;color:var(--amber)}.invalid{background:#ffe0dc;color:var(--red)}.disabled{background:#e9e3da;color:var(--muted)}table{width:100%;border-collapse:separate;border-spacing:0 10px}th{text-align:left;color:var(--muted);font-size:12px;font-weight:500;padding:0 10px}td{background:rgba(255,253,248,.92);border-top:1px solid var(--line);border-bottom:1px solid var(--line);padding:12px 10px;vertical-align:middle;font-size:14px}td:first-child{border-left:1px solid var(--line);border-radius:16px 0 0 16px}td:last-child{border-right:1px solid var(--line);border-radius:0 16px 16px 0}.mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace}.small{font-size:12px;color:var(--muted)}.row-actions{display:flex;gap:8px;flex-wrap:wrap}.row-actions button{padding:8px 10px;font-size:12px}.notice{margin-top:12px;color:var(--muted);font-size:13px}.login{max-width:440px;margin:12vh auto}.hidden{display:none}@media(max-width:760px){.grid,.hero{display:block}h1{font-size:34px}table{display:block;overflow:auto}}
</style>
</head>
<body>
<main id="loginView" class="login hidden">
  <section class="card">
    <h1>登录</h1>
    <div class="sub">输入 Cloudflare 中配置的 ADMIN_TOKEN 后进入管理面板。</div>
    <div style="height:18px"></div>
    <label>管理员 Token</label>
    <input id="loginToken" type="password" placeholder="ADMIN_TOKEN" autocomplete="current-password">
    <div class="actions"><button id="loginBtn">进入管理面板</button></div>
    <div class="notice" id="loginNotice">未登录时不会显示 Key 管理内容。</div>
  </section>
</main>
<main id="appView" class="hidden">
  <section class="hero">
    <div><h1>Gemini Key 管理</h1><div class="sub">Cloudflare Worker 版真实 Key 池、代理 Key 签发、429 当日隔离与失效标记。</div></div>
    <div class="actions"><button id="refreshBtn">刷新状态</button><button class="secondary" id="logoutBtn">退出登录</button></div>
  </section>
  <section class="card">
    <div class="grid">
      <div><label>真实 Key 名称（可选）</label><input id="name" placeholder="例如 account-a"></div>
      <div><label>当前登录</label><input id="tokenState" disabled></div>
    </div>
    <label>真实 Gemini API Keys（支持多行、逗号、分号分隔）</label>
    <textarea id="keys" placeholder="AIza...&#10;AIza..."></textarea>
    <div class="actions"><button id="addBtn">添加真实 Key</button></div>
    <div class="notice" id="notice">需要 Cloudflare KV 绑定 GEMINI_KEYS_KV，且设置 ADMIN_TOKEN。</div>
  </section>
  <section class="card">
    <div class="grid">
      <div><label>代理 Key 名称（可选）</label><input id="proxyName" placeholder="例如 openshorts"></div>
      <div><label>代理 Key（留空自动生成）</label><input id="proxyKey" placeholder="sk-..."></div>
    </div>
    <div class="actions"><button id="addProxyBtn">签发代理 Key</button></div>
  </section>
  <div class="toolbar"><h2>代理 Key</h2><div class="small" id="proxySummary">-</div></div>
  <section class="card"><table><thead><tr><th>代理 Key</th><th>状态</th><th>统计</th><th>最近使用</th><th>操作</th></tr></thead><tbody id="proxyTbody"></tbody></table></section>
  <div class="toolbar"><h2>真实 Gemini Key 池</h2><div class="small" id="summary">-</div></div>
  <section class="card"><table><thead><tr><th>Key</th><th>状态</th><th>统计</th><th>最近信息</th><th>操作</th></tr></thead><tbody id="tbody"></tbody></table></section>
</main>
<script>
const $=id=>document.getElementById(id);let token=localStorage.getItem('admin_token')||'';
const showLogin=msg=>{$('loginView').classList.remove('hidden');$('appView').classList.add('hidden');$('loginToken').value=token;if(msg)$('loginNotice').textContent=msg};
const showApp=()=>{$('loginView').classList.add('hidden');$('appView').classList.remove('hidden');$('tokenState').value='已登录'};
const api=async(path,opts={})=>{const r=await fetch(path,{...opts,headers:{'Content-Type':'application/json','Authorization':'Bearer '+token,...(opts.headers||{})}});const data=await r.json().catch(()=>({error:'Invalid response'}));if(!r.ok){const err=new Error(data.error||('HTTP '+r.status));err.status=r.status;throw err}return data};
const setNotice=t=>$('notice').textContent=t;
const badge=s=>'<span class="pill '+s+'">'+s+'</span>';
const load=async()=>{try{const data=await api('/admin/api/keys');showApp();const rows=data.keys||[];const proxies=data.proxyKeys||[];$('summary').textContent='共 '+rows.length+' 个，available '+rows.filter(x=>x.status==='available'&&!x.disabled).length+' 个';$('proxySummary').textContent='共 '+proxies.length+' 个，启用 '+proxies.filter(x=>!x.disabled).length+' 个';$('proxyTbody').innerHTML=proxies.map(k=>'<tr><td><div class="mono">'+k.maskedKey+'</div><div class="small">'+(k.name||k.id)+'</div></td><td>'+(k.disabled?badge('disabled'):badge('available'))+'</td><td>请求 '+k.requestCount+'</td><td><div class="small">'+(k.lastUsedAt||'-')+'</div></td><td><div class="row-actions"><button class="secondary" onclick="toggleProxy(\''+k.id+'\','+(!k.disabled)+')">'+(k.disabled?'启用':'禁用')+'</button><button class="danger" onclick="deleteProxy(\''+k.id+'\')">删除</button></div></td></tr>').join('')||'<tr><td colspan="5">暂无代理 Key</td></tr>';$('tbody').innerHTML=rows.map(k=>'<tr><td><div class="mono">'+k.maskedKey+'</div><div class="small">'+(k.name||k.id)+'</div></td><td>'+(k.disabled?badge('disabled'):badge(k.status))+'</td><td><div>请求 '+k.requestCount+' / 成功 '+k.successCount+' / 失败 '+k.failCount+'</div><div class="small">HTTP '+(k.lastStatus||'-')+'</div></td><td><div class="small">last: '+(k.lastUsedAt||'-')+'</div><div class="small">429: '+(k.last429At||'-')+'</div><div class="small">'+(k.lastError||'')+'</div></td><td><div class="row-actions"><button onclick="testKey(\''+k.id+'\')">检测</button><button class="secondary" onclick="toggleKey(\''+k.id+'\','+(!k.disabled)+')">'+(k.disabled?'启用':'禁用')+'</button><button class="secondary" onclick="resetKey(\''+k.id+'\')">重置</button><button class="danger" onclick="deleteKey(\''+k.id+'\')">删除</button></div></td></tr>').join('')||'<tr><td colspan="5">暂无真实 Gemini Key</td></tr>';setNotice('状态已刷新')}catch(e){if(e.status===401){localStorage.removeItem('admin_token');showLogin('ADMIN_TOKEN 不正确或 Cloudflare 未设置 ADMIN_TOKEN')}else{showApp();setNotice(e.message)}}};
const login=async()=>{token=$('loginToken').value.trim();localStorage.setItem('admin_token',token);await load()};
const logout=()=>{token='';localStorage.removeItem('admin_token');showLogin('已退出登录')};
const add=async()=>{try{await api('/admin/api/keys',{method:'POST',body:JSON.stringify({keys:$('keys').value,name:$('name').value})});$('keys').value='';await load()}catch(e){setNotice(e.message)}};
const addProxy=async()=>{try{const data=await api('/admin/api/proxy-keys',{method:'POST',body:JSON.stringify({key:$('proxyKey').value,name:$('proxyName').value})});$('proxyKey').value='';$('proxyName').value='';setNotice('代理 Key 已签发：'+data.proxyKey.maskedKey);await load()}catch(e){setNotice(e.message)}};
const testKey=async id=>{try{setNotice('检测中...');await api('/admin/api/keys/'+id+'/test',{method:'POST'});await load()}catch(e){setNotice(e.message)}};
const toggleKey=async(id,disabled)=>{try{await api('/admin/api/keys/'+id,{method:'PATCH',body:JSON.stringify({disabled})});await load()}catch(e){setNotice(e.message)}};
const resetKey=async id=>{try{await api('/admin/api/keys/'+id+'/reset',{method:'POST'});await load()}catch(e){setNotice(e.message)}};
const deleteKey=async id=>{if(!confirm('确定删除这个真实 Key？'))return;try{await api('/admin/api/keys/'+id,{method:'DELETE'});await load()}catch(e){setNotice(e.message)}};
const toggleProxy=async(id,disabled)=>{try{await api('/admin/api/proxy-keys/'+id,{method:'PATCH',body:JSON.stringify({disabled})});await load()}catch(e){setNotice(e.message)}};
const deleteProxy=async id=>{if(!confirm('确定删除这个代理 Key？'))return;try{await api('/admin/api/proxy-keys/'+id,{method:'DELETE'});await load()}catch(e){setNotice(e.message)}};
$('loginBtn').onclick=login;$('loginToken').onkeydown=e=>{if(e.key==='Enter')login()};$('addBtn').onclick=add;$('addProxyBtn').onclick=addProxy;$('refreshBtn').onclick=load;$('logoutBtn').onclick=logout;if(token){load()}else{showLogin()}
</script>
</body>
</html>`;
const generateProxyKey = () => {
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  return `sk-${[...bytes].map(b => b.toString(16).padStart(2, '0')).join('')}`;
};

const handleAdmin = async (request, env = {}) => {
  const url = new URL(request.url);
  if (url.pathname === '/admin') {
    return new Response(adminHtml, { headers: { 'Content-Type': 'text/html;charset=utf-8' } });
  }
  if (!isAdminRequest(request, env)) {
    return jsonResponse({ error: 'Unauthorized admin request.' }, 401);
  }
  const keys = await readStoredKeys(env);
  const proxyKeys = await readProxyKeys(env);
  if (!keys || !proxyKeys) {
    return jsonResponse({ error: 'Missing Cloudflare KV binding GEMINI_KEYS_KV.' }, 500);
  }
  if (url.pathname === '/admin/api/keys' && request.method === 'GET') {
    return jsonResponse({ keys: keys.map(publicKey), proxyKeys: proxyKeys.map(publicProxyKey) });
  }
  if (url.pathname === '/admin/api/keys' && request.method === 'POST') {
    const body = await request.json().catch(() => ({}));
    const inputKeys = splitKeys(String(body.keys || body.key || '').replace(/[;\n\r\t]+/g, ','));
    const existing = new Set(keys.map(item => item.id));
    for (const key of inputKeys) {
      const id = await createKeyId(key);
      if (!existing.has(id)) {
        keys.push({ id, key, name: body.name || '', status: 'available', disabled: false, requestCount: 0, successCount: 0, failCount: 0, lastStatus: 0, lastError: '', lastUsedAt: '', lastCheckedAt: '', last429At: '', rateLimitedUntil: 0 });
        existing.add(id);
      }
    }
    await writeStoredKeys(env, keys);
    return jsonResponse({ ok: true, keys: keys.map(publicKey), proxyKeys: proxyKeys.map(publicProxyKey) });
  }
  if (url.pathname === '/admin/api/proxy-keys' && request.method === 'POST') {
    const body = await request.json().catch(() => ({}));
    const key = String(body.key || '').trim() || generateProxyKey();
    const id = await createKeyId(key);
    if (!proxyKeys.some(item => item.id === id)) {
      proxyKeys.push({ id, key, name: body.name || '', disabled: false, requestCount: 0, lastUsedAt: '' });
      await writeProxyKeys(env, proxyKeys);
    }
    const saved = proxyKeys.find(item => item.id === id);
    return jsonResponse({ ok: true, proxyKey: publicProxyKey(saved) });
  }
  const proxyMatch = url.pathname.match(/^\/admin\/api\/proxy-keys\/([^/]+)$/);
  if (proxyMatch) {
    const id = proxyMatch[1];
    const index = proxyKeys.findIndex(item => item.id === id);
    if (index === -1) {
      return jsonResponse({ error: 'Proxy key not found.' }, 404);
    }
    if (request.method === 'DELETE') {
      proxyKeys.splice(index, 1);
      await writeProxyKeys(env, proxyKeys);
      return jsonResponse({ ok: true });
    }
    if (request.method === 'PATCH') {
      const body = await request.json().catch(() => ({}));
      proxyKeys[index] = { ...proxyKeys[index], ...Object.fromEntries(Object.entries(body).filter(([key]) => ['name', 'disabled'].includes(key))) };
      await writeProxyKeys(env, proxyKeys);
      return jsonResponse({ ok: true, proxyKey: publicProxyKey(proxyKeys[index]) });
    }
    return jsonResponse({ error: 'Method not allowed.' }, 405);
  }
  const match = url.pathname.match(/^\/admin\/api\/keys\/([^/]+)(?:\/(test|reset))?$/);
  if (!match) {
    return jsonResponse({ error: 'Not found.' }, 404);
  }
  const id = match[1];
  const action = match[2] || '';
  const index = keys.findIndex(item => item.id === id);
  if (index === -1) {
    return jsonResponse({ error: 'Key not found.' }, 404);
  }
  if (request.method === 'DELETE' && !action) {
    keys.splice(index, 1);
    await writeStoredKeys(env, keys);
    return jsonResponse({ ok: true });
  }
  if (request.method === 'PATCH' && !action) {
    const body = await request.json().catch(() => ({}));
    keys[index] = { ...keys[index], ...Object.fromEntries(Object.entries(body).filter(([key]) => ['name', 'disabled', 'status'].includes(key))) };
    await writeStoredKeys(env, keys);
    return jsonResponse({ ok: true, key: publicKey(keys[index]) });
  }
  if (request.method === 'POST' && action === 'reset') {
    keys[index] = { ...keys[index], status: 'available', disabled: false, lastStatus: 0, lastError: '', last429At: '', rateLimitedUntil: 0 };
    await writeStoredKeys(env, keys);
    return jsonResponse({ ok: true, key: publicKey(keys[index]) });
  }
  if (request.method === 'POST' && action === 'test') {
    const response = await fetch('https://generativelanguage.googleapis.com/v1beta/models', { headers: { 'x-goog-api-key': keys[index].key } });
    await updateKeyAfterResponse(env, { id, fromStore: true }, response);
    const latest = await readStoredKeys(env);
    return jsonResponse({ ok: response.ok, status: response.status, key: publicKey(latest.find(item => item.id === id)) });
  }
  return jsonResponse({ error: 'Method not allowed.' }, 405);
};

export async function handleRequest(request, env = {}) {

  const url = new URL(request.url);
  const pathname = url.pathname;
  const search = url.search;

  if (pathname === '/' || pathname === '/index.html') {
    return new Response('Proxy is Running!  More Details: https://github.com/tech-shrimp/gemini-balance-lite', {
      status: 200,
      headers: { 'Content-Type': 'text/html' }
    });
  }

  if (pathname === '/admin' || pathname.startsWith('/admin/api/')) {
    return handleAdmin(request, env);
  }

  if (pathname === '/verify' && request.method === 'POST') {
    return handleVerification(request, env);
  }

  const upstream = await selectUpstreamKey(request, env);
  if (upstream.error) {
    return upstream.error;
  }

  if (url.pathname.endsWith('/chat/completions') || url.pathname.endsWith('/completions') || url.pathname.endsWith('/embeddings') || url.pathname.endsWith('/models')) {
    const response = await openai.fetch(request, upstream.key);
    await updateKeyAfterResponse(env, upstream, response.clone());
    return response;
  }

  const targetUrl = `https://generativelanguage.googleapis.com${pathname}${search}`;

  try {
    const headers = new Headers();
    for (const [key, value] of request.headers.entries()) {
      const lowerKey = key.trim().toLowerCase();
      if (lowerKey === 'host' || lowerKey === 'authorization' || lowerKey === 'x-proxy-key' || lowerKey === 'x-goog-api-key') {
        continue;
      }
      headers.set(key, value);
    }
    headers.set('x-goog-api-key', upstream.key);

    console.log(`Gemini Selected API Key Source: ${upstream.fromEnv ? 'env' : upstream.fromStore ? 'kv' : 'request'}`);
    console.log('Request Sending to Gemini')
    console.log('targetUrl:'+targetUrl)

    const response = await fetch(targetUrl, {
      method: request.method,
      headers: headers,
      body: request.body
    });

    await updateKeyAfterResponse(env, upstream, response.clone());

    console.log('Call Gemini Success')

    const responseHeaders = new Headers(response.headers);

    responseHeaders.delete('transfer-encoding');
    responseHeaders.delete('connection');
    responseHeaders.delete('keep-alive');
    responseHeaders.delete('content-encoding');
    responseHeaders.set('Referrer-Policy', 'no-referrer');

    return new Response(response.body, {
      status: response.status,
      headers: responseHeaders
    });

  } catch (error) {
   console.error('Failed to fetch:', error);
   return new Response('Internal Server Error\n' + error?.stack, {
    status: 500,
    headers: { 'Content-Type': 'text/plain' }
   });
}
};

