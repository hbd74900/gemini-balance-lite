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

const readStoredKeys = async (env = {}) => {
  const store = getKeyStore(env);
  if (!store) {
    return null;
  }
  const keys = await store.get('keys', 'json');
  return Array.isArray(keys) ? keys : [];
};

const writeStoredKeys = async (env = {}, keys = []) => {
  const store = getKeyStore(env);
  if (!store) {
    return false;
  }
  await store.put('keys', JSON.stringify(keys));
  return true;
};

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
  const allowedAccessKeys = splitKeys(getEnvValue(env, 'PROXY_API_KEYS') || getEnvValue(env, 'PROXY_API_KEY'));
  const accessKey = resolveAccessKey(request);

  if (allowedAccessKeys.length > 0 && !allowedAccessKeys.includes(accessKey)) {
    return { error: jsonResponse({ error: 'Invalid proxy API key.' }, 401) };
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
    if (allowedAccessKeys.length === 0 && !accessKey) {
      return { error: jsonResponse({ error: 'Missing proxy API key.' }, 401) };
    }
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
:root{color-scheme:light;--bg:#f6f1e8;--ink:#201b16;--muted:#756a5f;--card:#fffaf1;--line:#dfd2c0;--green:#157347;--red:#b42318;--amber:#a15c00;--blue:#2458a6}body{margin:0;background:radial-gradient(circle at 10% 0,#ffe2b8,transparent 30%),linear-gradient(135deg,#f8ead4,#eef1e5 58%,#e5eef6);font-family:Georgia,'Times New Roman',serif;color:var(--ink)}main{max-width:1120px;margin:38px auto;padding:0 18px}.hero{display:flex;justify-content:space-between;gap:18px;align-items:end;margin-bottom:22px}h1{font-size:42px;margin:0;letter-spacing:-.04em}.sub{color:var(--muted);margin-top:8px}.card{background:rgba(255,250,241,.88);border:1px solid var(--line);box-shadow:0 24px 70px rgba(75,53,28,.13);border-radius:26px;padding:20px;backdrop-filter:blur(12px)}.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px}label{display:block;font-size:13px;color:var(--muted);margin-bottom:7px}input,textarea{box-sizing:border-box;width:100%;border:1px solid var(--line);border-radius:14px;background:#fffdf8;color:var(--ink);padding:12px 13px;font:14px ui-monospace,SFMono-Regular,Consolas,monospace}textarea{min-height:112px;resize:vertical}.actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:12px}button{border:0;border-radius:999px;background:var(--ink);color:#fff;padding:11px 16px;font-weight:700;cursor:pointer}button.secondary{background:#e6d7c1;color:var(--ink)}button.danger{background:var(--red)}button:disabled{opacity:.55;cursor:not-allowed}.toolbar{display:flex;justify-content:space-between;gap:12px;align-items:center;margin:18px 0 10px}.pill{display:inline-flex;align-items:center;border-radius:999px;padding:6px 10px;font-size:12px;font-weight:700}.available{background:#ddf3e6;color:var(--green)}.rate_limited{background:#fff0cf;color:var(--amber)}.invalid{background:#ffe0dc;color:var(--red)}.disabled{background:#e9e3da;color:var(--muted)}table{width:100%;border-collapse:separate;border-spacing:0 10px}th{text-align:left;color:var(--muted);font-size:12px;font-weight:500;padding:0 10px}td{background:rgba(255,253,248,.92);border-top:1px solid var(--line);border-bottom:1px solid var(--line);padding:12px 10px;vertical-align:middle;font-size:14px}td:first-child{border-left:1px solid var(--line);border-radius:16px 0 0 16px}td:last-child{border-right:1px solid var(--line);border-radius:0 16px 16px 0}.mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace}.small{font-size:12px;color:var(--muted)}.row-actions{display:flex;gap:8px;flex-wrap:wrap}.row-actions button{padding:8px 10px;font-size:12px}.notice{margin-top:12px;color:var(--muted);font-size:13px}@media(max-width:760px){.grid,.hero{display:block}h1{font-size:34px}table{display:block;overflow:auto}}
</style>
</head>
<body>
<main>
  <section class="hero">
    <div><h1>Gemini Key 管理</h1><div class="sub">Cloudflare Worker 版 Key 池、状态监听、429 当日隔离与失效标记。</div></div>
    <button id="refreshBtn">刷新状态</button>
  </section>
  <section class="card">
    <div class="grid">
      <div><label>管理员 Token</label><input id="token" type="password" placeholder="ADMIN_TOKEN"></div>
      <div><label>Key 名称（可选）</label><input id="name" placeholder="例如 account-a"></div>
    </div>
    <label>Gemini API Keys（支持多行、逗号、分号分隔）</label>
    <textarea id="keys" placeholder="AIza...&#10;AIza..."></textarea>
    <div class="actions"><button id="addBtn">添加 Key</button><button class="secondary" id="saveTokenBtn">保存 Token 到浏览器</button></div>
    <div class="notice" id="notice">需要 Cloudflare KV 绑定 GEMINI_KEYS_KV，且设置 ADMIN_TOKEN。</div>
  </section>
  <div class="toolbar"><h2>Key 池</h2><div class="small" id="summary">-</div></div>
  <section class="card"><table><thead><tr><th>Key</th><th>状态</th><th>统计</th><th>最近信息</th><th>操作</th></tr></thead><tbody id="tbody"></tbody></table></section>
</main>
<script>
const $=id=>document.getElementById(id);let token=localStorage.getItem('admin_token')||'';$('token').value=token;
const api=async(path,opts={})=>{token=$('token').value.trim();const r=await fetch(path,{...opts,headers:{'Content-Type':'application/json','Authorization':'Bearer '+token,...(opts.headers||{})}});const data=await r.json().catch(()=>({error:'Invalid response'}));if(!r.ok)throw new Error(data.error||('HTTP '+r.status));return data};
const setNotice=t=>$('notice').textContent=t;
const badge=s=>'<span class="pill '+s+'">'+s+'</span>';
const load=async()=>{try{const data=await api('/admin/api/keys');const rows=data.keys||[];$('summary').textContent='共 '+rows.length+' 个，available '+rows.filter(x=>x.status==='available'&&!x.disabled).length+' 个';$('tbody').innerHTML=rows.map(k=>'<tr><td><div class="mono">'+k.maskedKey+'</div><div class="small">'+(k.name||k.id)+'</div></td><td>'+(k.disabled?badge('disabled'):badge(k.status))+'</td><td><div>请求 '+k.requestCount+' / 成功 '+k.successCount+' / 失败 '+k.failCount+'</div><div class="small">HTTP '+(k.lastStatus||'-')+'</div></td><td><div class="small">last: '+(k.lastUsedAt||'-')+'</div><div class="small">429: '+(k.last429At||'-')+'</div><div class="small">'+(k.lastError||'')+'</div></td><td><div class="row-actions"><button onclick="testKey(\''+k.id+'\')">检测</button><button class="secondary" onclick="toggleKey(\''+k.id+'\','+(!k.disabled)+')">'+(k.disabled?'启用':'禁用')+'</button><button class="secondary" onclick="resetKey(\''+k.id+'\')">重置</button><button class="danger" onclick="deleteKey(\''+k.id+'\')">删除</button></div></td></tr>').join('')||'<tr><td colspan="5">暂无 Key</td></tr>';setNotice('状态已刷新')}catch(e){setNotice(e.message)}};
const add=async()=>{try{await api('/admin/api/keys',{method:'POST',body:JSON.stringify({keys:$('keys').value,name:$('name').value})});$('keys').value='';await load()}catch(e){setNotice(e.message)}};
const testKey=async id=>{try{setNotice('检测中...');await api('/admin/api/keys/'+id+'/test',{method:'POST'});await load()}catch(e){setNotice(e.message)}};
const toggleKey=async(id,disabled)=>{try{await api('/admin/api/keys/'+id,{method:'PATCH',body:JSON.stringify({disabled})});await load()}catch(e){setNotice(e.message)}};
const resetKey=async id=>{try{await api('/admin/api/keys/'+id+'/reset',{method:'POST'});await load()}catch(e){setNotice(e.message)}};
const deleteKey=async id=>{if(!confirm('确定删除这个 Key？'))return;try{await api('/admin/api/keys/'+id,{method:'DELETE'});await load()}catch(e){setNotice(e.message)}};
$('addBtn').onclick=add;$('refreshBtn').onclick=load;$('saveTokenBtn').onclick=()=>{localStorage.setItem('admin_token',$('token').value.trim());setNotice('已保存')};load();
</script>
</body>
</html>`;

const handleAdmin = async (request, env = {}) => {
  const url = new URL(request.url);
  if (url.pathname === '/admin') {
    return new Response(adminHtml, { headers: { 'Content-Type': 'text/html;charset=utf-8' } });
  }
  if (!isAdminRequest(request, env)) {
    return jsonResponse({ error: 'Unauthorized admin request.' }, 401);
  }
  const keys = await readStoredKeys(env);
  if (!keys) {
    return jsonResponse({ error: 'Missing Cloudflare KV binding GEMINI_KEYS_KV.' }, 500);
  }
  if (url.pathname === '/admin/api/keys' && request.method === 'GET') {
    return jsonResponse({ keys: keys.map(publicKey) });
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
    return jsonResponse({ ok: true, keys: keys.map(publicKey) });
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
