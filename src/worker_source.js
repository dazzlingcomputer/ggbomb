const PROXY_PREFIX = "/_gh/";

// ===== 参数区 =====
const ENABLE_EDGE_CACHE = true;

// 静态域 TTL
const STATIC_DEFAULT_TTL = 3600;
const RAW_TTL = 21600;
const ASSETS_TTL = 43200;
const AVATAR_TTL = 86400 * 7;
const CODELOAD_TTL = 1800;
const ERROR_STALE = 86400;
const SWR = 600;

// 搜索（匿名）全局缓存与限流
const SEARCH_TTL = 300;       // 新鲜期 5 分钟
const SEARCH_STALE = 1800;    // 陈旧可用 30 分钟
const GLOBAL_SEARCH_RATE = 8; // 全局 token/s
const GLOBAL_SEARCH_BURST = 16;

// GET/HEAD 重试
const MAX_RETRY = 3;
const RETRY_BASE_MS = 900;
const RETRY_JITTER_MS = 500;

// 认证相关
const AUTH_COOKIE_NAME = "gh_proxy_auth";
const AUTH_COOKIE_MAX_AGE = 86400 * 7; // 7天有效期

const DROP_RESPONSE_HEADERS = [
  "content-security-policy",
  "content-security-policy-report-only",
  "report-to",
  "nel",
  "cross-origin-embedder-policy",
  "cross-origin-opener-policy",
  "cross-origin-resource-policy",
];

const URL_ATTRS = [
  "href","src","action","poster","data-href","data-src","data-url",
  "data-download-url","data-clipboard-text","value",
];
const REWRITE_SELECTOR =
  "a,link,script,img,source,video,iframe,form,meta,include-fragment,turbo-frame,details-dialog,details-menu,clipboard-copy";

const PENDING = new Map();

// 生成认证页面HTML
function generateAuthPage(siteKey, errorMsg = "") {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>身份验证</title>
    <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        
        .auth-container {
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            padding: 40px;
            max-width: 400px;
            width: 100%;
            animation: slideUp 0.5s ease;
        }
        
        @keyframes slideUp {
            from {
                opacity: 0;
                transform: translateY(30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        .logo {
            text-align: center;
            margin-bottom: 30px;
        }
        
        .logo svg {
            width: 60px;
            height: 60px;
            fill: #667eea;
        }
        
        h1 {
            text-align: center;
            color: #333;
            margin-bottom: 10px;
            font-size: 24px;
        }
        
        .subtitle {
            text-align: center;
            color: #666;
            margin-bottom: 30px;
            font-size: 14px;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        label {
            display: block;
            margin-bottom: 8px;
            color: #555;
            font-weight: 500;
            font-size: 14px;
        }
        
        input[type="password"] {
            width: 100%;
            padding: 12px 15px;
            border: 2px solid #e1e4e8;
            border-radius: 10px;
            font-size: 16px;
            transition: all 0.3s;
        }
        
        input[type="password"]:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        
        .turnstile-container {
            margin: 25px 0;
            display: flex;
            justify-content: center;
        }
        
        .submit-btn {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 10px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .submit-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(102, 126, 234, 0.3);
        }
        
        .submit-btn:active {
            transform: translateY(0);
        }
        
        .submit-btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }
        
        .error-msg {
            background: #fee;
            color: #c33;
            padding: 10px 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-size: 14px;
            animation: shake 0.5s;
        }
        
        @keyframes shake {
            0%, 100% { transform: translateX(0); }
            25% { transform: translateX(-5px); }
            75% { transform: translateX(5px); }
        }
        
        .info {
            text-align: center;
            margin-top: 20px;
            color: #999;
            font-size: 12px;
        }
        
        .loading {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 3px solid rgba(255, 255, 255, 0.3);
            border-radius: 50%;
            border-top-color: white;
            animation: spin 1s ease-in-out infinite;
        }
        
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <div class="auth-container">
        <div class="logo">
            <svg viewBox="0 0 16 16">
                <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/>
            </svg>
        </div>
        <h1>GitHub Proxy</h1>
        <p class="subtitle">请输入密码继续访问</p>
        
        ${errorMsg ? `<div class="error-msg">${errorMsg}</div>` : ''}
        
        <form id="authForm" method="POST">
            <div class="form-group">
                <label for="password">访问密码</label>
                <input type="password" id="password" name="password" required placeholder="请输入访问密码" autocomplete="off">
            </div>
            
            <div class="turnstile-container">
                <div class="cf-turnstile" data-sitekey="${siteKey}" data-theme="light"></div>
            </div>
            
            <button type="submit" class="submit-btn" id="submitBtn">
                <span id="btnText">验证并继续</span>
            </button>
        </form>
        
        <div class="info">
            此服务需要身份验证以防止滥用
        </div>
    </div>
    
    <script>
        document.getElementById('authForm').addEventListener('submit', function(e) {
            const btn = document.getElementById('submitBtn');
            const btnText = document.getElementById('btnText');
            btn.disabled = true;
            btnText.innerHTML = '<span class="loading"></span>';
        });
    </script>
</body>
</html>`;
}

// 验证认证cookie
function verifyAuthCookie(req, secretKey) {
  const cookieHeader = req.headers.get("cookie");
  if (!cookieHeader) return false;
  
  const cookies = parseCookies(cookieHeader);
  const authToken = cookies[AUTH_COOKIE_NAME];
  if (!authToken) return false;
  
  try {
    const [timestamp, hash] = authToken.split(".");
    if (!timestamp || !hash) return false;
    
    // 检查时间戳是否过期
    const tokenTime = parseInt(timestamp);
    const now = Date.now();
    if (now - tokenTime > AUTH_COOKIE_MAX_AGE * 1000) return false;
    
    // 验证hash
    const expectedHash = sha256Simple(`${timestamp}.${secretKey}`);
    return hash === expectedHash;
  } catch {
    return false;
  }
}

// 简单的SHA256实现（用于生成token）
function sha256Simple(str) {
  // 这里使用简单的hash，实际生产环境建议使用crypto.subtle
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  return Math.abs(hash).toString(36);
}

// 生成认证cookie
function generateAuthCookie(secretKey) {
  const timestamp = Date.now();
  const hash = sha256Simple(`${timestamp}.${secretKey}`);
  return `${timestamp}.${hash}`;
}

// 验证Turnstile
async function verifyTurnstile(token, secretKey) {
  const formData = new FormData();
  formData.append('secret', secretKey);
  formData.append('response', token);
  
  const result = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
    method: 'POST',
    body: formData,
  });
  
  const outcome = await result.json();
  return outcome.success;
}

function sleep(ms){ return new Promise(r=>setTimeout(r,ms)); }
function getSetCookies(headers){
  if (typeof headers.getSetCookie === "function") return headers.getSetCookie();
  const single = headers.get("set-cookie"); if (!single) return [];
  return single.split(/,(?=[^;]+?=)/g);
}
function rewriteSetCookieToCurrentHost(sc){ return sc.replace(/;\s*Domain=[^;]+/gi,""); }

const ALLOWED_HOST = (h) => {
  if (!h) return false;
  h = h.toLowerCase();
  return (
    h === "github.com" ||
    h.endsWith(".github.com") ||
    h.endsWith(".githubusercontent.com") ||
    h.endsWith(".githubassets.com") ||
    h.endsWith(".github.io") ||
    h === "ghcr.io"
  );
};

function parseUpstreamFromPath(pathname){
  if (!pathname.startsWith(PROXY_PREFIX)) return null;
  const rest = pathname.slice(PROXY_PREFIX.length);
  const idx = rest.indexOf("/");
  let host = idx === -1 ? rest : rest.slice(0, idx);
  host = decodeURIComponent(host);
  const path = idx === -1 ? "/" : rest.slice(idx);
  return { host, path };
}
function inferHostFromReferer(reqUrl, headers){
  const ref = headers.get("referer") || headers.get("referrer");
  if (!ref) return null;
  try{
    const r = new URL(ref);
    if (r.host !== reqUrl.host) return null;
    const parsed = parseUpstreamFromPath(r.pathname);
    if (parsed && ALLOWED_HOST(parsed.host)) return parsed.host;
  }catch{}
  return null;
}

// github.com/.../raw/... -> raw.githubusercontent.com 直达
function shortcutGithubRaw(host, path){
  if (host !== "github.com") return null;
  const m = path.match(/^\/([^\/]+)\/([^\/]+)\/raw\/(.+)$/);
  if (!m) return null;
  const owner = m[1], repo = m[2], rest = m[3];
  let ref = "", fpath = "";
  if (rest.startsWith("refs/heads/") || rest.startsWith("refs/tags/")){
    const parts = rest.split("/");
    ref = parts[2] || "";
    fpath = parts.slice(3).join("/");
  }else{
    const parts = rest.split("/");
    ref = parts.shift() || "";
    fpath = parts.join("/");
  }
  if (!ref || !fpath) return null;
  return { host: "raw.githubusercontent.com", path: `/${owner}/${repo}/${ref}/${fpath}` };
}

function getUpstream(req){
  const url = new URL(req.url);
  const parsed = parseUpstreamFromPath(url.pathname);
  if (parsed && ALLOWED_HOST(parsed.host)) return { host: parsed.host, path: parsed.path, search: url.search };
  const refHost = inferHostFromReferer(url, req.headers);
  let res = { host: refHost || "github.com", path: url.pathname, search: url.search };
  const s = shortcutGithubRaw(res.host, res.path);
  if (s){ res.host = s.host; res.path = s.path; }
  return res;
}
function toProxyPath(absUrl){
  try{
    const u = new URL(absUrl);
    if (!ALLOWED_HOST(u.host)) return absUrl;
    if (u.host === "github.com") return `${u.pathname}${u.search}${u.hash||""}`;
    return `${PROXY_PREFIX}${u.host}${u.pathname}${u.search}${u.hash||""}`;
  }catch{ return absUrl; }
}
function rewriteLocationHeader(loc){
  if (!loc) return loc;
  try{
    if (loc.startsWith("http://") || loc.startsWith("https://")) return toProxyPath(loc);
    if (loc.startsWith("//")) return toProxyPath("https:"+loc);
    return loc;
  }catch{ return loc; }
}
function rewriteAttrValue(v){
  if (!v) return v;
  const lower = v.trim().toLowerCase();
  if (lower.startsWith("javascript:")||lower.startsWith("mailto:")||lower.startsWith("tel:")||lower.startsWith("data:")||lower.startsWith("#")) return v;
  if (lower.startsWith("//")) return toProxyPath("https:"+v);
  if (lower.startsWith("http://")||lower.startsWith("https://")) return toProxyPath(v);
  return v;
}
function rewriteSrcset(val){
  try{
    const parts = val.split(",").map(s=>s.trim());
    return parts.map(seg=>{
      const i = seg.indexOf(" ");
      if (i===-1) return rewriteAttrValue(seg);
      const u = seg.slice(0,i), d = seg.slice(i);
      return `${rewriteAttrValue(u)}${d}`;
    }).join(", ");
  }catch{ return val; }
}
class HtmlLinkRewriter{
  element(el){
    for (const a of URL_ATTRS){
      const v = el.getAttribute(a);
      if (v){
        if ((a==="value" || a==="data-clipboard-text") && !/^https?:|^\/\//i.test(v)) continue;
        const nv = rewriteAttrValue(v);
        if (nv!==v) el.setAttribute(a,nv);
      }
    }
    const ss = el.getAttribute("srcset");
    if (ss){ const nss = rewriteSrcset(ss); if (nss!==ss) el.setAttribute("srcset",nss); }
    if (el.tagName==="meta" && (el.getAttribute("http-equiv")||"").toLowerCase()==="refresh"){
      const c = el.getAttribute("content");
      if (c){
        const m = c.match(/^\s*\d+\s*;\s*url=(.+)\s*$/i);
        if (m){ const t=m[1], nv=rewriteAttrValue(t); if (nv!==t) el.setAttribute("content", c.replace(t,nv)); }
      }
    }
  }
}

// 客户端补丁
const CLIENT_FIXUP_JS = `
(() => {
  const PROXY_PREFIX=${JSON.stringify(PROXY_PREFIX)};
  const sameHost=location.host.toLowerCase();
  const ghHostRe=/(^|\\.)github\\.com$|(^|\\.)githubusercontent\\.com$|(^|\\.)githubassets\\.com$|^ghcr\\.io$/i;
  function toProxy(u){
    try{ const url=new URL(u,location.href); const host=url.host.toLowerCase();
      if (host===sameHost) return u; if (!ghHostRe.test(host)) return u;
      if (host==='github.com') return url.pathname+url.search+(url.hash||'');
      return PROXY_PREFIX+host+url.pathname+url.search+(url.hash||'');
    }catch{ return u; }
  }
  function isLikelyUrl(v){ const s=String(v||'').trim().toLowerCase(); return s.startsWith('http://')||s.startsWith('https://')||s.startsWith('//'); }
  function rewriteAttr(el, attr){
    const v=el.getAttribute(attr); if (!v) return;
    if ((attr==='value'||attr==='data-clipboard-text') && !isLikelyUrl(v)) return;
    const nv=toProxy(v); if (nv!==v) el.setAttribute(attr,nv);
  }
  function fix(el){
    ["src","href","action","data-src","data-href","data-url","data-download-url","data-clipboard-text","value"].forEach(a=>rewriteAttr(el,a));
  }
  function fixDeep(root){
    if (!(root instanceof Element)) return;
    const sel="a,form,link,script,img,source,video,iframe,include-fragment,turbo-frame,details-dialog,details-menu,clipboard-copy";
    if (root.matches && root.matches(sel)) fix(root);
    root.querySelectorAll && root.querySelectorAll(sel).forEach(fix);
  }
  fixDeep(document);
  const mo=new MutationObserver(list=>{
    for(const m of list){
      if (m.type==="childList"){ m.addedNodes.forEach(n=>fixDeep(n)); }
      else if (m.type==="attributes"){ const t=m.target; if (t instanceof Element) rewriteAttr(t,m.attributeName); }
    }
  });
  mo.observe(document.documentElement,{childList:true,subtree:true,attributes:true,attributeFilter:["src","href","action","data-src","data-href","data-url","data-download-url","data-clipboard-text","value"]});

  const of=window.fetch.bind(window);
  window.fetch=(input, init)=>{
    try{
      let url=input; if (input instanceof Request) url=input.url;
      const proxied=toProxy(url);
      if (typeof input==="string" || input instanceof URL) return of(proxied, init);
      if (input instanceof Request) return of(new Request(proxied, input), init);
    }catch{}
    return of(input, init);
  };
  const oo=XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open=function(m,u,...r){ try{u=toProxy(u);}catch{} return oo.call(this,m,u,...r); };
})();`;

// ===== 静态域缓存判定 =====
function isStaticHost(host){
  host = host.toLowerCase();
  return (
    host === "github.githubassets.com" ||
    host === "raw.githubusercontent.com" ||
    host === "codeload.github.com" ||
    host === "objects.githubusercontent.com" ||
    host === "user-images.githubusercontent.com" ||
    (host.endsWith(".githubusercontent.com") && host.includes("avatars"))
  );
}
function ttlFor(host){
  host = host.toLowerCase();
  if (host === "github.githubassets.com") return ASSETS_TTL;
  if (host === "raw.githubusercontent.com") return RAW_TTL;
  if (host === "codeload.github.com") return CODELOAD_TTL;
  if (host.includes("avatars") && host.endsWith(".githubusercontent.com")) return AVATAR_TTL;
  if (host === "objects.githubusercontent.com" || host === "user-images.githubusercontent.com") return STATIC_DEFAULT_TTL;
  return STATIC_DEFAULT_TTL;
}
function isCacheableRequest(req, upstreamHost){
  if (!ENABLE_EDGE_CACHE) return false;
  const m = req.method.toUpperCase(); if (m!=="GET" && m!=="HEAD") return false;
  const h = req.headers;
  if (h.has("authorization")) return false;
  if (h.has("cookie")) return false;
  if (h.has("range")) return false;
  const cc = (h.get("cache-control")||"").toLowerCase();
  if (cc.includes("no-cache") || cc.includes("no-store")) return false;
  return isStaticHost(upstreamHost);
}
function cacheKeyFromRequest(req){ return new Request(new URL(req.url).toString(), { method:"GET" }); }

// ===== HTML 与响应处理 =====
function isHtmlLikeResponse(resHeaders, reqHeaders){
  const ctype = (resHeaders.get("content-type")||"").toLowerCase();
  if (ctype.includes("text/html") || ctype.includes("application/xhtml+xml")) return true;
  const accept = (reqHeaders.get("accept")||"").toLowerCase();
  if (accept.includes("text/fragment+html")) return true;
  if (/text\/[^;,+]+\+html/.test(accept)) return true;
  return false;
}
function applyCachingHeaders(rh, ttlSec, staleIfErrorSec = ERROR_STALE){
  rh.set("cache-control", `public, max-age=${ttlSec}, stale-while-revalidate=${SWR}, stale-if-error=${staleIfErrorSec}`);
  return rh;
}
function appendVary(h, name){
  const v = h.get("vary");
  if (!v) h.set("vary", name);
  else if (!v.toLowerCase().split(",").map(s=>s.trim()).includes(name.toLowerCase())) h.set("vary", v + ", " + name);
}
function makePlainResponse(res, req){
  const rh = new Headers(res.headers);
  const loc = rh.get("location");
  if (loc){ const newLoc = rewriteLocationHeader(loc); if (newLoc && newLoc!==loc) rh.set("location", newLoc); }
  for (const k of DROP_RESPONSE_HEADERS) rh.delete(k);
  const setCookies = getSetCookies(res.headers);
  if (setCookies.length){
    rh.delete("set-cookie");
    for (const sc of setCookies) rh.append("set-cookie", rewriteSetCookieToCurrentHost(sc));
  }
  const reqOrigin = req.headers.get("origin");
  if (reqOrigin){
    rh.set("access-control-allow-origin", reqOrigin);
    rh.set("access-control-allow-credentials","true");
    const reqH = req.headers.get("access-control-request-headers");
    if (reqH) rh.set("access-control-allow-headers", reqH);
    rh.set("access-control-allow-methods","GET,HEAD,POST,PUT,DELETE,PATCH,OPTIONS");
  }
  return { headers: rh, status: res.status };
}

// ===== 上游 fetch（含重试、静态域 cf 缓存提示）=====
function parseRetryAfterSeconds(res){
  const ra = res.headers.get("retry-after"); if (!ra) return null;
  const n = Number(ra); if (!Number.isNaN(n)) return Math.max(0, Math.floor(n));
  const d = Date.parse(ra); if (!Number.isNaN(d)) return Math.max(0, Math.ceil((d - Date.now())/1000));
  return null;
}
async function fetchWithRetry(upstreamReq, isIdempotent, cfOpts){
  if (!isIdempotent) return fetch(upstreamReq);
  let attempt = 0;
  while (true){
    const res = await fetch(upstreamReq, cfOpts ? { cf: cfOpts } : undefined);
    const s = res.status;
    if (s!==429 && !(s===403 && res.headers.has("retry-after"))) return res;
    if (attempt>=MAX_RETRY) return res;
    const ra = parseRetryAfterSeconds(res);
    const backoff = (ra != null ? ra*1000 : Math.pow(2,attempt)*RETRY_BASE_MS) + Math.floor(Math.random()*RETRY_JITTER_MS);
    await sleep(backoff); attempt++;
  }
}
async function proxyFetch(req){
  const url = new URL(req.url);
  const upstream = getUpstream(req);
  const upstreamUrl = new URL(`https://${upstream.host}${upstream.path}${upstream.search}`);

  const h = new Headers(req.headers);
  const ref = h.get("referer") || h.get("referrer");
  if (ref){
    try{
      const r = new URL(ref);
      if (r.host === url.host){
        const parsed = parseUpstreamFromPath(r.pathname);
        if (parsed && ALLOWED_HOST(parsed.host)){
          const newRef = `https://${parsed.host}${parsed.path}${r.search||""}`;
          h.set("referer",newRef); h.set("referrer",newRef);
        }else{
          const newRef = `https://github.com${r.pathname}${r.search||""}`;
          h.set("referer",newRef); h.set("referrer",newRef);
        }
      }
    }catch{}
  }
  if (h.has("origin")) h.set("origin", `https://${upstream.host}`);
  h.delete("host");

  const method = req.method;
  const isGetHead = method==="GET" || method==="HEAD";

  const upstreamReq = new Request(upstreamUrl.toString(), {
    method, headers: h, body: isGetHead ? null : req.body, redirect: "manual",
  });

  const cfOpts = isGetHead && isStaticHost(upstream.host)
    ? { cacheEverything: true, cacheTtlByStatus: { "200-299": ttlFor(upstream.host), "300-599": 0 } }
    : undefined;

  const res = await fetchWithRetry(upstreamReq, isGetHead, cfOpts);
  return { res, upstream };
}

// ===== 搜索特化（匿名）: KV 全局缓存 + DO 全局限流 =====
function parseCookies(cookieStr){
  const map = {}; if (!cookieStr) return map;
  cookieStr.split(";").forEach(kv=>{ const i=kv.indexOf("="); if (i>-1){ map[kv.slice(0,i).trim()] = kv.slice(i+1).trim(); }});
  return map;
}
function isHtmlReq(req){
  const a = (req.headers.get("accept")||"").toLowerCase();
  return a.includes("text/html") || a.includes("application/xhtml+xml") || a==="*/*";
}
function isAnonSearchRequest(req){
  if (req.method.toUpperCase()!=="GET") return false;
  if (!isHtmlReq(req)) return false;
  const up = getUpstream(req);
  if (up.host!=="github.com") return false;
  if (!(up.path==="/search" || up.path.startsWith("/search"))) return false;
  const url = new URL(req.url); if (!url.searchParams.get("q")) return false;
  const cookies = parseCookies(req.headers.get("cookie")||"");
  const loggedIn = cookies["logged_in"]==="yes" || !!cookies["user_session"];
  return !loggedIn;
}
function primaryLang(acceptLang){
  if (!acceptLang) return "";
  const first = acceptLang.split(",")[0].trim();
  return first.slice(0,20);
}
function searchLocalKey(req){
  const url = new URL(req.url);
  const lang = primaryLang(req.headers.get("accept-language")||"");
  if (lang) url.searchParams.set("__w_s_v", "hl="+encodeURIComponent(lang));
  return new Request(url.toString(), { method:"GET" });
}
async function sha256b64url(str){
  const ab = new TextEncoder().encode(str);
  const d = await crypto.subtle.digest("SHA-256", ab);
  const b = String.fromCharCode(...new Uint8Array(d));
  return btoa(b).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
}
async function searchKvKey(req){
  const url = new URL(req.url);
  const lang = primaryLang(req.headers.get("accept-language")||"");
  const norm = url.origin + url.pathname + "?" + url.searchParams.toString();
  return "SEARCH:" + await sha256b64url(norm + "|lang=" + lang);
}
async function kvGetSearch(env, key){
  if (!env.SEARCH_KV) return null;
  const txt = await env.SEARCH_KV.get(key);
  if (!txt) return null;
  try{
    const j = JSON.parse(txt);
    const h = new Headers(j.headers||{});
    h.set("content-type","text/html; charset=utf-8");
    h.set("x-w-saved-at", String(j.savedAt||Date.now()));
    return new Response(j.body, { status: j.status||200, headers: h });
  }catch{return null;}
}
// 改为直接写字符串，避免再读流
async function kvPutSearchHTML(ctx, env, key, bodyText, status, headers){
  if (!env.SEARCH_KV) return;
  try{
    const savedAt = Date.now();
    const toStore = {
      body: bodyText,
      status,
      headers: { "content-type": "text/html; charset=utf-8" },
      savedAt,
    };
    ctx.waitUntil(env.SEARCH_KV.put(key, JSON.stringify(toStore), { expirationTtl: SEARCH_TTL + SEARCH_STALE + 3600 }));
  }catch{}
}
function savedAgeSeconds(resp){
  const t = Number(resp.headers.get("x-w-saved-at"));
  if (!Number.isFinite(t)) return null;
  return Math.max(0, Math.floor((Date.now()-t)/1000));
}
function isOkStatus(s){ return s>=200 && s<400; }
function makeAnonReq(req){
  const h = new Headers(req.headers);
  h.delete("cookie"); h.delete("authorization");
  return new Request(req.url, { method:"GET", headers:h, redirect:"manual" });
}

// DO 全局限流（失败则忽略，不影响主流程）
async function globalSearchGate(env){
  try{
    if (!env.SEARCH_DO) return;
    const id = env.SEARCH_DO.idFromName("GLOBAL");
    const stub = env.SEARCH_DO.get(id);
    await stub.fetch("https://do/take");
  }catch{}
}

class InjectFixupScript { element(el){ el.append(`<script>${CLIENT_FIXUP_JS}</script>`, { html:true }); } }

// 刷新搜索缓存的辅助函数
async function refreshSearch(env, ctx, req, localKey, kvKey) {
  try {
    const anonReq = makeAnonReq(req);
    const { res } = await proxyFetch(anonReq);
    
    if (!isOkStatus(res.status)) return;
    
    const base = makePlainResponse(res, anonReq);
    const rh = base.headers;
    const status = base.status;
    
    appendVary(rh, "Accept-Language");
    let bodyText;
    
    if (isHtmlLikeResponse(rh, anonReq.headers) && res.body) {
      rh.delete("content-length");
      rh.delete("content-encoding");
      applyCachingHeaders(rh, SEARCH_TTL, SEARCH_STALE);
      const transformed = new HTMLRewriter()
        .on(REWRITE_SELECTOR, new HtmlLinkRewriter())
        .on("head", new InjectFixupScript())
        .transform(new Response(res.body, { status, headers: rh }));
      bodyText = await transformed.text();
    } else {
      applyCachingHeaders(rh, SEARCH_TTL, SEARCH_STALE);
      bodyText = await new Response(res.body).text();
    }
    
    const outHeaders = new Headers(rh);
    outHeaders.set("x-w-saved-at", String(Date.now()));
    
    // 写本地缓存和KV
    const cache = caches.default;
    await cache.put(localKey, new Response(bodyText, { status: 200, headers: outHeaders }));
    await kvPutSearchHTML(ctx, env, kvKey, bodyText, 200, outHeaders);
  } catch {}
}

// ===== 主逻辑 =====
export default {
  async fetch(req, env, ctx){
    try{
      const url = new URL(req.url);
      const password = env.PASSWORD || "5d0c9dc5-ce48-4fde-81ee-adf06a47a7ca";
      const turnstileSiteKey = env.TURNSTILE_SITE_KEY;
      const turnstileSecretKey = env.TURNSTILE_SECRET_KEY;
      
      // 检查是否已经通过认证
      const isAuthenticated = verifyAuthCookie(req, password);
      
      // 如果未认证且不是认证请求，显示认证页面
      if (!isAuthenticated && req.method === "GET") {
        // 如果没有配置Turnstile，返回错误
        if (!turnstileSiteKey || !turnstileSecretKey) {
          return new Response("请先配置 TURNSTILE_SITE_KEY 和 TURNSTILE_SECRET_KEY 环境变量", {
            status: 500,
            headers: { "content-type": "text/plain; charset=utf-8" }
          });
        }
        
        return new Response(generateAuthPage(turnstileSiteKey), {
          status: 200,
          headers: { "content-type": "text/html; charset=utf-8" }
        });
      }
      
      // 处理认证POST请求
      if (!isAuthenticated && req.method === "POST") {
        const formData = await req.formData();
        const inputPassword = formData.get("password");
        const turnstileToken = formData.get("cf-turnstile-response");
        
        // 验证Turnstile
        if (!turnstileToken || !await verifyTurnstile(turnstileToken, turnstileSecretKey)) {
          return new Response(generateAuthPage(turnstileSiteKey, "人机验证失败，请重试"), {
            status: 200,
            headers: { "content-type": "text/html; charset=utf-8" }
          });
        }
        
        // 验证密码
        if (inputPassword !== password) {
          return new Response(generateAuthPage(turnstileSiteKey, "密码错误，请重试"), {
            status: 200,
            headers: { "content-type": "text/html; charset=utf-8" }
          });
        }
        
        // 认证成功，设置cookie并重定向
        const authToken = generateAuthCookie(password);
        const headers = new Headers({
          "Set-Cookie": `${AUTH_COOKIE_NAME}=${authToken}; Max-Age=${AUTH_COOKIE_MAX_AGE}; Path=/; HttpOnly; Secure; SameSite=Lax`,
          "Location": url.pathname + url.search
        });
        
        return new Response(null, { status: 302, headers });
      }
      
      // ===== 以下是原有的代理逻辑 =====
      
      if (req.method==="OPTIONS"){
        const rh = new Headers();
        const o = req.headers.get("origin") || "*";
        rh.set("access-control-allow-origin", o);
        rh.set("access-control-allow-credentials","true");
        rh.set("access-control-allow-methods","GET,HEAD,POST,PUT,DELETE,PATCH,OPTIONS");
        rh.set("access-control-max-age","86400");
        const reqH = req.headers.get("access-control-request-headers");
        if (reqH) rh.set("access-control-allow-headers", reqH);
        return new Response(null, { status:204, headers: rh });
      }

      // A) 匿名搜索：KV(全局) + 本地缓存 + DO 限流 + SWR
      if (isAnonSearchRequest(req)){
        const cache = caches.default;
        const localKey = searchLocalKey(req);
        const kvKey = await searchKvKey(req);

        // 1. 本地缓存
        const localHit = await cache.match(localKey);
        if (localHit){
          const age = savedAgeSeconds(localHit);
          if (age!==null){
            if (age <= SEARCH_TTL) return localHit;
            if (age <= SEARCH_TTL + SEARCH_STALE){
              // 立即回旧 + 后台刷新（不阻塞）
              ctx.waitUntil(refreshSearch(env, ctx, req, localKey, kvKey));
              const sh = new Headers(localHit.headers);
              applyCachingHeaders(sh, SEARCH_TTL, SEARCH_STALE);
              sh.set("x-worker-stale","1");
              return new Response(localHit.body, { status:200, headers: sh });
            }
          }
        }

        // 2. KV 全局缓存
        const kvHit = await kvGetSearch(env, kvKey);
        if (kvHit){
          const age = savedAgeSeconds(kvHit);
          const sh = new Headers(kvHit.headers);
          applyCachingHeaders(sh, SEARCH_TTL, SEARCH_STALE);
          // 同步进本地缓存（异步）
          sh.set("x-w-saved-at", String(Date.now())); // 给本地副本打上时间戳
          ctx.waitUntil(cache.put(localKey, new Response(await kvHit.clone().text(), { status:200, headers: sh })));
          // 如果 KV 副本已过期，后台刷新
          if (age!==null && age > SEARCH_TTL && age <= SEARCH_TTL+SEARCH_STALE){
            ctx.waitUntil(refreshSearch(env, ctx, req, localKey, kvKey));
          }
          return new Response(kvHit.body, { status:200, headers: sh });
        }

        // 3. 两边都没有：全局限流后回源
        await globalSearchGate(env);
        const anonReq = makeAnonReq(req);
        const pendingKey = "SEARCH|" + new URL(anonReq.url).toString();
        const ongoing = PENDING.get(pendingKey);
        if (ongoing){ try{ const r = await ongoing; return r.clone(); }catch{} }

        const task = (async()=>{
          const { res } = await proxyFetch(anonReq);
          if (!isOkStatus(res.status)){
            // 回退到旧的本地或 KV
            const oldLocal = localHit || await cache.match(localKey);
            const oldKv = kvHit || await kvGetSearch(env, kvKey);
            const fallback = oldLocal || oldKv;
            if (fallback){
              const sh = new Headers(fallback.headers);
              applyCachingHeaders(sh, SEARCH_TTL, SEARCH_STALE);
              sh.set("x-worker-stale","1");
              return new Response(fallback.body, { status:200, headers: sh });
            }
            const baseErr = makePlainResponse(res, anonReq);
            baseErr.headers.set("cache-control","no-store");
            return new Response(res.body, { status: res.status, headers: baseErr.headers });
          }

          // 2xx/3xx：重写 -> 读为字符串 -> 返回 + 本地缓存 + KV
          const base = makePlainResponse(res, anonReq);
          const rh = base.headers; const status = base.status;
          appendVary(rh, "Accept-Language");
          let bodyText;
          if (isHtmlLikeResponse(rh, anonReq.headers) && res.body){
            rh.delete("content-length"); rh.delete("content-encoding");
            applyCachingHeaders(rh, SEARCH_TTL, SEARCH_STALE);
            const transformed = new HTMLRewriter()
              .on(REWRITE_SELECTOR, new HtmlLinkRewriter())
              .on("head", new InjectFixupScript())
              .transform(new Response(res.body, { status, headers: rh }));
            bodyText = await transformed.text(); // 一次性转为字符串
          }else{
            applyCachingHeaders(rh, SEARCH_TTL, SEARCH_STALE);
            bodyText = await new Response(res.body).text();
          }
          // 构造返回和缓存（均用字符串，避免流复用）
          const outHeaders = new Headers(rh);
          outHeaders.set("x-w-saved-at", String(Date.now()));
          const finalRes = new Response(bodyText, { status: 200, headers: outHeaders });
          // 写本地缓存 + KV（后台）
          ctx.waitUntil(cache.put(localKey, new Response(bodyText, { status: 200, headers: outHeaders })));
          ctx.waitUntil(kvPutSearchHTML(ctx, env, kvKey, bodyText, 200, outHeaders));
          return finalRes;
        })();

        PENDING.set(pendingKey, task);
        try{ const out = await task; return out.clone(); }
        finally{ PENDING.delete(pendingKey); }
      }

      // B) 静态域强缓存
      const upstreamForCache = getUpstream(req);
      const cacheable = isCacheableRequest(req, upstreamForCache.host);
      if (cacheable){
        const cache = caches.default;
        const key = cacheKeyFromRequest(req);
        const hit = await cache.match(key);
        if (hit) return hit;

        const pendingKey = key.url;
        const ex = PENDING.get(pendingKey);
        if (ex){ try{ const r = await ex; return r.clone(); }catch{} }

        const task = (async()=>{
          const { res } = await proxyFetch(req);
          const { headers: rh, status } = makePlainResponse(res, req);
          const ttl = ttlFor(upstreamForCache.host);
          applyCachingHeaders(rh, ttl);
          // 保留压缩
          const finalRes = new Response(res.body, { status, headers: rh });
          ctx.waitUntil(cache.put(key, finalRes.clone()));
          return finalRes;
        })();

        PENDING.set(pendingKey, task);
        try{ const out = await task; return out.clone(); }
        finally{ PENDING.delete(pendingKey); }
      }

      // C) 普通代理（HTML 重写 + 客户端补丁）
      const { res } = await proxyFetch(req);
      if (res.status===101) return res;

      const base = makePlainResponse(res, req);
      const rh = base.headers; const status = base.status;
      const shouldRewrite = isHtmlLikeResponse(rh, req.headers);

      if (shouldRewrite && res.body){
        rh.delete("content-length"); rh.delete("content-encoding");
        const rw = new HTMLRewriter()
          .on(REWRITE_SELECTOR, new HtmlLinkRewriter())
          .on("head", new InjectFixupScript());
        return rw.transform(new Response(res.body, { status, headers: rh }));
      }
      return new Response(res.body, { status, headers: rh });
    }catch(e){
      return new Response("Proxy runtime error: " + e.message, { status: 502, headers: { "content-type":"text/plain; charset=utf-8" }});
    }
  },
};

// ===== Durable Object：全局搜索限流器（SQLite 迁移）=====
export class SearchShield {
  constructor(state, env){
    this.state = state;
    this.env = env;
    this.tokens = GLOBAL_SEARCH_BURST;
    this.last = Date.now();
  }
  _refill(){
    const now = Date.now();
    const delta = (now - this.last) / 1000;
    this.last = now;
    this.tokens = Math.min(GLOBAL_SEARCH_BURST, this.tokens + delta * GLOBAL_SEARCH_RATE);
  }
  async fetch(request){
    const url = new URL(request.url);
    if (url.pathname === "/take"){
      let waited = 0;
      while (true){
        this._refill();
        if (this.tokens >= 1){
          this.tokens -= 1;
          return new Response("ok", { status: 200 });
        }
        const needMs = Math.max(50, ((1 - this.tokens) / GLOBAL_SEARCH_RATE) * 1000);
        const chunk = Math.min(needMs, 200);
        await sleep(chunk);
        waited += chunk;
        if (waited > 2000){
          this.tokens = Math.max(0, this.tokens - 0.5);
          return new Response("ok", { status: 200 });
        }
      }
    }
    return new Response("Not found", { status: 404 });
  }
}