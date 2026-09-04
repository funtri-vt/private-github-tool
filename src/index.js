export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+/g, '/').replace(/\/$/, '') || '/';

    if (request.method === 'GET' && (path === '/' || path === '/dashboard')) {
      return new Response(renderDashboardHTML(), {
        headers: {
          'Content-Type': 'text/html; charset=utf-8',
          'X-Content-Type-Options': 'nosniff',
          'X-Frame-Options': 'DENY',
          'Content-Security-Policy': "default-src 'self' 'unsafe-inline' 'unsafe-eval';",
        },
      });
    }

    if (request.method === 'GET' && path === '/api/logs') {
      const authHeader = request.headers.get('Authorization') || '';
      const token = authHeader.replace(/^Bearer\s+/i, '').trim();
      const [providedUser, providedHash] = token.includes(':') ? token.split(':', 2) : ['', token];

      const expectedUser = (env.ADMIN_USER || 'admin').trim();
      const expectedPass = (env.ADMIN_PASS_HASH || env.AUTH_HASH || '').trim().toLowerCase();

      const validUser = await timingSafeEqual(providedUser.trim(), expectedUser);
      const validPass = await timingSafeEqual(providedHash.trim().toLowerCase(), expectedPass);

      if (!validUser || !validPass) {
        return new Response(JSON.stringify({ error: 'Unauthorized' }), {
          status: 401,
          headers: getSecurityHeaders(),
        });
      }

      const ipFilter = url.searchParams.get('ip');
      const actionFilter = url.searchParams.get('action');
      const limit = Math.min(parseInt(url.searchParams.get('limit') || '100', 10), 500);

      let query = 'SELECT * FROM access_logs WHERE 1=1';
      const params = [];

      if (ipFilter) {
        query += ' AND ip LIKE ?';
        params.push(`%${ipFilter.trim()}%`);
      }
      if (actionFilter && (actionFilter === 'read' || actionFilter === 'write')) {
        query += ' AND action = ?';
        params.push(actionFilter);
      }

      query += ' ORDER BY id DESC LIMIT ?';
      params.push(limit);

      try {
        const { results } = await env.DB.prepare(query).bind(...params).all();
        return new Response(JSON.stringify({ logs: results }), {
          headers: getSecurityHeaders(),
        });
      } catch (err) {
        return new Response(JSON.stringify({ error: 'Database query failed', details: err.message }), {
          status: 500,
          headers: getSecurityHeaders(),
        });
      }
    }

    if (request.method === 'POST' && path === '/token') {
      const clientIP = request.headers.get('cf-connecting-ip') || 'Unknown';

      try {
        const { action, auth } = await request.json();

        const expectedAuth = (env.AUTH_HASH || '').trim().toLowerCase();
        const isValidAuth = await timingSafeEqual((auth || '').trim().toLowerCase(), expectedAuth);

        if (!isValidAuth) {
          await logAccess(env.DB, clientIP, action || 'unknown', false);
          return new Response(JSON.stringify({ error: 'Unauthorized' }), {
            status: 401,
            headers: getSecurityHeaders(),
          });
        }

        const jwt = await generateJWT(env.GITHUB_APP_ID, env.GITHUB_PRIVATE_KEY);

        const ghResponse = await fetch(
          `https://api.github.com/app/installations/${env.GITHUB_INSTALLATION_ID}/access_tokens`,
          {
            method: 'POST',
            headers: {
              'Authorization': `Bearer ${jwt}`,
              'Accept': 'application/vnd.github+json',
              'User-Agent': 'Cloudflare-Worker-Git-Proxy',
            },
            body: JSON.stringify({
              repositories: [env.REPO_NAME],
              permissions: {
                contents: action === 'write' ? 'write' : 'read',
              },
            }),
          }
        );

        if (!ghResponse.ok) {
          const errData = await ghResponse.text();
          await logAccess(env.DB, clientIP, action, false);
          return new Response(JSON.stringify({ error: 'GitHub Authentication Failed', details: errData }), {
            status: 502,
            headers: getSecurityHeaders(),
          });
        }

        const ghData = await ghResponse.json();
        await logAccess(env.DB, clientIP, action, true);

        return new Response(JSON.stringify({ token: ghData.token }), {
          status: 200,
          headers: getSecurityHeaders(),
        });
      } catch (err) {
        // EXPOSING THE ERROR MESSAGE HERE SO WE CAN DIAGNOSE IT
        return new Response(JSON.stringify({ error: 'Internal Server Error', details: err.message }), {
          status: 500,
          headers: getSecurityHeaders(),
        });
      }
    }

    return new Response('Not Found', { status: 404 });
  },
};

// --- SECURITY & HELPER FUNCTIONS ---

function getSecurityHeaders() {
  return {
    'Content-Type': 'application/json',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
  };
}

// Updated to manual constant-time XOR to avoid Missing Web Crypto Method bugs
async function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const enc = new TextEncoder();
  const bufA = enc.encode(a);
  const bufB = enc.encode(b);
  if (bufA.byteLength !== bufB.byteLength) return false;

  let result = 0;
  for (let i = 0; i < bufA.byteLength; i++) {
    result |= bufA[i] ^ bufB[i];
  }
  return result === 0;
}

async function logAccess(db, ip, action, success) {
  if (!db) return;
  try {
    await db
    .prepare('INSERT INTO access_logs (ip, action, success, timestamp) VALUES (?, ?, ?, ?)')
    .bind(ip, action, success ? 1 : 0, new Date().toISOString())
    .run();
  } catch (e) {
    console.error('Database logging failed:', e);
  }
}

async function generateJWT(appId, pemKey) {
  if (!appId || !pemKey) {
    throw new Error('Missing GITHUB_APP_ID or GITHUB_PRIVATE_KEY environment variables.');
  }

  // Bulletproof cleaning: Strips headers (PKCS#1 and PKCS#8) and ALL non-base64 characters (including literal '\n')
  const cleanPem = pemKey
  .replace(/-----BEGIN (RSA )?PRIVATE KEY-----/g, '')
  .replace(/-----END (RSA )?PRIVATE KEY-----/g, '')
  .replace(/[^A-Za-z0-9+/=]/g, '');

  let binaryDer;
  try {
    binaryDer = Uint8Array.from(atob(cleanPem), (c) => c.charCodeAt(0));
  } catch (e) {
    throw new Error('Failed to base64-decode the private key. Check formatting.');
  }

  let privateKey;
  try {
    privateKey = await crypto.subtle.importKey(
      'pkcs8',
      binaryDer,
      { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' } },
      false,
      ['sign']
    );
  } catch (e) {
    throw new Error('Key import failed. Ensure your GitHub key is converted to PKCS#8 format. Native error: ' + e.message);
  }

  const now = Math.floor(Date.now() / 1000);
  const header = base64UrlEncode(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const payload = base64UrlEncode(
    JSON.stringify({
      iss: appId,
      iat: now - 60,
      exp: now + 600,
    })
  );

  const unsignedToken = `${header}.${payload}`;
  const signature = await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5',
    privateKey,
    new TextEncoder().encode(unsignedToken)
  );

  return `${unsignedToken}.${base64UrlEncode(signature)}`;
}

function base64UrlEncode(input) {
  const bytes = typeof input === 'string' ? new TextEncoder().encode(input) : new Uint8Array(input);
  const binary = String.fromCharCode(...bytes);
  return btoa(binary).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

// --- HTML DASHBOARD TEMPLATE ---

function renderDashboardHTML() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Git Proxy Analytics</title>
  <style>
    :root {
      --bg: #0f172a;
      --card-bg: #1e293b;
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --accent: #38bdf8;
      --success: #22c55e;
      --danger: #ef4444;
      --border: #334155;
    }
    body {
      font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background-color: var(--bg);
      color: var(--text);
      margin: 0;
      padding: 2rem;
    }
    .container { max-width: 1100px; margin: 0 auto; }
    h1 { font-size: 1.5rem; margin-bottom: 1.5rem; color: var(--accent); }
    
    .auth-card {
      background: var(--card-bg);
      padding: 1.5rem;
      border-radius: 8px;
      border: 1px solid var(--border);
      margin-bottom: 2rem;
      display: flex;
      gap: 1rem;
      align-items: center;
      flex-wrap: wrap;
    }
    input, select, button {
      background: #0f172a;
      border: 1px solid var(--border);
      color: var(--text);
      padding: 0.6rem 1rem;
      border-radius: 6px;
      font-size: 0.9rem;
    }
    button {
      background: var(--accent);
      color: #0f172a;
      font-weight: bold;
      cursor: pointer;
      border: none;
    }
    button:hover { opacity: 0.9; }

    .stats {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 1rem;
      margin-bottom: 2rem;
    }
    .stat-card {
      background: var(--card-bg);
      padding: 1rem 1.2rem;
      border-radius: 8px;
      border: 1px solid var(--border);
    }
    .stat-card .label { font-size: 0.8rem; color: var(--text-muted); }
    .stat-card .val { font-size: 1.8rem; font-weight: bold; margin-top: 0.3rem; }

    .filters {
      display: flex;
      gap: 1rem;
      margin-bottom: 1rem;
      flex-wrap: wrap;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      background: var(--card-bg);
      border-radius: 8px;
      overflow: hidden;
      border: 1px solid var(--border);
    }
    th, td {
      padding: 0.8rem 1rem;
      text-align: left;
      border-bottom: 1px solid var(--border);
      font-size: 0.9rem;
    }
    th { background: #111827; color: var(--text-muted); font-weight: 600; }
    
    .badge {
      display: inline-block;
      padding: 0.25rem 0.5rem;
      border-radius: 4px;
      font-size: 0.75rem;
      font-weight: bold;
    }
    .badge-success { background: rgba(34, 197, 94, 0.2); color: var(--success); }
    .badge-danger { background: rgba(239, 68, 68, 0.2); color: var(--danger); }
  </style>
</head>
<body>
  <div class="container">
    <h1>Git Proxy Access Logs</h1>

    <div class="auth-card">
      <input type="text" id="username" placeholder="Username" style="flex: 1; min-width: 150px;">
      <input type="password" id="password" placeholder="Password" style="flex: 1; min-width: 150px;">
      <button onclick="loadLogs()">Authenticate & Refresh</button>
    </div>

    <div class="stats">
      <div class="stat-card">
        <div class="label">Total Fetched Logs</div>
        <div class="val" id="stat-total">0</div>
      </div>
      <div class="stat-card">
        <div class="label">Successful Requests</div>
        <div class="val" id="stat-success" style="color: var(--success);">0</div>
      </div>
      <div class="stat-card">
        <div class="label">Failed Auth Attempts</div>
        <div class="val" id="stat-failed" style="color: var(--danger);">0</div>
      </div>
    </div>

    <div class="filters">
      <input type="text" id="filter-ip" placeholder="Filter by IP..." oninput="loadLogs()">
      <select id="filter-action" onchange="loadLogs()">
        <option value="all">All Actions</option>
        <option value="read">Read (Fetch/Clone)</option>
        <option value="write">Write (Push)</option>
      </select>
    </div>

    <table>
      <thead>
        <tr>
          <th>Timestamp</th>
          <th>IP Address</th>
          <th>Action</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody id="logs-body">
        <tr><td colspan="4" style="text-align:center; color: var(--text-muted);">Enter credentials to view logs</td></tr>
      </tbody>
    </table>
  </div>

  <script>
    async function sha256(message) {
      const msgBuffer = new TextEncoder().encode(message);
      const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }

    function escapeHtml(str) {
      const div = document.createElement('div');
      div.textContent = str;
      return div.innerHTML;
    }

    async function loadLogs() {
      const user = document.getElementById('username').value;
      const pwd = document.getElementById('password').value;
      if (!user || !pwd) return;

      const passHash = await sha256(pwd);
      const authPayload = user + ':' + passHash;
      const ip = document.getElementById('filter-ip').value;
      const action = document.getElementById('filter-action').value;

      const params = new URLSearchParams();
      if (ip) params.append('ip', ip);
      if (action !== 'all') params.append('action', action);

      try {
        const res = await fetch('/api/logs?' + params.toString(), {
          headers: { 'Authorization': 'Bearer ' + authPayload }
        });

        if (!res.ok) {
          document.getElementById('logs-body').innerHTML = 
            '<tr><td colspan="4" style="text-align:center; color: var(--danger);">Invalid username or password</td></tr>';
          return;
        }

        const data = await res.json();
        renderTableAndStats(data.logs);
      } catch (e) {
        console.error(e);
      }
    }

    function renderTableAndStats(logs) {
      const tbody = document.getElementById('logs-body');
      tbody.innerHTML = '';

      let successCount = 0;
      let failedCount = 0;

      logs.forEach(log => {
        if (log.success) successCount++;
        else failedCount++;

        const row = document.createElement('tr');
        const formattedDate = new Date(log.timestamp).toLocaleString();
        
        row.innerHTML = \`
          <td>\${escapeHtml(formattedDate)}</td>
          <td>\${escapeHtml(log.ip)}</td>
          <td><code>\${escapeHtml(log.action)}</code></td>
          <td>
            <span class="badge \${log.success ? 'badge-success' : 'badge-danger'}">
              \${log.success ? 'SUCCESS' : 'DENIED'}
            </span>
          </td>
        \`;
        tbody.appendChild(row);
      });

      document.getElementById('stat-total').innerText = logs.length;
      document.getElementById('stat-success').innerText = successCount;
      document.getElementById('stat-failed').innerText = failedCount;
    }
  </script>
</body>
</html>`;
}
