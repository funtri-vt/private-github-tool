export default {
  async fetch(request, env) {
    if (request.method !== 'POST') {
      return new Response('Method Not Allowed', { status: 405 });
    }

    const clientIP = request.headers.get('cf-connecting-ip') || 'Unknown';

    try {
      const { action, auth } = await request.json();

      // 1. Validate incoming password hash
      if (!auth || auth !== env.AUTH_HASH) {
        await logAccess(env.DB, clientIP, action || 'unknown', false);
        return new Response(JSON.stringify({ error: 'Unauthorized' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      // 2. Generate GitHub App JWT
      const jwt = await generateJWT(env.GITHUB_APP_ID, env.GITHUB_PRIVATE_KEY);

      // 3. Request scoped Installation Access Token from GitHub
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
        await logAccess(env.DB, clientIP, action, false);
        return new Response(JSON.stringify({ error: 'GitHub Authentication Failed' }), {
          status: 502,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      const ghData = await ghResponse.json();

      // 4. Log successful access request
      await logAccess(env.DB, clientIP, action, true);

      return new Response(JSON.stringify({ token: ghData.token }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    } catch (err) {
      return new Response(JSON.stringify({ error: 'Internal Server Error' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      });
    }
  },
};

// --- HELPER FUNCTIONS ---

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
  const cleanPem = pemKey
    .replace(/-----BEGIN PRIVATE KEY-----/, '')
    .replace(/-----END PRIVATE KEY-----/, '')
    .replace(/\s+/g, '');

  const binaryDer = Uint8Array.from(atob(cleanPem), (c) => c.charCodeAt(0));

  const privateKey = await crypto.subtle.importKey(
    'pkcs8',
    binaryDer,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign']
  );

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
