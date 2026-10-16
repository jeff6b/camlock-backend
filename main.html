<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Login</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@500&display=swap" rel="stylesheet">
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }

  html, body {
    height: 100%;
    font-family: 'Inter', system-ui, -apple-system, sans-serif;
  }

  body {
    min-height: 100vh;
    background:
      linear-gradient(160deg, rgba(6,10,14,0.75), rgba(6,10,14,0.55)),
      url('https://images.unsplash.com/photo-1441974231531-c6227db76b6e?auto=format&fit=crop&w=2000&q=80');
    background-size: cover;
    background-position: center;
    background-attachment: fixed;
  }

  #login {
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 24px;
    opacity: 0;
    animation: fadeUp 0.6s ease forwards;
  }

  @keyframes fadeUp {
    from { opacity: 0; transform: translateY(14px); }
    to { opacity: 1; transform: translateY(0); }
  }

  .panel-wrap {
    width: 100%;
    max-width: 460px;
    border-radius: 18px;
    box-shadow: 0 20px 50px rgba(0,0,0,0.55);
  }

  .panel {
    width: 100%;
    display: flex;
    border-radius: 18px;
    overflow: hidden;
    background:
      radial-gradient(120% 140% at 100% 0%, rgba(142,203,255,0.14), transparent 60%),
      #0a0a0c;
  }

  .panel-left {
    position: relative;
    flex: 1.1;
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    justify-content: flex-start;
    padding: 34px 26px 30px;
  }

  .form-heading {
    color: #f5f5f6;
    font-size: 15px;
    font-weight: 700;
    margin-bottom: 3px;
  }

  .form-heading .highlight { color: #8ecbff; }

  .form-sub {
    color: rgba(230,230,232,0.5);
    font-size: 11px;
    margin-bottom: 18px;
  }

  .field-group {
    width: 100%;
    margin-bottom: 11px;
  }

  .field-group label {
    display: block;
    color: rgba(230,230,232,0.55);
    font-size: 9.5px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    margin-bottom: 5px;
  }

  .input-shell {
    position: relative;
    display: flex;
    align-items: center;
  }

  .input-shell svg {
    position: absolute;
    left: 10px;
    width: 12px;
    height: 12px;
    opacity: 0.4;
  }

  .field-group input {
    width: 100%;
    background: transparent;
    border: 1px solid #1a1a1d;
    border-radius: 8px;
    padding: 8px 11px 8px 28px;
    color: #f2f2f3;
    font-size: 12px;
    font-family: inherit;
    outline: none;
    transition: border-color 0.15s ease, box-shadow 0.15s ease;
  }

  .field-group input:focus {
    border-color: #8ecbff;
    box-shadow: 0 0 0 3px rgba(142,203,255,0.12);
  }

  .login-btn {
    position: relative;
    width: 100%;
    margin-top: 8px;
    padding: 9px 0;
    border: none;
    border-radius: 8px;
    background: #ffffff;
    color: #0a0a0d;
    font-size: 12px;
    font-weight: 700;
    font-family: inherit;
    cursor: pointer;
    overflow: hidden;
    transition: transform 0.15s ease, opacity 0.15s ease;
  }

  .login-btn:hover {
    transform: translateY(-1px);
    opacity: 0.92;
  }

  .login-btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
    transform: none;
  }

  .login-btn::after {
    content: '';
    position: absolute;
    top: 0;
    left: -60%;
    width: 40%;
    height: 100%;
    background: linear-gradient(120deg, transparent, rgba(0,0,0,0.15), transparent);
    transition: left 0.5s ease;
  }

  .login-btn:hover:not(:disabled)::after {
    left: 120%;
  }

  .error-msg {
    color: #ff8080;
    font-size: 11px;
    margin-top: 10px;
    min-height: 14px;
    text-align: left;
    width: 100%;
  }

  .panel-right {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    justify-content: flex-start;
    padding: 34px 22px 30px;
    text-align: left;
  }

  .panel-right h1 {
    font-size: 15px;
    font-weight: 700;
    line-height: 1.25;
    color: #f2f2f3;
    letter-spacing: -0.3px;
    margin-bottom: 3px;
  }

  .panel-right h1 .highlight {
    background: linear-gradient(100deg, #8ecbff, #cfe9ff);
    -webkit-background-clip: text;
    background-clip: text;
    color: transparent;
  }

  .panel-right .form-sub {
    color: rgba(230,230,232,0.5);
    font-size: 11px;
    margin-bottom: 18px;
  }

  .stats {
    display: flex;
    flex-direction: column;
    gap: 11px;
    width: 100%;
  }

  .stat-box {
    background: transparent;
    border: 1px solid #1a1a1d;
    border-radius: 8px;
    padding: 8px 11px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    min-height: 34px;
  }

  .stat-label {
    font-size: 10px;
    font-weight: 600;
    color: rgba(230,230,232,0.55);
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }

  .stat-value {
    font-size: 12px;
    font-weight: 700;
    color: #8ecbff;
    font-family: 'JetBrains Mono', monospace;
  }

  @media (max-width: 420px) {
    .panel { flex-direction: column; }
    .panel-right { padding: 26px 20px; }
    .panel-left { padding-top: 30px; }
    .panel-right h1 { font-size: 15px; }
  }
</style>
</head>
<body>

  <div id="login">
    <div class="panel-wrap">
      <div class="panel">

        <div class="panel-left">
          <div class="form-heading">Welcome, <span class="highlight">User</span></div>
          <div class="form-sub">Sign in to continue</div>

          <div class="field-group">
            <label for="username">Username</label>
            <div class="input-shell">
              <svg viewBox="0 0 24 24" fill="none" stroke="#8ecbff" stroke-width="2"><circle cx="12" cy="8" r="4"/><path d="M4 21c0-4 4-6 8-6s8 2 8 6"/></svg>
              <input type="text" id="username" autocomplete="username">
            </div>
          </div>

          <div class="field-group">
            <label for="password">Password</label>
            <div class="input-shell">
              <svg viewBox="0 0 24 24" fill="none" stroke="#8ecbff" stroke-width="2"><rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>
              <input type="password" id="password" autocomplete="current-password">
            </div>
          </div>

          <button class="login-btn" id="loginBtn">Log in</button>
          <div class="error-msg" id="errorMsg"></div>
        </div>

        <div class="panel-right">
          <h1>Closet Cheating<br>Made <span class="highlight">Easy</span></h1>
          <div class="form-sub">&nbsp;</div>

          <div class="stats">
            <div class="stat-box">
              <span class="stat-label">Online Now</span>
              <span class="stat-value" id="statOnline">0</span>
            </div>
            <div class="stat-box">
              <span class="stat-label">Sessions</span>
              <span class="stat-value" id="statSessions">0</span>
            </div>
            <div class="stat-box">
              <span class="stat-label">Uptime</span>
              <span class="stat-value" id="statUptime">0%</span>
            </div>
          </div>
        </div>

      </div>
    </div>
  </div>

<script>
  // ═══════════════════════════════════════════════════════════
  //  BACKEND
  // ═══════════════════════════════════════════════════════════
  //  Point this at your Render backend URL.
  //  Local dev:   http://localhost:8000
  //  Production:  https://your-app.onrender.com
  //
  //  If the page is served BY the backend itself (FastAPI
  //  returns this HTML), you can leave it empty and it will
  //  use same-origin requests.
  // ═══════════════════════════════════════════════════════════

  const API_BASE = '';   // <- leave empty if served by FastAPI, or set full URL

  // Client ID from ?client=... in URL (set by the Python client
  // when it opens the webview). If present, we attach it to the
  // auth so the client can auto-detect login.
  function getClientId() {
    const urlParams = new URLSearchParams(window.location.search);
    const fromUrl = urlParams.get('client');
    if (fromUrl) {
      localStorage.setItem('client_id', fromUrl);
      return fromUrl;
    }
    return localStorage.getItem('client_id');
  }

  async function login() {
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    const btn = document.getElementById('loginBtn');
    const err = document.getElementById('errorMsg');

    err.textContent = '';

    if (!username || !password) {
      err.textContent = 'Please enter username and password';
      return;
    }

    btn.disabled = true;
    btn.textContent = 'Signing in...';

    try {
      const resp = await fetch(`${API_BASE}/api/user-login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',   // send/receive cookies
        body: JSON.stringify({ username, password })
      });

      const data = await resp.json();

      if (data.valid) {
        // If we have a client_id, authenticate the client too
        const clientId = getClientId();
        if (clientId) {
          try {
            await fetch(`${API_BASE}/api/client/authenticate`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              credentials: 'include',
              body: JSON.stringify({
                client_id: clientId,
                license_key: data.license_key,
                username: data.username
              })
            });
          } catch (e) {
            // Non-fatal — client will keep polling and pick it up next tick
            console.warn('Client authenticate failed:', e);
          }
        }

        // Redirect to dashboard
        window.location.href = '/dashboard';
      } else {
        err.textContent = data.error || 'Login failed';
        btn.disabled = false;
        btn.textContent = 'Log in';
      }
    } catch (e) {
      err.textContent = 'Connection error — please try again';
      btn.disabled = false;
      btn.textContent = 'Log in';
    }
  }

  // Enter key submits
  document.getElementById('password').addEventListener('keypress', (e) => {
    if (e.key === 'Enter') login();
  });
  document.getElementById('username').addEventListener('keypress', (e) => {
    if (e.key === 'Enter') login();
  });

  document.getElementById('loginBtn').addEventListener('click', login);

  // ═══════════════════════════════════════════════════════════
  //  LIVE STATS
  // ═══════════════════════════════════════════════════════════
  //  Polls your backend for online users / session count / uptime.
  //  Backend endpoint doesn't exist yet — leave this polling
  //  disabled until we add /api/public/stats on the FastAPI side.
  // ═══════════════════════════════════════════════════════════

  async function refreshStats() {
    try {
      const resp = await fetch(`${API_BASE}/api/public/stats`);
      if (!resp.ok) return;
      const data = await resp.json();
      if (data.online !== undefined) document.getElementById('statOnline').textContent = data.online;
      if (data.sessions !== undefined) document.getElementById('statSessions').textContent = data.sessions;
      if (data.uptime !== undefined) document.getElementById('statUptime').textContent = data.uptime + '%';
    } catch (e) {
      // Endpoint doesn't exist yet — silently ignore
    }
  }

  // Uncomment when you add /api/public/stats to the backend:
  // refreshStats();
  // setInterval(refreshStats, 10000);

  // ═══════════════════════════════════════════════════════════
  //  SESSION CHECK — if already logged in, skip this page
  // ═══════════════════════════════════════════════════════════

  (async () => {
    try {
      const resp = await fetch(`${API_BASE}/api/me`, { credentials: 'include' });
      const data = await resp.json();
      if (data.authenticated) {
        window.location.href = '/dashboard';
      }
    } catch (e) {
      // Not logged in or backend unreachable — stay on login page
    }
  })();
</script>

</body>
</html>
