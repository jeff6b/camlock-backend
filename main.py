# main.py — single file, FastAPI + login page
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel
from typing import Optional
import psycopg2
import sqlite3
import os
import json
import secrets
import re
from datetime import datetime, timedelta
import hashlib
import hmac

try:
    from slowapi import Limiter, _rate_limit_exceeded_handler
    from slowapi.util import get_remote_address
    from slowapi.errors import RateLimitExceeded
    from slowapi.middleware import SlowAPIMiddleware
    limiter = Limiter(key_func=get_remote_address)
    HAS_LIMITER = True
except ImportError:
    limiter = None
    HAS_LIMITER = False

app = FastAPI()

if HAS_LIMITER:
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.add_middleware(SlowAPIMiddleware)

# ═══════════════════════════════════════════════════════════
# DATABASE
# ═══════════════════════════════════════════════════════════

DATABASE_URL = os.getenv("DATABASE_URL")
USE_POSTGRES = DATABASE_URL is not None

def get_db():
    if USE_POSTGRES:
        return psycopg2.connect(DATABASE_URL)
    return sqlite3.connect("local.db")

def q(query):
    if USE_POSTGRES:
        return query
    return re.sub(r'(?<!%)%s(?!%)', '?', query)

def hash_password(password: str, salt: str = None):
    if salt is None:
        salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return f"{salt}:{key.hex()}", salt

def verify_password(stored_hash: str, password: str) -> bool:
    try:
        salt, stored_key = stored_hash.split(':')
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return hmac.compare_digest(key.hex(), stored_key)
    except:
        return False

def init_db():
    try:
        db = get_db()
        cur = db.cursor()
        if USE_POSTGRES:
            cur.execute("""CREATE TABLE IF NOT EXISTS keys (
                key TEXT PRIMARY KEY, duration TEXT NOT NULL,
                created_at TEXT NOT NULL, expires_at TEXT, redeemed_at TEXT,
                redeemed_by TEXT, hwid TEXT, hwid_resets INTEGER DEFAULT 0,
                active INTEGER DEFAULT 0, created_by TEXT)""")
            cur.execute("""CREATE TABLE IF NOT EXISTS user_accounts (
                id SERIAL PRIMARY KEY, license_key TEXT UNIQUE NOT NULL,
                username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
                email TEXT, created_at TEXT NOT NULL, last_login TEXT)""")
            cur.execute("""CREATE TABLE IF NOT EXISTS login_sessions (
                session_id TEXT PRIMARY KEY, username TEXT NOT NULL,
                license_key TEXT NOT NULL, created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL, ip_address TEXT)""")
            cur.execute("""CREATE TABLE IF NOT EXISTS saved_configs (
                id SERIAL PRIMARY KEY, license_key TEXT NOT NULL,
                config_name TEXT NOT NULL, config_data TEXT NOT NULL,
                created_at TEXT NOT NULL, UNIQUE(license_key, config_name))""")
            cur.execute("""CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY, config TEXT NOT NULL)""")
        else:
            cur.execute("""CREATE TABLE IF NOT EXISTS keys (
                key TEXT PRIMARY KEY, duration TEXT NOT NULL,
                created_at TEXT NOT NULL, expires_at TEXT, redeemed_at TEXT,
                redeemed_by TEXT, hwid TEXT, hwid_resets INTEGER DEFAULT 0,
                active INTEGER DEFAULT 0, created_by TEXT)""")
            cur.execute("""CREATE TABLE IF NOT EXISTS user_accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT, license_key TEXT UNIQUE NOT NULL,
                username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
                email TEXT, created_at TEXT NOT NULL, last_login TEXT)""")
            cur.execute("""CREATE TABLE IF NOT EXISTS login_sessions (
                session_id TEXT PRIMARY KEY, username TEXT NOT NULL,
                license_key TEXT NOT NULL, created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL, ip_address TEXT)""")
            cur.execute("""CREATE TABLE IF NOT EXISTS saved_configs (
                id INTEGER PRIMARY KEY AUTOINCREMENT, license_key TEXT NOT NULL,
                config_name TEXT NOT NULL, config_data TEXT NOT NULL,
                created_at TEXT NOT NULL, UNIQUE(license_key, config_name))""")
            cur.execute("""CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY, config TEXT NOT NULL)""")
        db.commit()
        db.close()
        print(f"DB initialized. Using: {'PostgreSQL' if USE_POSTGRES else 'SQLite'}")
    except Exception as e:
        print(f"DB init error: {e}")

init_db()

# ═══════════════════════════════════════════════════════════
# MODELS
# ═══════════════════════════════════════════════════════════

class UserLogin(BaseModel):
    username: str
    password: str

class SavedConfigRequest(BaseModel):
    config_name: str
    config_data: dict

# ═══════════════════════════════════════════════════════════
# API ENDPOINTS
# ═══════════════════════════════════════════════════════════

@app.post("/api/user-login")
async def user_login(request: Request, data: UserLogin):
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute(q("""SELECT ua.username, ua.password_hash, ua.license_key,
                        k.active, k.expires_at, k.hwid_resets
                        FROM user_accounts ua JOIN keys k ON ua.license_key = k.key
                        WHERE ua.username=%s"""), (data.username,))
        result = cur.fetchone()
        if not result:
            db.close()
            return {"valid": False, "error": "Invalid username or password"}

        username, password_hash, license_key, active, expires_at, hwid_resets = result

        if active == 0:
            db.close()
            return {"valid": False, "error": "License inactive"}
        if expires_at:
            try:
                if datetime.now() > datetime.fromisoformat(expires_at):
                    db.close()
                    return {"valid": False, "error": "License expired"}
            except:
                pass
        if not verify_password(password_hash, data.password):
            db.close()
            return {"valid": False, "error": "Invalid username or password"}

        cur.execute(q("UPDATE user_accounts SET last_login=%s WHERE username=%s"),
                    (datetime.now().isoformat(), username))

        session_id = secrets.token_hex(16)
        now = datetime.now().isoformat()
        exp = (datetime.now() + timedelta(days=30)).isoformat()
        cur.execute(q("""INSERT INTO login_sessions
                       (session_id, username, license_key, created_at, expires_at, ip_address)
                       VALUES (%s, %s, %s, %s, %s, %s)"""),
                    (session_id, username, license_key, now, exp, request.client.host))
        db.commit()
        db.close()

        subscription = "Lifetime" if expires_at is None else "Temporary"
        resp = JSONResponse({
            "valid": True, "message": "Login successful",
            "username": username, "license_key": license_key,
            "subscription": subscription, "hwid_resets": hwid_resets or 0
        })
        # Same-origin cookies — no need for SameSite=None
        resp.set_cookie("session_id", session_id, httponly=True, max_age=2592000, samesite="lax")
        resp.set_cookie("license_key", license_key, httponly=True, max_age=2592000, samesite="lax")
        resp.set_cookie("username", username, httponly=True, max_age=2592000, samesite="lax")
        return resp
    except Exception as e:
        db.close()
        return {"valid": False, "error": f"Server error: {str(e)}"}


@app.get("/api/me")
async def get_current_user(request: Request):
    license_key = request.cookies.get("license_key")
    session_id = request.cookies.get("session_id")
    if not license_key or not session_id:
        return {"authenticated": False}
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute(q("SELECT username, license_key FROM login_sessions WHERE session_id=%s AND expires_at > %s"),
                    (session_id, datetime.now().isoformat()))
        result = cur.fetchone()
        db.close()
        if result:
            return {"authenticated": True, "username": result[0], "license_key": result[1]}
        return {"authenticated": False}
    except:
        db.close()
        return {"authenticated": False}


@app.post("/api/logout")
async def logout():
    resp = JSONResponse({"success": True})
    resp.delete_cookie("session_id")
    resp.delete_cookie("license_key")
    resp.delete_cookie("username")
    return resp


@app.get("/api/dashboard")
async def get_dashboard(request: Request):
    license_key = request.cookies.get("license_key")
    if not license_key:
        raise HTTPException(status_code=401, detail="Not authenticated")
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute(q("SELECT key, duration, expires_at, active, hwid, redeemed_by, hwid_resets FROM keys WHERE key=%s"),
                    (license_key,))
        result = cur.fetchone()
        db.close()
        if not result:
            raise HTTPException(status_code=404, detail="Not found")
        key, duration, expires_at, active, hwid, discord_id, hwid_resets = result
        subscription = "Lifetime" if expires_at is None else "Temporary"
        return {
            "license_key": key, "duration": duration, "expires_at": expires_at,
            "active": active, "hwid": hwid, "discord_id": discord_id,
            "hwid_resets": hwid_resets or 0, "subscription": subscription
        }
    except HTTPException:
        raise
    except Exception as e:
        db.close()
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/config")
async def get_config(request: Request):
    license_key = request.cookies.get("license_key")
    if not license_key:
        raise HTTPException(status_code=401, detail="Not authenticated")
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute(q("SELECT config FROM settings WHERE key=%s"), (license_key,))
        result = cur.fetchone()
        if not result:
            cur.execute(q("INSERT INTO settings (key, config) VALUES (%s, %s)"),
                        (license_key, json.dumps({})))
            db.commit()
            db.close()
            return {}
        db.close()
        return json.loads(result[0])
    except Exception as e:
        db.close()
        return {}


@app.post("/api/config")
async def set_config(request: Request, data: dict):
    license_key = request.cookies.get("license_key")
    if not license_key:
        raise HTTPException(status_code=401, detail="Not authenticated")
    db = get_db()
    cur = db.cursor()
    try:
        if USE_POSTGRES:
            cur.execute("INSERT INTO settings (key, config) VALUES (%s, %s) ON CONFLICT (key) DO UPDATE SET config = EXCLUDED.config",
                        (license_key, json.dumps(data)))
        else:
            cur.execute("INSERT OR REPLACE INTO settings (key, config) VALUES (?, ?)",
                        (license_key, json.dumps(data)))
        db.commit()
        db.close()
        return {"status": "ok"}
    except Exception as e:
        db.close()
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/configs/list")
async def list_configs(request: Request):
    license_key = request.cookies.get("license_key")
    if not license_key:
        raise HTTPException(status_code=401, detail="Not authenticated")
    db = get_db()
    cur = db.cursor()
    cur.execute(q("SELECT config_name, created_at FROM saved_configs WHERE license_key=%s ORDER BY created_at DESC"),
                (license_key,))
    rows = cur.fetchall()
    db.close()
    return {"configs": [{"name": r[0], "created_at": r[1]} for r in rows]}


@app.post("/api/configs/save")
async def save_config(request: Request, data: SavedConfigRequest):
    license_key = request.cookies.get("license_key")
    if not license_key:
        raise HTTPException(status_code=401, detail="Not authenticated")
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute(q("SELECT id FROM saved_configs WHERE license_key=%s AND config_name=%s"),
                    (license_key, data.config_name))
        if cur.fetchone():
            cur.execute(q("UPDATE saved_configs SET config_data=%s WHERE license_key=%s AND config_name=%s"),
                        (json.dumps(data.config_data), license_key, data.config_name))
        else:
            cur.execute(q("INSERT INTO saved_configs (license_key, config_name, config_data, created_at) VALUES (%s, %s, %s, %s)"),
                        (license_key, data.config_name, json.dumps(data.config_data), datetime.now().isoformat()))
        db.commit()
        db.close()
        return {"success": True}
    except Exception as e:
        db.close()
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/configs/load/{config_name}")
async def load_config(request: Request, config_name: str):
    license_key = request.cookies.get("license_key")
    if not license_key:
        raise HTTPException(status_code=401, detail="Not authenticated")
    db = get_db()
    cur = db.cursor()
    cur.execute(q("SELECT config_data FROM saved_configs WHERE license_key=%s AND config_name=%s"),
                (license_key, config_name))
    row = cur.fetchone()
    db.close()
    if not row:
        raise HTTPException(status_code=404, detail="Config not found")
    return json.loads(row[0])


@app.delete("/api/configs/delete/{config_name}")
async def delete_config(request: Request, config_name: str):
    license_key = request.cookies.get("license_key")
    if not license_key:
        raise HTTPException(status_code=401, detail="Not authenticated")
    db = get_db()
    cur = db.cursor()
    cur.execute(q("DELETE FROM saved_configs WHERE license_key=%s AND config_name=%s"),
                (license_key, config_name))
    db.commit()
    db.close()
    return {"success": True}


@app.get("/api/keepalive")
def keepalive():
    return {"status": "alive", "timestamp": datetime.now().isoformat()}


# ═══════════════════════════════════════════════════════════
# HTML PAGES
# ═══════════════════════════════════════════════════════════

LOGIN_HTML = """<!DOCTYPE html>
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
  html, body { height: 100%; font-family: 'Inter', system-ui, -apple-system, sans-serif; }
  body {
    min-height: 100vh;
    background: linear-gradient(160deg, rgba(6,10,14,0.75), rgba(6,10,14,0.55)),
      url('https://images.unsplash.com/photo-1441974231531-c6227db76b6e?auto=format&fit=crop&w=2000&q=80');
    background-size: cover; background-position: center; background-attachment: fixed;
  }
  #login { min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 24px; opacity: 0; animation: fadeUp 0.6s ease forwards; }
  @keyframes fadeUp { from { opacity: 0; transform: translateY(14px); } to { opacity: 1; transform: translateY(0); } }
  .panel-wrap { width: 100%; max-width: 460px; border-radius: 18px; box-shadow: 0 20px 50px rgba(0,0,0,0.55); }
  .panel { width: 100%; display: flex; border-radius: 18px; overflow: hidden;
    background: radial-gradient(120% 140% at 100% 0%, rgba(142,203,255,0.14), transparent 60%), #0a0a0c; }
  .panel-left { position: relative; flex: 1.1; display: flex; flex-direction: column; align-items: flex-start; justify-content: flex-start; padding: 34px 26px 30px; }
  .form-heading { color: #f5f5f6; font-size: 15px; font-weight: 700; margin-bottom: 3px; }
  .form-heading .highlight { color: #8ecbff; }
  .form-sub { color: rgba(230,230,232,0.5); font-size: 11px; margin-bottom: 18px; }
  .field-group { width: 100%; margin-bottom: 11px; }
  .field-group label { display: block; color: rgba(230,230,232,0.55); font-size: 9.5px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 5px; }
  .input-shell { position: relative; display: flex; align-items: center; }
  .input-shell svg { position: absolute; left: 10px; width: 12px; height: 12px; opacity: 0.4; }
  .field-group input { width: 100%; background: transparent; border: 1px solid #1a1a1d; border-radius: 8px; padding: 8px 11px 8px 28px; color: #f2f2f3; font-size: 12px; font-family: inherit; outline: none; transition: border-color 0.15s ease, box-shadow 0.15s ease; }
  .field-group input:focus { border-color: #8ecbff; box-shadow: 0 0 0 3px rgba(142,203,255,0.12); }
  .login-btn { position: relative; width: 100%; margin-top: 8px; padding: 9px 0; border: none; border-radius: 8px; background: #ffffff; color: #0a0a0d; font-size: 12px; font-weight: 700; font-family: inherit; cursor: pointer; overflow: hidden; transition: transform 0.15s ease, opacity 0.15s ease; }
  .login-btn:hover { transform: translateY(-1px); opacity: 0.92; }
  .login-btn:disabled { opacity: 0.5; cursor: not-allowed; transform: none; }
  .error-msg { color: #ff8080; font-size: 11px; margin-top: 10px; min-height: 14px; text-align: left; width: 100%; }
  .panel-right { flex: 1; display: flex; flex-direction: column; align-items: flex-start; justify-content: flex-start; padding: 34px 22px 30px; text-align: left; }
  .panel-right h1 { font-size: 15px; font-weight: 700; line-height: 1.25; color: #f2f2f3; letter-spacing: -0.3px; margin-bottom: 3px; }
  .panel-right h1 .highlight { background: linear-gradient(100deg, #8ecbff, #cfe9ff); -webkit-background-clip: text; background-clip: text; color: transparent; }
  .panel-right .form-sub { color: rgba(230,230,232,0.5); font-size: 11px; margin-bottom: 18px; }
  .stats { display: flex; flex-direction: column; gap: 11px; width: 100%; }
  .stat-box { background: transparent; border: 1px solid #1a1a1d; border-radius: 8px; padding: 8px 11px; display: flex; align-items: center; justify-content: space-between; min-height: 34px; }
  .stat-label { font-size: 10px; font-weight: 600; color: rgba(230,230,232,0.55); text-transform: uppercase; letter-spacing: 0.04em; }
  .stat-value { font-size: 12px; font-weight: 700; color: #8ecbff; font-family: 'JetBrains Mono', monospace; }
  @media (max-width: 420px) { .panel { flex-direction: column; } .panel-right { padding: 26px 20px; } .panel-left { padding-top: 30px; } }
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
            <div class="stat-box"><span class="stat-label">Online Now</span><span class="stat-value">0</span></div>
            <div class="stat-box"><span class="stat-label">Sessions</span><span class="stat-value">0</span></div>
            <div class="stat-box"><span class="stat-label">Uptime</span><span class="stat-value">0%</span></div>
          </div>
        </div>
      </div>
    </div>
  </div>
<script>
  async function login() {
    const u = document.getElementById('username').value.trim();
    const p = document.getElementById('password').value;
    const btn = document.getElementById('loginBtn');
    const err = document.getElementById('errorMsg');
    err.textContent = '';
    if (!u || !p) { err.textContent = 'Please enter username and password'; return; }
    btn.disabled = true; btn.textContent = 'Signing in...';
    try {
      const r = await fetch('/api/user-login', {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        credentials: 'include',
        body: JSON.stringify({ username: u, password: p })
      });
      const data = await r.json();
      if (data.valid) {
        window.location.href = '/dashboard';
      } else {
        err.textContent = data.error || 'Login failed';
        btn.disabled = false; btn.textContent = 'Log in';
      }
    } catch (e) {
      err.textContent = 'Connection error';
      btn.disabled = false; btn.textContent = 'Log in';
    }
  }
  document.getElementById('loginBtn').addEventListener('click', login);
  document.getElementById('password').addEventListener('keypress', e => { if (e.key === 'Enter') login(); });
  document.getElementById('username').addEventListener('keypress', e => { if (e.key === 'Enter') login(); });
  (async () => {
    try {
      const r = await fetch('/api/me', { credentials: 'include' });
      const data = await r.json();
      if (data.authenticated) window.location.href = '/dashboard';
    } catch (e) {}
  })();
</script>
</body>
</html>"""


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@500&display=swap" rel="stylesheet">
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { min-height: 100vh; background: #0a0a0c; color: #e0e0e8; font-family: 'Inter', sans-serif; display: flex; flex-direction: column; align-items: center; padding: 40px 20px; }
  .header { width: 100%; max-width: 900px; display: flex; justify-content: space-between; align-items: center; margin-bottom: 40px; }
  .header h1 { font-size: 24px; color: #fff; }
  .logout { padding: 8px 16px; background: transparent; border: 1px solid #252529; border-radius: 6px; color: #888890; font-size: 12px; cursor: pointer; }
  .logout:hover { color: #fff; border-color: #fff; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 20px; width: 100%; max-width: 900px; }
  .card { background: rgba(17,17,19,0.65); border: 1px solid #1e1e22; border-radius: 10px; padding: 24px; }
  .card-header { font-size: 12px; color: #888890; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 12px; }
  .card-value { font-size: 20px; color: #fff; font-family: 'JetBrains Mono', monospace; word-break: break-all; }
  .card-value.blur { filter: blur(6px); transition: filter 0.2s; user-select: none; }
  .card-value.blur:hover { filter: blur(0); user-select: text; }
</style>
</head>
<body>
  <div class="header">
    <h1>Dashboard</h1>
    <button class="logout" onclick="logout()">Logout</button>
  </div>
  <div class="grid">
    <div class="card"><div class="card-header">Username</div><div class="card-value" id="username">-</div></div>
    <div class="card"><div class="card-header">License Key</div><div class="card-value blur" id="licenseKey">-</div></div>
    <div class="card"><div class="card-header">Subscription</div><div class="card-value" id="subscription">-</div></div>
    <div class="card"><div class="card-header">HWID</div><div class="card-value" id="hwid">-</div></div>
    <div class="card"><div class="card-header">HWID Resets</div><div class="card-value" id="hwidResets">0</div></div>
  </div>
<script>
  async function load() {
    const meRes = await fetch('/api/me', { credentials: 'include' });
    const me = await meRes.json();
    if (!me.authenticated) { window.location.href = '/'; return; }
    document.getElementById('username').textContent = me.username;
    const dRes = await fetch('/api/dashboard', { credentials: 'include' });
    if (dRes.ok) {
      const d = await dRes.json();
      document.getElementById('licenseKey').textContent = d.license_key;
      document.getElementById('subscription').textContent = d.subscription;
      document.getElementById('hwid').textContent = d.hwid || 'Not bound';
      document.getElementById('hwidResets').textContent = d.hwid_resets;
    }
  }
  async function logout() {
    await fetch('/api/logout', { method: 'POST' });
    window.location.href = '/';
  }
  load();
</script>
</body>
</html>"""


@app.get("/", response_class=HTMLResponse)
async def serve_login():
    return HTMLResponse(content=LOGIN_HTML)

@app.get("/menu", response_class=HTMLResponse)
async def serve_menu():
    return HTMLResponse(content=LOGIN_HTML)

@app.get("/dashboard", response_class=HTMLResponse)
async def serve_dashboard(request: Request):
    license_key = request.cookies.get("license_key")
    session_id = request.cookies.get("session_id")
    if not license_key or not session_id:
        return RedirectResponse(url="/")
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute(q("SELECT username FROM login_sessions WHERE session_id=%s AND license_key=%s AND expires_at > %s"),
                    (session_id, license_key, datetime.now().isoformat()))
        result = cur.fetchone()
        db.close()
        if not result:
            return RedirectResponse(url="/")
        return HTMLResponse(content=DASHBOARD_HTML)
    except:
        db.close()
        return RedirectResponse(url="/")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
