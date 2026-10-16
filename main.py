# main.py — Full backend + fullscreen login + fullscreen dashboard + HWID binding
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel
from typing import Optional
import psycopg2
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

DATABASE_URL = "postgresql://neondb_owner:npg_S7hoDMeaw2cQ@ep-wandering-dream-ah21egpt-pooler.c-3.us-east-1.aws.neon.tech/neondb?sslmode=require"

def get_db():
    return psycopg2.connect(DATABASE_URL)

def q(query):
    return query

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
        cur.execute("""CREATE TABLE IF NOT EXISTS clients (
            client_id TEXT PRIMARY KEY, hwid TEXT NOT NULL,
            session_token TEXT, license_key TEXT, username TEXT,
            created_at TEXT NOT NULL, last_ping TEXT,
            authenticated INTEGER DEFAULT 0)""")
        db.commit()
        db.close()
        print("DB initialized. Using: PostgreSQL", flush=True)
    except Exception as e:
        print(f"DB init error: {e}", flush=True)

def migrate_db():
    try:
        db = get_db()
        cur = db.cursor()
        migrations = [
            ("keys", "active", "INTEGER DEFAULT 0"),
            ("keys", "hwid", "TEXT"),
            ("keys", "hwid_resets", "INTEGER DEFAULT 0"),
            ("keys", "expires_at", "TEXT"),
            ("keys", "redeemed_at", "TEXT"),
            ("keys", "redeemed_by", "TEXT"),
            ("keys", "created_by", "TEXT"),
            ("keys", "duration", "TEXT DEFAULT 'lifetime'"),
            ("keys", "created_at", "TEXT DEFAULT ''"),
            ("user_accounts", "email", "TEXT"),
            ("user_accounts", "last_login", "TEXT"),
            ("user_accounts", "created_at", "TEXT DEFAULT ''"),
            ("login_sessions", "ip_address", "TEXT"),
            ("login_sessions", "expires_at", "TEXT"),
            ("login_sessions", "created_at", "TEXT DEFAULT ''"),
            ("clients", "authenticated", "INTEGER DEFAULT 0"),
            ("clients", "license_key", "TEXT"),
            ("clients", "username", "TEXT"),
            ("clients", "last_ping", "TEXT"),
            ("clients", "session_token", "TEXT"),
            ("clients", "created_at", "TEXT DEFAULT ''"),
            ("saved_configs", "created_at", "TEXT DEFAULT ''"),
            ("settings", "config", "TEXT DEFAULT '{}'"),
        ]
        for table, col, definition in migrations:
            try:
                cur.execute(f'ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {col} {definition}')
            except Exception as e:
                print(f"[MIGRATE] {table}.{col} skip: {e}", flush=True)
        db.commit()
        db.close()
        print("[MIGRATE] Schema migration complete.", flush=True)
    except Exception as e:
        print(f"[MIGRATE] Error: {e}", flush=True)

init_db()
migrate_db()

# ═══════════════════════════════════════════════════════════
# BOOTSTRAP TEST ACCOUNT
# ═══════════════════════════════════════════════════════════

def bootstrap_test_account():
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT username FROM user_accounts WHERE username=%s", ("light",))
        if cur.fetchone():
            print("[BOOTSTRAP] Account 'light' already exists — skipping.", flush=True)
            db.close()
            return
        license_key = "LIGHT-LIFE-TIME-0001"
        now = datetime.now().isoformat()
        cur.execute("SELECT key FROM keys WHERE key=%s", (license_key,))
        if not cur.fetchone():
            cur.execute("""INSERT INTO keys
                (key, duration, created_at, expires_at, active, redeemed_by, hwid_resets)
                VALUES (%s, %s, %s, %s, 1, %s, 0)""",
                (license_key, "lifetime", now, None, "bootstrap"))
        pw_hash, _ = hash_password("light")
        cur.execute("""INSERT INTO user_accounts
            (license_key, username, password_hash, email, created_at)
            VALUES (%s, %s, %s, %s, %s)""",
            (license_key, "light", pw_hash, "light@local", now))
        cur.execute("UPDATE keys SET active=1, redeemed_at=%s, redeemed_by=%s WHERE key=%s",
                    (now, "light", license_key))
        db.commit()
        db.close()
        print("[BOOTSTRAP] ✅ Test account created! user=light pass=light", flush=True)
    except Exception as e:
        print(f"[BOOTSTRAP] Error: {e}", flush=True)

bootstrap_test_account()

# ═══════════════════════════════════════════════════════════
# MODELS
# ═══════════════════════════════════════════════════════════

class UserLogin(BaseModel):
    username: str
    password: str
    client_id: Optional[str] = None

class SavedConfigRequest(BaseModel):
    config_name: str
    config_data: dict

class ClientRegister(BaseModel):
    client_id: str
    hwid: str

class ClientAuthStatus(BaseModel):
    client_id: str
    session_token: Optional[str] = None

class ClientAuthenticate(BaseModel):
    client_id: str
    license_key: str
    username: str

# ═══════════════════════════════════════════════════════════
# API — USER LOGIN (with HWID binding)
# ═══════════════════════════════════════════════════════════

@app.post("/api/user-login")
async def user_login(request: Request, data: UserLogin):
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("""SELECT ua.username, ua.password_hash, ua.license_key,
                       k.active, k.expires_at, k.hwid_resets, k.hwid
                       FROM user_accounts ua JOIN keys k ON ua.license_key = k.key
                       WHERE ua.username=%s""", (data.username,))
        result = cur.fetchone()
        if not result:
            db.close()
            return {"valid": False, "error": "Invalid username or password"}

        username, password_hash, license_key, active, expires_at, hwid_resets, bound_hwid = result

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

        # ── HWID binding ──
        if data.client_id:
            cur.execute("SELECT hwid FROM clients WHERE client_id=%s", (data.client_id,))
            crow = cur.fetchone()
            if not crow:
                db.close()
                return {"valid": False, "error": "Client not registered"}
            client_hwid = crow[0]

            if bound_hwid is None:
                # First login — bind HWID
                cur.execute("UPDATE keys SET hwid=%s WHERE key=%s", (client_hwid, license_key))
                print(f"[HWID] Bound {client_hwid[:12]}... to {license_key}", flush=True)
            elif bound_hwid != client_hwid:
                db.close()
                return {"valid": False, "error": "HWID mismatch — license bound to another PC"}

        cur.execute("UPDATE user_accounts SET last_login=%s WHERE username=%s",
                    (datetime.now().isoformat(), username))

        session_id = secrets.token_hex(16)
        now = datetime.now().isoformat()
        exp = (datetime.now() + timedelta(days=30)).isoformat()
        cur.execute("""INSERT INTO login_sessions
                       (session_id, username, license_key, created_at, expires_at, ip_address)
                       VALUES (%s, %s, %s, %s, %s, %s)""",
                    (session_id, username, license_key, now, exp, request.client.host))
        db.commit()
        db.close()

        subscription = "Lifetime" if expires_at is None else "Temporary"
        resp = JSONResponse({
            "valid": True, "message": "Login successful",
            "username": username, "license_key": license_key,
            "subscription": subscription, "hwid_resets": hwid_resets or 0
        })
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
        cur.execute("SELECT username, license_key FROM login_sessions WHERE session_id=%s AND expires_at > %s",
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
        cur.execute("SELECT key, duration, expires_at, active, hwid, redeemed_by, hwid_resets FROM keys WHERE key=%s",
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


# ═══════════════════════════════════════════════════════════
# API — CONFIG
# ═══════════════════════════════════════════════════════════

@app.get("/api/config")
async def get_config(request: Request):
    license_key = request.cookies.get("license_key")
    if not license_key:
        raise HTTPException(status_code=401, detail="Not authenticated")
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("SELECT config FROM settings WHERE key=%s", (license_key,))
        result = cur.fetchone()
        if not result:
            cur.execute("INSERT INTO settings (key, config) VALUES (%s, %s)",
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
        cur.execute("INSERT INTO settings (key, config) VALUES (%s, %s) ON CONFLICT (key) DO UPDATE SET config = EXCLUDED.config",
                    (license_key, json.dumps(data)))
        db.commit()
        db.close()
        return {"status": "ok"}
    except Exception as e:
        db.close()
        raise HTTPException(status_code=500, detail=str(e))


# ═══════════════════════════════════════════════════════════
# API — CLIENT (for Python cheat)
# ═══════════════════════════════════════════════════════════

@app.post("/api/client/register")
async def register_client(data: ClientRegister):
    db = get_db()
    cur = db.cursor()
    try:
        session_token = secrets.token_hex(32)
        now = datetime.now().isoformat()
        cur.execute("SELECT client_id FROM clients WHERE client_id=%s", (data.client_id,))
        if cur.fetchone():
            cur.execute("""UPDATE clients SET hwid=%s, session_token=%s, last_ping=%s, authenticated=0
                           WHERE client_id=%s""",
                        (data.hwid, session_token, now, data.client_id))
        else:
            cur.execute("""INSERT INTO clients
                           (client_id, hwid, session_token, created_at, last_ping, authenticated)
                           VALUES (%s, %s, %s, %s, %s, 0)""",
                        (data.client_id, data.hwid, session_token, now, now))
        db.commit()
        db.close()
        return {"success": True, "session_token": session_token,
                "client_id": data.client_id, "authenticated": False}
    except Exception as e:
        db.close()
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/client/auth-status")
async def client_auth_status(data: ClientAuthStatus):
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("""SELECT authenticated, license_key, username, hwid
                       FROM clients WHERE client_id=%s AND session_token=%s""",
                    (data.client_id, data.session_token))
        result = cur.fetchone()
        if not result:
            db.close()
            return {"authenticated": False, "error": "Invalid credentials"}
        authenticated, license_key, username, hwid = result
        cur.execute("UPDATE clients SET last_ping=%s WHERE client_id=%s",
                    (datetime.now().isoformat(), data.client_id))
        db.commit()
        db.close()
        return {"authenticated": bool(authenticated), "license_key": license_key,
                "username": username, "hwid": hwid}
    except Exception as e:
        db.close()
        return {"authenticated": False, "error": str(e)}


@app.post("/api/client/authenticate")
async def client_authenticate(data: ClientAuthenticate):
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("""UPDATE clients
                       SET authenticated=1, license_key=%s, username=%s, last_ping=%s
                       WHERE client_id=%s""",
                    (data.license_key, data.username, datetime.now().isoformat(), data.client_id))
        db.commit()
        db.close()
        return {"success": True}
    except Exception as e:
        db.close()
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/client/config")
async def get_client_config(data: dict):
    client_id = data.get("client_id")
    session_token = data.get("session_token")
    if not client_id or not session_token:
        raise HTTPException(status_code=401, detail="Missing credentials")
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("SELECT license_key FROM clients WHERE client_id=%s AND session_token=%s AND authenticated=1",
                    (client_id, session_token))
        result = cur.fetchone()
        if not result:
            db.close()
            raise HTTPException(status_code=401, detail="Not authenticated")
        license_key = result[0]
        cur.execute("SELECT config FROM settings WHERE key=%s", (license_key,))
        cfg = cur.fetchone()
        db.close()
        return json.loads(cfg[0]) if cfg else {}
    except HTTPException:
        raise
    except Exception as e:
        db.close()
        raise HTTPException(status_code=500, detail=str(e))


# ═══════════════════════════════════════════════════════════
# KEEPALIVE
# ═══════════════════════════════════════════════════════════

@app.get("/api/keepalive")
def keepalive():
    return {"status": "alive", "timestamp": datetime.now().isoformat()}


# ═══════════════════════════════════════════════════════════
# HTML — LOGIN PAGE (FULLSCREEN)
# ═══════════════════════════════════════════════════════════

LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Lumina — Login</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@500&display=swap" rel="stylesheet">
<style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
  html, body {
    width: 100%; height: 100%; overflow: hidden;
    font-family: 'Inter', system-ui, -apple-system, sans-serif;
  }
  body {
    background:
      linear-gradient(160deg, rgba(6,10,14,0.82), rgba(6,10,14,0.65)),
      url('https://images.unsplash.com/photo-1441974231531-c6227db76b6e?auto=format&fit=crop&w=2000&q=80');
    background-size: cover; background-position: center; background-attachment: fixed;
    display: flex; align-items: stretch; justify-content: stretch;
  }
  .panel-wrap {
    width: 100%; height: 100vh;
    opacity: 0; animation: fadeUp 0.6s ease forwards;
  }
  @keyframes fadeUp { from { opacity: 0; } to { opacity: 1; } }
  .panel {
    width: 100%; height: 100%;
    display: flex;
    background: radial-gradient(120% 140% at 100% 0%, rgba(142,203,255,0.16), transparent 60%), #0a0a0c;
  }
  .panel-left {
    flex: 1;
    display: flex; flex-direction: column; justify-content: center;
    padding: 80px 100px;
    max-width: 640px;
  }
  .form-heading { color: #f5f5f6; font-size: 32px; font-weight: 700; margin-bottom: 8px; letter-spacing: -0.5px; }
  .form-heading .highlight { color: #8ecbff; }
  .form-sub { color: rgba(230,230,232,0.5); font-size: 15px; margin-bottom: 44px; }
  .field-group { width: 100%; margin-bottom: 22px; }
  .field-group label { display: block; color: rgba(230,230,232,0.6); font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 9px; }
  .input-shell { position: relative; display: flex; align-items: center; }
  .input-shell svg { position: absolute; left: 16px; width: 16px; height: 16px; opacity: 0.45; }
  .field-group input {
    width: 100%; background: rgba(20,20,23,0.6);
    border: 1px solid #1a1a1d; border-radius: 11px;
    padding: 16px 18px 16px 46px;
    color: #f2f2f3; font-size: 15px; font-family: inherit;
    outline: none; transition: border-color 0.15s, box-shadow 0.15s;
  }
  .field-group input:focus { border-color: #8ecbff; box-shadow: 0 0 0 4px rgba(142,203,255,0.12); }
  .login-btn {
    width: 100%; margin-top: 14px; padding: 16px 0;
    border: none; border-radius: 11px;
    background: #ffffff; color: #0a0a0d;
    font-size: 15px; font-weight: 700; font-family: inherit;
    cursor: pointer; transition: transform 0.15s, opacity 0.15s;
  }
  .login-btn:hover { transform: translateY(-1px); opacity: 0.92; }
  .login-btn:disabled { opacity: 0.5; cursor: not-allowed; transform: none; }
  .error-msg { color: #ff8080; font-size: 13px; margin-top: 16px; min-height: 18px; }
  .panel-right {
    flex: 1;
    display: flex; flex-direction: column; justify-content: center;
    padding: 80px 100px;
    border-left: 1px solid #1a1a1d;
    background: radial-gradient(140% 160% at 0% 100%, rgba(142,203,255,0.08), transparent 60%);
  }
  .panel-right h1 { font-size: 48px; font-weight: 700; line-height: 1.1; color: #f2f2f3; letter-spacing: -1.2px; margin-bottom: 20px; }
  .panel-right h1 .highlight { background: linear-gradient(100deg, #8ecbff, #cfe9ff); -webkit-background-clip: text; background-clip: text; color: transparent; }
  .panel-right .desc { color: rgba(230,230,232,0.55); font-size: 16px; line-height: 1.7; margin-bottom: 44px; max-width: 480px; }
  .stats { display: flex; flex-direction: column; gap: 16px; width: 100%; max-width: 480px; }
  .stat-box { background: rgba(20,20,23,0.6); border: 1px solid #1a1a1d; border-radius: 11px; padding: 18px 22px; display: flex; align-items: center; justify-content: space-between; }
  .stat-label { font-size: 12px; font-weight: 600; color: rgba(230,230,232,0.55); text-transform: uppercase; letter-spacing: 0.06em; }
  .stat-value { font-size: 15px; font-weight: 700; color: #8ecbff; font-family: 'JetBrains Mono', monospace; }
  @media (max-width: 900px) {
    .panel { flex-direction: column; }
    .panel-left, .panel-right { padding: 60px 40px; max-width: unset; }
    .panel-right { border-left: none; border-top: 1px solid #1a1a1d; }
    .panel-right h1 { font-size: 32px; }
  }
</style>
</head>
<body>
  <div class="panel-wrap">
    <div class="panel">
      <div class="panel-left">
        <div class="form-heading">Welcome, <span class="highlight">Back</span></div>
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
        <button class="login-btn" id="loginBtn">Sign In</button>
        <div class="error-msg" id="errorMsg"></div>
      </div>
      <div class="panel-right">
        <h1>Closet Cheating<br>Made <span class="highlight">Easy</span></h1>
        <div class="desc">The simplest, cleanest camlock for Roblox. Hardware-locked. Cloud-synced. Config in the browser, aim in-game.</div>
        <div class="stats">
          <div class="stat-box"><span class="stat-label">Online Now</span><span class="stat-value">0</span></div>
          <div class="stat-box"><span class="stat-label">Active Sessions</span><span class="stat-value">0</span></div>
          <div class="stat-box"><span class="stat-label">Uptime</span><span class="stat-value">99.9%</span></div>
        </div>
      </div>
    </div>
  </div>
<script>
  function getClientId() {
    const p = new URLSearchParams(window.location.search);
    const fromUrl = p.get('client');
    if (fromUrl) { localStorage.setItem('client_id', fromUrl); return fromUrl; }
    return localStorage.getItem('client_id');
  }
  async function login() {
    const u = document.getElementById('username').value.trim();
    const p = document.getElementById('password').value;
    const btn = document.getElementById('loginBtn');
    const err = document.getElementById('errorMsg');
    err.textContent = '';
    if (!u || !p) { err.textContent = 'Please enter username and password'; return; }
    btn.disabled = true; btn.textContent = 'Signing in...';
    try {
      const clientId = getClientId();
      const r = await fetch('/api/user-login', {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        credentials: 'include',
        body: JSON.stringify({ username: u, password: p, client_id: clientId })
      });
      const data = await r.json();
      if (data.valid) {
        if (clientId) {
          try {
            await fetch('/api/client/authenticate', {
              method: 'POST', headers: {'Content-Type': 'application/json'},
              credentials: 'include',
              body: JSON.stringify({
                client_id: clientId,
                license_key: data.license_key,
                username: data.username
              })
            });
          } catch (e) { console.warn('Client auth failed:', e); }
        }
        window.location.href = '/dashboard';
      } else {
        err.textContent = data.error || 'Login failed';
        btn.disabled = false; btn.textContent = 'Sign In';
      }
    } catch (e) {
      err.textContent = 'Connection error';
      btn.disabled = false; btn.textContent = 'Sign In';
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


# ═══════════════════════════════════════════════════════════
# HTML — DASHBOARD (FULLSCREEN + MONACO + SAVE)
# ═══════════════════════════════════════════════════════════

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Lumina — Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@500&display=swap" rel="stylesheet">
<link rel="stylesheet" data-name="vs/editor/editor.main" href="https://cdnjs.cloudflare.com/ajax/libs/monaco-editor/0.34.1/min/vs/editor/editor.main.css">
<script src="https://cdnjs.cloudflare.com/ajax/libs/monaco-editor/0.34.1/min/vs/loader.min.js"></script>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  html, body { width: 100%; height: 100%; overflow: hidden; }
  body { background: #0a0a0c; color: #e0e0e8; font-family: 'Inter', sans-serif; display: flex; flex-direction: column; }
  .topbar {
    height: 60px; flex-shrink: 0;
    display: flex; align-items: center; justify-content: space-between;
    padding: 0 28px; border-bottom: 1px solid #1a1a1d;
    background: #0a0a0c;
  }
  .brand { font-size: 16px; font-weight: 700; color: #f5f5f6; letter-spacing: -0.3px; }
  .brand span { color: #8ecbff; }
  .topbar-right { display: flex; align-items: center; gap: 16px; }
  .user-badge { font-size: 13px; color: rgba(230,230,232,0.55); font-family: 'JetBrains Mono', monospace; }
  .user-badge strong { color: #fff; }
  .logout-btn {
    padding: 8px 16px; background: transparent; border: 1px solid #252529;
    border-radius: 8px; color: #888890; font-size: 12px; font-weight: 600;
    cursor: pointer; transition: 0.15s;
  }
  .logout-btn:hover { color: #fff; border-color: #fff; }
  .main { flex: 1; display: flex; min-height: 0; }
  .sidebar {
    width: 300px; flex-shrink: 0; padding: 24px;
    border-right: 1px solid #1a1a1d; overflow-y: auto;
    display: flex; flex-direction: column; gap: 22px;
  }
  .section-label { font-size: 10px; font-weight: 600; color: rgba(230,230,232,0.4); text-transform: uppercase; letter-spacing: 0.12em; margin-bottom: 10px; }
  .stat-box { background: rgba(20,20,23,0.6); border: 1px solid #1a1a1d; border-radius: 10px; padding: 12px 14px; display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px; }
  .stat-label { font-size: 11px; color: rgba(230,230,232,0.55); font-weight: 500; }
  .stat-value { font-size: 12px; color: #8ecbff; font-family: 'JetBrains Mono', monospace; font-weight: 700; word-break: break-all; text-align: right; max-width: 160px; }
  .stat-value.blur { filter: blur(6px); user-select: none; cursor: default; transition: filter 0.2s; }
  .stat-value.blur:hover { filter: blur(0); user-select: text; cursor: text; }
  .client-status { display: flex; align-items: center; gap: 8px; background: rgba(20,20,23,0.6); border: 1px solid #1a1a1d; border-radius: 10px; padding: 12px 14px; }
  .dot { width: 8px; height: 8px; border-radius: 50%; background: #ff8080; box-shadow: 0 0 8px rgba(255,128,128,0.6); }
  .dot.connected { background: #8effb0; box-shadow: 0 0 8px rgba(142,255,176,0.6); }
  .client-status-label { font-size: 12px; color: rgba(230,230,232,0.7); font-weight: 500; }
  .editor-area { flex: 1; display: flex; flex-direction: column; min-width: 0; }
  #editor { flex: 1; width: 100%; }
  .editor-bar {
    height: 56px; flex-shrink: 0;
    display: flex; align-items: center; justify-content: space-between;
    padding: 0 20px; border-top: 1px solid #1a1a1d;
    background: #0d0d0f;
  }
  .editor-bar-left { display: flex; align-items: center; gap: 10px; }
  .editor-bar-label { font-size: 12px; color: rgba(230,230,232,0.45); font-family: 'JetBrains Mono', monospace; }
  .save-btn {
    padding: 10px 24px; background: #ffffff; color: #0a0a0c;
    border: none; border-radius: 8px; font-weight: 700; font-size: 13px;
    cursor: pointer; transition: 0.15s; font-family: inherit;
  }
  .save-btn:hover:not(:disabled) { transform: scale(1.03); }
  .save-btn:disabled { opacity: 0.4; cursor: not-allowed; }
  .save-btn.saved { background: #8effb0; }
  .toast {
    position: fixed; bottom: 24px; right: 24px;
    background: #1a1a1d; border: 1px solid #252529; color: #fff;
    padding: 14px 20px; border-radius: 10px; font-size: 13px;
    opacity: 0; transform: translateY(10px); transition: 0.25s;
    pointer-events: none; z-index: 1000;
  }
  .toast.show { opacity: 1; transform: translateY(0); }
</style>
</head>
<body>
  <div class="topbar">
    <div class="brand">Lumina<span>.</span> Dashboard</div>
    <div class="topbar-right">
      <div class="user-badge">Signed in as <strong id="tbUser">...</strong></div>
      <button class="logout-btn" onclick="logout()">Logout</button>
    </div>
  </div>

  <div class="main">
    <div class="sidebar">
      <div>
        <div class="section-label">Client Status</div>
        <div class="client-status">
          <div class="dot" id="clientDot"></div>
          <div class="client-status-label" id="clientLabel">Disconnected</div>
        </div>
      </div>

      <div>
        <div class="section-label">Account</div>
        <div class="stat-box"><span class="stat-label">Username</span><span class="stat-value" id="sUser">-</span></div>
        <div class="stat-box"><span class="stat-label">License</span><span class="stat-value blur" id="sLicense">-</span></div>
        <div class="stat-box"><span class="stat-label">Subscription</span><span class="stat-value" id="sSub">-</span></div>
      </div>

      <div>
        <div class="section-label">Hardware</div>
        <div class="stat-box"><span class="stat-label">HWID</span><span class="stat-value blur" id="sHwid">-</span></div>
        <div class="stat-box"><span class="stat-label">Resets</span><span class="stat-value" id="sResets">0</span></div>
      </div>

      <div>
        <div class="section-label">Tips</div>
        <div style="font-size: 11px; color: rgba(230,230,232,0.4); line-height: 1.6;">
          Edit the JSON on the right and hit <strong style="color:#fff;">Save Config</strong>.<br>
          The cheat polls every 2 seconds and picks up changes live.
        </div>
      </div>
    </div>

    <div class="editor-area">
      <div id="editor"></div>
      <div class="editor-bar">
        <div class="editor-bar-left">
          <span class="editor-bar-label">config.json</span>
        </div>
        <button class="save-btn" id="saveBtn" disabled>Save Config</button>
      </div>
    </div>
  </div>

  <div class="toast" id="toast"></div>

<script>
  let editor = null;
  let dirty = false;
  let currentUser = null;

  require.config({ paths: { 'vs': 'https://cdnjs.cloudflare.com/ajax/libs/monaco-editor/0.34.1/min/vs' }});
  require(['vs/editor/editor.main'], function () {
    monaco.editor.defineTheme('lumina', {
      base: 'vs-dark', inherit: true,
      rules: [
        { token: 'string', foreground: '8ecbff' },
        { token: 'number', foreground: 'c3e88d' },
        { token: 'keyword', foreground: 'c792ea' },
      ],
      colors: {
        'editor.background': '#0d0d0f',
        'editor.foreground': '#d4d4d8',
        'editorLineNumber.foreground': '#3a3a3f',
        'editorLineNumber.activeForeground': '#8ecbff',
        'editorCursor.foreground': '#8ecbff',
        'editor.selectionBackground': '#8ecbff30',
        'editor.lineHighlightBackground': '#ffffff05',
      }
    });
    editor = monaco.editor.create(document.getElementById('editor'), {
      value: '{}',
      language: 'json',
      theme: 'lumina',
      automaticLayout: true,
      fontSize: 14,
      minimap: { enabled: false },
      scrollBeyondLastLine: false,
      tabSize: 2,
    });
    editor.onDidChangeModelContent(() => {
      if (!dirty) { dirty = true; document.getElementById('saveBtn').disabled = false; }
    });
    loadAll();
  });

  function toast(msg, ok) {
    const t = document.getElementById('toast');
    t.textContent = msg;
    t.style.borderColor = ok ? '#2a4a2e' : '#4a2a2a';
    t.classList.add('show');
    setTimeout(() => t.classList.remove('show'), 2200);
  }

  async function loadAll() {
    // auth check
    const meRes = await fetch('/api/me', { credentials: 'include' });
    const me = await meRes.json();
    if (!me.authenticated) { window.location.href = '/'; return; }
    currentUser = me.username;
    document.getElementById('tbUser').textContent = me.username;
    document.getElementById('sUser').textContent = me.username;

    // dashboard data
    const dRes = await fetch('/api/dashboard', { credentials: 'include' });
    if (dRes.ok) {
      const d = await dRes.json();
      document.getElementById('sLicense').textContent = d.license_key;
      document.getElementById('sSub').textContent = d.subscription;
      document.getElementById('sHwid').textContent = d.hwid || 'Not bound';
      document.getElementById('sResets').textContent = d.hwid_resets;
    }

    // config
    const cRes = await fetch('/api/config', { credentials: 'include' });
    const cfg = await cRes.json();
    const pretty = JSON.stringify(cfg, null, 2);
    editor.setValue(pretty);
    dirty = false;
    document.getElementById('saveBtn').disabled = true;

    pollClientStatus();
    setInterval(pollClientStatus, 3000);
  }

  async function pollClientStatus() {
    if (!currentUser) return;
    try {
      const r = await fetch(`/api/client/status-by-user/${currentUser}`, { credentials: 'include' });
      if (!r.ok) return;
      const d = await r.json();
      const dot = document.getElementById('clientDot');
      const lbl = document.getElementById('clientLabel');
      if (d.connected) {
        dot.classList.add('connected');
        lbl.textContent = 'Connected';
      } else {
        dot.classList.remove('connected');
        lbl.textContent = 'Disconnected';
      }
    } catch (e) {}
  }

  document.getElementById('saveBtn').addEventListener('click', async () => {
    const btn = document.getElementById('saveBtn');
    let parsed;
    try { parsed = JSON.parse(editor.getValue()); }
    catch (e) { toast('Invalid JSON: ' + e.message, false); return; }
    btn.disabled = true;
    btn.textContent = 'Saving...';
    try {
      const r = await fetch('/api/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(parsed)
      });
      if (r.ok) {
        btn.textContent = 'Saved ✓';
        btn.classList.add('saved');
        toast('Config saved', true);
        dirty = false;
        setTimeout(() => { btn.textContent = 'Save Config'; btn.classList.remove('saved'); }, 1500);
      } else {
        btn.textContent = 'Save Config';
        btn.disabled = false;
        toast('Save failed', false);
      }
    } catch (e) {
      btn.textContent = 'Save Config';
      btn.disabled = false;
      toast('Connection error', false);
    }
  });

  async function logout() {
    await fetch('/api/logout', { method: 'POST' });
    window.location.href = '/';
  }
</script>
</body>
</html>"""


# ═══════════════════════════════════════════════════════════
# ROUTES
# ═══════════════════════════════════════════════════════════

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
        cur.execute("SELECT username FROM login_sessions WHERE session_id=%s AND license_key=%s AND expires_at > %s",
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
