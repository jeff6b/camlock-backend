# main.py — FastAPI backend with HTML served from separate files
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel
from typing import Optional
import psycopg2
import os
import json
import secrets
import pathlib
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
# HTML TEMPLATES
# ═══════════════════════════════════════════════════════════

BASE_DIR = pathlib.Path(__file__).parent

def load_html(filename: str) -> str:
    path = BASE_DIR / filename
    if not path.exists():
        return f"<h1 style='color:#fff;background:#000;padding:40px'>Missing: {filename}</h1>"
    return path.read_text(encoding="utf-8")

LOGIN_HTML = load_html("login.html")
DASHBOARD_HTML = load_html("dashboard.html")

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
# BOOTSTRAP
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
        print("[BOOTSTRAP] Test account created! user=light pass=light", flush=True)
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
# API — USER
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

        if data.client_id:
            cur.execute("SELECT hwid FROM clients WHERE client_id=%s", (data.client_id,))
            crow = cur.fetchone()
            if not crow:
                db.close()
                return {"valid": False, "error": "Client not registered"}
            client_hwid = crow[0]

            if bound_hwid is None:
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
# API — CLIENT
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


@app.get("/api/client/status-by-user/{username}")
async def client_status_by_user(request: Request, username: str):
    license_key = request.cookies.get("license_key")
    if not license_key:
        raise HTTPException(status_code=401, detail="Not authenticated")
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("""SELECT last_ping FROM clients
                       WHERE license_key=%s AND authenticated=1
                       ORDER BY last_ping DESC LIMIT 1""", (license_key,))
        row = cur.fetchone()
        db.close()
        if not row or not row[0]:
            return {"connected": False}
        try:
            last = datetime.fromisoformat(row[0])
            connected = (datetime.now() - last).total_seconds() < 15
        except:
            connected = False
        return {"connected": connected}
    except Exception as e:
        db.close()
        return {"connected": False, "error": str(e)}


# ═══════════════════════════════════════════════════════════
# KEEPALIVE
# ═══════════════════════════════════════════════════════════

@app.get("/api/keepalive")
def keepalive():
    return {"status": "alive", "timestamp": datetime.now().isoformat()}


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
