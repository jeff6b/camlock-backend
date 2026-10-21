# main.py — backend for username/password accounts + community configs
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
        cur.execute("""CREATE TABLE IF NOT EXISTS user_accounts (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            license_key TEXT,
            email TEXT,
            discord_id TEXT,
            hwid TEXT,
            hwid_resets INTEGER DEFAULT 0,
            active INTEGER DEFAULT 1,
            created_at TEXT NOT NULL,
            last_login TEXT)""")
        cur.execute("""CREATE TABLE IF NOT EXISTS login_sessions (
            session_id TEXT PRIMARY KEY, username TEXT NOT NULL,
            license_key TEXT, created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL, ip_address TEXT)""")
        cur.execute("""CREATE TABLE IF NOT EXISTS saved_configs (
            id SERIAL PRIMARY KEY, username TEXT NOT NULL,
            config_name TEXT NOT NULL, config_data TEXT NOT NULL,
            created_at TEXT NOT NULL, UNIQUE(username, config_name))""")
        cur.execute("""CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY, config TEXT NOT NULL)""")
        cur.execute("""CREATE TABLE IF NOT EXISTS clients (
            client_id TEXT PRIMARY KEY, hwid TEXT NOT NULL,
            session_token TEXT, license_key TEXT, username TEXT,
            created_at TEXT NOT NULL, last_ping TEXT,
            authenticated INTEGER DEFAULT 0)""")

        # ── COMMUNITY CONFIGS ──
        cur.execute("""CREATE TABLE IF NOT EXISTS community_configs (
            id SERIAL PRIMARY KEY,
            author TEXT NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            config_data TEXT NOT NULL,
            likes INTEGER DEFAULT 0,
            created_at TEXT NOT NULL
        )""")
        cur.execute("""CREATE TABLE IF NOT EXISTS community_likes (
            id SERIAL PRIMARY KEY,
            config_id INTEGER NOT NULL REFERENCES community_configs(id) ON DELETE CASCADE,
            username TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(config_id, username)
        )""")
        cur.execute("""CREATE INDEX IF NOT EXISTS idx_community_configs_created
            ON community_configs(created_at DESC)""")
        cur.execute("""CREATE INDEX IF NOT EXISTS idx_community_likes_config
            ON community_likes(config_id)""")
        cur.execute("""CREATE INDEX IF NOT EXISTS idx_community_likes_user
            ON community_likes(username)""")

        db.commit()
        db.close()
        print("DB initialized", flush=True)
    except Exception as e:
        print(f"DB init error: {e}", flush=True)

def migrate_db():
    try:
        db = get_db()
        cur = db.cursor()
        migrations = [
            ("user_accounts", "discord_id", "TEXT"),
            ("user_accounts", "hwid", "TEXT"),
            ("user_accounts", "hwid_resets", "INTEGER DEFAULT 0"),
            ("user_accounts", "active", "INTEGER DEFAULT 1"),
            ("user_accounts", "email", "TEXT"),
            ("user_accounts", "last_login", "TEXT"),
            ("saved_configs", "username", "TEXT"),
        ]
        for table, col, definition in migrations:
            try:
                cur.execute(f'ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {col} {definition}')
            except Exception as e:
                print(f"[MIGRATE] {table}.{col} skip: {e}", flush=True)
        try:
            cur.execute("ALTER TABLE user_accounts ALTER COLUMN license_key DROP NOT NULL")
        except Exception:
            pass
        try:
            cur.execute("ALTER TABLE login_sessions ALTER COLUMN license_key DROP NOT NULL")
        except Exception:
            pass
        db.commit()
        db.close()
        print("[MIGRATE] Done", flush=True)
    except Exception as e:
        print(f"[MIGRATE] Error: {e}", flush=True)

init_db()
migrate_db()

# ═══════════════════════════════════════════════════════════
# DEFAULT CONFIG
# ═══════════════════════════════════════════════════════════

DEFAULT_CONFIG = {
    "Enabled": True, "Keybind": "Q", "KeybindMode": "toggle", "WebviewKeybind": "F8",
    "PredictTarget": True, "PredictionX": 0.10, "PredictionY": 0.10,
    "ClosestPoint": True, "FixedPart": "Head", "Smoothness": 0.35,
    "MaxStudsCheck": True, "MaxStuds": 500,
    "UnlockOnDeath": True, "SelfDeathCheck": True,
    "StickyMode": True,
    "CurveType": "quadratic",
    "StabilizerDeadzone": 3.0, "ReactionDelay": 0.12,
    "Streamproof": False,
    "CurveP1": {"x": 180, "y": 200}, "CurveP2": {"x": 420, "y": 80},
}

# ═══════════════════════════════════════════════════════════
# MODELS
# ═══════════════════════════════════════════════════════════

class UserLogin(BaseModel):
    username: str
    password: str
    client_id: Optional[str] = None

class ClientRegister(BaseModel):
    client_id: str
    hwid: str

class ClientAuthStatus(BaseModel):
    client_id: str
    session_token: Optional[str] = None

class ClientAuthenticate(BaseModel):
    client_id: str
    license_key: Optional[str] = None
    username: str

# ═══════════════════════════════════════════════════════════
# API — USER LOGIN
# ═══════════════════════════════════════════════════════════

@app.post("/api/user-login")
async def user_login(request: Request, data: UserLogin):
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("""
            SELECT username, password_hash, hwid, hwid_resets, active
            FROM user_accounts WHERE username = %s
        """, (data.username,))
        result = cur.fetchone()
        if not result:
            db.close()
            return {"valid": False, "error": "Invalid username or password"}

        username, password_hash, bound_hwid, hwid_resets, active = result

        if active == 0:
            db.close()
            return {"valid": False, "error": "Account inactive"}

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
                cur.execute("UPDATE user_accounts SET hwid=%s WHERE username=%s",
                            (client_hwid, username))
                print(f"[HWID] Bound {client_hwid[:12]}... to {username}", flush=True)
            elif bound_hwid != client_hwid:
                db.close()
                return {"valid": False, "error": "HWID mismatch — account bound to another PC"}

        cur.execute("UPDATE user_accounts SET last_login=%s WHERE username=%s",
                    (datetime.now().isoformat(), username))

        session_id = secrets.token_hex(16)
        now = datetime.now().isoformat()
        exp = (datetime.now() + timedelta(days=30)).isoformat()
        cur.execute("""
            INSERT INTO login_sessions
                (session_id, username, license_key, created_at, expires_at, ip_address)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (session_id, username, "", now, exp, request.client.host))
        db.commit()
        db.close()

        resp = JSONResponse({
            "valid": True, "message": "Login successful",
            "username": username, "license_key": "",
            "subscription": "Lifetime", "hwid_resets": hwid_resets or 0
        })
        resp.set_cookie("session_id", session_id, httponly=True, max_age=2592000, samesite="lax")
        resp.set_cookie("username", username, httponly=True, max_age=2592000, samesite="lax")
        return resp
    except Exception as e:
        db.close()
        return {"valid": False, "error": f"Server error: {str(e)}"}


@app.get("/api/me")
async def get_current_user(request: Request):
    username = request.cookies.get("username")
    session_id = request.cookies.get("session_id")
    if not username or not session_id:
        return {"authenticated": False}
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("SELECT username FROM login_sessions WHERE session_id=%s AND expires_at > %s",
                    (session_id, datetime.now().isoformat()))
        result = cur.fetchone()
        db.close()
        if result:
            return {"authenticated": True, "username": result[0], "license_key": ""}
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
    username = request.cookies.get("username")
    if not username:
        raise HTTPException(status_code=401, detail="Not authenticated")
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("SELECT username, hwid, hwid_resets, created_at, active FROM user_accounts WHERE username=%s",
                    (username,))
        result = cur.fetchone()
        db.close()
        if not result:
            raise HTTPException(status_code=404, detail="Not found")
        u, hwid, resets, created, active = result
        return {
            "username": u, "hwid": hwid, "hwid_resets": resets or 0,
            "created_at": created, "subscription": "Lifetime",
            "license_key": "", "active": active,
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
    username = request.cookies.get("username")
    if not username:
        raise HTTPException(status_code=401, detail="Not authenticated")
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("SELECT config FROM settings WHERE key=%s", (username,))
        result = cur.fetchone()
        if not result:
            cur.execute("INSERT INTO settings (key, config) VALUES (%s, %s)",
                        (username, json.dumps(DEFAULT_CONFIG)))
            db.commit()
            db.close()
            return DEFAULT_CONFIG
        db.close()
        try:
            return json.loads(result[0])
        except:
            return DEFAULT_CONFIG
    except Exception as e:
        db.close()
        return DEFAULT_CONFIG


@app.post("/api/config")
async def set_config(request: Request, data: dict):
    username = request.cookies.get("username")
    if not username:
        raise HTTPException(status_code=401, detail="Not authenticated")
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("INSERT INTO settings (key, config) VALUES (%s, %s) ON CONFLICT (key) DO UPDATE SET config = EXCLUDED.config",
                    (username, json.dumps(data)))
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
        cur.execute("""SELECT authenticated, username, hwid
                       FROM clients WHERE client_id=%s AND session_token=%s""",
                    (data.client_id, data.session_token))
        result = cur.fetchone()
        if not result:
            db.close()
            return {"authenticated": False, "error": "Invalid credentials"}
        authenticated, username, hwid = result
        cur.execute("UPDATE clients SET last_ping=%s WHERE client_id=%s",
                    (datetime.now().isoformat(), data.client_id))
        db.commit()
        db.close()
        return {"authenticated": bool(authenticated), "license_key": "",
                "username": username, "hwid": hwid}
    except Exception as e:
        db.close()
        return {"authenticated": False, "error": str(e)}


@app.post("/api/client/authenticate")
async def client_authenticate(data: ClientAuthenticate):
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("SELECT hwid FROM clients WHERE client_id=%s", (data.client_id,))
        crow = cur.fetchone()
        if not crow:
            db.close()
            raise HTTPException(status_code=404, detail="Client not registered")
        client_hwid = crow[0]

        cur.execute("""UPDATE clients
                       SET authenticated=1, username=%s, last_ping=%s
                       WHERE client_id=%s""",
                    (data.username, datetime.now().isoformat(), data.client_id))

        cur.execute("SELECT hwid FROM user_accounts WHERE username=%s", (data.username,))
        urow = cur.fetchone()
        if urow:
            current_hwid = urow[0]
            if not current_hwid:
                cur.execute("UPDATE user_accounts SET hwid=%s WHERE username=%s",
                            (client_hwid, data.username))
                print(f"[HWID] Bound {client_hwid[:12]}... to {data.username}", flush=True)
            elif current_hwid != client_hwid:
                db.close()
                raise HTTPException(status_code=403, detail="HWID mismatch — account bound to another PC")

        db.commit()
        db.close()
        return {"success": True}
    except HTTPException:
        raise
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
        cur.execute("SELECT username FROM clients WHERE client_id=%s AND session_token=%s AND authenticated=1",
                    (client_id, session_token))
        result = cur.fetchone()
        if not result:
            db.close()
            raise HTTPException(status_code=401, detail="Not authenticated")
        username = result[0]
        cur.execute("SELECT config FROM settings WHERE key=%s", (username,))
        cfg = cur.fetchone()
        db.close()
        if not cfg:
            return DEFAULT_CONFIG
        try:
            return json.loads(cfg[0])
        except:
            return DEFAULT_CONFIG
    except HTTPException:
        raise
    except Exception as e:
        db.close()
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/client/shutdown")
async def client_shutdown(request: Request):
    username = request.cookies.get("username")
    if not username:
        raise HTTPException(status_code=401, detail="Not authenticated")
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("UPDATE clients SET session_token = NULL WHERE username = %s", (username,))
        db.commit()
        db.close()
        return {"ok": True}
    except Exception as e:
        db.close()
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/client/status-by-user/{username}")
async def client_status_by_user(request: Request, username: str):
    if not request.cookies.get("username"):
        raise HTTPException(status_code=401, detail="Not authenticated")
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("""SELECT last_ping FROM clients
                       WHERE username=%s AND authenticated=1
                       ORDER BY last_ping DESC LIMIT 1""", (username,))
        row = cur.fetchone()
        db.close()
        if not row or not row[0]:
            return {"connected": False}
        try:
            last = datetime.fromisoformat(row[0])
            return {"connected": (datetime.now() - last).total_seconds() < 15}
        except:
            return {"connected": False}
    except Exception as e:
        db.close()
        return {"connected": False, "error": str(e)}

# ═══════════════════════════════════════════════════════════
# API — COMMUNITY CONFIGS
# ═══════════════════════════════════════════════════════════

@app.get("/api/community/configs")
async def list_community_configs(request: Request):
    username = request.cookies.get("username")
    if not username:
        raise HTTPException(status_code=401, detail="Not authenticated")
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("""
            SELECT id, author, name, description, config_data, likes, created_at
            FROM community_configs
            ORDER BY created_at DESC
        """)
        rows = cur.fetchall()
        cur.execute("SELECT config_id FROM community_likes WHERE username=%s", (username,))
        liked_ids = [r[0] for r in cur.fetchall()]
        db.close()
        configs = []
        for row in rows:
            cid, author, name, desc, cfg_json, likes, created = row
            try:
                cfg = json.loads(cfg_json)
            except:
                cfg = {}
            configs.append({
                "id": cid,
                "author": author,
                "name": name,
                "description": desc or "",
                "config_data": cfg,
                "likes": likes or 0,
                "created_at": created
            })
        return {"configs": configs, "liked_ids": liked_ids}
    except Exception as e:
        try:
            db.close()
        except:
            pass
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/community/configs")
async def create_community_config(request: Request, data: dict):
    username = request.cookies.get("username")
    if not username:
        raise HTTPException(status_code=401, detail="Not authenticated")
    name = (data.get("name") or "").strip()
    desc = (data.get("description") or "").strip()
    cfg = data.get("config_data")
    if not name:
        raise HTTPException(status_code=400, detail="Name required")
    if not cfg or not isinstance(cfg, dict):
        raise HTTPException(status_code=400, detail="Config data required")
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("""
            INSERT INTO community_configs (author, name, description, config_data, likes, created_at)
            VALUES (%s, %s, %s, %s, 0, %s)
            RETURNING id
        """, (username, name[:60], desc[:500], json.dumps(cfg), datetime.now().isoformat()))
        new_id = cur.fetchone()[0]
        db.commit()
        db.close()
        return {"success": True, "id": new_id}
    except Exception as e:
        try:
            db.close()
        except:
            pass
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/community/configs/{config_id}/like")
async def toggle_community_like(request: Request, config_id: int):
    username = request.cookies.get("username")
    if not username:
        raise HTTPException(status_code=401, detail="Not authenticated")
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("SELECT id FROM community_likes WHERE config_id=%s AND username=%s",
                    (config_id, username))
        existing = cur.fetchone()
        if existing:
            cur.execute("DELETE FROM community_likes WHERE id=%s", (existing[0],))
            cur.execute("UPDATE community_configs SET likes = GREATEST(likes - 1, 0) WHERE id=%s",
                        (config_id,))
            liked = False
        else:
            cur.execute("""
                INSERT INTO community_likes (config_id, username, created_at)
                VALUES (%s, %s, %s)
            """, (config_id, username, datetime.now().isoformat()))
            cur.execute("UPDATE community_configs SET likes = likes + 1 WHERE id=%s",
                        (config_id,))
            liked = True
        cur.execute("SELECT likes FROM community_configs WHERE id=%s", (config_id,))
        row = cur.fetchone()
        likes = row[0] if row else 0
        db.commit()
        db.close()
        return {"success": True, "liked": liked, "likes": likes}
    except Exception as e:
        try:
            db.close()
        except:
            pass
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/auto-login", response_class=HTMLResponse)
async def auto_login(request: Request, client: str = None):
    """Single-account build: auto-login via authenticated client_id."""
    if not client:
        return RedirectResponse(url="/")
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("SELECT username FROM clients WHERE client_id=%s AND authenticated=1", (client,))
        row = cur.fetchone()
        if not row:
            db.close()
            return RedirectResponse(url="/")
        username = row[0]
        cur.execute("SELECT username FROM user_accounts WHERE username=%s", (username,))
        urow = cur.fetchone()
        if not urow:
            db.close()
            return RedirectResponse(url="/")
        username = urow[0]
        session_id = secrets.token_hex(16)
        now = datetime.now().isoformat()
        exp = (datetime.now() + timedelta(days=30)).isoformat()
        cur.execute("""
            INSERT INTO login_sessions
                (session_id, username, license_key, created_at, expires_at, ip_address)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (session_id, username, "", now, exp, request.client.host))
        db.commit()
        db.close()
    except Exception:
        try:
            db.close()
        except:
            pass
        return RedirectResponse(url="/")
    resp = RedirectResponse(url="/dashboard", status_code=302)
    resp.set_cookie("session_id", session_id, httponly=True, max_age=2592000, samesite="lax")
    resp.set_cookie("username", username, httponly=True, max_age=2592000, samesite="lax")
    return resp


@app.post("/api/community/configs/save-mine")
async def save_community_to_mine(request: Request, data: dict):
    username = request.cookies.get("username")
    if not username:
        raise HTTPException(status_code=401, detail="Not authenticated")
    cid = data.get("community_config_id")
    if not cid:
        raise HTTPException(status_code=400, detail="Missing config id")
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("SELECT name, config_data FROM community_configs WHERE id=%s", (cid,))
        row = cur.fetchone()
        if not row:
            db.close()
            raise HTTPException(status_code=404, detail="Config not found")
        base_name, cfg_json = row
        name = base_name
        suffix = 1
        while True:
            cur.execute("SELECT id FROM saved_configs WHERE username=%s AND config_name=%s",
                        (username, name))
            if not cur.fetchone():
                break
            name = f"{base_name} ({suffix})"
            suffix += 1
        cur.execute("""
            INSERT INTO saved_configs (username, config_name, config_data, created_at)
            VALUES (%s, %s, %s, %s)
        """, (username, name, cfg_json, datetime.now().isoformat()))
        db.commit()
        db.close()
        return {"success": True, "name": name}
    except HTTPException:
        raise
    except Exception as e:
        try:
            db.close()
        except:
            pass
        raise HTTPException(status_code=500, detail=str(e))

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
    username = request.cookies.get("username")
    session_id = request.cookies.get("session_id")
    if not username or not session_id:
        return RedirectResponse(url="/")
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("SELECT username FROM login_sessions WHERE session_id=%s AND expires_at > %s",
                    (session_id, datetime.now().isoformat()))
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
