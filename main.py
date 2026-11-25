# main.py — Vile backend
# License-key auth + HWID. Redeem-token flow. No pairing/launcher/username.

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from typing import Optional
import psycopg2
import os
import json
import secrets
import pathlib
from datetime import datetime, timedelta

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

BASE_DIR = pathlib.Path(__file__).parent


def load_html(filename: str) -> str:
    path = BASE_DIR / filename
    if not path.exists():
        return f"<h1 style='color:#fff;background:#000;padding:40px'>Missing: {filename}</h1>"
    return path.read_text(encoding="utf-8")


CONNECT_HTML = load_html("vile-dashboard.html")

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://neondb_owner:npg_S7hoDMeaw2cQ@ep-wandering-dream-ah21egpt-pooler.c-3.us-east-1.aws.neon.tech/neondb?sslmode=require",
)

BOT_SHARED_SECRET = os.environ.get("BOT_SHARED_SECRET", "change-me-please")


def get_db():
    return psycopg2.connect(DATABASE_URL)


def init_db():
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute("""CREATE TABLE IF NOT EXISTS licenses (
            license_key TEXT PRIMARY KEY,
            discord_id TEXT,
            hwid TEXT,
            hwid_resets INTEGER DEFAULT 0,
            active INTEGER DEFAULT 1,
            expires_at TEXT,
            created_at TEXT NOT NULL,
            last_login TEXT)""")
        cur.execute("""CREATE TABLE IF NOT EXISTS login_sessions (
            session_id TEXT PRIMARY KEY,
            license_key TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            ip_address TEXT)""")
        cur.execute("""CREATE TABLE IF NOT EXISTS redeem_tokens (
            token TEXT PRIMARY KEY,
            discord_id TEXT NOT NULL,
            license_key TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            redeemed INTEGER DEFAULT 0,
            redeemed_at TEXT)""")
        cur.execute("""CREATE TABLE IF NOT EXISTS saved_configs (
            id SERIAL PRIMARY KEY,
            license_key TEXT NOT NULL,
            config_name TEXT NOT NULL,
            config_data TEXT NOT NULL,
            visibility TEXT DEFAULT 'private',
            created_at TEXT NOT NULL,
            UNIQUE(license_key, config_name))""")
        cur.execute("""CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            config TEXT NOT NULL)""")
        cur.execute("""CREATE TABLE IF NOT EXISTS clients (
            client_id TEXT PRIMARY KEY,
            hwid TEXT NOT NULL,
            session_token TEXT,
            license_key TEXT,
            created_at TEXT NOT NULL,
            last_ping TEXT,
            authenticated INTEGER DEFAULT 0)""")
        cur.execute("""CREATE TABLE IF NOT EXISTS community_configs (
            id SERIAL PRIMARY KEY,
            author TEXT NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            config_data TEXT NOT NULL,
            likes INTEGER DEFAULT 0,
            created_at TEXT NOT NULL)""")
        cur.execute("""CREATE TABLE IF NOT EXISTS community_likes (
            id SERIAL PRIMARY KEY,
            config_id INTEGER NOT NULL REFERENCES community_configs(id) ON DELETE CASCADE,
            author_license TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(config_id, author_license))""")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_redeem_tokens_discord ON redeem_tokens(discord_id)")
        db.commit()
        db.close()
        print("DB initialized", flush=True)
    except Exception as e:
        print(f"DB init error: {e}", flush=True)


init_db()


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class LicenseLogin(BaseModel):
    license_key: str
    hwid: str

class ClientRegister(BaseModel):
    client_id: str
    hwid: str

class ClientAuthStatus(BaseModel):
    client_id: str
    session_token: Optional[str] = None

class ClientAuthenticate(BaseModel):
    client_id: str
    license_key: str

class _BotCreateKeyReq(BaseModel):
    discord_id: str
    days: int = 30

class _BotDiscReq(BaseModel):
    discord_id: str

class _BotRedeemReq(BaseModel):
    discord_id: str
    token: str

class _BotResetReq(BaseModel):
    license_key: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now() -> str:
    return datetime.now().isoformat()

def _expired(exp_iso: Optional[str]) -> bool:
    if not exp_iso:
        return False
    try:
        return datetime.now() > datetime.fromisoformat(exp_iso)
    except Exception:
        return False

def _resolve_session(cur, session_id: Optional[str]):
    if not session_id:
        return None
    cur.execute("SELECT license_key, expires_at FROM login_sessions WHERE session_id=%s", (session_id,))
    row = cur.fetchone()
    if not row:
        return None
    lic_key, exp = row
    if _expired(exp):
        cur.execute("DELETE FROM login_sessions WHERE session_id=%s", (session_id,))
        return None
    return lic_key

def _require_license(cur, request: Request) -> str:
    session_id = request.cookies.get("session_id")
    lic_key = _resolve_session(cur, session_id)
    if not lic_key:
        raise HTTPException(status_code=401, detail="Not authenticated")
    cur.execute("SELECT active, expires_at FROM licenses WHERE license_key=%s", (lic_key,))
    row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="License no longer exists")
    active, exp = row
    if not active:
        raise HTTPException(status_code=403, detail="License inactive")
    if _expired(exp):
        raise HTTPException(status_code=403, detail="License expired")
    return lic_key

def _check_bot_auth(request: Request):
    auth = request.headers.get("x-bot-secret", "")
    if not auth or auth != BOT_SHARED_SECRET:
        raise HTTPException(status_code=401, detail="Invalid bot secret")


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

@app.post("/api/login")
async def login(request: Request, data: LicenseLogin):
    key = (data.license_key or "").strip()
    hwid = (data.hwid or "").strip()
    if not key or not hwid:
        raise HTTPException(status_code=400, detail="License key and HWID required")

    db = get_db()
    cur = db.cursor()
    try:
        cur.execute(
            "SELECT license_key, hwid, hwid_resets, active, expires_at FROM licenses WHERE license_key=%s",
            (key,),
        )
        row = cur.fetchone()
        if not row:
            db.close()
            raise HTTPException(status_code=401, detail="Invalid license key")
        lic_key, bound_hwid, hwid_resets, active, exp = row
        if not active:
            db.close()
            raise HTTPException(status_code=403, detail="License inactive")
        if _expired(exp):
            db.close()
            raise HTTPException(status_code=403, detail="License expired")

        if not bound_hwid:
            cur.execute("UPDATE licenses SET hwid=%s, last_login=%s WHERE license_key=%s",
                        (hwid, _now(), lic_key))
        elif bound_hwid != hwid:
            db.close()
            raise HTTPException(status_code=403, detail="HWID mismatch — license bound to another PC")
        else:
            cur.execute("UPDATE licenses SET last_login=%s WHERE license_key=%s", (_now(), lic_key))

        session_id = secrets.token_hex(16)
        exp_iso = (datetime.now() + timedelta(days=30)).isoformat()
        cur.execute(
            """INSERT INTO login_sessions (session_id, license_key, created_at, expires_at, ip_address)
               VALUES (%s, %s, %s, %s, %s)""",
            (session_id, lic_key, _now(), exp_iso, request.client.host if request.client else None),
        )
        db.commit()
        db.close()

        resp = JSONResponse({
            "valid": True,
            "license_key": lic_key,
            "expires_at": exp,
            "hwid_resets": hwid_resets or 0,
        })
        resp.set_cookie("session_id", session_id, httponly=True, max_age=2592000, samesite="lax")
        resp.set_cookie("license_key", lic_key, httponly=True, max_age=2592000, samesite="lax")
        return resp
    except HTTPException:
        raise
    except Exception as e:
        try: db.close()
        except: pass
        raise HTTPException(status_code=500, detail=f"login failed: {e}")


@app.get("/api/me")
async def get_current_user(request: Request):
    session_id = request.cookies.get("session_id")
    if not session_id:
        return {"authenticated": False}
    db = get_db()
    cur = db.cursor()
    try:
        lic_key = _resolve_session(cur, session_id)
        if not lic_key:
            db.close()
            return {"authenticated": False}
        cur.execute(
            "SELECT license_key, hwid, hwid_resets, active, expires_at, created_at FROM licenses WHERE license_key=%s",
            (lic_key,),
        )
        row = cur.fetchone()
        db.close()
        if not row:
            return {"authenticated": False}
        lic_key, hwid, resets, active, exp, created = row
        return {
            "authenticated": True,
            "license_key": lic_key,
            "hwid": hwid,
            "hwid_resets": resets or 0,
            "expires_at": exp,
            "created_at": created,
            "active": active,
        }
    except Exception:
        try: db.close()
        except: pass
        return {"authenticated": False}


@app.post("/api/logout")
async def logout(request: Request):
    session_id = request.cookies.get("session_id")
    if session_id:
        try:
            db = get_db()
            cur = db.cursor()
            cur.execute("DELETE FROM login_sessions WHERE session_id=%s", (session_id,))
            db.commit()
            db.close()
        except Exception:
            pass
    resp = JSONResponse({"success": True})
    resp.delete_cookie("session_id")
    resp.delete_cookie("license_key")
    return resp


# ---------------------------------------------------------------------------
# Config (the exact JSON shape)
# ---------------------------------------------------------------------------

@app.get("/api/config")
async def get_config(request: Request):
    db = get_db()
    cur = db.cursor()
    try:
        lic_key = _require_license(cur, request)
        cur.execute("SELECT config FROM settings WHERE key=%s", (lic_key,))
        row = cur.fetchone()
        db.close()
        if not row:
            return {}
        try:
            return json.loads(row[0])
        except Exception:
            return {}
    except HTTPException:
        try: db.close()
        except: pass
        raise
    except Exception:
        try: db.close()
        except: pass
        return {}


@app.post("/api/config")
async def set_config(request: Request, data: dict):
    db = get_db()
    cur = db.cursor()
    try:
        lic_key = _require_license(cur, request)
        cur.execute(
            """INSERT INTO settings (key, config) VALUES (%s, %s)
               ON CONFLICT (key) DO UPDATE SET config = EXCLUDED.config""",
            (lic_key, json.dumps(data)),
        )
        db.commit()
        db.close()
        return {"status": "ok"}
    except HTTPException:
        try: db.close()
        except: pass
        raise
    except Exception as e:
        try: db.close()
        except: pass
        raise HTTPException(status_code=500, detail=str(e))


# ---------------------------------------------------------------------------
# Saved configs
# ---------------------------------------------------------------------------

@app.get("/api/configs")
async def list_saved_configs(request: Request):
    db = get_db()
    cur = db.cursor()
    try:
        lic_key = _require_license(cur, request)
        cur.execute(
            """SELECT id, config_name, config_data, visibility, created_at
               FROM saved_configs WHERE license_key=%s ORDER BY created_at DESC""",
            (lic_key,),
        )
        rows = cur.fetchall()
        db.close()
        configs = []
        for row in rows:
            cid, name, data_json, vis, created = row
            try:
                data = json.loads(data_json) if data_json else {}
            except Exception:
                data = {}
            configs.append({
                "id": cid, "name": name, "data": data,
                "visibility": vis or "private", "created_at": created,
            })
        return {"configs": configs}
    except HTTPException:
        try: db.close()
        except: pass
        raise
    except Exception as e:
        try: db.close()
        except: pass
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/configs")
async def create_saved_config(request: Request, data: dict):
    name = (data.get("name") or "").strip()
    cfg = data.get("data")
    vis = (data.get("visibility") or "private").strip().lower()
    if vis not in ("private", "public"):
        vis = "private"
    if not name:
        raise HTTPException(status_code=400, detail="Name required")
    if not isinstance(cfg, dict):
        raise HTTPException(status_code=400, detail="Config required")
    db = get_db()
    cur = db.cursor()
    try:
        lic_key = _require_license(cur, request)
        cur.execute(
            """INSERT INTO saved_configs (license_key, config_name, config_data, visibility, created_at)
               VALUES (%s, %s, %s, %s, %s)
               ON CONFLICT (license_key, config_name) DO UPDATE
                 SET config_data = EXCLUDED.config_data,
                     visibility = EXCLUDED.visibility
               RETURNING id""",
            (lic_key, name[:60], json.dumps(cfg), vis, _now()),
        )
        new_id = cur.fetchone()[0]
        db.commit()
        db.close()
        return {"success": True, "id": new_id}
    except HTTPException:
        try: db.close()
        except: pass
        raise
    except Exception as e:
        try: db.close()
        except: pass
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/configs/{config_id}")
async def delete_saved_config(request: Request, config_id: int):
    db = get_db()
    cur = db.cursor()
    try:
        lic_key = _require_license(cur, request)
        cur.execute("DELETE FROM saved_configs WHERE id=%s AND license_key=%s", (config_id, lic_key))
        db.commit()
        db.close()
        return {"success": True}
    except HTTPException:
        try: db.close()
        except: pass
        raise
    except Exception as e:
        try: db.close()
        except: pass
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/configs/{config_id}/visibility")
async def set_config_visibility(request: Request, config_id: int, data: dict):
    vis = (data.get("visibility") or "private").strip().lower()
    if vis not in ("private", "public"):
        raise HTTPException(status_code=400, detail="Invalid visibility")
    db = get_db()
    cur = db.cursor()
    try:
        lic_key = _require_license(cur, request)
        cur.execute("UPDATE saved_configs SET visibility=%s WHERE id=%s AND license_key=%s",
                    (vis, config_id, lic_key))
        db.commit()
        db.close()
        return {"success": True}
    except HTTPException:
        try: db.close()
        except: pass
        raise
    except Exception as e:
        try: db.close()
        except: pass
        raise HTTPException(status_code=500, detail=str(e))


# ---------------------------------------------------------------------------
# Clients
# ---------------------------------------------------------------------------

@app.post("/api/client/register")
async def register_client(data: ClientRegister):
    db = get_db()
    cur = db.cursor()
    try:
        session_token = secrets.token_hex(32)
        now = _now()
        cur.execute("SELECT client_id FROM clients WHERE client_id=%s", (data.client_id,))
        if cur.fetchone():
            cur.execute(
                """UPDATE clients SET hwid=%s, session_token=%s, last_ping=%s, authenticated=0
                   WHERE client_id=%s""",
                (data.hwid, session_token, now, data.client_id),
            )
        else:
            cur.execute(
                """INSERT INTO clients (client_id, hwid, session_token, created_at, last_ping, authenticated)
                   VALUES (%s, %s, %s, %s, %s, 0)""",
                (data.client_id, data.hwid, session_token, now, now),
            )
        db.commit()
        db.close()
        return {"success": True, "session_token": session_token,
                "client_id": data.client_id, "authenticated": False}
    except Exception as e:
        try: db.close()
        except: pass
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/client/auth-status")
async def client_auth_status(data: ClientAuthStatus):
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute(
            """SELECT authenticated, license_key, hwid
               FROM clients WHERE client_id=%s AND session_token=%s""",
            (data.client_id, data.session_token),
        )
        result = cur.fetchone()
        if not result:
            db.close()
            return {"authenticated": False, "error": "Invalid credentials"}
        authenticated, lic_key, hwid = result
        cur.execute("UPDATE clients SET last_ping=%s WHERE client_id=%s", (_now(), data.client_id))
        db.commit()
        db.close()
        return {"authenticated": bool(authenticated), "license_key": lic_key, "hwid": hwid}
    except Exception as e:
        try: db.close()
        except: pass
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

        lic_key = (data.license_key or "").strip()
        if not lic_key:
            db.close()
            raise HTTPException(status_code=400, detail="License key required")

        cur.execute("SELECT hwid, active, expires_at FROM licenses WHERE license_key=%s", (lic_key,))
        lrow = cur.fetchone()
        if not lrow:
            db.close()
            raise HTTPException(status_code=401, detail="Invalid license key")
        bound_hwid, active, exp = lrow
        if not active:
            db.close()
            raise HTTPException(status_code=403, detail="License inactive")
        if _expired(exp):
            db.close()
            raise HTTPException(status_code=403, detail="License expired")
        if bound_hwid and bound_hwid != client_hwid:
            db.close()
            raise HTTPException(status_code=403, detail="HWID mismatch")
        if not bound_hwid:
            cur.execute("UPDATE licenses SET hwid=%s WHERE license_key=%s", (client_hwid, lic_key))

        cur.execute(
            """UPDATE clients SET authenticated=1, license_key=%s, last_ping=%s
               WHERE client_id=%s""",
            (lic_key, _now(), data.client_id),
        )
        db.commit()
        db.close()
        return {"success": True}
    except HTTPException:
        raise
    except Exception as e:
        try: db.close()
        except: pass
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
        cur.execute(
            "SELECT license_key FROM clients WHERE client_id=%s AND session_token=%s AND authenticated=1",
            (client_id, session_token),
        )
        result = cur.fetchone()
        if not result:
            db.close()
            raise HTTPException(status_code=401, detail="Not authenticated")
        lic_key = result[0]
        cur.execute("SELECT config FROM settings WHERE key=%s", (lic_key,))
        cfg = cur.fetchone()
        db.close()
        if not cfg:
            return {}
        try:
            return json.loads(cfg[0])
        except Exception:
            return {}
    except HTTPException:
        raise
    except Exception as e:
        try: db.close()
        except: pass
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/client/config/save")
async def client_config_save(data: dict):
    client_id = data.get("client_id")
    session_token = data.get("session_token")
    config = data.get("config")
    if not client_id or not session_token or not isinstance(config, dict):
        raise HTTPException(status_code=400, detail="Missing credentials or config")
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute(
            "SELECT license_key FROM clients WHERE client_id=%s AND session_token=%s AND authenticated=1",
            (client_id, session_token),
        )
        result = cur.fetchone()
        if not result:
            db.close()
            raise HTTPException(status_code=401, detail="Not authenticated")
        lic_key = result[0]
        cur.execute(
            """INSERT INTO settings (key, config) VALUES (%s, %s)
               ON CONFLICT (key) DO UPDATE SET config = EXCLUDED.config""",
            (lic_key, json.dumps(config)),
        )
        db.commit()
        db.close()
        return {"success": True}
    except HTTPException:
        raise
    except Exception as e:
        try: db.close()
        except: pass
        raise HTTPException(status_code=500, detail=str(e))


# ---------------------------------------------------------------------------
# Community configs
# ---------------------------------------------------------------------------

@app.get("/api/community/configs")
async def list_community_configs(request: Request):
    db = get_db()
    cur = db.cursor()
    try:
        lic_key = _require_license(cur, request)
        cur.execute(
            """SELECT id, author, name, description, config_data, likes, created_at
               FROM community_configs ORDER BY created_at DESC""",
        )
        rows = cur.fetchall()
        cur.execute("SELECT config_id FROM community_likes WHERE author_license=%s", (lic_key,))
        liked_ids = [r[0] for r in cur.fetchall()]
        db.close()
        configs = []
        for row in rows:
            cid, author, name, desc, cfg_json, likes, created = row
            try:
                cfg = json.loads(cfg_json) if cfg_json else {}
            except Exception:
                cfg = {}
            configs.append({
                "id": cid, "author": author, "name": name,
                "description": desc or "", "config_data": cfg,
                "likes": likes or 0, "created_at": created,
            })
        return {"configs": configs, "liked_ids": liked_ids}
    except HTTPException:
        try: db.close()
        except: pass
        raise
    except Exception as e:
        try: db.close()
        except: pass
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/community/configs")
async def create_community_config(request: Request, data: dict):
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
        lic_key = _require_license(cur, request)
        author = f"{lic_key[:6]}…{lic_key[-4:]}" if len(lic_key) > 12 else lic_key
        cur.execute(
            """INSERT INTO community_configs (author, name, description, config_data, likes, created_at)
               VALUES (%s, %s, %s, %s, 0, %s) RETURNING id""",
            (author, name[:60], desc[:500], json.dumps(cfg), _now()),
        )
        new_id = cur.fetchone()[0]
        db.commit()
        db.close()
        return {"success": True, "id": new_id}
    except HTTPException:
        try: db.close()
        except: pass
        raise
    except Exception as e:
        try: db.close()
        except: pass
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/community/configs/{config_id}/like")
async def toggle_community_like(request: Request, config_id: int):
    db = get_db()
    cur = db.cursor()
    try:
        lic_key = _require_license(cur, request)
        cur.execute("SELECT id FROM community_likes WHERE config_id=%s AND author_license=%s",
                    (config_id, lic_key))
        existing = cur.fetchone()
        if existing:
            cur.execute("DELETE FROM community_likes WHERE id=%s", (existing[0],))
            cur.execute("UPDATE community_configs SET likes = GREATEST(likes - 1, 0) WHERE id=%s",
                        (config_id,))
            liked = False
        else:
            cur.execute(
                """INSERT INTO community_likes (config_id, author_license, created_at)
                   VALUES (%s, %s, %s)""",
                (config_id, lic_key, _now()),
            )
            cur.execute("UPDATE community_configs SET likes = likes + 1 WHERE id=%s", (config_id,))
            liked = True
        cur.execute("SELECT likes FROM community_configs WHERE id=%s", (config_id,))
        row = cur.fetchone()
        likes = row[0] if row else 0
        db.commit()
        db.close()
        return {"success": True, "liked": liked, "likes": likes}
    except HTTPException:
        try: db.close()
        except: pass
        raise
    except Exception as e:
        try: db.close()
        except: pass
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/community/configs/save-mine")
async def save_community_to_mine(request: Request, data: dict):
    cid = data.get("community_config_id")
    if not cid:
        raise HTTPException(status_code=400, detail="Missing config id")
    db = get_db()
    cur = db.cursor()
    try:
        lic_key = _require_license(cur, request)
        cur.execute("SELECT name, config_data FROM community_configs WHERE id=%s", (cid,))
        row = cur.fetchone()
        if not row:
            db.close()
            raise HTTPException(status_code=404, detail="Config not found")
        base_name, cfg_json = row
        name = base_name
        suffix = 1
        while True:
            cur.execute("SELECT id FROM saved_configs WHERE license_key=%s AND config_name=%s",
                        (lic_key, name))
            if not cur.fetchone():
                break
            name = f"{base_name} ({suffix})"
            suffix += 1
        cur.execute(
            """INSERT INTO saved_configs (license_key, config_name, config_data, visibility, created_at)
               VALUES (%s, %s, %s, %s, %s)""",
            (lic_key, name, cfg_json, "private", _now()),
        )
        db.commit()
        db.close()
        return {"success": True, "name": name}
    except HTTPException:
        raise
    except Exception as e:
        try: db.close()
        except: pass
        raise HTTPException(status_code=500, detail=str(e))


# ---------------------------------------------------------------------------
# Discord bot endpoints
# ---------------------------------------------------------------------------

@app.post("/api/bot/create-key")
async def bot_create_key(request: Request, data: _BotCreateKeyReq):
    """
    Creates license + one-time redeem token, both bound to discord_id.
    Returns license_key AND token. Admin should show both or let bot DM user.
    """
    _check_bot_auth(request)
    now = datetime.now()
    exp = (now + timedelta(days=max(1, int(data.days)))).isoformat()
    license_key = "VILE-" + "-".join(secrets.token_hex(2).upper() for _ in range(4))
    token = secrets.token_urlsafe(9)
    token_exp = (now + timedelta(minutes=10)).isoformat()

    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("SELECT license_key FROM licenses WHERE discord_id=%s", (data.discord_id,))
        if cur.fetchone():
            db.close()
            raise HTTPException(status_code=409, detail="This Discord already has a license")
        cur.execute(
            """INSERT INTO licenses (license_key, discord_id, active, expires_at, created_at)
               VALUES (%s, %s, 1, %s, %s)""",
            (license_key, data.discord_id, exp, now.isoformat()),
        )
        cur.execute(
            """INSERT INTO redeem_tokens (token, discord_id, license_key, created_at, expires_at, redeemed)
               VALUES (%s, %s, %s, %s, %s, 0)""",
            (token, data.discord_id, license_key, now.isoformat(), token_exp),
        )
        db.commit()
        db.close()
        return {
            "ok": True,
            "license_key": license_key,
            "token": token,
            "token_expires_at": token_exp,
            "license_expires_at": exp,
            "days": data.days,
        }
    except HTTPException:
        raise
    except Exception as e:
        try: db.close()
        except: pass
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/bot/redeem-token")
async def bot_redeem_token(request: Request, data: _BotRedeemReq):
    """
    Called by the bot when the user DMs it their token. Returns their license key once.
    """
    _check_bot_auth(request)
    token = (data.token or "").strip()
    if not token:
        raise HTTPException(status_code=400, detail="Token required")

    db = get_db()
    cur = db.cursor()
    try:
        cur.execute(
            "SELECT discord_id, license_key, expires_at, redeemed FROM redeem_tokens WHERE token=%s",
            (token,),
        )
        row = cur.fetchone()
        if not row:
            db.close()
            raise HTTPException(status_code=404, detail="Invalid token")
        owner_discord, license_key, expires_at, redeemed = row
        if redeemed:
            db.close()
            raise HTTPException(status_code=409, detail="Token already redeemed")
        if owner_discord != data.discord_id:
            db.close()
            raise HTTPException(status_code=403, detail="Token belongs to a different Discord account")
        if _expired(expires_at):
            db.close()
            raise HTTPException(status_code=410, detail="Token expired")

        cur.execute("SELECT expires_at FROM licenses WHERE license_key=%s", (license_key,))
        lrow = cur.fetchone()
        license_exp = lrow[0] if lrow else None

        cur.execute("UPDATE redeem_tokens SET redeemed=1, redeemed_at=%s WHERE token=%s",
                    (_now(), token))
        db.commit()
        db.close()
        return {
            "ok": True,
            "license_key": license_key,
            "license_expires_at": license_exp,
        }
    except HTTPException:
        raise
    except Exception as e:
        try: db.close()
        except: pass
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/bot/delete-account")
async def bot_delete_account(request: Request, data: _BotDiscReq):
    _check_bot_auth(request)
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("SELECT license_key FROM licenses WHERE discord_id=%s", (data.discord_id,))
        row = cur.fetchone()
        if not row:
            db.close()
            raise HTTPException(status_code=404, detail="No license linked to this Discord")
        lic_key = row[0]
        cur.execute("DELETE FROM licenses WHERE license_key=%s", (lic_key,))
        cur.execute("DELETE FROM redeem_tokens WHERE discord_id=%s", (data.discord_id,))
        cur.execute("DELETE FROM settings WHERE key=%s", (lic_key,))
        cur.execute("DELETE FROM saved_configs WHERE license_key=%s", (lic_key,))
        cur.execute("DELETE FROM login_sessions WHERE license_key=%s", (lic_key,))
        cur.execute("DELETE FROM clients WHERE license_key=%s", (lic_key,))
        cur.execute("DELETE FROM community_likes WHERE author_license=%s", (lic_key,))
        db.commit()
        db.close()
        return {"ok": True, "license_key": lic_key}
    except HTTPException:
        raise
    except Exception as e:
        try: db.close()
        except: pass
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/bot/reset-hwid")
async def bot_reset_hwid(request: Request, data: _BotResetReq):
    _check_bot_auth(request)
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("SELECT license_key FROM licenses WHERE license_key=%s", (data.license_key,))
        if not cur.fetchone():
            db.close()
            raise HTTPException(status_code=404, detail="License not found")
        cur.execute(
            "UPDATE licenses SET hwid=NULL, hwid_resets=COALESCE(hwid_resets,0)+1 WHERE license_key=%s",
            (data.license_key,),
        )
        db.commit()
        db.close()
        return {"ok": True, "license_key": data.license_key}
    except HTTPException:
        raise
    except Exception as e:
        try: db.close()
        except: pass
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/bot/lookup/{discord_id}")
async def bot_lookup(request: Request, discord_id: str):
    _check_bot_auth(request)
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute(
            """SELECT license_key, hwid, hwid_resets, active, expires_at, created_at
               FROM licenses WHERE discord_id=%s""",
            (discord_id,),
        )
        row = cur.fetchone()
        db.close()
        if not row:
            raise HTTPException(status_code=404, detail="Not linked")
        return {
            "license_key": row[0], "hwid": row[1], "hwid_resets": row[2] or 0,
            "active": bool(row[3]), "expires_at": row[4], "created_at": row[5],
        }
    except HTTPException:
        raise
    except Exception as e:
        try: db.close()
        except: pass
        raise HTTPException(status_code=500, detail=str(e))


# ---------------------------------------------------------------------------
# HTML routes
# ---------------------------------------------------------------------------

_NOT_FOUND_HTML = (
    "<!DOCTYPE html><html><body style='background:#0a0a0c;margin:0;"
    "display:flex;align-items:center;justify-content:center;height:100vh;"
    "font-family:sans-serif;color:#666'>"
    "<div style='text-align:center'><h1 style='margin:0;font-size:28px'>404</h1>"
    "<p style='margin:8px 0 0;font-size:13px'>Not found</p></div>"
    "</body></html>"
)


@app.get("/", response_class=HTMLResponse)
async def serve_root():
    return HTMLResponse(_NOT_FOUND_HTML, status_code=404)


@app.get("/connect", response_class=HTMLResponse)
async def serve_connect():
    return HTMLResponse(content=CONNECT_HTML)


@app.get("/dashboard", response_class=HTMLResponse)
async def serve_dashboard():
    return HTMLResponse(_NOT_FOUND_HTML, status_code=404)


@app.get("/api/keepalive")
def keepalive():
    return {"status": "alive", "timestamp": datetime.now().isoformat()}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
