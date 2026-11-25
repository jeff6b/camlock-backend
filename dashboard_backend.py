# dashboard_backend.py — Vile dashboard backend (standalone)
# Serves dashboard.html at / and provides license+token login, config,
# saved configs, community configs, /api/me, /api/logout.
# Uses the same Postgres schema as main.py (licenses, login_sessions,
# redeem_tokens, settings, saved_configs, community_configs, community_likes).
# Run:  uvicorn dashboard_backend:app --host 0.0.0.0 --port 8000

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

app = FastAPI(title="Vile Dashboard")

BASE_DIR = pathlib.Path(__file__).parent
DASHBOARD_HTML_PATH = BASE_DIR / "dashboard.html"


def load_dashboard() -> str:
    if DASHBOARD_HTML_PATH.exists():
        return DASHBOARD_HTML_PATH.read_text(encoding="utf-8")
    return "<h1 style='color:#fff;background:#000;padding:40px'>Missing: dashboard.html</h1>"


DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://neondb_owner:npg_S7hoDMeaw2cQ@ep-wandering-dream-ah21egpt-pooler.c-3.us-east-1.aws.neon.tech/neondb?sslmode=require",
)


def get_db():
    return psycopg2.connect(DATABASE_URL)


def _now() -> str:
    return datetime.now().isoformat()


def _expired(exp_iso: Optional[str]) -> bool:
    if not exp_iso or exp_iso == "never":
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


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class LicenseLogin(BaseModel):
    license_key: str
    token: str
    fingerprint: Optional[str] = None


# ---------------------------------------------------------------------------
# Login / me / logout
# ---------------------------------------------------------------------------

@app.post("/api/login")
async def login(request: Request, data: LicenseLogin):
    key = (data.license_key or "").strip()
    tok = (data.token or "").strip()
    if not key or not tok:
        raise HTTPException(status_code=400, detail="License key and token required")

    fp = request.cookies.get("vile_fp") or (data.fingerprint or "").strip()
    if not fp:
        fp = secrets.token_hex(16)

    db = get_db()
    cur = db.cursor()
    try:
        cur.execute(
            "SELECT license_key, hwid, hwid_resets, active, expires_at, discord_id FROM licenses WHERE license_key=%s",
            (key,),
        )
        row = cur.fetchone()
        if not row:
            db.close()
            raise HTTPException(status_code=401, detail="Invalid license key")
        lic_key, bound_hwid, hwid_resets, active, exp, lic_discord = row
        if not active:
            db.close()
            raise HTTPException(status_code=403, detail="License inactive")
        if _expired(exp):
            db.close()
            raise HTTPException(status_code=403, detail="License expired")

        cur.execute(
            "SELECT discord_id FROM redeem_tokens WHERE token=%s AND license_key=%s",
            (tok, lic_key),
        )
        trow = cur.fetchone()
        if not trow:
            db.close()
            raise HTTPException(status_code=401, detail="Invalid token for this license")
        tok_discord = trow[0]
        if lic_discord and tok_discord and lic_discord != tok_discord:
            db.close()
            raise HTTPException(status_code=403, detail="Token does not belong to this license")

        if not bound_hwid:
            cur.execute("UPDATE licenses SET hwid=%s, last_login=%s WHERE license_key=%s",
                        (fp, _now(), lic_key))
        elif bound_hwid != fp:
            db.close()
            raise HTTPException(
                status_code=403,
                detail="This license is locked to another browser. Ask admin to reset HWID.",
            )
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
        resp.set_cookie("vile_fp", fp, httponly=True, max_age=60 * 60 * 24 * 365, samesite="lax")
        return resp
    except HTTPException:
        raise
    except Exception as e:
        try: db.close()
        except: pass
        raise HTTPException(status_code=500, detail=f"login failed: {e}")


@app.get("/api/me")
async def me(request: Request):
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
async def list_saved(request: Request):
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
        out = []
        for row in rows:
            cid, name, data_json, vis, created = row
            try: data = json.loads(data_json) if data_json else {}
            except Exception: data = {}
            out.append({"id": cid, "name": name, "data": data,
                        "visibility": vis or "private", "created_at": created})
        return {"configs": out}
    except HTTPException:
        try: db.close()
        except: pass
        raise
    except Exception as e:
        try: db.close()
        except: pass
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/configs")
async def create_saved(request: Request, data: dict):
    name = (data.get("name") or "").strip()
    cfg = data.get("data")
    vis = (data.get("visibility") or "private").strip().lower()
    if vis not in ("private", "public"): vis = "private"
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
async def delete_saved(request: Request, config_id: int):
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
async def set_visibility(request: Request, config_id: int, data: dict):
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
# Community configs
# ---------------------------------------------------------------------------

@app.get("/api/community/configs")
async def list_community(request: Request):
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
        liked = [r[0] for r in cur.fetchall()]
        db.close()
        out = []
        for row in rows:
            cid, author, name, desc, cfg_json, likes, created = row
            try: cfg = json.loads(cfg_json) if cfg_json else {}
            except Exception: cfg = {}
            out.append({"id": cid, "author": author, "name": name,
                        "description": desc or "", "config_data": cfg,
                        "likes": likes or 0, "created_at": created})
        return {"configs": out, "liked_ids": liked}
    except HTTPException:
        try: db.close()
        except: pass
        raise
    except Exception as e:
        try: db.close()
        except: pass
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/community/configs")
async def create_community(request: Request, data: dict):
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
async def toggle_like(request: Request, config_id: int):
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
                "INSERT INTO community_likes (config_id, author_license, created_at) VALUES (%s, %s, %s)",
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
# Serve dashboard
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    return HTMLResponse(load_dashboard())


@app.get("/api/keepalive")
def keepalive():
    return {"status": "alive", "timestamp": datetime.now().isoformat()}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
