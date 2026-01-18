from fastapi import FastAPI, Path, HTTPException, Depends, Header, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import json
import random
import os
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Annotated  # ← Annotated is here

app = FastAPI(title="Axion Backend")

# CORS - permissive for development (restrict origins in production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ======================
#   DATABASE SETUP
# ======================
DATABASE_URL = os.environ.get("DATABASE_URL")
USE_POSTGRES = False

if DATABASE_URL and DATABASE_URL.startswith("postgresql"):
    try:
        import psycopg2
        from psycopg2.extras import RealDictCursor
        USE_POSTGRES = True
    except ImportError:
        print("PostgreSQL requested but psycopg2 not installed → using SQLite")

if not USE_POSTGRES:
    import sqlite3

def get_db():
    if USE_POSTGRES:
        return psycopg2.connect(DATABASE_URL, connect_timeout=10)
    else:
        return sqlite3.connect(os.environ.get("DB_PATH", "database.db"))

def execute_query(query, params=None, fetch_one=False, fetch_all=False):
    db = get_db()
    try:
        cur = db.cursor()
        if params:
            cur.execute(query, params)
        else:
            cur.execute(query)
        
        if fetch_one:
            result = cur.fetchone()
            db.close()
            return result
        elif fetch_all:
            result = cur.fetchall()
            db.close()
            return result
        else:
            db.commit()
            db.close()
            return True
    except Exception as e:
        db.close()
        raise e

def init_db():
    db = get_db()
    cur = db.cursor()
    
    if USE_POSTGRES:
        cur.execute("""CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY, config TEXT)""")
        cur.execute("""CREATE TABLE IF NOT EXISTS keys (
            key TEXT PRIMARY KEY, duration TEXT NOT NULL, created_at TEXT NOT NULL,
            expires_at TEXT, redeemed_at TEXT, redeemed_by TEXT, hwid TEXT,
            active INTEGER DEFAULT 0, created_by TEXT)""")
        cur.execute("""CREATE TABLE IF NOT EXISTS saved_configs (
            id SERIAL PRIMARY KEY, license_key TEXT NOT NULL,
            config_name TEXT NOT NULL, config_data TEXT NOT NULL,
            created_at TEXT NOT NULL, UNIQUE(license_key, config_name))""")
        cur.execute("""CREATE TABLE IF NOT EXISTS public_configs (
            id SERIAL PRIMARY KEY, config_name TEXT NOT NULL,
            author_name TEXT NOT NULL, game_name TEXT NOT NULL,
            description TEXT, config_data TEXT NOT NULL,
            license_key TEXT NOT NULL, created_at TEXT NOT NULL,
            downloads INTEGER DEFAULT 0)""")
    else:
        cur.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, config TEXT)")
        cur.execute("""CREATE TABLE IF NOT EXISTS keys (
            key TEXT PRIMARY KEY, duration TEXT NOT NULL, created_at TEXT NOT NULL,
            expires_at TEXT, redeemed_at TEXT, redeemed_by TEXT, hwid TEXT,
            active INTEGER DEFAULT 0, created_by TEXT)""")
        cur.execute("""CREATE TABLE IF NOT EXISTS saved_configs (
            id INTEGER PRIMARY KEY AUTOINCREMENT, license_key TEXT NOT NULL,
            config_name TEXT NOT NULL, config_data TEXT NOT NULL,
            created_at TEXT NOT NULL, UNIQUE(license_key, config_name))""")
        cur.execute("""CREATE TABLE IF NOT EXISTS public_configs (
            id INTEGER PRIMARY KEY AUTOINCREMENT, config_name TEXT NOT NULL,
            author_name TEXT NOT NULL, game_name TEXT NOT NULL,
            description TEXT, config_data TEXT NOT NULL,
            license_key TEXT NOT NULL, created_at TEXT NOT NULL,
            downloads INTEGER DEFAULT 0)""")
    
    db.commit()
    db.close()

init_db()

# ======================
#   LICENSE KEY VALIDATION DEPENDENCY
# ======================
async def get_valid_license_key(
    authorization: Annotated[str | None, Header()] = None
) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Missing or invalid Authorization header. Use: Bearer YOUR_LICENSE_KEY"
        )
    
    license_key = authorization.replace("Bearer ", "").strip()
    
    db = get_db()
    try:
        cur = db.cursor()
        cur.execute(
            "SELECT key, redeemed_by, active, expires_at FROM keys WHERE key = ?",
            (license_key,)
        )
        result = cur.fetchone()
        
        if not result:
            raise HTTPException(401, "Invalid license key")
        
        key, redeemed_by, active, expires_at = result
        
        if not redeemed_by:
            raise HTTPException(403, "License not redeemed yet")
        
        if not active:
            raise HTTPException(403, "License is inactive")
        
        if expires_at:
            try:
                exp_date = datetime.fromisoformat(expires_at)
                if exp_date < datetime.now():
                    raise HTTPException(403, "License has expired")
            except:
                pass  # ignore malformed date
        
        return license_key
    finally:
        db.close()

# ======================
#   MODELS
# ======================
class LicenseLogin(BaseModel):
    license_key: str

class PublicConfig(BaseModel):
    config_name: str
    author_name: str
    game_name: str
    description: str
    config_data: dict

class SavedConfig(BaseModel):
    config_name: str
    config_data: dict

class KeyCreate(BaseModel):
    duration: str
    created_by: str

class KeyRedeem(BaseModel):
    key: str
    user_id: str

class KeyValidate(BaseModel):
    key: str
    hwid: str

# ======================
#   ENDPOINTS - COMPLETE SET
# ======================

@app.get("/health")
async def health_check():
    return {"status": "ok", "message": "Backend is running"}

@app.get("/auth/me")
async def get_current_user(license_key: str = Depends(get_valid_license_key)):
    return {"license_key": license_key, "authenticated": True}

@app.get("/api/public-configs")
async def get_public_configs(license_key: str = Depends(get_valid_license_key)):
    db = get_db()
    try:
        cur = db.cursor()
        cur.execute("""
            SELECT id, config_name, author_name, game_name, description, 
                   config_data, license_key, created_at, downloads 
            FROM public_configs ORDER BY created_at DESC
        """)
        results = cur.fetchall()
        
        configs = []
        for r in results:
            configs.append({
                "id": r[0],
                "config_name": r[1],
                "author_name": r[2],
                "game_name": r[3],
                "description": r[4],
                "config_data": json.loads(r[5]),
                "license_key": r[6][:8] + "...",  # masked
                "created_at": r[7],
                "downloads": r[8]
            })
        return {"configs": configs}
    finally:
        db.close()

@app.post("/api/public-configs/create")
async def create_public_config(
    data: PublicConfig,
    license_key: str = Depends(get_valid_license_key)
):
    db = get_db()
    try:
        cur = db.cursor()
        cur.execute("""
            INSERT INTO public_configs 
            (config_name, author_name, game_name, description, config_data, license_key, created_at, downloads)
            VALUES (?, ?, ?, ?, ?, ?, ?, 0)
        """, (
            data.config_name, data.author_name, data.game_name,
            data.description, json.dumps(data.config_data),
            license_key, datetime.now().isoformat()
        ))
        db.commit()
        return {"success": True, "message": "Config published successfully"}
    except Exception as e:
        raise HTTPException(500, str(e))
    finally:
        db.close()

@app.post("/api/public-configs/{config_id}/download")
async def increment_download(config_id: int):
    # Public - anyone can increment download count
    db = get_db()
    try:
        cur = db.cursor()
        cur.execute("UPDATE public_configs SET downloads = downloads + 1 WHERE id = ?", (config_id,))
        db.commit()
        return {"success": True}
    finally:
        db.close()

@app.get("/api/my-configs")
async def get_my_saved_configs(license_key: str = Depends(get_valid_license_key)):
    db = get_db()
    try:
        cur = db.cursor()
        cur.execute("""
            SELECT config_name, config_data FROM saved_configs 
            WHERE license_key = ? ORDER BY created_at DESC
        """, (license_key,))
        configs = cur.fetchall()
        return {
            "configs": [
                {"name": c[0], "data": json.loads(c[1])} for c in configs
            ]
        }
    finally:
        db.close()

# ── Per-key Config Storage ──────────────────────────────
DEFAULT_CONFIG = {
    "triggerbot": {
        "Enabled": True, "Keybind": "Right Mouse", "Delay": 0.05, "MaxStuds": 120,
        "StudCheck": True, "DeathCheck": True, "KnifeCheck": True, "TeamCheck": True,
        "TargetMode": False, "TargetKeybind": "Middle Mouse", "Prediction": 0.1, "FOV": 25
    },
    "camlock": {
        "Enabled": True, "Keybind": "Q", "FOV": 280.0, "SmoothX": 14.0, "SmoothY": 14.0,
        "EnableSmoothing": True, "EasingStyle": "Linear", "Prediction": 0.14, "EnablePrediction": True,
        "MaxStuds": 120.0, "UnlockOnDeath": True, "SelfDeathCheck": True, "BodyPart": "Head",
        "ClosestPart": False, "ScaleToggle": True, "Scale": 1.0
    }
}

@app.get("/api/config/{key}")
async def get_config(key: str):
    db = get_db()
    try:
        cur = db.cursor()
        if USE_POSTGRES:
            cur.execute("INSERT INTO settings (key, config) VALUES (%s, %s) ON CONFLICT (key) DO NOTHING",
                       (key, json.dumps(DEFAULT_CONFIG)))
        else:
            cur.execute("INSERT OR IGNORE INTO settings (key, config) VALUES (?, ?)",
                       (key, json.dumps(DEFAULT_CONFIG)))
        db.commit()
        
        cur.execute("SELECT config FROM settings WHERE key = ?", (key,))
        result = cur.fetchone()
        return json.loads(result[0]) if result else DEFAULT_CONFIG
    finally:
        db.close()

@app.post("/api/config/{key}")
async def set_config(key: str, data: Dict):
    db = get_db()
    try:
        cur = db.cursor()
        if USE_POSTGRES:
            cur.execute("INSERT INTO settings(key, config) VALUES(%s, %s) ON CONFLICT (key) DO UPDATE SET config=excluded.config",
                       (key, json.dumps(data)))
        else:
            cur.execute("INSERT OR REPLACE INTO settings(key, config) VALUES(?, ?)",
                       (key, json.dumps(data)))
        db.commit()
        return {"status": "ok"}
    finally:
        db.close()

# ── Saved Configs Management ────────────────────────────
@app.get("/api/configs/{key}/list")
async def list_saved_configs(key: str):
    db = get_db()
    try:
        cur = db.cursor()
        cur.execute("""
            SELECT config_name, created_at FROM saved_configs 
            WHERE license_key = ? ORDER BY created_at DESC
        """, (key,))
        results = cur.fetchall()
        return {"configs": [{"name": r[0], "created_at": r[1]} for r in results]}
    finally:
        db.close()

@app.post("/api/configs/{key}/save")
async def save_config(key: str, data: SavedConfig):
    db = get_db()
    try:
        cur = db.cursor()
        cur.execute("""
            INSERT INTO saved_configs (license_key, config_name, config_data, created_at)
            VALUES (?, ?, ?, ?)
        """, (key, data.config_name, json.dumps(data.config_data), datetime.now().isoformat()))
        db.commit()
        return {"status": "saved"}
    except:
        cur.execute("""
            UPDATE saved_configs SET config_data = ?, created_at = ?
            WHERE license_key = ? AND config_name = ?
        """, (json.dumps(data.config_data), datetime.now().isoformat(), key, data.config_name))
        db.commit()
        return {"status": "updated"}
    finally:
        db.close()

@app.get("/api/configs/{key}/load/{config_name}")
async def load_saved_config(key: str, config_name: str):
    db = get_db()
    try:
        cur = db.cursor()
        cur.execute("""
            SELECT config_data FROM saved_configs 
            WHERE license_key = ? AND config_name = ?
        """, (key, config_name))
        result = cur.fetchone()
        if not result:
            raise HTTPException(404, "Config not found")
        return json.loads(result[0])
    finally:
        db.close()

@app.delete("/api/configs/{key}/delete/{config_name}")
async def delete_saved_config(key: str, config_name: str):
    db = get_db()
    try:
        cur = db.cursor()
        cur.execute("""
            DELETE FROM saved_configs 
            WHERE license_key = ? AND config_name = ?
        """, (key, config_name))
        db.commit()
        return {"status": "deleted"}
    finally:
        db.close()

@app.post("/api/configs/{key}/rename")
async def rename_saved_config(key: str, data: Dict):
    old_name = data.get("old_name")
    new_name = data.get("new_name")
    if not old_name or not new_name:
        raise HTTPException(400, "Missing old_name or new_name")
    
    db = get_db()
    try:
        cur = db.cursor()
        cur.execute("""
            UPDATE saved_configs SET config_name = ?
            WHERE license_key = ? AND config_name = ?
        """, (new_name, key, old_name))
        db.commit()
        return {"status": "renamed"}
    finally:
        db.close()

# ── Key Management ──────────────────────────────────────
def generate_key():
    return '-'.join([''.join([str(random.randint(0, 9)) for _ in range(4)]) for _ in range(4)])

def get_expiry_date(duration: str, from_date: Optional[datetime] = None) -> Optional[str]:
    base = from_date or datetime.now()
    if duration == "weekly":
        return (base + timedelta(weeks=1)).isoformat()
    elif duration == "monthly":
        return (base + timedelta(days=30)).isoformat()
    elif duration == "3monthly":
        return (base + timedelta(days=90)).isoformat()
    return None

@app.post("/api/keys/create")
async def create_key(data: KeyCreate):
    key = generate_key()
    db = get_db()
    try:
        cur = db.cursor()
        cur.execute(
            "INSERT INTO keys (key, duration, created_at, active, created_by) VALUES (?, ?, ?, 0, ?)",
            (key, data.duration, datetime.now().isoformat(), data.created_by)
        )
        db.commit()
        return {"key": key, "duration": data.duration, "status": "awaiting_redemption"}
    except Exception as e:
        raise HTTPException(500, str(e))
    finally:
        db.close()

@app.post("/api/keys/redeem")
async def redeem_key(data: KeyRedeem):
    db = get_db()
    try:
        cur = db.cursor()
        cur.execute("SELECT * FROM keys WHERE key = ?", (data.key,))
        result = cur.fetchone()
        if not result:
            raise HTTPException(404, "Invalid key")
        
        key, duration, created_at, expires_at, redeemed_at, redeemed_by, hwid, active, created_by = result
        
        if redeemed_by:
            raise HTTPException(400, "Key already redeemed by another user")
        
        expiry = get_expiry_date(duration)
        now = datetime.now().isoformat()
        cur.execute(
            "UPDATE keys SET redeemed_at = ?, redeemed_by = ?, expires_at = ?, active = 1 WHERE key = ?",
            (now, data.user_id, expiry, data.key)
        )
        db.commit()
        return {
            "success": True,
            "key": data.key,
            "duration": duration,
            "expires_at": expiry,
            "message": "Key redeemed successfully"
        }
    finally:
        db.close()

@app.delete("/api/users/{user_id}/license")
async def delete_user_license(user_id: str):
    db = get_db()
    try:
        cur = db.cursor()
        cur.execute("SELECT key FROM keys WHERE redeemed_by = ?", (user_id,))
        result = cur.fetchone()
        if not result:
            raise HTTPException(404, "No license found for this user")
        key = result[0]
        cur.execute("DELETE FROM keys WHERE redeemed_by = ?", (user_id,))
        db.commit()
        return {"status": "deleted", "key": key, "user_id": user_id}
    finally:
        db.close()

@app.get("/api/users/{user_id}/license")
async def get_user_license(user_id: str):
    db = get_db()
    try:
        cur = db.cursor()
        cur.execute("SELECT * FROM keys WHERE redeemed_by = ?", (user_id,))
        result = cur.fetchone()
        if not result:
            return {"active": False, "message": "No license found"}
        
        key, duration, created_at, expires_at, redeemed_at, redeemed_by, hwid, active, created_by = result
        
        is_expired = False
        if expires_at:
            try:
                is_expired = datetime.now() > datetime.fromisoformat(expires_at)
            except:
                pass
        
        return {
            "active": active and not is_expired,
            "expired": is_expired,
            "key": key,
            "duration": duration,
            "expires_at": expires_at,
            "redeemed_at": redeemed_at,
            "hwid": hwid
        }
    finally:
        db.close()

@app.post("/api/users/{user_id}/reset-hwid")
async def reset_user_hwid(user_id: str):
    db = get_db()
    try:
        cur = db.cursor()
        cur.execute("SELECT hwid FROM keys WHERE redeemed_by = ?", (user_id,))
        result = cur.fetchone()
        if not result:
            raise HTTPException(404, "No license found for this user")
        old_hwid = result[0]
        cur.execute("UPDATE keys SET hwid = NULL WHERE redeemed_by = ?", (user_id,))
        db.commit()
        return {"status": "reset", "user_id": user_id, "old_hwid": old_hwid}
    finally:
        db.close()

@app.get("/api/keys/{key}")
async def get_key_info(key: str):
    db = get_db()
    try:
        cur = db.cursor()
        cur.execute("SELECT * FROM keys WHERE key = ?", (key,))
        result = cur.fetchone()
        if not result:
            raise HTTPException(404, "Key not found")
        return {
            "key": result[0],
            "duration": result[1],
            "created_at": result[2],
            "expires_at": result[3],
            "redeemed_at": result[4],
            "redeemed_by": result[5],
            "hwid": result[6],
            "active": result[7],
            "created_by": result[8]
        }
    finally:
        db.close()

@app.get("/api/keys/list")
async def list_keys():
    db = get_db()
    try:
        cur = db.cursor()
        cur.execute("SELECT * FROM keys ORDER BY created_at DESC")
        results = cur.fetchall()
        keys = []
        for r in results:
            keys.append({
                "key": r[0],
                "duration": r[1],
                "created_at": r[2],
                "expires_at": r[3],
                "redeemed_at": r[4],
                "redeemed_by": r[5],
                "hwid": r[6],
                "active": r[7],
                "created_by": r[8]
            })
        return {"keys": keys}
    finally:
        db.close()

@app.post("/api/validate")
async def validate_key(data: KeyValidate):
    db = get_db()
    try:
        cur = db.cursor()
        cur.execute("SELECT * FROM keys WHERE key = ?", (data.key,))
        result = cur.fetchone()
        if not result:
            return {"valid": False, "error": "Invalid key"}, 401
        
        key, duration, created_at, expires_at, redeemed_at, redeemed_by, hwid, active, created_by = result
        
        if not redeemed_by:
            return {"valid": False, "error": "Key not redeemed yet"}, 401
        
        if expires_at and datetime.now() > datetime.fromisoformat(expires_at):
            return {"valid": False, "error": "Key expired"}, 401
        
        if hwid is None:
            cur.execute("UPDATE keys SET hwid = ? WHERE key = ?", (data.hwid, data.key))
            db.commit()
            return {"valid": True, "message": "HWID bound successfully", "key": key, "expires_at": expires_at}
        
        if hwid == data.hwid:
            return {"valid": True, "message": "Authentication successful", "key": key, "expires_at": expires_at}
        
        return {"valid": False, "error": "HWID mismatch"}, 401
    finally:
        db.close()

# Legacy path-based UI (kept as fallback/compatibility)
@app.get("/{license_key:path}", response_class=HTMLResponse)
async def serve_ui(license_key: str):
    db = get_db()
    try:
        cur = db.cursor()
        cur.execute("SELECT key, redeemed_by, active FROM keys WHERE key = ?", (license_key,))
        result = cur.fetchone()
        
        if not result:
            return """
            <!DOCTYPE html>
            <html>
            <head><title>Invalid License</title></head>
            <body style="margin:0;padding:0;height:100vh;display:flex;justify-content:center;align-items:center;background:#0c0c0c;color:#fff;font-family:sans-serif;">
                <div style="text-align:center;padding:40px;background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.1);border-radius:12px;">
                    <h1 style="color:#ff4444;margin:0 0 20px 0;">invalid license LOL</h1>
                    <p style="margin:0;color:#888;">The license key you entered does not exist.</p>
                </div>
            </body>
            </html>
            """
        
        return f"<h1>Valid key: {license_key}</h1><p>Use the dashboard with Bearer token login.</p>"
    finally:
        db.close()

print("Axion Backend fully loaded - Bearer token authentication active")
