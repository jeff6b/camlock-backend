# main.py
from fastapi import FastAPI, HTTPException, Cookie, Response
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import psycopg2
import sqlite3
import os
import json
import secrets
from datetime import datetime, timedelta

app = FastAPI()

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Default configuration
DEFAULT_CONFIG = {
    "triggerbot": {
        "Enabled": True,
        "Keybind": "Right Mouse",
        "Delay": 0.0,
        "MaxStuds": 120,
        "StudCheck": True,
        "DeathCheck": True,
        "KnifeCheck": True,
        "TeamCheck": True,
        "TargetMode": False,
        "TargetKeybind": "Middle Mouse",
        "Prediction": 0.1,
        "FOV": 25
    },
    "camlock": {
        "Enabled": True,
        "Keybind": "Q",
        "FOV": 280.0,
        "SmoothX": 14.0,
        "SmoothY": 14.0,
        "EnableSmoothing": True,
        "EasingStyle": "Linear",
        "Prediction": 0.14,
        "EnablePrediction": True,
        "MaxStuds": 120.0,
        "UnlockOnDeath": True,
        "SelfDeathCheck": True,
        "BodyPart": "Head",
        "ClosestPart": False,
        "ScaleToggle": True,
        "Scale": 1.0
    }
}

# Database config
DATABASE_URL = os.getenv("DATABASE_URL")
USE_POSTGRES = DATABASE_URL is not None

def get_db():
    if USE_POSTGRES:
        return psycopg2.connect(DATABASE_URL)
    else:
        return sqlite3.connect("local.db")

def q(query):
    """Convert PostgreSQL placeholders to SQLite if needed"""
    if USE_POSTGRES:
        return query
    return query.replace("%s", "?")

def init_db():
    db = get_db()
    cur = db.cursor()
    
    if USE_POSTGRES:
        # PostgreSQL tables
        cur.execute("""CREATE TABLE IF NOT EXISTS keys (
            key TEXT PRIMARY KEY,
            duration TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT,
            redeemed_at TEXT,
            redeemed_by TEXT,
            hwid TEXT,
            hwid_resets INTEGER DEFAULT 0,
            active INTEGER DEFAULT 0,
            created_by TEXT
        )""")
        
        try:
            cur.execute("ALTER TABLE keys ADD COLUMN IF NOT EXISTS hwid_resets INTEGER DEFAULT 0")
            db.commit()
        except:
            pass
        
        cur.execute("""CREATE TABLE IF NOT EXISTS saved_configs (
            id SERIAL PRIMARY KEY,
            license_key TEXT NOT NULL,
            config_name TEXT NOT NULL,
            config_data TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(license_key, config_name)
        )""")
        
        cur.execute("""CREATE TABLE IF NOT EXISTS public_configs (
            id SERIAL PRIMARY KEY,
            config_name TEXT NOT NULL,
            author_name TEXT NOT NULL,
            game_name TEXT NOT NULL,
            description TEXT,
            config_data TEXT NOT NULL,
            license_key TEXT NOT NULL,
            created_at TEXT NOT NULL,
            downloads INTEGER DEFAULT 0
        )""")
        
        try:
            cur.execute("SELECT discord_id FROM public_configs LIMIT 1")
            cur.execute("DROP TABLE IF EXISTS public_configs")
            cur.execute("""CREATE TABLE public_configs (
                id SERIAL PRIMARY KEY,
                config_name TEXT NOT NULL,
                author_name TEXT NOT NULL,
                game_name TEXT NOT NULL,
                description TEXT,
                config_data TEXT NOT NULL,
                license_key TEXT NOT NULL,
                created_at TEXT NOT NULL,
                downloads INTEGER DEFAULT 0
            )""")
            db.commit()
        except Exception as e:
            db.rollback()
            
        cur.execute("""CREATE TABLE IF NOT EXISTS user_sessions (
            session_id TEXT PRIMARY KEY,
            license_key TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        )""")
        
        # Add settings table for config storage
        cur.execute("""CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            config TEXT NOT NULL
        )""")
    else:
        # SQLite tables
        cur.execute("""CREATE TABLE IF NOT EXISTS keys (
            key TEXT PRIMARY KEY,
            duration TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT,
            redeemed_at TEXT,
            redeemed_by TEXT,
            hwid TEXT,
            hwid_resets INTEGER DEFAULT 0,
            active INTEGER DEFAULT 0,
            created_by TEXT
        )""")
        
        try:
            cur.execute("ALTER TABLE keys ADD COLUMN hwid_resets INTEGER DEFAULT 0")
            db.commit()
        except:
            pass
        
        cur.execute("""CREATE TABLE IF NOT EXISTS saved_configs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key TEXT NOT NULL,
            config_name TEXT NOT NULL,
            config_data TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(license_key, config_name)
        )""")
        
        cur.execute("""CREATE TABLE IF NOT EXISTS public_configs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            config_name TEXT NOT NULL,
            author_name TEXT NOT NULL,
            game_name TEXT NOT NULL,
            description TEXT,
            config_data TEXT NOT NULL,
            license_key TEXT NOT NULL,
            created_at TEXT NOT NULL,
            downloads INTEGER DEFAULT 0
        )""")
        
        try:
            cur.execute("SELECT discord_id FROM public_configs LIMIT 1")
            cur.execute("DROP TABLE IF EXISTS public_configs")
            cur.execute("""CREATE TABLE public_configs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                config_name TEXT NOT NULL,
                author_name TEXT NOT NULL,
                game_name TEXT NOT NULL,
                description TEXT,
                config_data TEXT NOT NULL,
                license_key TEXT NOT NULL,
                created_at TEXT NOT NULL,
                downloads INTEGER DEFAULT 0
            )""")
            db.commit()
        except Exception as e:
            try:
                db.rollback()
            except:
                pass
                
        cur.execute("""CREATE TABLE IF NOT EXISTS user_sessions (
            session_id TEXT PRIMARY KEY,
            license_key TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        )""")
        
        # Add settings table for config storage
        cur.execute("""CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            config TEXT NOT NULL
        )""")
    
    db.commit()
    db.close()
    print("✅ Database initialized")

# Pydantic models
class KeyValidate(BaseModel):
    key: str
    hwid: str

class ConfigData(BaseModel):
    name: str
    data: dict

class KeyCreate(BaseModel):
    duration: str
    created_by: str

class PublicConfig(BaseModel):
    config_name: str
    author_name: str
    game_name: str
    description: str
    config_data: dict

class SaveConfig(BaseModel):
    name: str
    data: dict

class RedeemRequest(BaseModel):
    key: str
    discord_id: str

# === VALIDATION ===

@app.post("/api/validate")
def validate_user(data: KeyValidate):
    """Validate license key"""
    db = get_db()
    cur = db.cursor()
    
    cur.execute(q("SELECT key, active, expires_at, hwid FROM keys WHERE key=%s"), (data.key,))
    result = cur.fetchone()
    
    if not result:
        db.close()
        return {"valid": False, "error": "Invalid license key"}
    
    key, active, expires_at, hwid = result
    
    if active == 0:
        db.close()
        return {"valid": False, "error": "License inactive"}
    
    if expires_at and datetime.now() > datetime.fromisoformat(expires_at):
        db.close()
        return {"valid": False, "error": "License expired"}
    
    if data.hwid != 'web-login':
        if hwid is None:
            cur.execute(q("UPDATE keys SET hwid=%s WHERE key=%s"), (data.hwid, data.key))
            db.commit()
            db.close()
            return {"valid": True, "message": "HWID bound successfully"}
        elif hwid == data.hwid:
            db.close()
            return {"valid": True, "message": "Authentication successful"}
        else:
            db.close()
            return {"valid": False, "error": "HWID mismatch"}
    
    db.close()
    return {"valid": True, "message": "Authentication successful"}

# === CONFIG ENDPOINTS (FIXED) ===

@app.get("/api/config/{license_key}")
def get_config(license_key: str):
    """Get config for a license key - FIXED VERSION"""
    db = get_db()
    cur = db.cursor()
    
    try:
        # Check if config exists
        cur.execute(q("SELECT config FROM settings WHERE key=%s"), (license_key,))
        result = cur.fetchone()
        
        if not result:
            # Insert default config if doesn't exist
            if USE_POSTGRES:
                cur.execute(
                    "INSERT INTO settings (key, config) VALUES (%s, %s) ON CONFLICT (key) DO NOTHING",
                    (license_key, json.dumps(DEFAULT_CONFIG))
                )
            else:
                cur.execute(
                    "INSERT OR IGNORE INTO settings (key, config) VALUES (?, ?)",
                    (license_key, json.dumps(DEFAULT_CONFIG))
                )
            db.commit()
            db.close()
            return DEFAULT_CONFIG
        
        db.close()
        return json.loads(result[0])
        
    except Exception as e:
        db.close()
        print(f"Error in get_config: {e}")
        return DEFAULT_CONFIG

@app.post("/api/config/{license_key}")
def set_config(license_key: str, data: dict):
    """Save config for a license key - FIXED VERSION"""
    db = get_db()
    cur = db.cursor()
    
    try:
        if USE_POSTGRES:
            cur.execute(
                """INSERT INTO settings (key, config) VALUES (%s, %s)
                   ON CONFLICT (key) DO UPDATE SET config = EXCLUDED.config""",
                (license_key, json.dumps(data))
            )
        else:
            cur.execute(
                """INSERT INTO settings (key, config) VALUES (?, ?)
                   ON CONFLICT (key) DO UPDATE SET config = excluded.config""",
                (license_key, json.dumps(data))
            )
        
        db.commit()
        db.close()
        return {"status": "ok"}
        
    except Exception as e:
        db.close()
        print(f"Error in set_config: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/configs/{license_key}/list")
def list_configs(license_key: str):
    """List saved configs"""
    db = get_db()
    cur = db.cursor()
    cur.execute(q("SELECT config_name FROM saved_configs WHERE license_key=%s ORDER BY created_at DESC"), (license_key,))
    rows = cur.fetchall()
    db.close()
    
    configs = [row[0] for row in rows]
    return {"configs": configs}

@app.post("/api/configs/{license_key}/save")
def save_config(license_key: str, data: ConfigData):
    """Save a config"""
    db = get_db()
    cur = db.cursor()
    
    try:
        cur.execute(q("SELECT id FROM saved_configs WHERE license_key=%s AND config_name=%s"), (license_key, data.name))
        existing = cur.fetchone()
        
        if existing:
            cur.execute(q("UPDATE saved_configs SET config_data=%s WHERE license_key=%s AND config_name=%s"),
                       (json.dumps(data.data), license_key, data.name))
        else:
            cur.execute(q("INSERT INTO saved_configs (license_key, config_name, config_data, created_at) VALUES (%s, %s, %s, %s)"),
                       (license_key, data.name, json.dumps(data.data), datetime.now().isoformat()))
        
        db.commit()
        db.close()
        return {"success": True, "message": "Config saved"}
    except Exception as e:
        db.close()
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/configs/{license_key}/load/{config_name}")
def load_config(license_key: str, config_name: str):
    """Load a saved config"""
    db = get_db()
    cur = db.cursor()
    cur.execute(q("SELECT config_data FROM saved_configs WHERE license_key=%s AND config_name=%s"), (license_key, config_name))
    row = cur.fetchone()
    db.close()
    
    if not row:
        raise HTTPException(status_code=404, detail="Config not found")
    
    return {"config_data": json.loads(row[0])}

@app.post("/api/configs/{license_key}/rename")
def rename_config(license_key: str, data: dict):
    """Rename a config"""
    old_name = data.get("old_name")
    new_name = data.get("new_name")
    
    db = get_db()
    cur = db.cursor()
    cur.execute(q("UPDATE saved_configs SET config_name=%s WHERE license_key=%s AND config_name=%s"),
               (new_name, license_key, old_name))
    db.commit()
    db.close()
    
    return {"success": True}

@app.post("/api/configs/{license_key}/delete/{config_name}")
def delete_config(license_key: str, config_name: str):
    """Delete a config"""
    db = get_db()
    cur = db.cursor()
    cur.execute(q("DELETE FROM saved_configs WHERE license_key=%s AND config_name=%s"), (license_key, config_name))
    db.commit()
    db.close()
    
    return {"success": True}

# === PUBLIC CONFIGS ===

@app.get("/api/public-configs")
def get_public_configs():
    """Get all public configs"""
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute(q("SELECT id, config_name, author_name, game_name, description, downloads, created_at FROM public_configs ORDER BY created_at DESC"))
        rows = cur.fetchall()
        db.close()
        
        configs = []
        for row in rows:
            configs.append({
                "id": row[0],
                "config_name": row[1],
                "author_name": row[2],
                "game_name": row[3],
                "description": row[4],
                "downloads": row[5],
                "created_at": row[6]
            })
        
        return {"configs": configs}
    except Exception as e:
        print(f"Error: {e}")
        return {"configs": []}

@app.post("/api/public-configs/create")
def create_public_config(data: PublicConfig):
    """Create a public config"""
    db = get_db()
    cur = db.cursor()
    
    try:
        cur.execute(q("INSERT INTO public_configs (config_name, author_name, game_name, description, config_data, license_key, created_at, downloads) VALUES (%s, %s, %s, %s, %s, %s, %s, 0)"),
                   (data.config_name, data.author_name, data.game_name, data.description, json.dumps(data.config_data), "web-user", datetime.now().isoformat()))
        db.commit()
        db.close()
        return {"success": True}
    except Exception as e:
        db.close()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/public-configs/{config_id}")
def get_public_config(config_id: int):
    """Get a single config"""
    db = get_db()
    cur = db.cursor()
    cur.execute(q("SELECT id, config_name, author_name, game_name, description, config_data, downloads FROM public_configs WHERE id=%s"), (config_id,))
    row = cur.fetchone()
    db.close()
    
    if not row:
        raise HTTPException(status_code=404, detail="Not found")
    
    return {
        "id": row[0],
        "config_name": row[1],
        "author_name": row[2],
        "game_name": row[3],
        "description": row[4],
        "config_data": json.loads(row[5]) if row[5] else {},
        "downloads": row[6]
    }

@app.post("/api/public-configs/{config_id}/download")
def download_config(config_id: int):
    """Increment downloads"""
    db = get_db()
    cur = db.cursor()
    cur.execute(q("UPDATE public_configs SET downloads = downloads + 1 WHERE id=%s"), (config_id,))
    db.commit()
    db.close()
    return {"success": True}

# === KEY MANAGEMENT ===

@app.post("/api/keys/create")
def create_key(data: KeyCreate):
    """Create a license key"""
    key = f"{secrets.randbelow(10000):04d}-{secrets.randbelow(10000):04d}-{secrets.randbelow(10000):04d}-{secrets.randbelow(10000):04d}"
    
    db = get_db()
    cur = db.cursor()
    
    try:
        cur.execute(q("INSERT INTO keys (key, duration, created_at, active, created_by) VALUES (%s, %s, %s, 0, %s)"),
                   (key, data.duration, datetime.now().isoformat(), data.created_by))
        db.commit()
        db.close()
        return {"key": key, "duration": data.duration}
    except Exception as e:
        db.close()
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/keys/{license_key}")
def delete_key(license_key: str):
    """Delete a key"""
    db = get_db()
    cur = db.cursor()
    cur.execute(q("DELETE FROM keys WHERE key=%s"), (license_key,))
    db.commit()
    db.close()
    return {"success": True}

# === DASHBOARD API ===

@app.get("/api/dashboard/{license_key}")
def get_dashboard_data(license_key: str):
    """Get dashboard data"""
    db = get_db()
    cur = db.cursor()
    
    cur.execute(q("SELECT key, duration, expires_at, active, hwid, redeemed_by, hwid_resets FROM keys WHERE key=%s"), (license_key,))
    result = cur.fetchone()
    
    db.close()
    
    if not result:
        raise HTTPException(status_code=404, detail="Not found")
    
    key, duration, expires_at, active, hwid, discord_id, hwid_resets = result
    
    return {
        "license_key": key,
        "duration": duration,
        "expires_at": expires_at,
        "active": active,
        "hwid": hwid,
        "discord_id": discord_id,
        "hwid_resets": hwid_resets if hwid_resets else 0
    }

@app.post("/api/redeem")
def redeem_key(data: RedeemRequest):
    """Redeem a key"""
    db = get_db()
    cur = db.cursor()
    
    cur.execute(q("SELECT key, duration, redeemed_at FROM keys WHERE key=%s"), (data.key,))
    result = cur.fetchone()
    
    if not result:
        db.close()
        raise HTTPException(status_code=404, detail="Invalid key")
    
    key, duration, redeemed_at = result
    
    if redeemed_at:
        db.close()
        raise HTTPException(status_code=400, detail="Already redeemed")
    
    now = datetime.now()
    expires_at = None
    if duration == "monthly":
        expires_at = (now + timedelta(days=30)).isoformat()
    elif duration == "weekly":
        expires_at = (now + timedelta(days=7)).isoformat()
    elif duration == "3monthly":
        expires_at = (now + timedelta(days=90)).isoformat()
    
    cur.execute(q("UPDATE keys SET redeemed_at=%s, redeemed_by=%s, expires_at=%s, active=1 WHERE key=%s"),
               (now.isoformat(), data.discord_id, expires_at, data.key))
    db.commit()
    db.close()
    
    return {"success": True, "duration": duration, "expires_at": expires_at, "message": "Key redeemed successfully"}

@app.post("/api/reset-hwid/{license_key}")
def reset_hwid(license_key: str):
    """Reset HWID"""
    db = get_db()
    cur = db.cursor()
    
    cur.execute(q("SELECT hwid_resets FROM keys WHERE key=%s"), (license_key,))
    result = cur.fetchone()
    
    if not result:
        db.close()
        raise HTTPException(status_code=404, detail="Not found")
    
    resets = result[0] if result[0] else 0
    
    cur.execute(q("UPDATE keys SET hwid=NULL, hwid_resets=%s WHERE key=%s"), (resets + 1, license_key))
    db.commit()
    db.close()
    
    return {"success": True, "hwid_resets": resets + 1}

@app.get("/api/users/{user_id}/license")
def get_user_license(user_id: str):
    """Get user's license by Discord ID"""
    db = get_db()
    cur = db.cursor()
    
    cur.execute(q("SELECT key, duration, expires_at, redeemed_at, hwid, active FROM keys WHERE redeemed_by=%s"), (user_id,))
    result = cur.fetchone()
    db.close()
    
    if not result:
        return {"active": False, "message": "No license found"}
    
    key, duration, expires_at, redeemed_at, hwid, active = result
    
    if expires_at:
        is_expired = datetime.now() > datetime.fromisoformat(expires_at)
        if is_expired:
            return {"active": False, "expired": True, "key": key}
    
    return {
        "active": True,
        "key": key,
        "duration": duration,
        "expires_at": expires_at,
        "redeemed_at": redeemed_at,
        "hwid": hwid
    }

@app.delete("/api/users/{user_id}/license")
def delete_user_license(user_id: str):
    """Delete user's license by Discord ID"""
    db = get_db()
    cur = db.cursor()
    
    cur.execute(q("SELECT key FROM keys WHERE redeemed_by=%s"), (user_id,))
    result = cur.fetchone()
    
    if not result:
        db.close()
        raise HTTPException(status_code=404, detail="No license found")
    
    key = result[0]
    cur.execute(q("DELETE FROM keys WHERE redeemed_by=%s"), (user_id,))
    db.commit()
    db.close()
    
    return {"status": "deleted", "key": key, "user_id": user_id}

@app.post("/api/users/{user_id}/reset-hwid")
def reset_user_hwid(user_id: str):
    """Reset HWID for user's license"""
    db = get_db()
    cur = db.cursor()
    
    cur.execute(q("SELECT hwid, hwid_resets FROM keys WHERE redeemed_by=%s"), (user_id,))
    result = cur.fetchone()
    
    if not result:
        db.close()
        raise HTTPException(status_code=404, detail="No license found")
    
    old_hwid, resets = result
    resets = resets if resets else 0
    
    cur.execute(q("UPDATE keys SET hwid=NULL, hwid_resets=%s WHERE redeemed_by=%s"), (resets + 1, user_id))
    db.commit()
    db.close()
    
    return {"status": "reset", "user_id": user_id, "old_hwid": old_hwid}

@app.get("/api/keepalive")
def keepalive():
    """Keep server awake"""
    return {"status": "alive"}

# === HTML ROUTES ===

@app.get("/", response_class=HTMLResponse)
@app.get("/home", response_class=HTMLResponse)
def serve_home():
    """Home page"""
    _INDEX_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Axion — Home</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    
    body, html {
      height: 100%;
      background-color: rgb(12, 12, 12);
      color: #fff;
      font-family: system-ui, -apple-system, sans-serif;
      overflow-x: hidden;
    }

    .image-container {
      width: 100%;
      height: 100vh;
      background-image: url('https://image2url.com/r2/default/images/1768674767693-4fff24d5-abfa-4be9-a3ee-bd44454bad9f.blob');
      background-size: cover;
      background-position: center;
      opacity: 0.01;
      position: fixed;
      inset: 0;
      z-index: 1;
    }

    .navbar {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      padding: 1.2rem 2rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      z-index: 100;
      backdrop-filter: blur(12px);
      background: rgba(12, 12, 12, 0.6);
      border-bottom: 1px solid rgba(255,255,255,0.08);
    }

    .nav-links {
      display: flex;
      gap: 2rem;
    }

    .nav-links a {
      color: rgba(255, 255, 255, 0.6);
      text-decoration: none;
      font-size: 0.95rem;
      font-weight: 500;
      transition: color 0.3s;
      cursor: pointer;
    }

    .nav-links a:hover {
      color: rgba(255, 255, 255, 1);
    }

    .content {
      position: fixed;
      inset: 0;
      z-index: 5;
      overflow-y: auto;
      pointer-events: none;
      display: flex;
      justify-content: center;
      align-items: center;
    }

    .content > * {
      pointer-events: auto;
    }

    .title-wrapper {
      display: flex;
      gap: 0.8rem;
      flex-wrap: wrap;
      justify-content: center;
    }

    .title-word {
      font-size: 3.8rem;
      font-weight: 900;
      letter-spacing: -1.5px;
      text-shadow: 0 0 25px rgba(0,0,0,0.7);
    }
  </style>
</head>
<body>
  <div class="image-container"></div>

  <nav class="navbar">
    <div class="nav-links">
      <a href="/">Home</a>
      <a href="https://discord.gg/yourserver">Discord</a>
    </div>
  </nav>

  <div class="content">
    <div class="title-wrapper">
      <span class="title-word" style="color:#ffffff;">WELCOME</span>
      <span class="title-word" style="color:#ffffff;">TO</span>
      <span class="title-word" style="color:#888888;">Axion</span>
    </div>
  </div>
</body>
</html>"""
    return _INDEX_HTML

@app.get("/{license_key}", response_class=HTMLResponse)
def serve_dashboard(license_key: str):
    """Full dashboard with toggles, sliders, dropdowns"""
    if license_key in ["api", "favicon.ico", "home"]:
        raise HTTPException(status_code=404)
   
    db = get_db()
    cur = db.cursor()
   
    cur.execute(q("SELECT * FROM keys WHERE key=%s"), (license_key,))
    result = cur.fetchone()
    db.close()
   
    if not result:
        return "<html><body style='background:rgb(12,12,12);color:white;font-family:Arial;display:flex;align-items:center;justify-content:center;height:100vh'><div style='text-align:center'><h1 style='color:rgb(255,68,68)'>Invalid License</h1><p>Not valid</p></div></body></html>"
   
    cfg = json.dumps(DEFAULT_CONFIG)
    key = license_key
   
    return f"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<title>Axion - {key}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box;user-select:none}}
body{{height:100vh;background:radial-gradient(circle at top,#0f0f0f,#050505);font-family:Arial,sans-serif;color:#cfcfcf;display:flex;align-items:center;justify-content:center}}
.window{{width:860px;height:620px;background:linear-gradient(#111,#0a0a0a);border:1px solid #2a2a2a;box-shadow:0 0 40px rgba(0,0,0,0.8);display:flex;flex-direction:column;overflow:hidden;border-radius:8px}}
.topbar{{height:42px;background:linear-gradient(#1a1a1a,#0e0e0e);border-bottom:1px solid #2b2b2b;display:flex;align-items:center;padding:0 16px;gap:20px}}
.title{{font-size:14px;color:#bfbfbf;font-weight:600;padding-right:20px;border-right:1px solid #2a2a2a}}
.tabs{{display:flex;gap:24px;font-size:13px}}
.tab{{color:#9a9a9a;cursor:pointer;transition:color 0.2s;padding:0 4px}}
.tab:hover,.tab.active{{color:#ffffff;text-shadow:0 0 4px rgba(255,255,255,0.3)}}
.topbar-right{{margin-left:auto;display:flex;align-items:center;gap:12px}}
.search-container{{position:relative;width:200px}}
.search-bar{{width:100%;height:28px;background:#0f0f0f;border:1px solid #2a2a2a;color:#cfcfcf;font-size:12px;padding:0 12px 0 36px;outline:none;border-radius:4px}}
.search-bar::placeholder{{color:#666}}
.search-icon{{position:absolute;left:12px;top:50%;transform:translateY(-50%);width:16px;height:16px;pointer-events:none;opacity:0.6}}
.content{{flex:1;padding:16px;background:#0c0c0c;overflow:hidden;position:relative}}
.tab-content{{width:100%;height:100%;display:none}}
.tab-content.active{{display:block}}
.merged-panel{{width:100%;height:100%;background:#0c0c0c;border:1px solid #222;overflow:hidden;display:flex;align-items:center;justify-content:center}}
.inner-container{{width:98%;height:96%;display:flex;gap:16px;overflow:hidden}}
.half-panel{{flex:1;background:#111;border:1px solid #2a2a2a;box-shadow:0 0 25px rgba(0,0,0,0.6) inset;overflow-y:auto;padding:20px 18px;position:relative;border-radius:6px}}
.panel-header{{position:sticky;top:0;left:0;background:#111;color:#bfbfbf;font-size:12px;font-weight:600;padding:8px 0 12px;z-index:2;border-bottom:1px solid #222;margin-bottom:12px}}
.toggle-row{{display:flex;align-items:center;gap:12px;margin-bottom:14px}}
.toggle-text{{display:flex;align-items:center;gap:12px;flex:1}}
.toggle{{width:16px;height:16px;background:transparent;border:1.2px solid #444;border-radius:3px;cursor:pointer;transition:all 0.15s}}
.toggle.active{{background:#aaa;border-color:#aaa;box-shadow:inset 0 0 6px rgba(0,0,0,0.6)}}
.enable-text{{color:#9a9a9a;font-size:12px;transition:color 0.2s}}
.toggle.active + .enable-text{{color:#e0e0e0}}
.keybind-picker{{min-width:90px;height:26px;background:#0f0f0f;border:1px solid #2a2a2a;color:#cfcfcf;font-size:11px;display:flex;align-items:center;justify-content:center;cursor:pointer;border-radius:4px;transition:all 0.15s}}
.keybind-picker:hover{{border-color:#555;background:#1a1a1a}}
.slider-label{{color:#bfbfbf;font-size:11px;margin-bottom:6px;display:block}}
.slider-container{{width:100%;height:10px;background:#0f0f0f;border:1px solid #2a2a2a;border-radius:5px;overflow:hidden;position:relative;cursor:pointer}}
.slider-track{{position:absolute;inset:0}}
.slider-fill{{position:absolute;top:0;left:0;height:100%;background:#888;width:50%;transition:width 0.08s}}
.slider-value{{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);font-size:10px;font-weight:bold;pointer-events:none;color:#000;text-shadow:0 0 3px rgba(255,255,255,0.6)}}
.half-panel::-webkit-scrollbar{{width:6px}}
.half-panel::-webkit-scrollbar-track{{background:#0a0a0a}}
.half-panel::-webkit-scrollbar-thumb{{background:#333;border-radius:3px}}
.half-panel::-webkit-scrollbar-thumb:hover{{background:#555}}
.custom-dropdown{{width:100%;position:relative;margin-bottom:16px}}
.dropdown-header{{width:100%;height:32px;background:#0f0f0f;border:1px solid #2a2a2a;color:#cfcfcf;font-size:12px;display:flex;align-items:center;padding:0 12px;cursor:pointer;border-radius:4px}}
.dropdown-list{{position:absolute;top:100%;left:0;width:100%;max-height:220px;background:#0f0f0f;border:1px solid #2a2a2a;border-top:none;overflow-y:auto;display:none;z-index:10;box-shadow:0 8px 20px rgba(0,0,0,0.7);border-radius:0 0 4px 4px}}
.dropdown-list.open{{display:block}}
.dropdown-item{{padding:8px 12px;font-size:12px;color:#cfcfcf;cursor:pointer;transition:background 0.15s}}
.dropdown-item:hover{{background:#1e1e1e}}
.dropdown-item.selected{{background:#2a2a2a;color:#fff}}
.config-list{{margin-top:8px}}
.config-item{{background:#0f0f0f;border:1px solid #2a2a2a;padding:10px 12px;margin-bottom:8px;display:flex;align-items:center;gap:12px;border-radius:4px;transition:all 0.15s}}
.config-item:hover{{background:#181818;border-color:#444}}
.config-name{{flex:1;font-size:12px;color:#fff}}
.config-dots{{width:24px;height:24px;display:flex;align-items:center;justify-content:center;cursor:pointer;color:#aaa;font-size:18px;font-weight:bold}}
.config-dots:hover{{color:#fff}}
.config-menu{{position:absolute;right:12px;top:36px;background:#0f0f0f;border:1px solid #2a2a2a;display:none;z-index:200;box-shadow:0 6px 16px rgba(0,0,0,0.7);min-width:120px;border-radius:4px;overflow:hidden}}
.config-menu.open{{display:block}}
.config-menu-item{{padding:8px 14px;font-size:11px;color:#cfcfcf;cursor:pointer;transition:background 0.15s}}
.config-menu-item:hover{{background:#222;color:#fff}}
.input-box{{width:100%;height:32px;background:#0f0f0f;border:1px solid #2a2a2a;color:#cfcfcf;font-size:12px;padding:0 12px;border-radius:4px;margin-bottom:10px}}
.config-btn{{width:100%;height:34px;background:#1a1a1a;border:1px solid #333;color:#cfcfcf;font-size:12px;cursor:pointer;border-radius:4px;transition:all 0.2s}}
.config-btn:hover{{background:#252525;border-color:#555}}
.modal-overlay{{position:fixed;inset:0;background:rgba(0,0,0,0.75);backdrop-filter:blur(6px);display:none;align-items:center;justify-content:center;z-index:9999}}
.modal-overlay.active{{display:flex}}
.modal-box{{background:linear-gradient(#111,#0a0a0a);border:1px solid #2a2a2a;padding:28px;width:360px;max-width:90%;border-radius:8px;box-shadow:0 10px 40px rgba(0,0,0,0.8)}}
.modal-title{{color:#fff;font-size:14px;margin-bottom:20px;font-weight:600}}
.modal-input{{width:100%;height:36px;background:#0f0f0f;border:1px solid #2a2a2a;color:#cfcfcf;font-size:13px;padding:0 14px;border-radius:4px;margin-bottom:16px}}
.modal-buttons{{display:flex;gap:12px}}
.modal-btn{{flex:1;height:38px;background:#0f0f0f;border:1px solid #2a2a2a;color:#cfcfcf;font-size:13px;cursor:pointer;border-radius:4px;transition:all 0.2s}}
.modal-btn:hover{{background:#222}}
.modal-btn.primary{{background:#222;border-color:#444}}
.modal-btn.primary:hover{{background:#2a2a2a}}
</style>
</head>
<body>

<div class="window">
  <div class="topbar">
    <div class="title">Axion</div>
    <div class="tabs">
      <div class="tab active" data-tab="aimbot">Aimbot</div>
      <div class="tab" data-tab="triggerbot">Triggerbot</div>
      <div class="tab" data-tab="settings">Settings</div>
    </div>
    <div class="topbar-right">
      <div class="search-container">
        <img src="https://img.icons8.com/ios-filled/50/ffffff/search.png" class="search-icon" alt="Search"/>
        <input type="text" id="searchInput" class="search-bar" placeholder="Search settings..."/>
      </div>
    </div>
  </div>

  <div class="content">
    <!-- Aimbot Tab -->
    <div class="tab-content active" id="aimbot">
      <div class="merged-panel">
        <div class="inner-container">
          <div class="half-panel">
            <div class="panel-header">Aimbot</div>
            <div class="toggle-row">
              <div class="toggle-text">
                <div class="toggle active" data-setting="camlock.Enabled"></div>
                <span class="enable-text">Enable Camlock</span>
              </div>
              <div class="keybind-picker" data-setting="camlock.Keybind">Q</div>
            </div>
            <div class="toggle-row">
              <div class="toggle active" data-setting="camlock.EnableSmoothing"></div>
              <span class="enable-text">Enable Smoothing</span>
            </div>
            <div class="toggle-row">
              <div class="toggle active" data-setting="camlock.EnablePrediction"></div>
              <span class="enable-text">Enable Prediction</span>
            </div>
            <div class="toggle-row">
              <div class="toggle" data-setting="camlock.UnlockOnDeath"></div>
              <span class="enable-text">Unlock on Death</span>
            </div>
            <div class="toggle-row">
              <div class="toggle" data-setting="camlock.SelfDeathCheck"></div>
              <span class="enable-text">Self Death Check</span>
            </div>
            <div class="toggle-row">
              <div class="toggle" data-setting="camlock.ClosestPart"></div>
              <span class="enable-text">Closest Part</span>
            </div>
            <div class="toggle-row">
              <div class="toggle active" data-setting="camlock.ScaleToggle"></div>
              <span class="enable-text">Scale Toggle</span>
            </div>

            <div class="slider-label">Body Part</div>
            <div class="custom-dropdown">
              <div class="dropdown-header" id="bodyPartHeader">Head</div>
              <div class="dropdown-list" id="bodyPartList">
                <div class="dropdown-item selected" data-value="Head">Head</div>
                <div class="dropdown-item" data-value="UpperTorso">UpperTorso</div>
                <div class="dropdown-item" data-value="LowerTorso">LowerTorso</div>
                <div class="dropdown-item" data-value="HumanoidRootPart">HumanoidRootPart</div>
              </div>
            </div>

            <div class="slider-label">Easing Style</div>
            <div class="custom-dropdown">
              <div class="dropdown-header" id="easingHeader">Linear</div>
              <div class="dropdown-list" id="easingList">
                <div class="dropdown-item selected" data-value="Linear">Linear</div>
                <div class="dropdown-item" data-value="Sine">Sine</div>
                <div class="dropdown-item" data-value="Quad">Quad</div>
                <div class="dropdown-item" data-value="Cubic">Cubic</div>
                <div class="dropdown-item" data-value="Expo">Expo</div>
              </div>
            </div>
          </div>

          <div class="half-panel">
            <div class="panel-header">Aimbot Settings</div>

            <div class="slider-label">FOV</div>
            <div class="slider-container" id="fovSlider" data-setting="camlock.FOV">
              <div class="slider-track">
                <div class="slider-fill" id="fovFill"></div>
                <div class="slider-value" id="fovValue">280</div>
              </div>
            </div>

            <div class="slider-label">Smooth X</div>
            <div class="slider-container" id="smoothXSlider" data-setting="camlock.SmoothX">
              <div class="slider-track">
                <div class="slider-fill" id="smoothXFill"></div>
                <div class="slider-value" id="smoothXValue">14</div>
              </div>
            </div>

            <div class="slider-label">Smooth Y</div>
            <div class="slider-container" id="smoothYSlider" data-setting="camlock.SmoothY">
              <div class="slider-track">
                <div class="slider-fill" id="smoothYFill"></div>
                <div class="slider-value" id="smoothYValue">14</div>
              </div>
            </div>

            <div class="slider-label">Prediction</div>
            <div class="slider-container" id="camlockPredSlider" data-setting="camlock.Prediction">
              <div class="slider-track">
                <div class="slider-fill" id="camlockPredFill"></div>
                <div class="slider-value" id="camlockPredValue">0.14</div>
              </div>
            </div>

            <div class="slider-label">Max Studs</div>
            <div class="slider-container" id="camlockMaxStudsSlider" data-setting="camlock.MaxStuds">
              <div class="slider-track">
                <div class="slider-fill" id="camlockMaxStudsFill"></div>
                <div class="slider-value" id="camlockMaxStudsValue">120</div>
              </div>
            </div>

            <div class="slider-label">Scale</div>
            <div class="slider-container" id="scaleSlider" data-setting="camlock.Scale">
              <div class="slider-track">
                <div class="slider-fill" id="scaleFill"></div>
                <div class="slider-value" id="scaleValue">1.0</div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Triggerbot Tab -->
    <div class="tab-content" id="triggerbot">
      <div class="merged-panel">
        <div class="inner-container">
          <div class="half-panel">
            <div class="panel-header">Triggerbot</div>
            <div class="toggle-row">
              <div class="toggle-text">
                <div class="toggle active" data-setting="triggerbot.Enabled"></div>
                <span class="enable-text">Enable Triggerbot</span>
              </div>
              <div class="keybind-picker" data-setting="triggerbot.Keybind">Right Mouse</div>
            </div>
            <div class="toggle-row">
              <div class="toggle-text">
                <div class="toggle" data-setting="triggerbot.TargetMode"></div>
                <span class="enable-text">Target Mode</span>
              </div>
              <div class="keybind-picker" data-setting="triggerbot.TargetKeybind">Middle Mouse</div>
            </div>
          </div>

          <div class="half-panel">
            <div class="panel-header">Triggerbot Settings</div>
            <div class="toggle-row">
              <div class="toggle active" data-setting="triggerbot.StudCheck"></div>
              <span class="enable-text">Stud Check</span>
            </div>
            <div class="toggle-row">
              <div class="toggle active" data-setting="triggerbot.DeathCheck"></div>
              <span class="enable-text">Death Check</span>
            </div>
            <div class="toggle-row">
              <div class="toggle active" data-setting="triggerbot.KnifeCheck"></div>
              <span class="enable-text">Knife Check</span>
            </div>
            <div class="toggle-row">
              <div class="toggle active" data-setting="triggerbot.TeamCheck"></div>
              <span class="enable-text">Team Check</span>
            </div>

            <div class="slider-label">Delay (s)</div>
            <div class="slider-container" id="delaySlider" data-setting="triggerbot.Delay">
              <div class="slider-track">
                <div class="slider-fill" id="delayFill"></div>
                <div class="slider-value" id="delayValue">0.00</div>
              </div>
            </div>

            <div class="slider-label">Max Studs</div>
            <div class="slider-container" id="maxStudsSlider" data-setting="triggerbot.MaxStuds">
              <div class="slider-track">
                <div class="slider-fill" id="maxStudsFill"></div>
                <div class="slider-value" id="maxStudsValue">120</div>
              </div>
            </div>

            <div class="slider-label">Prediction</div>
            <div class="slider-container" id="predSlider" data-setting="triggerbot.Prediction">
              <div class="slider-track">
                <div class="slider-fill" id="predFill"></div>
                <div class="slider-value" id="predValue">0.10</div>
              </div>
            </div>

            <div class="slider-label">FOV</div>
            <div class="slider-container" id="trigFovSlider" data-setting="triggerbot.FOV">
              <div class="slider-track">
                <div class="slider-fill" id="trigFovFill"></div>
                <div class="slider-value" id="trigFovValue">25</div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Settings / Configs Tab -->
    <div class="tab-content" id="settings">
      <div class="merged-panel">
        <div class="inner-container">
          <div class="half-panel">
            <div class="panel-header">Saved Configs</div>
            <div class="config-list" id="configList"></div>
          </div>
          <div class="half-panel">
            <div class="panel-header">Actions</div>
            <div style="padding:16px;">
              <div style="margin-bottom:16px;">
                <div style="font-size:12px;color:#bfbfbf;margin-bottom:6px;">Save Current Settings As</div>
                <input type="text" id="saveConfigInput" class="input-box" placeholder="Enter config name..."/>
                <button class="config-btn" onclick="saveCurrentConfig()">Save Config</button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>

<!-- Rename Modal -->
<div class="modal-overlay" id="renameModal">
  <div class="modal-box">
    <div class="modal-title">Rename Config</div>
    <input type="text" id="renameInput" class="modal-input" placeholder="New name..."/>
    <div class="modal-buttons">
      <button class="modal-btn" onclick="closeRenameModal()">Cancel</button>
      <button class="modal-btn primary" onclick="confirmRename()">Rename</button>
    </div>
  </div>
</div>

<script>
// ────────────────────────────────────────────────
let config = {cfg};

const sliders = {{}};

// ─── Tab Switching ─────────────────────────────────
document.querySelectorAll('.tab').forEach(tab => {{
  tab.addEventListener('click', () => {{
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(tc => tc.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById(tab.dataset.tab).classList.add('active');
  }});
}});

// ─── Toggle Click ──────────────────────────────────
document.querySelectorAll('.toggle[data-setting]').forEach(toggle => {{
  toggle.addEventListener('click', () => {{
    toggle.classList.toggle('active');
    const [sec, key] = toggle.dataset.setting.split('.');
    config[sec][key] = toggle.classList.contains('active');
    saveConfig();
  }});
}});

// ─── Keybind Picker ────────────────────────────────
document.querySelectorAll('.keybind-picker[data-setting]').forEach(picker => {{
  picker.addEventListener('click', () => {{
    picker.textContent = '...';
    const listener = e => {{
      e.preventDefault();
      let name = '';
      if (e.button !== undefined) {{
        name = e.button === 0 ? 'Left Mouse' :
               e.button === 2 ? 'Right Mouse' :
               e.button === 1 ? 'Middle Mouse' : `Mouse ${{e.button}}`;
      }} else if (e.key) {{
        name = e.key.toUpperCase();
        if (name === ' ') name = 'SPACE';
      }}
      picker.textContent = name || 'NONE';
      const [sec, key] = picker.dataset.setting.split('.');
      config[sec][key] = name;
      saveConfig();
      document.removeEventListener('keydown', listener);
      document.removeEventListener('mousedown', listener);
    }};
    document.addEventListener('keydown', listener, {{once: true}});
    document.addEventListener('mousedown', listener, {{once: true}});
  }});
}});

// ─── Dropdowns ─────────────────────────────────────
function setupDropdown(headerId, listId, settingPath) {{
  const header = document.getElementById(headerId);
  const list = document.getElementById(listId);
  header.addEventListener('click', () => list.classList.toggle('open'));
  list.querySelectorAll('.dropdown-item').forEach(item => {{
    item.addEventListener('click', () => {{
      header.textContent = item.textContent;
      list.querySelectorAll('.dropdown-item').forEach(i => i.classList.remove('selected'));
      item.classList.add('selected');
      list.classList.remove('open');
      const [sec, key] = settingPath.split('.');
      config[sec][key] = item.dataset.value;
      saveConfig();
    }});
  }});
}}

setupDropdown('bodyPartHeader', 'bodyPartList', 'camlock.BodyPart');
setupDropdown('easingHeader', 'easingList', 'camlock.EasingStyle');

// ─── Custom Sliders ────────────────────────────────
function makeSlider(containerId, fillId, valueId, min, max, step, decimals, setting) {{
  const container = document.getElementById(containerId);
  if (!container) return null;
  const fill = document.getElementById(fillId);
  const valEl = document.getElementById(valueId);

  let current = parseFloat(valEl.textContent);
  const obj = {{
    get value() {{ return current; }},
    set value(v) {{
      current = Math.max(min, Math.min(max, Math.round(v / step) * step));
      const pct = ((current - min) / (max - min)) * 100;
      fill.style.width = pct + '%';
      valEl.textContent = decimals > 0 ? current.toFixed(decimals) : Math.round(current);
    }},
    updateUI() {{ this.value = current; }}
  }};

  container.addEventListener('mousedown', e => {{
    const move = ev => {{
      const rect = container.getBoundingClientRect();
      let pct = (ev.clientX - rect.left) / rect.width;
      pct = Math.max(0, Math.min(1, pct));
      obj.value = min + pct * (max - min);
      const [sec, key] = setting.split('.');
      config[sec][key] = obj.value;
      saveConfig();
    }};
    const up = () => {{
      document.removeEventListener('mousemove', move);
      document.removeEventListener('mouseup', up);
    }};
    document.addEventListener('mousemove', move);
    document.addEventListener('mouseup', up);
    move(e);
  }});

  obj.updateUI();
  return obj;
}}

sliders.fov               = makeSlider('fovSlider',               'fovFill',               'fovValue',               10,  500,  1,   0, 'camlock.FOV');
sliders.smoothX           = makeSlider('smoothXSlider',           'smoothXFill',           'smoothXValue',           1,   50,   1,   0, 'camlock.SmoothX');
sliders.smoothY           = makeSlider('smoothYSlider',           'smoothYFill',           'smoothYValue',           1,   50,   1,   0, 'camlock.SmoothY');
sliders.camlockPred       = makeSlider('camlockPredSlider',       'camlockPredFill',       'camlockPredValue',       0,   1,    0.01,2, 'camlock.Prediction');
sliders.camlockMaxStuds   = makeSlider('camlockMaxStudsSlider',   'camlockMaxStudsFill',   'camlockMaxStudsValue',   50,  300,  1,   0, 'camlock.MaxStuds');
sliders.scale             = makeSlider('scaleSlider',             'scaleFill',             'scaleValue',             0.5, 2,    0.1, 1, 'camlock.Scale');
sliders.delay             = makeSlider('delaySlider',             'delayFill',             'delayValue',             0,   1,    0.01,2, 'triggerbot.Delay');
sliders.maxStuds          = makeSlider('maxStudsSlider',          'maxStudsFill',          'maxStudsValue',          50,  300,  1,   0, 'triggerbot.MaxStuds');
sliders.pred              = makeSlider('predSlider',              'predFill',              'predValue',              0,   1,    0.01,2, 'triggerbot.Prediction');
sliders.trigFov           = makeSlider('trigFovSlider',           'trigFovFill',           'trigFovValue',           5,   100,  1,   0, 'triggerbot.FOV');

// ─── Config Save / Load ────────────────────────────
async function saveConfig() {{
  try {{
    await fetch(`/api/config/{key}`, {{
      method: 'POST',
      headers: {{ 'Content-Type': 'application/json' }},
      body: JSON.stringify(config)
    }});
  }} catch(e) {{
    console.error('Save failed', e);
  }}
}}

async function loadConfig() {{
  try {{
    const res = await fetch(`/api/config/{key}`);
    config = await res.json();
    applyConfigToUI();
  }} catch(e) {{
    console.error('Load failed', e);
  }}
}}

function applyConfigToUI() {{
  // Toggles
  document.querySelectorAll('.toggle[data-setting]').forEach(el => {{
    const [sec, key] = el.dataset.setting.split('.');
    if (config[sec]?.[key] !== undefined) {{
      el.classList.toggle('active', !!config[sec][key]);
    }}
  }});

  // Keybinds
  document.querySelectorAll('.keybind-picker[data-setting]').forEach(el => {{
    const [sec, key] = el.dataset.setting.split('.');
    if (config[sec]?.[key]) el.textContent = config[sec][key];
  }});

  // Dropdowns
  if (config.camlock?.BodyPart) {{
    document.getElementById('bodyPartHeader').textContent = config.camlock.BodyPart;
    document.querySelectorAll('#bodyPartList .dropdown-item').forEach(it => {{
      it.classList.toggle('selected', it.dataset.value === config.camlock.BodyPart);
    }});
  }}
  if (config.camlock?.EasingStyle) {{
    document.getElementById('easingHeader').textContent = config.camlock.EasingStyle;
    document.querySelectorAll('#easingList .dropdown-item').forEach(it => {{
      it.classList.toggle('selected', it.dataset.value === config.camlock.EasingStyle);
    }});
  }}

  // Sliders
  Object.entries(sliders).forEach(([name, slider]) => {{
    if (slider) {{
      const path = name.replace(/([A-Z])/g, '.$1').toLowerCase();
      slider.value = eval(`config.${{path}}`) || slider.value;
      slider.updateUI();
    }}
  }});
}}

// ─── Saved Configs ─────────────────────────────────
async function loadSavedConfigs() {{
  try {{
    const res = await fetch(`/api/configs/{key}/list`);
    const data = await res.json();
    const list = document.getElementById('configList');
    list.innerHTML = '';
    data.configs.forEach((cfg, i) => {{
      const item = document.createElement('div');
      item.className = 'config-item';
      item.innerHTML = `
        <div class="config-name">${{cfg}}</div>
        <div class="config-dots" onclick="toggleConfigMenu(event, ${{i}})">⋮</div>
        <div class="config-menu" id="menu${{i}}">
          <div class="config-menu-item" onclick="loadConfigByName('${{cfg}}')">Load</div>
          <div class="config-menu-item" onclick="renameConfigPrompt('${{cfg}}')">Rename</div>
          <div class="config-menu-item" onclick="deleteConfigByName('${{cfg}}')">Delete</div>
        </div>
      `;
      list.appendChild(item);
    }});
  }} catch(e) {{
    console.error(e);
  }}
}}

function toggleConfigMenu(e, idx) {{
  e.stopPropagation();
  document.querySelectorAll('.config-menu').forEach(m => m.classList.remove('open'));
  document.getElementById(`menu${{idx}}`).classList.toggle('open');
}}

document.addEventListener('click', () => {{
  document.querySelectorAll('.config-menu').forEach(m => m.classList.remove('open'));
}});

async function saveCurrentConfig() {{
  const name = document.getElementById('saveConfigInput').value.trim();
  if (!name) return alert('Enter a name');
  try {{
    await fetch(`/api/configs/{key}/save`, {{
      method: 'POST',
      headers: {{ 'Content-Type': 'application/json' }},
      body: JSON.stringify({{ name, data: config }})
    }});
    document.getElementById('saveConfigInput').value = '';
    loadSavedConfigs();
  }} catch(e) {{
    alert('Save failed');
  }}
}}

async function loadConfigByName(name) {{
  try {{
    const res = await fetch(`/api/configs/{key}/load/${{name}}`, {{method: 'POST'}});
    const data = await res.json();
    config = data.config_data;
    applyConfigToUI();
    saveConfig();
  }} catch(e) {{
    alert('Load failed');
  }}
}}

let renameTarget = null;
function renameConfigPrompt(oldName) {{
  renameTarget = oldName;
  document.getElementById('renameInput').value = oldName;
  document.getElementById('renameModal').classList.add('active');
}}

function closeRenameModal() {{
  document.getElementById('renameModal').classList.remove('active');
  renameTarget = null;
}}

async function confirmRename() {{
  const newName = document.getElementById('renameInput').value.trim();
  if (!newName || newName === renameTarget) return closeRenameModal();
  try {{
    await fetch(`/api/configs/{key}/rename`, {{
      method: 'POST',
      headers: {{ 'Content-Type': 'application/json' }},
      body: JSON.stringify({{ old_name: renameTarget, new_name: newName }})
    }});
    loadSavedConfigs();
    closeRenameModal();
  }} catch(e) {{
    alert('Rename failed');
    closeRenameModal();
  }}
}}

async function deleteConfigByName(name) {{
  if (!confirm(`Delete ${{name}}?`)) return;
  try {{
    await fetch(`/api/configs/{key}/delete/${{name}}`, {{ method: 'POST' }});
    loadSavedConfigs();
  }} catch(e) {{
    alert('Delete failed');
  }}
}}

// Init
loadConfig();
loadSavedConfigs();
setInterval(loadConfig, 3000);  // optional live refresh

// Close modal on Esc
document.addEventListener('keydown', e => {{
  if (e.key === 'Escape') closeRenameModal();
}});
</script>
</body>
</html>
"""

if __name__ == "__main__":
    init_db()
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
