# main.py - Complete FastAPI Backend
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
        
        cur.execute("""CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            config TEXT NOT NULL
        )""")
    else:
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

class SavedConfigRequest(BaseModel):
    config_name: str
    config_data: dict

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

# === CONFIG SYNC ENDPOINTS (FIXED) ===

@app.get("/api/config/{key}")
def get_config(key: str):
    """Get config for a license key"""
    db = get_db()
    cur = db.cursor()
    
    try:
        cur.execute(q("SELECT config FROM settings WHERE key=%s"), (key,))
        result = cur.fetchone()
        
        if not result:
            if USE_POSTGRES:
                cur.execute(
                    "INSERT INTO settings (key, config) VALUES (%s, %s) ON CONFLICT (key) DO NOTHING",
                    (key, json.dumps(DEFAULT_CONFIG))
                )
            else:
                cur.execute(
                    "INSERT OR IGNORE INTO settings (key, config) VALUES (?, ?)",
                    (key, json.dumps(DEFAULT_CONFIG))
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

@app.post("/api/config/{key}")
def set_config(key: str, data: dict):
    """Save config for a license key"""
    db = get_db()
    cur = db.cursor()
    
    try:
        if USE_POSTGRES:
            cur.execute(
                """INSERT INTO settings (key, config) VALUES (%s, %s)
                   ON CONFLICT (key) DO UPDATE SET config = EXCLUDED.config""",
                (key, json.dumps(data))
            )
        else:
            cur.execute(
                """INSERT INTO settings (key, config) VALUES (?, ?)
                   ON CONFLICT (key) DO UPDATE SET config = excluded.config""",
                (key, json.dumps(data))
            )
        
        db.commit()
        db.close()
        return {"status": "ok"}
        
    except Exception as e:
        db.close()
        print(f"Error in set_config: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# === SAVED CONFIGS ENDPOINTS ===

@app.get("/api/configs/{license_key}/list")
def list_configs(license_key: str):
    """List saved configs"""
    db = get_db()
    cur = db.cursor()
    cur.execute(q("SELECT config_name, created_at FROM saved_configs WHERE license_key=%s ORDER BY created_at DESC"), (license_key,))
    rows = cur.fetchall()
    db.close()
    
    configs = [{"name": row[0], "created_at": row[1]} for row in rows]
    return {"configs": configs}

@app.post("/api/configs/{license_key}/save")
def save_config(license_key: str, data: SavedConfigRequest):
    """Save a config"""
    db = get_db()
    cur = db.cursor()
    
    try:
        cur.execute(q("SELECT id FROM saved_configs WHERE license_key=%s AND config_name=%s"), (license_key, data.config_name))
        existing = cur.fetchone()
        
        if existing:
            cur.execute(q("UPDATE saved_configs SET config_data=%s WHERE license_key=%s AND config_name=%s"),
                       (json.dumps(data.config_data), license_key, data.config_name))
        else:
            cur.execute(q("INSERT INTO saved_configs (license_key, config_name, config_data, created_at) VALUES (%s, %s, %s, %s)"),
                       (license_key, data.config_name, json.dumps(data.config_data), datetime.now().isoformat()))
        
        db.commit()
        db.close()
        return {"success": True, "message": "Config saved"}
    except Exception as e:
        db.close()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/configs/{license_key}/load/{config_name}")
def load_config(license_key: str, config_name: str):
    """Load a saved config"""
    db = get_db()
    cur = db.cursor()
    cur.execute(q("SELECT config_data FROM saved_configs WHERE license_key=%s AND config_name=%s"), (license_key, config_name))
    row = cur.fetchone()
    db.close()
    
    if not row:
        raise HTTPException(status_code=404, detail="Config not found")
    
    return json.loads(row[0])

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

@app.delete("/api/configs/{license_key}/delete/{config_name}")
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

    .nav-right {
      display: flex;
      gap: 1.5rem;
      align-items: center;
    }

    .nav-right a {
      color: rgba(255, 255, 255, 0.7);
      text-decoration: none;
      font-size: 0.95rem;
      font-weight: 500;
      transition: color 0.3s;
    }

    .nav-right a:hover {
      color: rgba(255, 255, 255, 1);
    }

    .login-btn {
      padding: 8px 20px;
      background: rgba(255,255,255,0.1);
      border: 1px solid rgba(255,255,255,0.2);
      border-radius: 6px;
      color: white;
      cursor: pointer;
      transition: all 0.2s;
      font-size: 0.9rem;
    }

    .login-btn:hover {
      background: rgba(255,255,255,0.15);
    }

    .user-info {
      padding: 8px 20px;
      background: rgba(255,255,255,0.05);
      border: 1px solid rgba(255,255,255,0.15);
      border-radius: 6px;
      color: white;
      cursor: pointer;
      transition: all 0.2s;
      font-size: 0.9rem;
    }

    .user-info:hover {
      background: rgba(255,255,255,0.1);
    }

    .content {
      position: fixed;
      inset: 0;
      z-index: 5;
      overflow-y: auto;
      pointer-events: none;
    }

    .content > * {
      pointer-events: auto;
    }

    .page {
      position: absolute;
      inset: 0;
      display: flex;
      flex-direction: column;
      justify-content: center;
      align-items: center;
      opacity: 0;
      pointer-events: none;
      transition: opacity 0.6s ease;
    }

    .page.active {
      opacity: 1;
      pointer-events: auto;
    }

    .configs-page {
      justify-content: flex-start;
      padding-top: 15vh;
    }

    .about-page {
      padding: 20px;
    }

    .about-page .description {
      max-width: 600px;
      text-align: center;
      font-size: 18px;
      line-height: 1.8;
      color: #aaa;
      margin-top: 40px;
    }

    .pricing-page {
      justify-content: flex-start;
      padding-top: 15vh;
    }

    .pricing-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 30px;
      width: 90%;
      max-width: 1000px;
      margin-top: 60px;
    }

    .pricing-card {
      background: rgba(18,18,22,0.6);
      border: 1px solid rgba(255,255,255,0.1);
      border-radius: 12px;
      padding: 32px;
      text-align: center;
      transition: all 0.3s;
    }

    .pricing-card:hover {
      transform: translateY(-8px);
      border-color: rgba(255,255,255,0.2);
      background: rgba(22,22,26,0.7);
    }

    .pricing-card.featured {
      border-color: rgba(255,255,255,0.3);
      background: rgba(25,25,30,0.8);
    }

    .plan-name {
      font-size: 24px;
      font-weight: 700;
      color: #fff;
      margin-bottom: 16px;
    }

    .plan-price {
      font-size: 48px;
      font-weight: 900;
      color: #fff;
      margin-bottom: 8px;
    }

    .plan-duration {
      font-size: 14px;
      color: #888;
      margin-bottom: 24px;
    }

    .plan-features {
      list-style: none;
      text-align: left;
      margin-top: 24px;
    }

    .plan-features li {
      padding: 10px 0;
      color: #aaa;
      font-size: 15px;
      border-bottom: 1px solid rgba(255,255,255,0.05);
    }

    .plan-features li:last-child {
      border-bottom: none;
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

    .configs-container {
      width: 90%;
      max-width: 1200px;
      margin-top: 60px;
    }

    .login-required {
      text-align: center;
      padding: 60px 20px;
      background: rgba(18,18,22,0.5);
      border-radius: 12px;
      border: 1px solid rgba(255,255,255,0.08);
    }

    .create-btn {
      padding: 14px 32px;
      background: transparent;
      border: 1px solid rgba(255,255,255,0.15);
      border-radius: 8px;
      color: #fff;
      font-size: 15px;
      cursor: pointer;
      transition: all 0.3s ease;
      margin-bottom: 30px;
      backdrop-filter: blur(10px);
      -webkit-backdrop-filter: blur(10px);
    }

    .create-btn:hover {
      background: rgba(255,255,255,0.05);
      border-color: rgba(255,255,255,0.25);
      transform: translateY(-2px);
    }

    .pagination {
      display: flex;
      justify-content: center;
      gap: 10px;
      margin-top: 30px;
      margin-bottom: 60px;
    }

    .page-btn {
      padding: 8px 16px;
      background: transparent;
      border: 1px solid rgba(255,255,255,0.15);
      border-radius: 6px;
      color: #fff;
      font-size: 14px;
      cursor: pointer;
      transition: all 0.2s;
      backdrop-filter: blur(10px);
    }

    .page-btn:hover:not(:disabled) {
      background: rgba(255,255,255,0.05);
      border-color: rgba(255,255,255,0.25);
    }

    .page-btn.active {
      background: rgba(255,255,255,0.1);
      border-color: rgba(255,255,255,0.3);
    }

    .page-btn:disabled {
      opacity: 0.3;
      cursor: not-allowed;
    }

    .config-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
      gap: 20px;
      margin-bottom: 40px;
    }

    .config-card {
      background: rgba(25,25,30,0.6);
      border: 1px solid rgba(255,255,255,0.08);
      border-radius: 12px;
      padding: 24px;
      transition: all 0.3s;
      cursor: pointer;
    }

    .config-card:hover {
      background: rgba(30,30,35,0.7);
      border-color: rgba(255,255,255,0.15);
      transform: translateY(-4px);
    }

    .config-name {
      font-size: 20px;
      font-weight: 700;
      margin-bottom: 8px;
    }

    .config-game {
      font-size: 12px;
      color: #888;
      background: rgba(255,255,255,0.05);
      padding: 4px 10px;
      border-radius: 4px;
      display: inline-block;
      margin-bottom: 12px;
    }

    .config-description {
      font-size: 14px;
      color: #aaa;
      line-height: 1.5;
      margin: 12px 0;
    }

    .config-footer {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-top: 16px;
      padding-top: 16px;
      border-top: 1px solid rgba(255,255,255,0.06);
      font-size: 13px;
      color: #666;
    }

    /* Modal */
    .modal {
      display: none;
      position: fixed;
      inset: 0;
      background: rgba(0,0,0,0.85);
      backdrop-filter: blur(10px);
      z-index: 1000;
      justify-content: center;
      align-items: center;
      opacity: 0;
      transition: opacity 0.3s ease;
    }

    .modal.active {
      display: flex;
      animation: fadeIn 0.3s ease forwards;
    }

    @keyframes fadeIn {
      from { opacity: 0; }
      to { opacity: 1; }
    }

    .modal-content {
      background: #1a1a1f;
      border: 1px solid rgba(255,255,255,0.1);
      border-radius: 8px;
      padding: 24px;
      width: 90%;
      max-width: 460px;
      max-height: 80vh;
      overflow-y: auto;
      box-shadow: 0 20px 60px rgba(0,0,0,0.5);
      transform: scale(0.95);
      animation: modalZoom 0.3s ease forwards;
    }

    @keyframes modalZoom {
      from { transform: scale(0.95); }
      to { transform: scale(1); }
    }

    .modal-title {
      font-size: 20px;
      font-weight: 600;
      margin-bottom: 20px;
      color: #fff;
    }

    .form-group {
      margin-bottom: 16px;
    }

    .form-label {
      display: block;
      font-size: 13px;
      color: #888;
      margin-bottom: 6px;
      font-weight: 500;
    }

    .form-input, .form-select, .form-textarea {
      width: 100%;
      padding: 10px 14px;
      background: transparent;
      border: 1px solid rgba(255,255,255,0.12);
      border-radius: 6px;
      color: #fff;
      font-size: 14px;
      font-family: inherit;
      transition: all 0.2s;
    }

    .form-input:focus, .form-select:focus, .form-textarea:focus {
      outline: none;
      border-color: rgba(255,255,255,0.3);
      background: rgba(255,255,255,0.02);
    }

    .form-textarea {
      resize: vertical;
      min-height: 90px;
    }

    .form-select {
      cursor: pointer;
    }

    .form-select option {
      background: #1a1a1f;
      color: #fff;
    }

    .modal-actions {
      display: flex;
      gap: 10px;
      margin-top: 20px;
    }

    .modal-btn {
      flex: 1;
      padding: 11px;
      background: transparent;
      border: 1px solid rgba(255,255,255,0.15);
      border-radius: 6px;
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s;
      color: #fff;
      backdrop-filter: blur(5px);
    }

    .modal-btn:hover {
      background: rgba(255,255,255,0.05);
      border-color: rgba(255,255,255,0.25);
    }

    .config-detail-modal .modal-content {
      max-width: 600px;
      background: #16161a;
      padding: 28px;
    }

    .config-stats {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 16px;
      margin: 20px 0;
      padding: 20px;
      background: rgba(255,255,255,0.02);
      border: 1px solid rgba(255,255,255,0.08);
      border-radius: 8px;
    }

    .stat-item {
      text-align: center;
    }

    .stat-label {
      font-size: 11px;
      color: #666;
      margin-bottom: 6px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .stat-value {
      font-size: 18px;
      font-weight: 700;
      color: #fff;
    }

    .detail-section {
      margin: 20px 0;
    }

    .detail-label {
      font-size: 12px;
      color: #666;
      margin-bottom: 8px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .detail-content {
      color: #aaa;
      line-height: 1.6;
      font-size: 14px;
      padding: 12px;
      background: rgba(255,255,255,0.02);
      border: 1px solid rgba(255,255,255,0.06);
      border-radius: 6px;
    }

    @media (max-width: 768px) {
      .title-word {
        font-size: 2.5rem;
      }
      
      .config-grid {
        grid-template-columns: 1fr;
      }
      
      .pricing-grid {
        grid-template-columns: 1fr;
      }
    }
  </style>
</head>
<body>
  <div class="image-container"></div>

  <nav class="navbar">
    <div class="nav-links">
      <a onclick="showPage('home')">Home</a>
      <a onclick="showPage('about')">About</a>
      <a onclick="showPage('pricing')">Pricing</a>
      <a onclick="showPage('configs')">Configs</a>
    </div>
    <div class="nav-right">
      <a href="https://dashboard.getaxion.lol">Menu</a>
      <div id="userArea"></div>
    </div>
  </nav>

  <div class="content">
    <!-- Home Page -->
    <div id="home" class="page active">
      <div class="title-wrapper">
        <span class="title-word" style="color:#ffffff;">WELCOME</span>
        <span class="title-word" style="color:#ffffff;">TO</span>
        <span class="title-word" style="color:#888888;">Axion</span>
      </div>
    </div>

    <!-- About Page -->
    <div id="about" class="page about-page">
      <div class="title-wrapper">
        <span class="title-word" style="color:#ffffff;">About</span>
        <span class="title-word" style="color:#888888;">Axion</span>
      </div>
      <div class="description">
        Axion is a Da Hood external designed to integrate seamlessly in-game. It delivers smooth, reliable performance while bypassing PC checks, giving you a consistent edge during star tryouts and competitive play.
      </div>
    </div>

    <!-- Pricing Page -->
    <div id="pricing" class="page pricing-page">
      <div class="title-wrapper">
        <span class="title-word" style="color:#ffffff;">Pricing</span>
      </div>
      <div class="pricing-grid">
        <div class="pricing-card">
          <div class="plan-name">Weekly</div>
          <div class="plan-price">$5</div>
          <div class="plan-duration">7 days</div>
          <ul class="plan-features">
            <li>✓ Full access to Axion</li>
            <li>✓ All features unlocked</li>
            <li>✓ Discord support</li>
          </ul>
        </div>
        <div class="pricing-card">
          <div class="plan-name">Monthly</div>
          <div class="plan-price">$15</div>
          <div class="plan-duration">30 days</div>
          <ul class="plan-features">
            <li>✓ Full access to Axion</li>
            <li>✓ All features unlocked</li>
            <li>✓ Priority support</li>
          </ul>
        </div>
        <div class="pricing-card featured">
          <div class="plan-name">Lifetime</div>
          <div class="plan-price">$40</div>
          <div class="plan-duration">forever</div>
          <ul class="plan-features">
            <li>✓ Full access to Axion</li>
            <li>✓ All features unlocked</li>
            <li>✓ VIP support</li>
            <li>✓ Best value</li>
          </ul>
        </div>
      </div>
    </div>

    <!-- Configs Page -->
    <div id="configs" class="page configs-page">
      <div class="title-wrapper">
        <span class="title-word" style="color:#ffffff;">Community</span>
        <span class="title-word" style="color:#888888;">Configs</span>
      </div>
      
      <div class="configs-container" id="configsContent">
        <div class="login-required">
          <h3 style="font-size: 24px; margin-bottom: 12px;">Login Required</h3>
          <p style="color: #888; margin-bottom: 20px;">Please login to view and create configs</p>
          <button class="login-btn" onclick="showLoginModal()">Login</button>
        </div>
      </div>
    </div>
  </div>

  <!-- Login Modal -->
  <div class="modal" id="loginModal">
    <div class="modal-content">
      <h2 class="modal-title">Login to Axion</h2>
      
      <div class="form-group">
        <label class="form-label">License Key</label>
        <input type="text" class="form-input" id="licenseKeyInput" placeholder="XXXX-XXXX-XXXX-XXXX">
      </div>

      <div class="modal-actions">
        <button class="modal-btn" onclick="closeLoginModal()">Cancel</button>
        <button class="modal-btn" onclick="submitLogin()">Login</button>
      </div>
    </div>
  </div>

  <!-- Create Config Modal -->
  <div class="modal" id="createModal">
    <div class="modal-content">
      <h2 class="modal-title">Create Public Config</h2>
      
      <div class="form-group">
        <label class="form-label">Select Your Saved Config</label>
        <select class="form-select" id="savedConfigSelect">
          <option value="">Loading your configs...</option>
        </select>
      </div>

      <div class="form-group">
        <label class="form-label">Config Name</label>
        <input type="text" class="form-input" id="configName" placeholder="e.g., Pro Camlock Settings">
      </div>

      <div class="form-group">
        <label class="form-label">Author Name</label>
        <input type="text" class="form-input" id="authorName" placeholder="Your name">
      </div>

      <div class="form-group">
        <label class="form-label">Game</label>
        <input type="text" class="form-input" id="gameName" placeholder="e.g., Da Hood, Hood Modded, etc.">
      </div>

      <div class="form-group">
        <label class="form-label">Description</label>
        <textarea class="form-textarea" id="configDescription" placeholder="Describe your config..."></textarea>
      </div>

      <div class="modal-actions">
        <button class="modal-btn" onclick="closeCreateModal()">Cancel</button>
        <button class="modal-btn" onclick="publishConfig()">Publish Config</button>
      </div>
    </div>
  </div>

  <!-- View Config Modal -->
  <div class="modal config-detail-modal" id="viewModal">
    <div class="modal-content">
      <h2 class="modal-title" id="viewConfigName">Config Name</h2>
      
      <div class="config-stats">
        <div class="stat-item">
          <div class="stat-label">Game</div>
          <div class="stat-value" id="viewGame">-</div>
        </div>
        <div class="stat-item">
          <div class="stat-label">Author</div>
          <div class="stat-value" id="viewAuthor">-</div>
        </div>
        <div class="stat-item">
          <div class="stat-label">Downloads</div>
          <div class="stat-value" id="viewDownloads">0</div>
        </div>
      </div>

      <div class="detail-section">
        <div class="detail-label">Description</div>
        <div class="detail-content" id="viewDescription">-</div>
      </div>

      <div class="modal-actions">
        <button class="modal-btn" onclick="closeViewModal()">Close</button>
        <button class="modal-btn" onclick="saveConfigToMenu()">Load to Menu</button>
      </div>
    </div>
  </div>

  <script>
    let currentUser = null;
    let allConfigs = [];
    let currentPage = 1;
    let currentViewConfig = null;
    const CONFIGS_PER_PAGE = 6;

    function showPage(pageId) {
      document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
      document.getElementById(pageId).classList.add('active');
      
      if (pageId === 'configs' && currentUser) {
        loadConfigs();
      }
    }

    function showLoginModal() {
      document.getElementById('loginModal').classList.add('active');
    }

    function closeLoginModal() {
      document.getElementById('loginModal').classList.remove('active');
    }

    async function submitLogin() {
      const licenseKey = document.getElementById('licenseKeyInput').value.trim();

      if (!licenseKey) {
        alert('Please enter your license key');
        return;
      }

      try {
        const res = await fetch(`/api/validate`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ key: licenseKey, hwid: 'web-login' })
        });

        if (res.ok) {
          const data = await res.json();
          
          if (data.valid) {
            currentUser = { 
              license_key: licenseKey
            };
            
            document.getElementById('userArea').innerHTML = `
              <div class="user-info" onclick="logout()">
                <span>${licenseKey.substring(0, 12)}...</span>
              </div>
            `;
            
            closeLoginModal();
            loadConfigs();
          } else {
            alert('Invalid or expired license key');
          }
        } else {
          alert('Invalid license key');
        }
      } catch (e) {
        alert('Connection error. Please check your internet connection.');
        console.error('Login error:', e);
      }
    }

    function logout() {
      currentUser = null;
      document.getElementById('userArea').innerHTML = `
        <button class="login-btn" onclick="showLoginModal()">Login</button>
      `;
      document.getElementById('configsContent').innerHTML = `
        <div class="login-required">
          <h3 style="font-size: 24px; margin-bottom: 12px;">Login Required</h3>
          <p style="color: #888; margin-bottom: 20px;">Please login to view and create configs</p>
          <button class="login-btn" onclick="showLoginModal()">Login</button>
        </div>
      `;
    }

    async function loadConfigs() {
      try {
        const res = await fetch('/api/public-configs');
        const data = await res.json();
        
        allConfigs = data.configs || [];
        renderConfigsPage();
      } catch (e) {
        console.error('Load error:', e);
        document.getElementById('configsContent').innerHTML = '<p>Error loading configs</p>';
      }
    }

    function renderConfigsPage() {
      const startIndex = (currentPage - 1) * CONFIGS_PER_PAGE;
      const endIndex = startIndex + CONFIGS_PER_PAGE;
      const pageConfigs = allConfigs.slice(startIndex, endIndex);
      const totalPages = Math.ceil(allConfigs.length / CONFIGS_PER_PAGE);

      let html = '<button class="create-btn" onclick="openCreateModal()">+ Create Config</button>';
      html += '<div class="config-grid">';
      
      if (pageConfigs.length > 0) {
        pageConfigs.forEach(config => {
          html += `
            <div class="config-card" onclick="viewConfig(${config.id})">
              <div class="config-name">${config.config_name}</div>
              <div class="config-game">${config.game_name}</div>
              <div class="config-description">${config.description}</div>
              <div class="config-footer">
                <div>by ${config.author_name}</div>
                <div>${config.downloads} downloads</div>
              </div>
            </div>
          `;
        });
      } else {
        html += '<p style="color: #888; text-align: center; padding: 40px;">No configs yet! Be the first to create one.</p>';
      }
      
      html += '</div>';

      if (totalPages > 1) {
        html += '<div class="pagination">';
        html += `<button class="page-btn" onclick="changePage(${currentPage - 1})" ${currentPage === 1 ? 'disabled' : ''}>Previous</button>`;
        
        for (let i = 1; i <= totalPages; i++) {
          html += `<button class="page-btn ${i === currentPage ? 'active' : ''}" onclick="changePage(${i})">${i}</button>`;
        }
        
        html += `<button class="page-btn" onclick="changePage(${currentPage + 1})" ${currentPage === totalPages ? 'disabled' : ''}>Next</button>`;
        html += '</div>';
      }
      
      document.getElementById('configsContent').innerHTML = html;
    }

    function changePage(page) {
      const totalPages = Math.ceil(allConfigs.length / CONFIGS_PER_PAGE);
      if (page < 1 || page > totalPages) return;
      currentPage = page;
      renderConfigsPage();
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }

    async function openCreateModal() {
      document.getElementById('createModal').classList.add('active');
      
      try {
        const res = await fetch(`/api/configs/${currentUser.license_key}/list`);
        const data = await res.json();
        
        const select = document.getElementById('savedConfigSelect');
        select.innerHTML = '<option value="">Select a config...</option>';
        
        if (data.configs && data.configs.length > 0) {
          data.configs.forEach(cfg => {
            select.innerHTML += `<option value="${cfg.name}">${cfg.name}</option>`;
          });
        } else {
          select.innerHTML = '<option value="">No saved configs found</option>';
        }
      } catch (e) {
        console.error('Error loading configs:', e);
      }
    }

    function closeCreateModal() {
      document.getElementById('createModal').classList.remove('active');
    }

    async function publishConfig() {
      const selectedConfig = document.getElementById('savedConfigSelect').value;
      const configName = document.getElementById('configName').value.trim();
      const authorName = document.getElementById('authorName').value.trim();
      const gameName = document.getElementById('gameName').value.trim();
      const description = document.getElementById('configDescription').value.trim();

      if (!selectedConfig) {
        alert('Please select a config');
        return;
      }
      if (!configName || !authorName || !gameName || !description) {
        alert('Please fill in all fields');
        return;
      }

      try {
        const configRes = await fetch(`/api/configs/${currentUser.license_key}/load/${selectedConfig}`);
        const configData = await configRes.json();

        const res = await fetch('/api/public-configs/create', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            config_name: configName,
            author_name: authorName,
            game_name: gameName,
            description: description,
            config_data: configData
          })
        });

        if (res.ok) {
          alert('Config published successfully!');
          closeCreateModal();
          loadConfigs();
        } else {
          const error = await res.json();
          alert('Error: ' + (error.detail || 'Failed to publish'));
        }
      } catch (e) {
        alert('Error publishing config: ' + e.message);
      }
    }

    async function viewConfig(configId) {
      try {
        const res = await fetch(`/api/public-configs/${configId}`);
        const data = await res.json();
        
        currentViewConfig = data;
        
        document.getElementById('viewConfigName').textContent = data.config_name;
        document.getElementById('viewGame').textContent = data.game_name;
        document.getElementById('viewAuthor').textContent = data.author_name;
        document.getElementById('viewDownloads').textContent = data.downloads;
        document.getElementById('viewDescription').textContent = data.description;
        
        document.getElementById('viewModal').classList.add('active');
        
        fetch(`/api/public-configs/${configId}/download`, { method: 'POST' });
      } catch (e) {
        alert('Error loading config');
      }
    }

    function closeViewModal() {
      document.getElementById('viewModal').classList.remove('active');
    }

    async function saveConfigToMenu() {
      if (!currentUser || !currentViewConfig) {
        alert('Please login first');
        return;
      }

      try {
        const res = await fetch(`/api/configs/${currentUser.license_key}/save`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            config_name: currentViewConfig.config_name,
            config_data: currentViewConfig.config_data
          })
        });

        if (res.ok) {
          alert('Config loaded to your menu!');
          closeViewModal();
        } else {
          alert('Failed to save config');
        }
      } catch (e) {
        alert('Error saving config: ' + e.message);
      }
    }

    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        closeLoginModal();
        closeCreateModal();
        closeViewModal();
      }
    });

    document.getElementById('userArea').innerHTML = `
      <button class="login-btn" onclick="showLoginModal()">Login</button>
    `;
  </script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
@app.get("/home", response_class=HTMLResponse)
def serve_home():
    """SPA Homepage with all tabs"""
    return _INDEX_HTML


@app.get("/{license_key}", response_class=HTMLResponse)
def serve_dashboard(license_key: str):
    """Personal dashboard"""
    if license_key in ["api", "favicon.ico", "home"]:
        raise HTTPException(status_code=404)
   
    db = get_db()
    cur = db.cursor()
   
    cur.execute(q("SELECT * FROM keys WHERE key=%s"), (license_key,))
    result = cur.fetchone()
    db.close()
   
    if not result:
        return "<html><body style='background:rgb(12,12,12);color:white;font-family:Arial;display:flex;align-items:center;justify-content:center;height:100vh'><div style='text-align:center'><h1 style='color:rgb(255,68,68)'>Invalid License</h1><p>License key not found</p></div></body></html>"
   
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<title>Axion Dashboard</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box;user-select:none}}
body{{height:100vh;background:radial-gradient(circle at top,#0f0f0f,#050505);font-family:Arial,sans-serif;color:#cfcfcf;display:flex;align-items:center;justify-content:center}}
.window{{width:760px;height:520px;background:linear-gradient(#111,#0a0a0a);border:1px solid #2a2a2a;box-shadow:0 0 40px rgba(0,0,0,0.8);display:flex;flex-direction:column;overflow:hidden}}
.topbar{{height:38px;background:linear-gradient(#1a1a1a,#0e0e0e);border-bottom:1px solid #2b2b2b;display:flex;align-items:center;padding:0 12px;gap:16px}}
.title{{font-size:13px;color:#bfbfbf;padding-right:16px;border-right:1px solid #2a2a2a}}
.tabs{{display:flex;gap:18px;font-size:12px}}
.tab{{color:#9a9a9a;cursor:pointer;transition:color 0.2s}}
.tab:hover,.tab.active{{color:#ffffff;text-shadow:0 0 4px rgba(255,255,255,0.3)}}
.topbar-right{{margin-left:auto;display:flex;align-items:center}}
.search-container{{position:relative;width:180px}}
.search-bar{{width:100%;height:26px;background:#0f0f0f;border:1px solid #2a2a2a;color:#cfcfcf;font-size:11px;padding:0 10px 0 32px;outline:none;transition:border-color 0.2s}}
.search-bar::placeholder{{color:#666}}
.search-bar:focus{{border-color:#555}}
.search-icon{{position:absolute;left:10px;top:50%;transform:translateY(-50%);width:14px;height:14px;pointer-events:none}}
.content{{flex:1;padding:10px;background:#0c0c0c;display:flex;align-items:center;justify-content:center;position:relative}}
.tab-content{{width:100%;height:100%;display:none}}
.tab-content.active{{display:block}}
.merged-panel{{width:100%;height:100%;background:#0c0c0c;border:1px solid #222;overflow:hidden;display:flex;align-items:center;justify-content:center}}
.inner-container{{width:98%;height:96%;display:flex;gap:14px;overflow:hidden}}
.half-panel{{flex:1;background:#111;border:1px solid #2a2a2a;box-shadow:0 0 25px rgba(0,0,0,0.6) inset;overflow-y:auto;padding:14px 16px;position:relative}}
.panel-header{{position:absolute;top:10px;left:16px;color:#bfbfbf;font-size:11px;font-weight:normal;pointer-events:none;z-index:1}}
.toggle-row{{position:absolute;left:16px;display:flex;align-items:center;gap:12px;z-index:1}}
.toggle-text{{display:flex;align-items:center;gap:12px}}
.toggle{{width:14px;height:14px;background:transparent;border:0.8px solid #1a1a1a;cursor:pointer;transition:background 0.2s;flex-shrink:0}}
.toggle.active{{background:#ccc;box-shadow:inset 0 0 4px rgba(0,0,0,0.5)}}
.enable-text{{color:#9a9a9a;font-size:11px;line-height:1;transition:color 0.25s;pointer-events:none}}
.toggle.active + .enable-text{{color:#e0e0e0}}
.keybind-picker{{width:80px;height:20px;background:#0f0f0f;border:1px solid #2a2a2a;color:#cfcfcf;font-size:10px;display:flex;align-items:center;justify-content:center;cursor:pointer}}
.slider-label{{position:absolute;left:16px;color:#bfbfbf;font-size:11px;font-weight:normal;z-index:1}}
.slider-container{{position:absolute;left:16px;width:210px;height:14px;background:#0f0f0f;border:1px solid #2a2a2a;overflow:hidden;z-index:10}}
.slider-track{{position:absolute;top:0;left:0;width:100%;height:100%;background:#0f0f0f}}
.slider-fill{{position:absolute;top:0;left:0;height:100%;background:#ccc;width:50%;transition:width 0.1s}}
.slider-value{{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);font-size:9px;font-weight:bold;pointer-events:none;z-index:3;transition:color 0.2s}}
.half-panel::-webkit-scrollbar{{width:5px}}
.half-panel::-webkit-scrollbar-track{{background:#0a0a0a;border-left:1px solid #111}}
.half-panel::-webkit-scrollbar-thumb{{background:#222}}
.half-panel::-webkit-scrollbar-thumb:hover{{background:#444}}
.custom-dropdown{{position:absolute;left:16px;width:210px;height:16px;z-index:100}}
.dropdown-header{{width:100%;height:100%;background:#0f0f0f;border:1px solid #2a2a2a;display:flex;align-items:center;padding:0 8px;cursor:pointer;font-size:10px;color:#cfcfcf}}
.dropdown-list{{position:absolute;top:100%;left:0;width:100%;max-height:160px;background:#0f0f0f;border:1px solid #2a2a2a;border-top:none;overflow-y:auto;display:none;z-index:101;box-shadow:0 8px 16px rgba(0,0,0,0.6)}}
.dropdown-list.open{{display:block}}
.dropdown-item{{padding:5px 10px;font-size:11px;color:#cfcfcf;cursor:pointer;transition:background 0.15s}}
.dropdown-item:hover{{background:#1a1a1a}}
.dropdown-item.selected{{background:#222;color:#fff}}
.config-list{{position:absolute;top:32px;left:16px;right:16px;bottom:16px;overflow-y:auto}}
.config-list::-webkit-scrollbar{{width:6px}}
.config-list::-webkit-scrollbar-track{{background:#0a0a0a;border-left:1px solid #111}}
.config-list::-webkit-scrollbar-thumb{{background:#333;border-radius:3px}}
.config-list::-webkit-scrollbar-thumb:hover{{background:#555}}
.config-item{{background:#0f0f0f;border:1px solid #2a2a2a;padding:6px 10px;margin-bottom:6px;display:flex;align-items:center;gap:10px;position:relative}}
.config-item:hover{{background:#1a1a1a}}
.config-name{{flex:1;font-size:10px;color:#fff;font-weight:normal}}
.config-dots{{width:20px;height:20px;display:flex;align-items:center;justify-content:center;cursor:pointer;color:#9a9a9a;font-size:16px;font-weight:bold;transition:color 0.2s;flex-shrink:0}}
.config-dots:hover{{color:#fff}}
.config-menu{{position:absolute;right:8px;top:28px;background:#0f0f0f;border:1px solid #2a2a2a;display:none;z-index:200;box-shadow:0 4px 12px rgba(0,0,0,0.6);min-width:100px}}
.config-menu.open{{display:block}}
.config-menu-item{{padding:6px 12px;font-size:10px;color:#cfcfcf;cursor:pointer;transition:background 0.2s;border-bottom:1px solid #1a1a1a;white-space:nowrap}}
.config-menu-item:last-child{{border-bottom:none}}
.config-menu-item:hover{{background:#1a1a1a;color:#fff}}
.input-box{{width:100%;height:24px;background:#0f0f0f;border:1px solid #2a2a2a;color:#cfcfcf;font-size:11px;padding:0 8px;outline:none}}
.config-btn{{background:#0f0f0f;border:1px solid #2a2a2a;padding:6px 12px;font-size:11px;color:#cfcfcf;cursor:pointer;transition:background 0.2s;width:100%;margin-top:6px}}
.config-btn:hover{{background:#222}}
.modal-overlay{{position:fixed;top:0;left:0;width:100vw;height:100vh;background:rgba(0,0,0,0.7);backdrop-filter:blur(4px);display:none;align-items:center;justify-content:center;z-index:9999}}
.modal-overlay.active{{display:flex}}
.modal-box{{background:linear-gradient(#111,#0a0a0a);border:1px solid #2a2a2a;padding:24px;min-width:300px;box-shadow:0 8px 32px rgba(0,0,0,0.8)}}
.modal-title{{color:#fff;font-size:13px;margin-bottom:16px;font-weight:normal}}
.modal-input{{width:100%;height:28px;background:#0f0f0f;border:1px solid #2a2a2a;color:#cfcfcf;font-size:11px;padding:0 10px;outline:none;margin-bottom:12px}}
.modal-input:focus{{border-color:#555}}
.modal-buttons{{display:flex;gap:8px}}
.modal-btn{{flex:1;height:28px;background:#0f0f0f;border:1px solid #2a2a2a;color:#cfcfcf;font-size:11px;cursor:pointer;transition:background 0.2s}}
.modal-btn:hover{{background:#222}}
.modal-btn.primary{{background:#1a1a1a}}
.modal-btn.primary:hover{{background:#252525}}
</style>
</head>
<body>
<div class="window">
    <div class="topbar">
        <div class="title">Axion</div>
        <div class="tabs">
            <div class="tab active" data-tab="aimbot">aimbot</div>
            <div class="tab" data-tab="triggerbot">triggerbot</div>
            <div class="tab" data-tab="settings">settings</div>
        </div>
        <div class="topbar-right">
            <div class="search-container">
                <img src="https://img.icons8.com/?size=100&id=14079&format=png&color=FFFFFF" alt="Search" class="search-icon">
                <input type="text" id="searchInput" class="search-bar" placeholder="Search...">
            </div>
        </div>
    </div>
    <div class="content">
        <div class="tab-content active" id="aimbot">
            <div class="merged-panel">
                <div class="inner-container">
                    <div class="half-panel">
                        <div class="panel-header">aimbot</div>
                        <div class="toggle-row" style="top:32px">
                            <div class="toggle-text">
                                <div class="toggle active" data-setting="camlock.Enabled"></div>
                                <span class="enable-text">Enable Aimbot</span>
                            </div>
                            <div class="keybind-picker" data-setting="camlock.Keybind">Q</div>
                        </div>
                        <div class="toggle-row" style="top:58px">
                            <div class="toggle" data-setting="camlock.UnlockOnDeath"></div>
                            <span class="enable-text">Unlock On Death</span>
                        </div>
                        <div class="toggle-row" style="top:82px">
                            <div class="toggle" data-setting="camlock.SelfDeathCheck"></div>
                            <span class="enable-text">Self Death Check</span>
                        </div>
                        <div class="toggle-row" style="top:106px">
                            <div class="toggle" data-setting="camlock.ClosestPart"></div>
                            <span class="enable-text">Closest Part</span>
                        </div>
                        <div class="toggle-row" style="top:130px">
                            <div class="toggle active" data-setting="camlock.EnableSmoothing"></div>
                            <span class="enable-text">Enable Smoothing</span>
                        </div>
                        <div class="toggle-row" style="top:154px">
                            <div class="toggle active" data-setting="camlock.EnablePrediction"></div>
                            <span class="enable-text">Enable Prediction</span>
                        </div>
                        <div class="slider-label" style="top:180px">Body Part</div>
                        <div class="custom-dropdown" style="top:194px" id="bodyPartDropdown" data-setting="camlock.BodyPart">
                            <div class="dropdown-header" id="bodyPartHeader">Head</div>
                            <div class="dropdown-list" id="bodyPartList">
                                <div class="dropdown-item selected" data-value="Head">Head</div>
                                <div class="dropdown-item" data-value="UpperTorso">UpperTorso</div>
                                <div class="dropdown-item" data-value="LowerTorso">LowerTorso</div>
                                <div class="dropdown-item" data-value="HumanoidRootPart">HumanoidRootPart</div>
                                <div class="dropdown-item" data-value="LeftUpperArm">LeftUpperArm</div>
                                <div class="dropdown-item" data-value="RightUpperArm">RightUpperArm</div>
                                <div class="dropdown-item" data-value="LeftLowerArm">LeftLowerArm</div>
                                <div class="dropdown-item" data-value="RightLowerArm">RightLowerArm</div>
                                <div class="dropdown-item" data-value="LeftHand">LeftHand</div>
                                <div class="dropdown-item" data-value="RightHand">RightHand</div>
                                <div class="dropdown-item" data-value="LeftUpperLeg">LeftUpperLeg</div>
                                <div class="dropdown-item" data-value="RightUpperLeg">RightUpperLeg</div>
                                <div class="dropdown-item" data-value="LeftLowerLeg">LeftLowerLeg</div>
                                <div class="dropdown-item" data-value="RightLowerLeg">RightLowerLeg</div>
                                <div class="dropdown-item" data-value="LeftFoot">LeftFoot</div>
                                <div class="dropdown-item" data-value="RightFoot">RightFoot</div>
                            </div>
                        </div>
                    </div>
                    <div class="half-panel">
                        <div class="panel-header">aimbot settings</div>
                        <div class="slider-label" style="top:32px">FOV</div>
                        <div class="slider-container" id="fovSlider" style="top:46px" data-setting="camlock.FOV">
                            <div class="slider-track">
                                <div class="slider-fill" id="fovFill"></div>
                                <div class="slider-value" id="fovValue">280</div>
                            </div>
                        </div>
                        <div class="slider-label" style="top:72px">Smooth X</div>
                        <div class="slider-container" id="smoothXSlider" style="top:86px" data-setting="camlock.SmoothX">
                            <div class="slider-track">
                                <div class="slider-fill" id="smoothXFill"></div>
                                <div class="slider-value" id="smoothXValue">14</div>
                            </div>
                        </div>
                        <div class="slider-label" style="top:112px">Smooth Y</div>
                        <div class="slider-container" id="smoothYSlider" style="top:126px" data-setting="camlock.SmoothY">
                            <div class="slider-track">
                                <div class="slider-fill" id="smoothYFill"></div>
                                <div class="slider-value" id="smoothYValue">14</div>
                            </div>
                        </div>
                        <div class="slider-label" style="top:152px">Prediction</div>
                        <div class="slider-container" id="camlockPredSlider" style="top:166px" data-setting="camlock.Prediction">
                            <div class="slider-track">
                                <div class="slider-fill" id="camlockPredFill"></div>
                                <div class="slider-value" id="camlockPredValue">0.14</div>
                            </div>
                        </div>
                        <div class="slider-label" style="top:192px">Max Studs</div>
                        <div class="slider-container" id="camlockMaxStudsSlider" style="top:206px" data-setting="camlock.MaxStuds">
                            <div class="slider-track">
                                <div class="slider-fill" id="camlockMaxStudsFill"></div>
                                <div class="slider-value" id="camlockMaxStudsValue">120</div>
                            </div>
                        </div>
                        <div class="slider-label" style="top:232px">Easing Style</div>
                        <div class="custom-dropdown" style="top:246px" id="easingDropdown" data-setting="camlock.EasingStyle">
                            <div class="dropdown-header" id="easingHeader">Linear</div>
                            <div class="dropdown-list" id="easingList">
                                <div class="dropdown-item selected" data-value="Linear">Linear</div>
                                <div class="dropdown-item" data-value="Sine">Sine</div>
                                <div class="dropdown-item" data-value="Quad">Quad</div>
                                <div class="dropdown-item" data-value="Cubic">Cubic</div>
                                <div class="dropdown-item" data-value="Quart">Quart</div>
                                <div class="dropdown-item" data-value="Quint">Quint</div>
                                <div class="dropdown-item" data-value="Expo">Expo</div>
                                <div class="dropdown-item" data-value="Circ">Circ</div>
                                <div class="dropdown-item" data-value="Back">Back</div>
                                <div class="dropdown-item" data-value="Elastic">Elastic</div>
                                <div class="dropdown-item" data-value="Bounce">Bounce</div>
                            </div>
                        </div>
                        <div class="toggle-row" style="top:272px">
                            <div class="toggle active" data-setting="camlock.ScaleToggle"></div>
                            <span class="enable-text">Scale Toggle</span>
                        </div>
                        <div class="slider-label" style="top:298px">Scale</div>
                        <div class="slider-container" id="scaleSlider" style="top:312px" data-setting="camlock.Scale">
                            <div class="slider-track">
                                <div class="slider-fill" id="scaleFill"></div>
                                <div class="slider-value" id="scaleValue">1.0</div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="tab-content" id="triggerbot">
            <div class="merged-panel">
                <div class="inner-container">
                    <div class="half-panel">
                        <div class="panel-header">triggerbot</div>
                        <div class="toggle-row" style="top:32px">
                            <div class="toggle-text">
                                <div class="toggle active" data-setting="triggerbot.Enabled"></div>
                                <span class="enable-text">Enable Triggerbot</span>
                            </div>
                            <div class="keybind-picker" data-setting="triggerbot.Keybind">Right Mouse</div>
                        </div>
                        <div class="toggle-row" style="top:58px">
                            <div class="toggle-text">
                                <div class="toggle" data-setting="triggerbot.TargetMode"></div>
                                <span class="enable-text">Target Mode</span>
                            </div>
                            <div class="keybind-picker" data-setting="triggerbot.TargetKeybind">Middle Mouse</div>
                        </div>
                    </div>
                    <div class="half-panel">
                        <div class="panel-header">triggerbot settings</div>
                        <div class="toggle-row" style="top:32px">
                            <div class="toggle active" data-setting="triggerbot.StudCheck"></div>
                            <span class="enable-text">Stud Check</span>
                        </div>
                        <div class="toggle-row" style="top:56px">
                            <div class="toggle active" data-setting="triggerbot.DeathCheck"></div>
                            <span class="enable-text">Death Check</span>
                        </div>
                        <div class="toggle-row" style="top:80px">
                            <div class="toggle active" data-setting="triggerbot.KnifeCheck"></div>
                            <span class="enable-text">Knife Check</span>
                        </div>
                        <div class="toggle-row" style="top:104px">
                            <div class="toggle active" data-setting="triggerbot.TeamCheck"></div>
                            <span class="enable-text">Team Check</span>
                        </div>
                        <div class="slider-label" style="top:130px">Delay (s)</div>
                        <div class="slider-container" id="delaySlider" style="top:144px" data-setting="triggerbot.Delay">
                            <div class="slider-track">
                                <div class="slider-fill" id="delayFill"></div>
                                <div class="slider-value" id="delayValue">0.05</div>
                            </div>
                        </div>
                        <div class="slider-label" style="top:170px">Max Studs</div>
                        <div class="slider-container" id="maxStudsSlider" style="top:184px" data-setting="triggerbot.MaxStuds">
                            <div class="slider-track">
                                <div class="slider-fill" id="maxStudsFill"></div>
                                <div class="slider-value" id="maxStudsValue">120</div>
                            </div>
                        </div>
                        <div class="slider-label" style="top:210px">Prediction</div>
                        <div class="slider-container" id="predSlider" style="top:224px" data-setting="triggerbot.Prediction">
                            <div class="slider-track">
                                <div class="slider-fill" id="predFill"></div>
                                <div class="slider-value" id="predValue">0.10</div>
                            </div>
                        </div>
                        <div class="slider-label" style="top:250px">FOV</div>
                        <div class="slider-container" id="trigFovSlider" style="top:264px" data-setting="triggerbot.FOV">
                            <div class="slider-track">
                                <div class="slider-fill" id="trigFovFill"></div>
                                <div class="slider-value" id="trigFovValue">25</div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="tab-content" id="settings">
            <div class="merged-panel">
                <div class="inner-container">
                    <div class="half-panel">
                        <div class="panel-header">saved configs</div>
                        <div class="config-list" id="configList"></div>
                    </div>
                    <div class="half-panel">
                        <div class="panel-header">actions</div>
                        <div style="position:absolute;top:32px;left:16px;right:16px">
                            <div style="margin-bottom:12px">
                                <div style="font-size:11px;color:#bfbfbf;margin-bottom:4px">Save Current Config</div>
                                <input type="text" id="saveConfigInput" class="input-box" placeholder="Config name...">
                                <button class="config-btn" style="margin-top:4px;width:100%" onclick="saveCurrentConfig()">Save</button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<div class="modal-overlay" id="renameModal">
    <div class="modal-box">
        <div class="modal-title">Rename Config</div>
        <input type="text" id="renameInput" class="modal-input" placeholder="Enter new name...">
        <div class="modal-buttons">
            <button class="modal-btn" onclick="closeRenameModal()">Cancel</button>
            <button class="modal-btn primary" onclick="confirmRename()">Rename</button>
        </div>
    </div>
</div>

<script>
const key = "{license_key}";

let config = {{
    "triggerbot": {{
        "Enabled": true,
        "Keybind": "Right Mouse",
        "Delay": 0.05,
        "MaxStuds": 120,
        "StudCheck": true,
        "DeathCheck": true,
        "KnifeCheck": true,
        "TeamCheck": true,
        "TargetMode": false,
        "TargetKeybind": "Middle Mouse",
        "Prediction": 0.1,
        "FOV": 25
    }},
    "camlock": {{
        "Enabled": true,
        "Keybind": "Q",
        "FOV": 280.0,
        "SmoothX": 14.0,
        "SmoothY": 14.0,
        "EnableSmoothing": true,
        "EasingStyle": "Linear",
        "Prediction": 0.14,
        "EnablePrediction": true,
        "MaxStuds": 120.0,
        "UnlockOnDeath": true,
        "SelfDeathCheck": true,
        "BodyPart": "Head",
        "ClosestPart": false,
        "ScaleToggle": true,
        "Scale": 1.0
    }}
}};

document.querySelectorAll('.tab').forEach(tab => {{
    tab.addEventListener('click', () => {{
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(tc => tc.classList.remove('active'));
        tab.classList.add('active');
        document.getElementById(tab.getAttribute('data-tab')).classList.add('active');
    }});
}});

async function saveConfig() {{
    try {{
        await fetch(`/api/config/${{key}}`, {{
            method: 'POST',
            headers: {{'Content-Type': 'application/json'}},
            body: JSON.stringify(config)
        }});
    }} catch(e) {{
        console.error('Save failed:', e);
    }}
}}

async function loadConfig() {{
    try {{
        const res = await fetch(`/api/config/${{key}}`);
        config = await res.json();
        applyConfigToUI();
    }} catch(e) {{
        console.error('Load failed:', e);
    }}
}}

function applyConfigToUI() {{
    document.querySelectorAll('.toggle[data-setting]').forEach(toggle => {{
        const setting = toggle.dataset.setting;
        const [section, key] = setting.split('.');
        if (config[section] && config[section][key] !== undefined) {{
            toggle.classList.toggle('active', config[section][key]);
        }}
    }});

    document.querySelectorAll('.keybind-picker[data-setting]').forEach(picker => {{
        const setting = picker.dataset.setting;
        const [section, key] = setting.split('.');
        if (config[section] && config[section][key] !== undefined) {{
            picker.textContent = config[section][key];
        }}
    }});

    if (sliders.delay)       {{ sliders.delay.current = config.triggerbot.Delay;       sliders.delay.update(); }}
    if (sliders.maxStuds)    {{ sliders.maxStuds.current = config.triggerbot.MaxStuds; sliders.maxStuds.update(); }}
    if (sliders.pred)        {{ sliders.pred.current = config.triggerbot.Prediction;   sliders.pred.update(); }}
    if (sliders.trigFov)     {{ sliders.trigFov.current = config.triggerbot.FOV;       sliders.trigFov.update(); }}
    if (sliders.fov)         {{ sliders.fov.current = config.camlock.FOV;              sliders.fov.update(); }}
    if (sliders.smoothX)     {{ sliders.smoothX.current = config.camlock.SmoothX;      sliders.smoothX.update(); }}
    if (sliders.smoothY)     {{ sliders.smoothY.current = config.camlock.SmoothY;      sliders.smoothY.update(); }}
    if (sliders.camlockPred) {{ sliders.camlockPred.current = config.camlock.Prediction; sliders.camlockPred.update(); }}
    if (sliders.camlockMaxStuds) {{ sliders.camlockMaxStuds.current = config.camlock.MaxStuds; sliders.camlockMaxStuds.update(); }}
    if (sliders.scale)       {{ sliders.scale.current = config.camlock.Scale;          sliders.scale.update(); }}

    if (config.camlock.BodyPart) {{
        document.getElementById('bodyPartHeader').textContent = config.camlock.BodyPart;
        document.querySelectorAll('#bodyPartList .dropdown-item').forEach(item => {{
            item.classList.toggle('selected', item.dataset.value === config.camlock.BodyPart);
        }});
    }}
    if (config.camlock.EasingStyle) {{
        document.getElementById('easingHeader').textContent = config.camlock.EasingStyle;
        document.querySelectorAll('#easingList .dropdown-item').forEach(item => {{
            item.classList.toggle('selected', item.dataset.value === config.camlock.EasingStyle);
        }});
    }}
}}

document.querySelectorAll('.toggle[data-setting]').forEach(toggle => {{
    toggle.addEventListener('click', () => {{
        toggle.classList.toggle('active');
        const setting = toggle.dataset.setting;
        const [section, key] = setting.split('.');
        config[section][key] = toggle.classList.contains('active');
        saveConfig();
    }});
}});

document.querySelectorAll('.keybind-picker[data-setting]').forEach(picker => {{
    picker.addEventListener('click', () => {{
        picker.textContent = '...';
        const listener = (e) => {{
            e.preventDefault();
            let keyName = '';
            if (e.button !== undefined) {{
                keyName = e.button === 0 ? 'Left Mouse' :
                          e.button === 2 ? 'Right Mouse' :
                          e.button === 1 ? 'Middle Mouse' : `Mouse${{e.button}}`;
            }} else if (e.key) {{
                keyName = e.key.toUpperCase();
                if (keyName === ' ') keyName = 'SPACE';
            }}
            picker.textContent = keyName || 'NONE';
            const setting = picker.dataset.setting;
            const [section, key] = setting.split('.');
            config[section][key] = keyName;
            saveConfig();
            document.removeEventListener('keydown', listener);
            document.removeEventListener('mousedown', listener);
        }};
        document.addEventListener('keydown', listener, {{once: true}});
        document.addEventListener('mousedown', listener, {{once: true}});
    }});
}});

document.getElementById('bodyPartHeader').addEventListener('click', () => {{
    document.getElementById('bodyPartList').classList.toggle('open');
}});

document.querySelectorAll('#bodyPartList .dropdown-item').forEach(item => {{
    item.addEventListener('click', () => {{
        const value = item.dataset.value;
        document.getElementById('bodyPartHeader').textContent = value;
        document.querySelectorAll('#bodyPartList .dropdown-item').forEach(i => i.classList.remove('selected'));
        item.classList.add('selected');
        document.getElementById('bodyPartList').classList.remove('open');
        config.camlock.BodyPart = value;
        saveConfig();
    }});
}});

document.getElementById('easingHeader').addEventListener('click', () => {{
    document.getElementById('easingList').classList.toggle('open');
}});

document.querySelectorAll('#easingList .dropdown-item').forEach(item => {{
    item.addEventListener('click', () => {{
        const value = item.dataset.value;
        document.getElementById('easingHeader').textContent = value;
        document.querySelectorAll('#easingList .dropdown-item').forEach(i => i.classList.remove('selected'));
        item.classList.add('selected');
        document.getElementById('easingList').classList.remove('open');
        config.camlock.EasingStyle = value;
        saveConfig();
    }});
}});

const sliders = {{}};

function createDecimalSlider(id, fillId, valueId, defaultVal, min, max, step, setting, textColorThreshold = 0.5) {{
    const slider = document.getElementById(id);
    if (!slider) return null;
    const fill = document.getElementById(fillId);
    const valueText = document.getElementById(valueId);
    
    const obj = {{
        current: defaultVal,
        min: min,
        max: max,
        step: step,
        setting: setting,
        threshold: textColorThreshold,
        update: function() {{
            const percent = ((this.current - this.min) / (this.max - this.min)) * 100;
            fill.style.width = percent + '%';
            valueText.textContent = this.current.toFixed(2);
            valueText.style.color = this.current < this.threshold ? '#fff' : '#000';
        }}
    }};

    slider.addEventListener('mousedown', (e) => {{
        const rect = slider.getBoundingClientRect();
        function move(e) {{
            const x = e.clientX - rect.left;
            let percent = Math.max(0, Math.min(100, (x / rect.width) * 100));
            obj.current = obj.min + (percent / 100) * (obj.max - obj.min);
            obj.current = Math.round(obj.current / obj.step) * obj.step;
            obj.current = Math.max(obj.min, Math.min(obj.max, obj.current));
            obj.update();
            const [section, key] = obj.setting.split('.');
            config[section][key] = obj.current;
            saveConfig();
        }}
        function up() {{
            document.removeEventListener('mousemove', move);
            document.removeEventListener('mouseup', up);
        }}
        document.addEventListener('mousemove', move);
        document.addEventListener('mouseup', up);
        move(e);
    }});

    obj.update();
    return obj;
}}

function createIntSlider(id, fillId, valueId, defaultVal, max, blackThreshold, setting) {{
    const slider = document.getElementById(id);
    if (!slider) return null;
    const fill = document.getElementById(fillId);
    const valueText = document.getElementById(valueId);
    const obj = {{
        current: defaultVal,
        max: max,
        blackThreshold: blackThreshold,
        setting: setting,
        update: function() {{
            const percent = (this.current / this.max) * 100;
            fill.style.width = percent + '%';
            valueText.textContent = Math.round(this.current);
            valueText.style.color = this.current >= this.blackThreshold ? '#000' : '#fff';
        }}
    }};
    slider.addEventListener('mousedown', (e) => {{
        const rect = slider.getBoundingClientRect();
        function move(e) {{
            const x = e.clientX - rect.left;
            const percent = Math.max(0, Math.min(100, (x / rect.width) * 100));
            obj.current = (percent / 100) * obj.max;
            obj.update();
            const [section, key] = obj.setting.split('.');
            config[section][key] = Math.round(obj.current);
            saveConfig();
        }}
        function up() {{
            document.removeEventListener('mousemove', move);
            document.removeEventListener('mouseup', up);
        }}
        document.addEventListener('mousemove', move);
        document.addEventListener('mouseup', up);
        move(e);
    }});
    obj.update();
    return obj;
}}

sliders.delay           = createDecimalSlider('delaySlider',       'delayFill',       'delayValue',       0.05, 0.01, 1.00, 0.01, 'triggerbot.Delay');
sliders.maxStuds        = createIntSlider(   'maxStudsSlider',    'maxStudsFill',    'maxStudsValue',    120,  300,  150,   'triggerbot.MaxStuds');
sliders.pred            = createDecimalSlider('predSlider',        'predFill',        'predValue',        0.10, 0.01, 1.00, 0.01, 'triggerbot.Prediction');
sliders.trigFov         = createIntSlider(   'trigFovSlider',     'trigFovFill',     'trigFovValue',     25,   100,  50,    'triggerbot.FOV');
sliders.fov             = createIntSlider(   'fovSlider',         'fovFill',         'fovValue',         280,  500,  250,   'camlock.FOV');
sliders.smoothX         = createIntSlider(   'smoothXSlider',     'smoothXFill',     'smoothXValue',     14,   30,   15,    'camlock.SmoothX');
sliders.smoothY         = createIntSlider(   'smoothYSlider',     'smoothYFill',     'smoothYValue',     14,   30,   15,    'camlock.SmoothY');
sliders.camlockPred     = createDecimalSlider('camlockPredSlider', 'camlockPredFill', 'camlockPredValue', 0.14, 0.01, 1.00, 0.01, 'camlock.Prediction');
sliders.camlockMaxStuds = createIntSlider(   'camlockMaxStudsSlider', 'camlockMaxStudsFill', 'camlockMaxStudsValue', 120, 300, 150, 'camlock.MaxStuds');
sliders.scale = createDecimalSlider('scaleSlider', 'scaleFill', 'scaleValue', 1.0, 0.5, 2.0, 0.1, 'camlock.Scale', 1.20);

async function loadSavedConfigs() {{
    try {{
        const res = await fetch(`/api/configs/${{key}}/list`);
        const data = await res.json();
        const list = document.getElementById('configList');
        list.innerHTML = '';
        data.configs.forEach((cfg, idx) => {{
            const div = document.createElement('div');
            div.className = 'config-item';
            div.innerHTML = `
                <div class="config-name">${{cfg.name}}</div>
                <div class="config-dots" onclick="toggleConfigMenu(event, ${{idx}})">⋮</div>
                <div class="config-menu" id="configMenu${{idx}}">
                    <div class="config-menu-item" onclick="loadConfigByName('${{cfg.name}}')">Load</div>
                    <div class="config-menu-item" onclick="renameConfigPrompt('${{cfg.name}}')">Rename</div>
                    <div class="config-menu-item" onclick="deleteConfigByName('${{cfg.name}}')">Delete</div>
                </div>
            `;
            list.appendChild(div);
        }});
    }} catch(e) {{
        console.error(e);
    }}
}}

function toggleConfigMenu(e, idx) {{
    e.stopPropagation();
    const menu = document.getElementById(`configMenu${{idx}}`);
    document.querySelectorAll('.config-menu').forEach(m => {{
        if (m !== menu) m.classList.remove('open');
    }});
    menu.classList.toggle('open');
}}

document.addEventListener('click', () => {{
    document.querySelectorAll('.config-menu').forEach(m => m.classList.remove('open'));
}});

async function saveCurrentConfig() {{
    const name = document.getElementById('saveConfigInput').value.trim();
    if (!name) return alert('Enter config name');
    try {{
        await fetch(`/api/configs/${{key}}/save`, {{
            method: 'POST',
            headers: {{'Content-Type': 'application/json'}},
            body: JSON.stringify({{config_name: name, config_data: config}})
        }});
        document.getElementById('saveConfigInput').value = '';
        await loadSavedConfigs();
    }} catch(e) {{
        alert('Failed to save');
    }}
}}

async function loadConfigByName(name) {{
    try {{
        const res = await fetch(`/api/configs/${{key}}/load/${{name}}`);
        config = await res.json();
        applyConfigToUI();
        await saveConfig();
    }} catch(e) {{
        alert('Failed to load');
    }}
}}

let currentRenameConfig = null;

function renameConfigPrompt(oldName) {{
    currentRenameConfig = oldName;
    document.getElementById('renameInput').value = oldName;
    document.getElementById('renameModal').classList.add('active');
    document.getElementById('renameInput').focus();
    document.getElementById('renameInput').select();
}}

function closeRenameModal() {{
    document.getElementById('renameModal').classList.remove('active');
    currentRenameConfig = null;
}}

async function confirmRename() {{
    const newName = document.getElementById('renameInput').value.trim();
    if (!newName || newName === currentRenameConfig) {{
        closeRenameModal();
        return;
    }}
    try {{
        await fetch(`/api/configs/${{key}}/rename`, {{
            method: 'POST',
            headers: {{'Content-Type': 'application/json'}},
            body: JSON.stringify({{old_name: currentRenameConfig, new_name: newName}})
        }});
        await loadSavedConfigs();
        closeRenameModal();
    }} catch(e) {{
        alert('Failed to rename');
        closeRenameModal();
    }}
}}

document.getElementById('renameInput').addEventListener('keypress', (e) => {{
    if (e.key === 'Enter') confirmRename();
    if (e.key === 'Escape') closeRenameModal();
}});

async function deleteConfigByName(name) {{
    try {{
        await fetch(`/api/configs/${{key}}/delete/${{name}}`, {{method: 'DELETE'}});
        await loadSavedConfigs();
    }} catch(e) {{
        alert('Failed to delete');
    }}
}}

loadSavedConfigs();
loadConfig();
setInterval(loadConfig, 1000);
</script>
</body>
</html>"""

if __name__ == "__main__":
    init_db()
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
