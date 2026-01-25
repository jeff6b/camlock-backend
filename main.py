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

# === CONFIG ENDPOINTS ===

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

@app.get("/api/config/{key}")
def get_config(key: str):
    """Get config for a license key"""
    db = get_db()
    cur = db.cursor()
    
    # Insert default if doesn't exist
    cur.execute(q("INSERT OR IGNORE INTO settings (key, config) VALUES (%s, %s)"), (key, json.dumps(DEFAULT_CONFIG)))
    db.commit()
    
    cur.execute(q("SELECT config FROM settings WHERE key=%s"), (key,))
    result = cur.fetchone()
    db.close()
    
    return json.loads(result[0]) if result else DEFAULT_CONFIG

@app.post("/api/config/{key}")
def set_config(key: str, data: dict):
    """Save config for a license key"""
    db = get_db()
    cur = db.cursor()
    
    cur.execute(q("INSERT INTO settings(key, config) VALUES(%s, %s) ON CONFLICT(key) DO UPDATE SET config=excluded.config"), 
                (key, json.dumps(data)))
    db.commit()
    db.close()
    
    return {"status": "ok"}

@app.get("/api/keepalive")
def keepalive():
    """Keep server awake"""
    return {"status": "alive"}

# === HTML CONSTANTS ===

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
        <button class="modal-btn" onclick="saveConfigToMenu()">Load to Menu</button>
      </div>
    </div>
  </div>

  <script>
    let currentUser = null;
    let allConfigs = [];
    let currentPage = 1;
    let currentViewConfig = null;
    const CONFIGS_PER_PAGE = 4;

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
        const res = await fetch(`https://dashboard.getaxion.lol/api/validate`, {
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
            
            // Update UI - show first 12 chars of license
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
        const res = await fetch('https://dashboard.getaxion.lol/api/public-configs');
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

      // Add pagination
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
    }

    async function openCreateModal() {
      document.getElementById('createModal').classList.add('active');
      
      // Load user's saved configs from dashboard backend
      try {
        const res = await fetch(`https://dashboard.getaxion.lol/api/configs/${currentUser.license_key}/list`);
        const data = await res.json();
        
        const select = document.getElementById('savedConfigSelect');
        select.innerHTML = '<option value="">Select a config...</option>';
        
        if (data.configs && data.configs.length > 0) {
          data.configs.forEach(name => {
            select.innerHTML += `<option value="${name}">${name}</option>`;
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
        // Load the actual config data
        const configRes = await fetch(`https://dashboard.getaxion.lol/api/configs/${currentUser.license_key}/load/${selectedConfig}`, {
          method: 'POST'
        });
        const configData = await configRes.json();

        // Publish to public configs
        const res = await fetch('https://dashboard.getaxion.lol/api/public-configs/create', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            config_name: configName,
            author_name: authorName,
            game_name: gameName,
            description: description,
            config_data: configData.config_data
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
        
        // Increment downloads
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
        const res = await fetch(`https://dashboard.getaxion.lol/api/configs/${currentUser.license_key}/save`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            name: currentViewConfig.config_name,
            data: currentViewConfig.config_data
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

    // Close modals on Escape
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        closeLoginModal();
        closeCreateModal();
        closeViewModal();
      }
    });

    // Initialize - show login button
    document.getElementById('userArea').innerHTML = `
      <button class="login-btn" onclick="showLoginModal()">Login</button>
    `;
  </script>
</body>
</html>
"""

# === HTML ROUTES (Must be after all API routes) ===

@app.get("/", response_class=HTMLResponse)
@app.get("/home", response_class=HTMLResponse)
def serve_home():
    """Home page"""
    return _INDEX_HTML

@app.get("/{license_key}", response_class=HTMLResponse)
@app.get("/{license_key}", response_class=HTMLResponse)
def serve_dashboard(license_key: str):
    """Full dashboard with toggles, sliders, dropdowns"""
    if license_key in ["api", "favicon.ico"]:
        raise HTTPException(status_code=404)
    
    db = get_db()
    cur = db.cursor()
    
    if USE_POSTGRES:
        cur.execute("SELECT * FROM keys WHERE key=%s", (license_key,))
    else:
        cur.execute("SELECT * FROM keys WHERE key=?", (license_key,))
    
    result = cur.fetchone()
    db.close()
    
    if not result:
        return "<html><body style='background:rgb(12,12,12);color:white;font-family:Arial;display:flex;align-items:center;justify-content:center;height:100vh'><div style='text-align:center'><h1 style='color:rgb(255,68,68)'>Invalid License</h1><p>Not valid</p></div></body></html>"
    
    cfg = json.dumps(DEFAULT_CONFIG)
    key = license_key
    
    return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"/><title>Axion</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box;user-select:none}}
body{{height:100vh;background:radial-gradient(circle,rgb(15,15,15),rgb(5,5,5));font-family:Arial;color:rgb(207,207,207);display:flex;align-items:center;justify-content:center}}
.win{{width:760px;height:520px;background:linear-gradient(rgb(17,17,17),rgb(10,10,10));border:1px solid rgb(42,42,42);display:flex;flex-direction:column}}
.top{{height:38px;background:linear-gradient(rgb(26,26,26),rgb(14,14,14));border-bottom:1px solid rgb(43,43,43);display:flex;align-items:center;padding:0 12px;gap:16px}}
.tabs{{display:flex;gap:18px;font-size:12px}}
.tab{{color:rgb(154,154,154);cursor:pointer;padding:8px 0}}
.tab.active{{color:white}}
.content{{flex:1;padding:20px;overflow-y:auto}}
.tc{{display:none}}
.tc.active{{display:block}}
.row{{display:flex;align-items:center;margin-bottom:16px;gap:12px}}
label{{min-width:120px;font-size:13px}}
input[type=checkbox]{{width:16px;height:16px;cursor:pointer}}
input[type=range]{{flex:1;cursor:pointer}}
select{{flex:1;background:rgb(26,26,26);color:white;border:1px solid rgb(42,42,42);padding:6px;font-size:12px}}
.val{{min-width:50px;text-align:right;font-size:12px;color:rgb(154,154,154)}}
</style>
</head><body><div class="win">
<div class="top"><div>Axion</div><div class="tabs">
<div class="tab active" data-tab="aimbot">aimbot</div>
<div class="tab" data-tab="triggerbot">triggerbot</div>
</div></div>
<div class="content">
<div class="tc active" id="aimbot">
<div class="row"><label>Enabled</label><input type="checkbox" id="camlock_enabled" checked/></div>
<div class="row"><label>Keybind</label><select id="camlock_keybind"><option>Q</option><option>E</option><option>C</option><option>X</option></select></div>
<div class="row"><label>FOV</label><input type="range" id="camlock_fov" min="10" max="500" value="280"/><span class="val" id="camlock_fov_val">280</span></div>
<div class="row"><label>Smoothing</label><input type="checkbox" id="camlock_smoothing" checked/></div>
<div class="row"><label>SmoothX</label><input type="range" id="camlock_smoothx" min="1" max="50" value="14"/><span class="val" id="camlock_smoothx_val">14</span></div>
<div class="row"><label>SmoothY</label><input type="range" id="camlock_smoothy" min="1" max="50" value="14"/><span class="val" id="camlock_smoothy_val">14</span></div>
<div class="row"><label>Prediction</label><input type="checkbox" id="camlock_prediction" checked/></div>
<div class="row"><label>Pred Value</label><input type="range" id="camlock_predval" min="0" max="50" step="0.01" value="0.14"/><span class="val" id="camlock_predval_val">0.14</span></div>
<div class="row"><label>Body Part</label><select id="camlock_bodypart"><option>Head</option><option>UpperTorso</option><option>LowerTorso</option><option>HumanoidRootPart</option></select></div>
<div class="row"><label>Easing</label><select id="camlock_easing"><option>Linear</option><option>Sine</option><option>Quad</option><option>Cubic</option><option>Expo</option></select></div>
</div>
<div class="tc" id="triggerbot">
<div class="row"><label>Enabled</label><input type="checkbox" id="trig_enabled" checked/></div>
<div class="row"><label>Keybind</label><select id="trig_keybind"><option>Right Mouse</option><option>Left Mouse</option><option>Middle Mouse</option></select></div>
<div class="row"><label>Delay</label><input type="range" id="trig_delay" min="0" max="100" step="1" value="0"/><span class="val" id="trig_delay_val">0</span></div>
<div class="row"><label>FOV</label><input type="range" id="trig_fov" min="5" max="100" value="25"/><span class="val" id="trig_fov_val">25</span></div>
<div class="row"><label>Prediction</label><input type="range" id="trig_pred" min="0" max="50" step="0.01" value="0.1"/><span class="val" id="trig_pred_val">0.1</span></div>
<div class="row"><label>Death Check</label><input type="checkbox" id="trig_death" checked/></div>
<div class="row"><label>Knife Check</label><input type="checkbox" id="trig_knife" checked/></div>
<div class="row"><label>Team Check</label><input type="checkbox" id="trig_team" checked/></div>
</div>
</div></div>
<script>
let config={cfg};
document.querySelectorAll('.tab').forEach(tab=>{{tab.addEventListener('click',()=>{{document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));document.querySelectorAll('.tc').forEach(tc=>tc.classList.remove('active'));tab.classList.add('active');document.getElementById(tab.getAttribute('data-tab')).classList.add('active');}});}});
document.querySelectorAll('input[type=range]').forEach(r=>{{r.addEventListener('input',()=>{{document.getElementById(r.id+'_val').textContent=r.value;}});}});
async function save(){{try{{await fetch('/api/config/{key}',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{
camlock:{{Enabled:document.getElementById('camlock_enabled').checked,Keybind:document.getElementById('camlock_keybind').value,FOV:parseFloat(document.getElementById('camlock_fov').value),EnableSmoothing:document.getElementById('camlock_smoothing').checked,SmoothX:parseFloat(document.getElementById('camlock_smoothx').value),SmoothY:parseFloat(document.getElementById('camlock_smoothy').value),EnablePrediction:document.getElementById('camlock_prediction').checked,Prediction:parseFloat(document.getElementById('camlock_predval').value),BodyPart:document.getElementById('camlock_bodypart').value,EasingStyle:document.getElementById('camlock_easing').value}},
triggerbot:{{Enabled:document.getElementById('trig_enabled').checked,Keybind:document.getElementById('trig_keybind').value,Delay:parseFloat(document.getElementById('trig_delay').value)/1000,FOV:parseFloat(document.getElementById('trig_fov').value),Prediction:parseFloat(document.getElementById('trig_pred').value),DeathCheck:document.getElementById('trig_death').checked,KnifeCheck:document.getElementById('trig_knife').checked,TeamCheck:document.getElementById('trig_team').checked}}
}}))}})}}catch(e){{}}}}
setInterval(save,1000);
</script></body></html>"""

if __name__ == "__main__":
    init_db()
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
