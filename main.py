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
    
    cur.execute(q("UPDATE keys SET redeemed_at=%s, redeemed_by=%s, expires_at=%s, active=1 WHERE key=%s"),
               (now.isoformat(), data.discord_id, expires_at, data.key))
    db.commit()
    db.close()
    
    return {"success": True}

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


# === HTML PAGES ===

@app.get("/", response_class=HTMLResponse)
@app.get("/home", response_class=HTMLResponse)
def serve_home():
    """Home page"""
    return """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>AXION — Home</title>
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
      <a href="/dashboard">Dashboard</a>
      <div id="userArea"></div>
    </div>
  </nav>

  <div class="content">
    <!-- Home Page -->
    <div id="home" class="page active">
      <div class="title-wrapper">
        <span class="title-word" style="color:#ffffff;">WELCOME</span>
        <span class="title-word" style="color:#ffffff;">TO</span>
        <span class="title-word" style="color:#888888;">AXION</span>
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

"""

@app.get("/dashboard/{license_key}", response_class=HTMLResponse)
def serve_dashboard(license_key: str):
    """Dashboard page"""
    return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - Axion</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            background: rgb(12,12,12);
            background-image: radial-gradient(circle at 3px 3px, rgb(15,15,15) 1px, transparent 0);
            background-size: 6px 6px;
            color: #ccc;
            font-family: 'Segoe UI', system-ui, sans-serif;
            min-height: 100vh;
            display: flex;
        }
        .sidebar {
            width: 180px;
            background: rgb(13,13,13);
            border-right: 1px solid rgb(35,35,35);
            padding: 32px 16px;
            position: fixed;
            top: 0;
            bottom: 0;
            overflow-y: auto;
            text-align: center;
        }
        .logo {
            font-size: 24px;
            font-weight: bold;
            color: white;
            margin-bottom: 40px;
        }
        nav ul {
            list-style: none;
        }
        nav li {
            margin: 12px 0;
        }
        nav a {
            display: block;
            color: #888;
            text-decoration: none;
            padding: 10px 14px;
            border-radius: 6px;
            transition: color 0.2s;
            cursor: pointer;
        }
        nav a:hover {
            color: white;
        }
        nav a.active {
            color: white;
        }
        .main-content {
            margin-left: 180px;
            flex: 1;
            padding: 32px 24px 40px 200px;
        }
        .container {
            max-width: 1300px;
            margin: 0 auto;
        }
        h1 {
            font-size: 28px;
            font-weight: 600;
            color: white;
            margin-bottom: 8px;
        }
        .subtitle {
            font-size: 15px;
            color: #888;
            margin-bottom: 28px;
        }
        .divider {
            height: 1px;
            background: rgb(35,35,35);
            margin: 0 0 36px 0;
        }
        .tab-content {
            display: none;
        }
        .tab-content.active {
            display: block;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 20px;
            margin-bottom: 48px;
        }
        .stat-card {
            background: rgb(18,18,18);
            border: 1px solid rgb(35,35,35);
            border-radius: 10px;
            padding: 24px 20px;
            text-align: center;
        }
        .stat-label {
            font-size: 14px;
            color: #777;
            margin-bottom: 12px;
        }
        .stat-value {
            font-size: 32px;
            font-weight: bold;
            color: white;
        }
        .stat-sub {
            font-size: 13px;
            color: #666;
            margin-top: 6px;
        }
        .manage-grid, .security-grid {
            display: grid;
            grid-template-columns: 1fr;
            gap: 28px;
        }
        .card {
            background: rgb(18,18,18);
            border: 1px solid rgb(35,35,35);
            border-radius: 12px;
            padding: 28px;
            overflow: hidden;
        }
        .card-title {
            font-size: 20px;
            font-weight: 600;
            color: white;
            margin-bottom: 8px;
        }
        .card-subtitle {
            font-size: 14px;
            color: #888;
            margin-bottom: 28px;
        }
        .input-group {
            margin-bottom: 20px;
        }
        .input-label {
            font-size: 14px;
            color: #aaa;
            margin-bottom: 8px;
            display: block;
        }
        input[type="text"], input[type="password"] {
            width: 100%;
            padding: 14px 16px;
            background: rgb(25,25,25);
            border: 1px solid rgb(45,45,45);
            border-radius: 8px;
            color: white;
            font-family: monospace;
            font-size: 15px;
        }
        input::placeholder {
            color: #666;
            opacity: 1;
        }
        .redeem-btn {
            width: 100%;
            padding: 14px;
            background: white;
            border: none;
            border-radius: 8px;
            color: black;
            font-size: 15px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.25s ease;
            transform: scale(1);
        }
        .redeem-btn:hover {
            transform: scale(1.03);
            background: rgb(240,240,240);
            box-shadow: 0 4px 12px rgba(0,0,0,0.4);
        }
        .info-item {
            margin-bottom: 24px;
        }
        .info-label {
            font-size: 14px;
            color: #aaa;
            margin-bottom: 8px;
            display: block;
        }
        .info-value {
            width: 100%;
            padding: 14px 16px;
            background: rgb(25,25,25);
            border: 1px solid rgb(45,45,45);
            border-radius: 8px;
            color: white;
            font-family: monospace;
            font-size: 15px;
            filter: blur(6px);
            transition: filter 0.3s ease;
            user-select: none;
            cursor: pointer;
            position: relative;
        }
        .info-value:hover {
            filter: blur(0);
        }
        .info-value.clickable {
            cursor: pointer;
        }
        .info-value.clickable:hover {
            border-color: rgb(65,65,65);
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
        }
        .modal.active {
            display: flex;
        }
        .modal-content {
            background: #1a1a1f;
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 8px;
            padding: 28px;
            width: 90%;
            max-width: 420px;
        }
        .modal-title {
            font-size: 20px;
            font-weight: 600;
            color: #fff;
            margin-bottom: 12px;
        }
        .modal-text {
            color: #aaa;
            margin-bottom: 24px;
            line-height: 1.5;
        }
        .modal-actions {
            display: flex;
            gap: 10px;
        }
        .modal-btn {
            flex: 1;
            padding: 12px;
            background: transparent;
            border: 1px solid rgba(255,255,255,0.15);
            border-radius: 6px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            color: #fff;
        }
        .modal-btn:hover {
            background: rgba(255,255,255,0.05);
            border-color: rgba(255,255,255,0.25);
        }
        .modal-btn-danger {
            background: rgba(220,53,69,0.1);
            border-color: rgba(220,53,69,0.3);
        }
        .modal-btn-danger:hover {
            background: rgba(220,53,69,0.2);
            border-color: rgba(220,53,69,0.5);
        }

        @media (max-width: 900px) {
            .sidebar {
                width: 100%;
                height: auto;
                position: relative;
                border-right: none;
                border-bottom: 1px solid rgb(35,35,35);
                padding: 20px;
                display: flex;
                flex-direction: column;
                align-items: center;
            }
            .logo {
                margin-bottom: 20px;
            }
            nav ul {
                display: flex;
                justify-content: center;
                gap: 8px;
                flex-wrap: wrap;
            }
            .main-content {
                margin-left: 0;
                padding: 24px 16px;
            }
            .stats {
                grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            }
        }
    </style>
</head>
<body>
    <aside class="sidebar">
        <div class="logo">Axion</div>
        <nav>
            <ul>
                <li><a class="active" data-tab="subscriptions">Subscriptions</a></li>
                <li><a data-tab="manage">Manage</a></li>
                <li><a data-tab="security">Security</a></li>
            </ul>
        </nav>
    </aside>

    <main class="main-content">
        <div class="container">
            <h1 id="page-title">Subscriptions</h1>
            <div class="subtitle" id="subtitle">Manage and view your active subscriptions</div>
            <div class="divider"></div>

            <!-- Subscriptions Tab -->
            <div id="subscriptions" class="tab-content active">
                <div class="stats">
                    <div class="stat-card">
                        <div class="stat-label">Active Subscriptions</div>
                        <div class="stat-value" id="activeCount">1</div>
                        <div class="stat-sub">subscriptions</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Total HWID Resets</div>
                        <div class="stat-value" id="hwidResets">0</div>
                        <div class="stat-sub">all time</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">License Status</div>
                        <div class="stat-value" id="licenseStatus">Active</div>
                        <div class="stat-sub" id="licenseExpiry">Lifetime</div>
                    </div>
                </div>
                <div class="card">
                    <div class="card-title">Your Subscription</div>
                    <div class="card-subtitle">License key information</div>
                    <div class="info-item">
                        <div class="info-label">License Key</div>
                        <div class="info-value" id="displayLicenseKey">Loading...</div>
                    </div>
                </div>
            </div>

            <!-- Manage Tab -->
            <div id="manage" class="tab-content">
                <div class="manage-grid">
                    <div class="card">
                        <div class="card-title">Redeem Key</div>
                        <div class="card-subtitle">Activate a new subscription</div>
                        <div class="input-group">
                            <div class="input-label">Subscription Key</div>
                            <input type="text" id="redeemKeyInput" placeholder="XXXX-XXXX-XXXX-XXXX">
                        </div>
                        <div class="input-group">
                            <div class="input-label">Discord User ID</div>
                            <input type="text" id="discordIdInput" placeholder="123456789012345678">
                        </div>
                        <button class="redeem-btn" onclick="redeemKey()">Redeem Key</button>
                    </div>
                </div>
            </div>

            <!-- Security Tab -->
            <div id="security" class="tab-content">
                <div class="security-grid">
                    <div class="card">
                        <div class="card-title">Account Security</div>
                        <div class="card-subtitle">View and manage your security details</div>

                        <div class="info-item">
                            <div class="info-label">License Key</div>
                            <div class="info-value" id="securityLicenseKey">Loading...</div>
                        </div>

                        <div class="info-item">
                            <div class="info-label">HWID <span style="font-size: 12px; color: #666;">(Click to reset)</span></div>
                            <div class="info-value clickable" id="hwidDisplay" onclick="openResetModal()">Loading...</div>
                        </div>

                        <div class="info-item">
                            <div class="info-label">Discord ID</div>
                            <div class="info-value" id="discordIdDisplay">Loading...</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </main>

    <!-- HWID Reset Confirmation Modal -->
    <div class="modal" id="resetModal">
        <div class="modal-content">
            <div class="modal-title">Reset HWID</div>
            <div class="modal-text">
                Are you sure you want to reset your HWID? This action cannot be undone and will log you out from all devices.
            </div>
            <div class="modal-actions">
                <button class="modal-btn" onclick="closeResetModal()">Cancel</button>
                <button class="modal-btn modal-btn-danger" onclick="confirmReset()">Reset HWID</button>
            </div>
        </div>
    </div>

    <script>
        let userData = null;

        // Get license key from URL
        const licenseKey = window.location.pathname.split('/dashboard/')[1] || window.location.hash.substring(1);

        if (!licenseKey) {
            alert('No license key provided');
            window.location.href = '/';
        }

        // Load user data
        async function loadUserData() {
            try {
                const res = await fetch(`https://dashboard.getaxion.lol/api/dashboard/${licenseKey}`);
                if (res.status === 404) {
                    alert('License not found');
                    window.location.href = '/';
                    return;
                }
                const data = await res.json();
                userData = data;
                updateUI();
            } catch (e) {
                console.error('Error loading data:', e);
                alert('Error loading dashboard');
            }
        }

        function updateUI() {
            // Subscriptions tab
            document.getElementById('activeCount').textContent = userData.active ? '1' : '0';
            document.getElementById('hwidResets').textContent = userData.hwid_resets || 0;
            document.getElementById('licenseStatus').textContent = userData.active ? 'Active' : 'Inactive';
            
            // Calculate expiry
            if (userData.expires_at) {
                const expiry = new Date(userData.expires_at);
                const now = new Date();
                const daysLeft = Math.ceil((expiry - now) / (1000 * 60 * 60 * 24));
                document.getElementById('licenseExpiry').textContent = daysLeft > 0 ? `${daysLeft} days left` : 'Expired';
            } else {
                document.getElementById('licenseExpiry').textContent = 'Lifetime';
            }

            // Display license keys
            document.getElementById('displayLicenseKey').textContent = userData.license_key;
            document.getElementById('securityLicenseKey').textContent = userData.license_key;
            
            // HWID
            document.getElementById('hwidDisplay').textContent = userData.hwid || 'Not set';
            
            // Discord ID
            document.getElementById('discordIdDisplay').textContent = userData.discord_id || 'Not set';
        }

        // Tab switching
        document.querySelectorAll('nav a').forEach(link => {
            link.addEventListener('click', function() {
                const targetTab = this.getAttribute('data-tab');
                
                // Remove active from all tabs and links
                document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
                document.querySelectorAll('nav a').forEach(a => a.classList.remove('active'));
                
                // Add active to clicked
                document.getElementById(targetTab).classList.add('active');
                this.classList.add('active');
                
                // Update title
                const titles = {
                    'subscriptions': 'Subscriptions',
                    'manage': 'Manage',
                    'security': 'Security'
                };
                const subtitles = {
                    'subscriptions': 'Manage and view your active subscriptions',
                    'manage': 'Redeem keys and manage your account',
                    'security': 'Manage account security and HWID'
                };
                document.getElementById('page-title').textContent = titles[targetTab];
                document.getElementById('subtitle').textContent = subtitles[targetTab];
            });
        });

        // Redeem key function
        async function redeemKey() {
            const key = document.getElementById('redeemKeyInput').value.trim();
            const discordId = document.getElementById('discordIdInput').value.trim();

            if (!key) {
                alert('Please enter a key');
                return;
            }
            if (!discordId) {
                alert('Please enter your Discord User ID');
                return;
            }

            try {
                const res = await fetch('https://dashboard.getaxion.lol/api/redeem', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ key, discord_id: discordId })
                });

                const data = await res.json();
                
                if (res.ok) {
                    alert('Key redeemed successfully!');
                    // Reload to new license key dashboard
                    window.location.href = `/dashboard.html#${key}`;
                } else {
                    alert(data.error || 'Failed to redeem key');
                }
            } catch (e) {
                alert('Error redeeming key');
            }
        }

        // HWID Reset Modal
        function openResetModal() {
            document.getElementById('resetModal').classList.add('active');
        }

        function closeResetModal() {
            document.getElementById('resetModal').classList.remove('active');
        }

        async function confirmReset() {
            try {
                const res = await fetch(`https://dashboard.getaxion.lol/api/reset-hwid/${licenseKey}`, {
                    method: 'POST'
                });

                const data = await res.json();
                
                if (res.ok) {
                    alert('HWID reset successfully!');
                    closeResetModal();
                    loadUserData(); // Reload data
                } else {
                    alert(data.error || 'Failed to reset HWID');
                }
            } catch (e) {
                alert('Error resetting HWID');
            }
        }

        // Load data on page load
        loadUserData();
    </script>
</body>
</html>
"""

@app.get("/{license_key}", response_class=HTMLResponse)
def serve_menu(license_key: str):
    """Menu system"""
    return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Axion Menu</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            background: rgb(12, 12, 12);
            color: #fff;
            font-family: 'Segoe UI', system-ui, sans-serif;
            padding: 40px 20px;
        }}
        
        .container {{
            max-width: 800px;
            margin: 0 auto;
        }}
        
        h1 {{
            font-size: 32px;
            margin-bottom: 10px;
            color: #fff;
        }}
        
        .license-key {{
            color: #888;
            font-size: 14px;
            margin-bottom: 40px;
            font-family: monospace;
        }}
        
        .section {{
            background: rgba(18, 18, 22, 0.6);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 20px;
        }}
        
        .section-title {{
            font-size: 20px;
            font-weight: 600;
            margin-bottom: 16px;
            color: #fff;
        }}
        
        .controls {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
        }}
        
        .control-group {{
            margin-bottom: 16px;
        }}
        
        label {{
            display: block;
            font-size: 13px;
            color: #aaa;
            margin-bottom: 6px;
        }}
        
        input[type="range"] {{
            width: 100%;
            height: 6px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 3px;
            outline: none;
            -webkit-appearance: none;
        }}
        
        input[type="range"]::-webkit-slider-thumb {{
            -webkit-appearance: none;
            width: 16px;
            height: 16px;
            background: #fff;
            border-radius: 50%;
            cursor: pointer;
        }}
        
        input[type="checkbox"] {{
            width: 20px;
            height: 20px;
            cursor: pointer;
        }}
        
        .value-display {{
            display: inline-block;
            min-width: 40px;
            text-align: right;
            color: #fff;
            font-weight: 600;
        }}
        
        .btn {{
            padding: 12px 24px;
            background: rgba(255, 255, 255, 0.1);
            border: 1px solid rgba(255, 255, 255, 0.2);
            border-radius: 8px;
            color: #fff;
            cursor: pointer;
            transition: all 0.2s;
            font-size: 14px;
        }}
        
        .btn:hover {{
            background: rgba(255, 255, 255, 0.15);
        }}
        
        .config-section {{
            margin-top: 20px;
        }}
        
        .config-list {{
            display: flex;
            flex-direction: column;
            gap: 8px;
            margin-top: 12px;
        }}
        
        .config-item {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 12px;
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 6px;
        }}
        
        .config-item:hover {{
            background: rgba(255, 255, 255, 0.08);
        }}
        
        .config-actions {{
            display: flex;
            gap: 8px;
        }}
        
        .btn-small {{
            padding: 6px 12px;
            font-size: 12px;
        }}
        
        .input-text {{
            padding: 8px 12px;
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.15);
            border-radius: 6px;
            color: #fff;
            font-size: 14px;
        }}
        
        .input-text:focus {{
            outline: none;
            border-color: rgba(255, 255, 255, 0.3);
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Axion Menu</h1>
        <div class="license-key">License: {license_key}</div>
        
        <!-- Triggerbot Section -->
        <div class="section">
            <div class="section-title">Triggerbot Settings</div>
            <div class="controls">
                <div class="control-group">
                    <label>
                        <input type="checkbox" id="triggerbotEnabled"> Enabled
                    </label>
                </div>
                <div class="control-group">
                    <label>Delay (ms): <span class="value-display" id="triggerbotDelayValue">50</span></label>
                    <input type="range" id="triggerbotDelay" min="0" max="200" value="50">
                </div>
                <div class="control-group">
                    <label>Hold Time (ms): <span class="value-display" id="triggerbotHoldValue">100</span></label>
                    <input type="range" id="triggerbotHold" min="50" max="500" value="100">
                </div>
            </div>
        </div>
        
        <!-- Camlock Section -->
        <div class="section">
            <div class="section-title">Camlock Settings</div>
            <div class="controls">
                <div class="control-group">
                    <label>
                        <input type="checkbox" id="camlockEnabled"> Enabled
                    </label>
                </div>
                <div class="control-group">
                    <label>Smoothness: <span class="value-display" id="camlockSmoothnessValue">10</span></label>
                    <input type="range" id="camlockSmoothness" min="1" max="20" value="10">
                </div>
                <div class="control-group">
                    <label>Prediction: <span class="value-display" id="camlockPredictionValue">5</span></label>
                    <input type="range" id="camlockPrediction" min="0" max="20" value="5">
                </div>
                <div class="control-group">
                    <label>FOV: <span class="value-display" id="camlockFovValue">100</span></label>
                    <input type="range" id="camlockFov" min="50" max="300" value="100">
                </div>
            </div>
        </div>
        
        <!-- Config Management -->
        <div class="section config-section">
            <div class="section-title">Config Management</div>
            <div style="display: flex; gap: 12px; margin-bottom: 16px;">
                <input type="text" id="configName" placeholder="Config name..." class="input-text" style="flex: 1;">
                <button class="btn" onclick="saveConfig()">Save Config</button>
            </div>
            
            <div class="config-list" id="configList">
                <!-- Configs loaded here -->
            </div>
        </div>
    </div>
    
    <script>
        const licenseKey = '{license_key}';
        
        // Update value displays
        document.getElementById('triggerbotDelay').addEventListener('input', (e) => {{
            document.getElementById('triggerbotDelayValue').textContent = e.target.value;
        }});
        
        document.getElementById('triggerbotHold').addEventListener('input', (e) => {{
            document.getElementById('triggerbotHoldValue').textContent = e.target.value;
        }});
        
        document.getElementById('camlockSmoothness').addEventListener('input', (e) => {{
            document.getElementById('camlockSmoothnessValue').textContent = e.target.value;
        }});
        
        document.getElementById('camlockPrediction').addEventListener('input', (e) => {{
            document.getElementById('camlockPredictionValue').textContent = e.target.value;
        }});
        
        document.getElementById('camlockFov').addEventListener('input', (e) => {{
            document.getElementById('camlockFovValue').textContent = e.target.value;
        }});
        
        // Get current config
        function getCurrentConfig() {{
            return {{
                triggerbot: {{
                    enabled: document.getElementById('triggerbotEnabled').checked,
                    delay: parseInt(document.getElementById('triggerbotDelay').value),
                    holdTime: parseInt(document.getElementById('triggerbotHold').value)
                }},
                camlock: {{
                    enabled: document.getElementById('camlockEnabled').checked,
                    smoothness: parseInt(document.getElementById('camlockSmoothness').value),
                    prediction: parseInt(document.getElementById('camlockPrediction').value),
                    fov: parseInt(document.getElementById('camlockFov').value)
                }}
            }};
        }}
        
        // Apply config
        function applyConfig(config) {{
            if (config.triggerbot) {{
                document.getElementById('triggerbotEnabled').checked = config.triggerbot.enabled || false;
                document.getElementById('triggerbotDelay').value = config.triggerbot.delay || 50;
                document.getElementById('triggerbotDelayValue').textContent = config.triggerbot.delay || 50;
                document.getElementById('triggerbotHold').value = config.triggerbot.holdTime || 100;
                document.getElementById('triggerbotHoldValue').textContent = config.triggerbot.holdTime || 100;
            }}
            
            if (config.camlock) {{
                document.getElementById('camlockEnabled').checked = config.camlock.enabled || false;
                document.getElementById('camlockSmoothness').value = config.camlock.smoothness || 10;
                document.getElementById('camlockSmoothnessValue').textContent = config.camlock.smoothness || 10;
                document.getElementById('camlockPrediction').value = config.camlock.prediction || 5;
                document.getElementById('camlockPredictionValue').textContent = config.camlock.prediction || 5;
                document.getElementById('camlockFov').value = config.camlock.fov || 100;
                document.getElementById('camlockFovValue').textContent = config.camlock.fov || 100;
            }}
        }}
        
        // Save config
        async function saveConfig() {{
            const name = document.getElementById('configName').value.trim();
            if (!name) {{
                alert('Please enter a config name');
                return;
            }}
            
            const config = getCurrentConfig();
            
            try {{
                const res = await fetch(`/api/configs/${{licenseKey}}/save`, {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{ name, data: config }})
                }});
                
                if (res.ok) {{
                    alert('Config saved!');
                    document.getElementById('configName').value = '';
                    loadConfigs();
                }} else {{
                    alert('Failed to save config');
                }}
            }} catch (e) {{
                alert('Error saving config');
            }}
        }}
        
        // Load config
        async function loadConfig(name) {{
            try {{
                const res = await fetch(`/api/configs/${{licenseKey}}/load/${{name}}`, {{
                    method: 'POST'
                }});
                
                if (res.ok) {{
                    const data = await res.json();
                    applyConfig(data.config_data);
                    alert(`Config "${{name}}" loaded!`);
                }} else {{
                    alert('Failed to load config');
                }}
            }} catch (e) {{
                alert('Error loading config');
            }}
        }}
        
        // Delete config
        async function deleteConfig(name) {{
            if (!confirm(`Delete config "${{name}}"?`)) return;
            
            try {{
                const res = await fetch(`/api/configs/${{licenseKey}}/delete/${{name}}`, {{
                    method: 'POST'
                }});
                
                if (res.ok) {{
                    alert('Config deleted!');
                    loadConfigs();
                }} else {{
                    alert('Failed to delete config');
                }}
            }} catch (e) {{
                alert('Error deleting config');
            }}
        }}
        
        // Rename config
        async function renameConfig(oldName) {{
            const newName = prompt('Enter new name:', oldName);
            if (!newName || newName === oldName) return;
            
            try {{
                const res = await fetch(`/api/configs/${{licenseKey}}/rename`, {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{ old_name: oldName, new_name: newName }})
                }});
                
                if (res.ok) {{
                    alert('Config renamed!');
                    loadConfigs();
                }} else {{
                    alert('Failed to rename config');
                }}
            }} catch (e) {{
                alert('Error renaming config');
            }}
        }}
        
        // Load configs list
        async function loadConfigs() {{
            try {{
                const res = await fetch(`/api/configs/${{licenseKey}}/list`);
                const data = await res.json();
                
                const list = document.getElementById('configList');
                
                if (data.configs && data.configs.length > 0) {{
                    list.innerHTML = data.configs.map(name => `
                        <div class="config-item">
                            <span>${{name}}</span>
                            <div class="config-actions">
                                <button class="btn btn-small" onclick="loadConfig('${{name}}')">Load</button>
                                <button class="btn btn-small" onclick="renameConfig('${{name}}')">Rename</button>
                                <button class="btn btn-small" onclick="deleteConfig('${{name}}')">Delete</button>
                            </div>
                        </div>
                    `).join('');
                }} else {{
                    list.innerHTML = '<p style="color: #888; text-align: center; padding: 20px;">No saved configs</p>';
                }}
            }} catch (e) {{
                console.error('Error loading configs:', e);
            }}
        }}
        
        // Load configs on page load
        loadConfigs();
    </script>
</body>
</html>
"""

if __name__ == "__main__":
    init_db()
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
