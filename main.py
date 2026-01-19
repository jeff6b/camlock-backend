# main.py - FULL BACKEND ON RENDER
from fastapi import FastAPI, Path, HTTPException, Request, Response, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import json
import random
import os
import secrets
from datetime import datetime, timedelta
from typing import Optional

app = FastAPI()

# CORS - Allow requests from Vercel frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://bibbobg.vercel.app",
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5500",
        "*"  # Allow all as fallback
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=3600,
)

# Session storage (in-memory for now, use Redis in production)
sessions = {}

# FREE Database Options (no paid plan needed):
# 1. Use environment variable DATABASE_URL for external database
# 2. Supabase (free tier): https://supabase.com
# 3. PlanetScale (free tier): https://planetscale.com
# 4. Neon (free tier): https://neon.tech

DATABASE_URL = os.environ.get("DATABASE_URL")

# Determine which database to use
USE_POSTGRES = False
if DATABASE_URL and DATABASE_URL.startswith("postgresql"):
    try:
        import psycopg2
        from psycopg2.extras import RealDictCursor
        USE_POSTGRES = True
    except ImportError:
        print("❌ psycopg2 not installed")
        USE_POSTGRES = False

if not USE_POSTGRES:
    import sqlite3

# Unified database functions
def get_db():
    if USE_POSTGRES:
        return psycopg2.connect(DATABASE_URL, connect_timeout=10)
    else:
        return sqlite3.connect(os.environ.get("DB_PATH", "database.db"))

def execute_query(query, params=None, fetch_one=False, fetch_all=False):
    """Execute query with automatic PostgreSQL/SQLite compatibility"""
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
    if USE_POSTGRES:
        try:
            db = get_db()
            cur = db.cursor()
            cur.execute("""CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY, 
                config TEXT
            )""")
            cur.execute("""CREATE TABLE IF NOT EXISTS keys (
                key TEXT PRIMARY KEY, 
                duration TEXT NOT NULL, 
                created_at TEXT NOT NULL,
                expires_at TEXT, 
                redeemed_at TEXT, 
                redeemed_by TEXT, 
                hwid TEXT,
                active INTEGER DEFAULT 0, 
                created_by TEXT
            )""")
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
            cur.execute("""CREATE TABLE IF NOT EXISTS user_sessions (
                session_id TEXT PRIMARY KEY,
                license_key TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )""")
            cur.execute("""CREATE TABLE IF NOT EXISTS freemium_settings (
                id SERIAL PRIMARY KEY,
                enabled BOOLEAN DEFAULT FALSE,
                updated_at TEXT NOT NULL
            )""")
            # Initialize freemium as disabled
            cur.execute("INSERT INTO freemium_settings (enabled, updated_at) VALUES (FALSE, %s) ON CONFLICT DO NOTHING", (datetime.now().isoformat(),))
            db.commit()
            db.close()
            print(f"✅ PostgreSQL database connected successfully!")
        except Exception as e:
            print(f"❌ PostgreSQL connection failed: {e}")
            raise
    else:
        db = get_db()
        cur = db.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, config TEXT)")
        cur.execute("""CREATE TABLE IF NOT EXISTS keys (
            key TEXT PRIMARY KEY, duration TEXT NOT NULL, created_at TEXT NOT NULL,
            expires_at TEXT, redeemed_at TEXT, redeemed_by TEXT, hwid TEXT,
            active INTEGER DEFAULT 0, created_by TEXT)""")
        cur.execute("""CREATE TABLE IF NOT EXISTS saved_configs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key TEXT NOT NULL,
            config_name TEXT NOT NULL,
            config_data TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(license_key, config_name))""")
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
        cur.execute("""CREATE TABLE IF NOT EXISTS user_sessions (
            session_id TEXT PRIMARY KEY,
            license_key TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        )""")
        cur.execute("""CREATE TABLE IF NOT EXISTS freemium_settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            enabled INTEGER DEFAULT 0,
            updated_at TEXT NOT NULL
        )""")
        # Initialize freemium as disabled
        cur.execute("INSERT OR IGNORE INTO freemium_settings (enabled, updated_at) VALUES (0, ?)", (datetime.now().isoformat(),))
        db.commit()
        db.close()
        print(f"⚠️  SQLite (TEMPORARY - data will be lost on redeploy!)")

def q(query, params=None):
    """Convert SQLite query to PostgreSQL if needed"""
    if USE_POSTGRES:
        # Convert parameter placeholders
        query = query.replace('?', '%s')
        # Convert INSERT OR IGNORE to PostgreSQL syntax
        query = query.replace('INSERT OR IGNORE', 'INSERT ... ON CONFLICT DO NOTHING').replace('...', '')
        # Convert ON CONFLICT(key) syntax
        if 'ON CONFLICT(key) DO UPDATE' in query:
            query = query.replace('ON CONFLICT(key)', 'ON CONFLICT (key)')
    return query

init_db()

# === CORS PREFLIGHT HANDLERS ===
@app.options("/auth/login")
async def options_login():
    return {"message": "OK"}

@app.options("/api/public-configs/create")
async def options_create_config():
    return {"message": "OK"}

@app.options("/api/my-configs")
async def options_my_configs():
    return {"message": "OK"}

# === HEALTH CHECK ===
@app.get("/health")
def health_check():
    """Simple health check"""
    return {"status": "ok", "message": "Backend is running"}

# === LICENSE KEY AUTHENTICATION ===

class LicenseLogin(BaseModel):
    license_key: str

@app.post("/auth/login")
def license_login(data: LicenseLogin):
    """Login with license key"""
    license_key = data.license_key.strip()
    
    if not license_key:
        raise HTTPException(status_code=400, detail="License key required")
    
    # Verify license exists and is active
    db = get_db()
    cur = db.cursor()
    cur.execute(q("SELECT key, redeemed_by, active, expires_at FROM keys WHERE key=?"), (license_key,))
    result = cur.fetchone()
    
    if not result:
        db.close()
        raise HTTPException(status_code=404, detail="Invalid license key")
    
    key, redeemed_by, active, expires_at = result
    
    if not redeemed_by:
        db.close()
        raise HTTPException(status_code=403, detail="License not redeemed yet")
    
    if active == 0:  # Check for 0 instead of falsy value
        db.close()
        raise HTTPException(status_code=403, detail="License is inactive")
    
    # Check if expired
    if expires_at:
        try:
            exp_date = datetime.fromisoformat(expires_at)
            if exp_date < datetime.now():
                db.close()
                raise HTTPException(status_code=403, detail="License has expired")
        except:
            pass
    
    # Create session
    session_id = secrets.token_urlsafe(32)
    expires_at_session = (datetime.now() + timedelta(days=30)).isoformat()
    
    try:
        cur.execute(q("INSERT INTO user_sessions (session_id, license_key, created_at, expires_at) VALUES (?, ?, ?, ?)"),
                   (session_id, license_key, datetime.now().isoformat(), expires_at_session))
        db.commit()
    except Exception as e:
        print(f"Session creation error: {e}")
        # Continue anyway, session not critical for config page
    
    db.close()
    
    # Return response with cookie
    response = JSONResponse({
        "success": True,
        "license_key": license_key,
        "session_id": session_id
    })
    
    response.set_cookie(
        key="session_id",
        value=session_id,
        max_age=30 * 24 * 60 * 60,  # 30 days
        httponly=False,  # Allow JavaScript access for cross-origin
        samesite="none",
        secure=True,
        path="/"
    )
    
    return response

@app.get("/auth/me")
def get_current_user(session_id: Optional[str] = Cookie(None)):
    """Get current logged in user"""
    if not session_id:
        raise HTTPException(status_code=401, detail="Not logged in")
    
    db = get_db()
    cur = db.cursor()
    cur.execute(q("SELECT license_key, expires_at FROM user_sessions WHERE session_id=?"), (session_id,))
    result = cur.fetchone()
    db.close()
    
    if not result:
        raise HTTPException(status_code=401, detail="Invalid session")
    
    license_key, expires_at = result
    
    # Check if session expired
    if datetime.fromisoformat(expires_at) < datetime.now():
        raise HTTPException(status_code=401, detail="Session expired")
    
    return {
        "license_key": license_key,
        "authenticated": True
    }

@app.post("/auth/logout")
def logout(session_id: Optional[str] = Cookie(None)):
    """Logout user"""
    if session_id:
        db = get_db()
        cur = db.cursor()
        cur.execute(q("DELETE FROM user_sessions WHERE session_id=?"), (session_id,))
        db.commit()
        db.close()
    
    response = JSONResponse({"success": True})
    response.delete_cookie("session_id")
    return response

# === PUBLIC CONFIGS ENDPOINTS ===

class PublicConfig(BaseModel):
    config_name: str
    author_name: str
    game_name: str
    description: str
    config_data: dict

@app.get("/api/public-configs")
def get_public_configs():
    """Get all public configs"""
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute(q("SELECT id, config_name, author_name, game_name, description, config_data, license_key, created_at, downloads FROM public_configs ORDER BY created_at DESC"))
        results = cur.fetchall()
        db.close()
        
        return {
            "configs": [
                {
                    "id": r[0],
                    "config_name": r[1],
                    "author_name": r[2],
                    "game_name": r[3],
                    "description": r[4],
                    "config_data": json.loads(r[5]),
                    "created_by": r[6][:8] + "...",  # Hide full license key
                    "created_at": r[7],
                    "downloads": r[8]
                } for r in results
            ]
        }
    except Exception as e:
        print(f"Public configs error: {e}")
        # Return empty list if table doesn't exist
        return {"configs": []}

@app.post("/api/public-configs/create")
def create_public_config(data: PublicConfig, authorization: Optional[str] = None, session_id: Optional[str] = Cookie(None)):
    """Create a public config (requires login)"""
    # Try Authorization header first
    token = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization.replace("Bearer ", "")
    elif session_id:
        token = session_id
    
    license_key = "website-user"  # Default
    
    if token:
        # Get license key from session
        db = get_db()
        cur = db.cursor()
        
        try:
            cur.execute(q("SELECT license_key FROM user_sessions WHERE session_id=?"), (token,))
            result = cur.fetchone()
            
            if result:
                license_key = result[0]
            
            db.close()
        except:
            try:
                db.close()
            except:
                pass
    
    # Insert public config with fresh connection
    db = get_db()
    cur = db.cursor()
    
    try:
        cur.execute(q("INSERT INTO public_configs (config_name, author_name, game_name, description, config_data, license_key, created_at, downloads) VALUES (?, ?, ?, ?, ?, ?, ?, 0)"),
                   (data.config_name, data.author_name, data.game_name, data.description, json.dumps(data.config_data), license_key, datetime.now().isoformat()))
        db.commit()
        db.close()
        return {"success": True, "message": "Config published successfully"}
    except Exception as e:
        try:
            db.close()
        except:
            pass
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/public-configs/{config_id}/download")
def download_public_config(config_id: int):
    """Increment download count"""
    db = get_db()
    cur = db.cursor()
    cur.execute(q("UPDATE public_configs SET downloads = downloads + 1 WHERE id=?"), (config_id,))
    db.commit()
    db.close()
    return {"success": True}

@app.get("/api/my-configs")
def get_my_saved_configs(session_id: Optional[str] = Cookie(None)):
    """Get current user's saved configs (for dropdown)"""
    if not session_id:
        raise HTTPException(status_code=401, detail="Not logged in")
    
    db = get_db()
    cur = db.cursor()
    cur.execute(q("SELECT license_key FROM user_sessions WHERE session_id=?"), (session_id,))
    result = cur.fetchone()
    
    if not result:
        db.close()
        raise HTTPException(status_code=403, detail="No license found")
    
    license_key = result[0]
    
    # Get user's saved configs
    cur.execute(q("SELECT config_name, config_data FROM saved_configs WHERE license_key=?"), (license_key,))
    configs = cur.fetchall()
    db.close()
    
    return {
        "configs": [
            {
                "name": c[0],
                "data": json.loads(c[1])
            } for c in configs
        ]
    }

DEFAULT_CONFIG = {
    "triggerbot": {"Enabled": True, "Keybind": "Right Mouse", "Delay": 0.05, "MaxStuds": 120,
        "StudCheck": True, "DeathCheck": True, "KnifeCheck": True, "TeamCheck": True,
        "TargetMode": False, "TargetKeybind": "Middle Mouse", "Prediction": 0.1, "FOV": 25},
    "camlock": {"Enabled": True, "Keybind": "Q", "FOV": 280.0, "SmoothX": 14.0, "SmoothY": 14.0,
        "EnableSmoothing": True, "EasingStyle": "Linear", "Prediction": 0.14, "EnablePrediction": True,
        "MaxStuds": 120.0, "UnlockOnDeath": True, "SelfDeathCheck": True, "BodyPart": "Head",
        "ClosestPart": False, "ScaleToggle": True, "Scale": 1.0}
}

class KeyCreate(BaseModel):
    duration: str
    created_by: str

class FreemiumToggle(BaseModel):
    enabled: int

class KeyRedeem(BaseModel):
    key: str
    user_id: str

class KeyValidate(BaseModel):
    key: str
    hwid: str

class SavedConfig(BaseModel):
    config_name: str
    config_data: dict

def generate_key():
    return '-'.join([''.join([str(random.randint(0, 9)) for _ in range(4)]) for _ in range(4)])

def get_expiry_date(duration, from_date=None):
    base = from_date if from_date else datetime.now()
    if duration == "weekly": return (base + timedelta(weeks=1)).isoformat()
    elif duration == "monthly": return (base + timedelta(days=30)).isoformat()
    elif duration == "3monthly": return (base + timedelta(days=90)).isoformat()
    return None

@app.get("/api/config/{key}")
def get_config(key: str = Path(...)):
    db = get_db()
    cur = db.cursor()
    
    # Try to insert default config if not exists (database-agnostic way)
    try:
        if USE_POSTGRES:
            cur.execute("INSERT INTO settings (key, config) VALUES (%s, %s) ON CONFLICT (key) DO NOTHING", 
                       (key, json.dumps(DEFAULT_CONFIG)))
        else:
            cur.execute("INSERT OR IGNORE INTO settings (key, config) VALUES (?, ?)", 
                       (key, json.dumps(DEFAULT_CONFIG)))
        db.commit()
    except:
        db.rollback()
    
    cur.execute(q("SELECT config FROM settings WHERE key=?"), (key,))
    result = cur.fetchone()
    db.close()
    return json.loads(result[0]) if result else DEFAULT_CONFIG

@app.post("/api/config/{key}")
def set_config(key: str, data: dict):
    db = get_db()
    cur = db.cursor()
    
    if USE_POSTGRES:
        cur.execute("INSERT INTO settings(key, config) VALUES(%s, %s) ON CONFLICT (key) DO UPDATE SET config=excluded.config", 
                   (key, json.dumps(data)))
    else:
        cur.execute("INSERT INTO settings(key, config) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET config=excluded.config", 
                   (key, json.dumps(data)))
    
    db.commit()
    db.close()
    return {"status": "ok"}

@app.get("/api/keepalive")
def keepalive():
    return {"status": "alive"}

@app.get("/api/debug/database")
def debug_database():
    """Debug endpoint to check database contents"""
    try:
        db = get_db()
        cur = db.cursor()
        
        # Count keys
        cur.execute(q("SELECT COUNT(*) FROM keys"))
        key_count = cur.fetchone()[0] if not USE_POSTGRES else cur.fetchone()[0]
        
        # Count configs
        cur.execute(q("SELECT COUNT(*) FROM saved_configs"))
        config_count = cur.fetchone()[0] if not USE_POSTGRES else cur.fetchone()[0]
        
        # List all keys
        cur.execute(q("SELECT key, duration, created_by, redeemed_by, active FROM keys"))
        keys = cur.fetchall()
        
        db.close()
        
        return {
            "database_type": "PostgreSQL" if USE_POSTGRES else "SQLite",
            "total_keys": key_count,
            "total_configs": config_count,
            "keys": [
                {
                    "key": k[0][:8] + "...",
                    "duration": k[1],
                    "created_by": k[2],
                    "redeemed_by": k[3],
                    "active": k[4]
                } for k in keys
            ]
        }
    except Exception as e:
        return {"error": str(e)}

@app.get("/api/configs/{key}/list")
def list_saved_configs(key: str):
    db = get_db()
    cur = db.cursor()
    cur.execute(q("SELECT config_name, created_at FROM saved_configs WHERE license_key=? ORDER BY created_at DESC"), (key,))
    results = cur.fetchall()
    db.close()
    return {"configs": [{"name": r[0], "created_at": r[1]} for r in results]}

@app.post("/api/configs/{key}/save")
def save_config(key: str, data: SavedConfig):
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute(q("INSERT INTO saved_configs (license_key, config_name, config_data, created_at) VALUES (?, ?, ?, ?)"),
                   (key, data.config_name, json.dumps(data.config_data), datetime.now().isoformat()))
        db.commit()
        db.close()
        return {"status": "saved"}
    except:
        cur.execute(q("UPDATE saved_configs SET config_data=?, created_at=? WHERE license_key=? AND config_name=?"),
                   (json.dumps(data.config_data), datetime.now().isoformat(), key, data.config_name))
        db.commit()
        db.close()
        return {"status": "updated"}
        return {"status": "updated"}

@app.get("/api/configs/{key}/load/{config_name}")
def load_saved_config(key: str, config_name: str):
    db = get_db()
    cur = db.cursor()
    cur.execute(q("SELECT config_data FROM saved_configs WHERE license_key=? AND config_name=?"), (key, config_name))
    result = cur.fetchone()
    db.close()
    if not result:
        raise HTTPException(status_code=404, detail="Config not found")
    return json.loads(result[0])

@app.delete("/api/configs/{key}/delete/{config_name}")
def delete_saved_config(key: str, config_name: str):
    db = get_db()
    cur = db.cursor()
    cur.execute(q("DELETE FROM saved_configs WHERE license_key=? AND config_name=?"), (key, config_name))
    db.commit()
    db.close()
    return {"status": "deleted"}

@app.post("/api/configs/{key}/rename")
def rename_saved_config(key: str, data: dict):
    old_name = data.get("old_name")
    new_name = data.get("new_name")
    db = get_db()
    cur = db.cursor()
    cur.execute(q("UPDATE saved_configs SET config_name=? WHERE license_key=? AND config_name=?"), (new_name, key, old_name))
    db.commit()
    db.close()
    return {"status": "renamed"}

@app.post("/api/keys/create")
def create_key(data: KeyCreate):
    db = get_db()
    cur = db.cursor()
    key = generate_key()
    try:
        cur.execute(q("INSERT INTO keys (key, duration, created_at, active, created_by) VALUES (?, ?, ?, 0, ?)"), 
                    (key, data.duration, datetime.now().isoformat(), data.created_by))
        db.commit()
        db.close()
        return {"key": key, "duration": data.duration, "status": "awaiting_redemption"}
    except Exception as e:
        db.close()
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/keys/redeem")
def redeem_key(data: KeyRedeem):
    db = get_db()
    cur = db.cursor()
    cur.execute(q("SELECT * FROM keys WHERE key=?"), (data.key,))
    result = cur.fetchone()
    if not result:
        db.close()
        raise HTTPException(status_code=404, detail="Invalid key")
    key, duration, created_at, expires_at, redeemed_at, redeemed_by, hwid, active, created_by = result
    if redeemed_by:
        db.close()
        raise HTTPException(status_code=400, detail="Key already redeemed by another user")
    now = datetime.now()
    expiry = get_expiry_date(duration, now)
    cur.execute(q("UPDATE keys SET redeemed_at=?, redeemed_by=?, expires_at=?, active=1 WHERE key=?"), 
                (now.isoformat(), data.user_id, expiry, data.key))
    db.commit()
    db.close()
    return {"success": True, "key": data.key, "duration": duration, "expires_at": expiry, "message": "Key redeemed successfully"}

@app.delete("/api/users/{user_id}/license")
def delete_user_license(user_id: str):
    db = get_db()
    cur = db.cursor()
    cur.execute(q("SELECT key FROM keys WHERE redeemed_by=?"), (user_id,))
    result = cur.fetchone()
    if not result:
        db.close()
        raise HTTPException(status_code=404, detail="No license found for this user")
    key = result[0]
    cur.execute(q("DELETE FROM keys WHERE redeemed_by=?"), (user_id,))
    db.commit()
    db.close()
    return {"status": "deleted", "key": key, "user_id": user_id}

@app.get("/api/users/{user_id}/license")
def get_user_license(user_id: str):
    db = get_db()
    cur = db.cursor()
    cur.execute(q("SELECT * FROM keys WHERE redeemed_by=?"), (user_id,))
    result = cur.fetchone()
    db.close()
    if not result:
        return {"active": False, "message": "No license found"}
    key, duration, created_at, expires_at, redeemed_at, redeemed_by, hwid, active, created_by = result
    if expires_at:
        is_expired = datetime.now() > datetime.fromisoformat(expires_at)
        if is_expired:
            return {"active": False, "expired": True, "key": key}
    return {"active": True, "key": key, "duration": duration, "expires_at": expires_at, "redeemed_at": redeemed_at, "hwid": hwid}

@app.post("/api/users/{user_id}/reset-hwid")
def reset_user_hwid(user_id: str):
    db = get_db()
    cur = db.cursor()
    cur.execute(q("SELECT hwid FROM keys WHERE redeemed_by=?"), (user_id,))
    result = cur.fetchone()
    if not result:
        db.close()
        raise HTTPException(status_code=404, detail="No license found for this user")
    old_hwid = result[0]
    cur.execute(q("UPDATE keys SET hwid=NULL WHERE redeemed_by=?"), (user_id,))
    db.commit()
    db.close()
    return {"status": "reset", "user_id": user_id, "old_hwid": old_hwid}

@app.get("/api/keys/{key}")
def get_key_info(key: str):
    db = get_db()
    cur = db.cursor()
    cur.execute(q("SELECT * FROM keys WHERE key=?"), (key,))
    result = cur.fetchone()
    db.close()
    if not result:
        raise HTTPException(status_code=404, detail="Key not found")
    return {"key": result[0], "duration": result[1], "created_at": result[2], "expires_at": result[3],
            "redeemed_at": result[4], "redeemed_by": result[5], "hwid": result[6], "active": result[7], "created_by": result[8]}

@app.get("/api/keys/list")
def list_keys():
    db = get_db()
    cur = db.cursor()
    cur.execute(q("SELECT * FROM keys ORDER BY created_at DESC"))
    results = cur.fetchall()
    db.close()
    keys = []
    for r in results:
        keys.append({"key": r[0], "duration": r[1], "created_at": r[2], "expires_at": r[3],
                     "redeemed_at": r[4], "redeemed_by": r[5], "hwid": r[6], "active": r[7], "created_by": r[8]})
    return {"keys": keys}

@app.post("/admin/freemium")
def toggle_freemium(data: FreemiumToggle):
    """Toggle freemium mode"""
    enabled = data.enabled
    
    db = get_db()
    cur = db.cursor()
    
    # Update or insert freemium setting
    try:
        if USE_POSTGRES:
            cur.execute("UPDATE freemium_settings SET enabled = %s, updated_at = %s WHERE id = 1", 
                       (enabled, datetime.now().isoformat()))
        else:
            cur.execute("UPDATE freemium_settings SET enabled = ?, updated_at = ? WHERE id = 1", 
                       (enabled, datetime.now().isoformat()))
        
        db.commit()
    except Exception as e:
        print(f"Freemium update error: {e}")
        db.rollback()
    
    db.close()
    
    return {
        "success": True,
        "enabled": enabled,
        "message": f"Freemium mode {'enabled' if enabled else 'disabled'}"
    }

@app.get("/admin/freemium/status")
def freemium_status():
    """Check freemium status"""
    db = get_db()
    cur = db.cursor()
    cur.execute(q("SELECT enabled FROM freemium_settings LIMIT 1"))
    result = cur.fetchone()
    db.close()
    
    enabled = result[0] if result else 0
    return {
        "enabled": enabled == 1 or enabled == True,
        "status": "enabled" if (enabled == 1 or enabled == True) else "disabled"
    }

@app.post("/api/validate")
def validate_key(data: KeyValidate):
    db = get_db()
    cur = db.cursor()
    
    # Check if freemium is enabled (handle missing table)
    freemium_enabled = False
    try:
        cur.execute(q("SELECT enabled FROM freemium_settings LIMIT 1"))
        freemium_result = cur.fetchone()
        freemium_enabled = freemium_result[0] if freemium_result else False
        if freemium_enabled == 1 or freemium_enabled == True:
            freemium_enabled = True
    except:
        # Table doesn't exist yet, freemium disabled
        freemium_enabled = False
    
    if freemium_enabled:
        # Freemium mode - any key works
        db.close()
        return {"valid": True, "message": "Freemium mode enabled - access granted", "key": data.key, "expires_at": None, "freemium": True}
    
    # Normal validation
    cur.execute(q("SELECT * FROM keys WHERE key=?"), (data.key,))
    result = cur.fetchone()
    if not result:
        db.close()
        return {"valid": False, "error": "Invalid key"}, 401
    key, duration, created_at, expires_at, redeemed_at, redeemed_by, hwid, active, created_by = result
    if not redeemed_by:
        db.close()
        return {"valid": False, "error": "Key not redeemed yet"}, 401
    if expires_at and datetime.now() > datetime.fromisoformat(expires_at):
        db.close()
        return {"valid": False, "error": "Key expired"}, 401
    if hwid is None:
        cur.execute(q("UPDATE keys SET hwid=? WHERE key=?"), (data.hwid, data.key))
        db.commit()
        db.close()
        return {"valid": True, "message": "HWID bound successfully", "key": key, "expires_at": expires_at}
    elif hwid == data.hwid:
        db.close()
        return {"valid": True, "message": "Authentication successful", "key": key, "expires_at": expires_at}
    else:
        db.close()
        return {"valid": False, "error": "HWID mismatch"}, 401

@app.get("/configs", response_class=HTMLResponse)
def serve_configs_page():
    """Public configs marketplace page"""
    return """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>AXION — Configs</title>
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
      top: 40px;
      left: 50%;
      transform: translateX(-50%);
      z-index: 10;
      width: 82%;
      max-width: 950px;
      padding: 12px 48px 12px 40px;
      border: 1px solid #1f1f1f;
      border-radius: 12px;
      background: transparent;
      backdrop-filter: blur(3px);
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 40px;
      font-size: 15px;
      letter-spacing: 0.8px;
    }

    .nav-links {
      display: flex;
      gap: 50px;
    }

    .nav-links a {
      text-decoration: none;
      color: #ffffff;
      cursor: pointer;
      transition: color 0.3s ease;
    }

    .nav-links a:hover {
      color: #ccc;
    }

    .user-info {
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 6px 12px;
      background: rgba(255,255,255,0.05);
      border-radius: 8px;
      cursor: pointer;
    }

    .user-info:hover {
      background: rgba(255,255,255,0.08);
    }

    .content {
      position: fixed;
      inset: 0;
      z-index: 5;
      overflow-y: auto;
      pointer-events: none;
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

    .about-page, .configs-page {
      justify-content: flex-start;
      padding-top: 15vh;
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

    .description {
      font-size: 1.15rem;
      max-width: 680px;
      text-align: center;
      line-height: 1.55;
      color: #ffffff;
      margin-top: 20px;
    }

    .configs-container {
      width: 90%;
      max-width: 1200px;
      margin-top: 60px;
    }

    .login-box {
      max-width: 400px;
      margin: 0 auto;
      padding: 40px;
      background: rgba(25,25,30,0.6);
      border: 1px solid rgba(255,255,255,0.08);
      border-radius: 12px;
      text-align: center;
    }

    .login-input {
      width: 100%;
      padding: 12px 16px;
      background: rgba(255,255,255,0.05);
      border: 1px solid rgba(255,255,255,0.1);
      border-radius: 8px;
      color: #fff;
      font-size: 15px;
      margin: 20px 0;
    }

    .login-input:focus {
      outline: none;
      border-color: rgba(255,255,255,0.3);
    }

    .btn {
      padding: 12px 32px;
      background: rgba(255,255,255,0.15);
      border: 1px solid rgba(255,255,255,0.25);
      border-radius: 8px;
      color: #fff;
      font-size: 15px;
      cursor: pointer;
      transition: all 0.2s;
    }

    .btn:hover {
      background: rgba(255,255,255,0.2);
    }

    .config-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
      gap: 20px;
      margin-bottom: 100px;
    }

    .config-card {
      background: rgba(25,25,30,0.6);
      border: 1px solid rgba(255,255,255,0.08);
      border-radius: 12px;
      padding: 24px;
      transition: all 0.3s;
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

    .download-btn {
      margin-top: 12px;
      width: 100%;
      padding: 10px;
      background: rgba(255,255,255,0.1);
      border: 1px solid rgba(255,255,255,0.2);
      border-radius: 6px;
      color: #fff;
      cursor: pointer;
      transition: all 0.2s;
    }

    .download-btn:hover {
      background: rgba(255,255,255,0.15);
    }

    .create-btn {
      padding: 14px 32px;
      background: rgba(255,255,255,0.15);
      border: 1px solid rgba(255,255,255,0.25);
      border-radius: 8px;
      color: #fff;
      font-size: 15px;
      cursor: pointer;
      transition: all 0.2s;
      margin-bottom: 30px;
    }

    .create-btn:hover {
      background: rgba(255,255,255,0.2);
      transform: translateY(-2px);
    }

    /* Modal */
    .modal {
      display: none;
      position: fixed;
      inset: 0;
      background: rgba(0,0,0,0.85);
      backdrop-filter: blur(10px);
      z-index: 100;
      justify-content: center;
      align-items: center;
    }

    .modal.active {
      display: flex;
    }

    .modal-content {
      background: rgba(18,18,22,0.98);
      border: 1px solid rgba(255,255,255,0.12);
      border-radius: 12px;
      padding: 28px 32px;
      width: 90%;
      max-width: 480px;
      max-height: 80vh;
      overflow-y: auto;
      box-shadow: 0 20px 60px rgba(0,0,0,0.5);
    }

    .modal-title {
      font-size: 22px;
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
      color: #999;
      margin-bottom: 6px;
      font-weight: 500;
    }

    .form-input, .form-select, .form-textarea {
      width: 100%;
      padding: 10px 14px;
      background: rgba(255,255,255,0.04);
      border: 1px solid rgba(255,255,255,0.08);
      border-radius: 6px;
      color: #fff;
      font-size: 14px;
      font-family: inherit;
      transition: all 0.2s;
    }

    .form-input:focus, .form-select:focus, .form-textarea:focus {
      outline: none;
      border-color: rgba(255,255,255,0.25);
      background: rgba(255,255,255,0.06);
    }

    .form-textarea {
      resize: vertical;
      min-height: 90px;
    }

    .modal-actions {
      display: flex;
      gap: 10px;
      margin-top: 20px;
    }

    .modal-btn {
      flex: 1;
      padding: 11px;
      border-radius: 6px;
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s;
      border: 1px solid rgba(255,255,255,0.15);
    }

    .modal-btn-cancel {
      background: rgba(255,255,255,0.04);
      color: #fff;
    }

    .modal-btn-cancel:hover {
      background: rgba(255,255,255,0.08);
    }

    .modal-btn-submit {
      background: rgba(255,255,255,0.12);
      color: #fff;
    }

    .modal-btn-submit:hover {
      background: rgba(255,255,255,0.18);
    }

    /* View Config Modal */
    .config-detail-modal .modal-content {
      max-width: 700px;
    }

    .config-stats {
      display: flex;
      gap: 20px;
      margin: 20px 0;
      padding: 16px;
      background: rgba(255,255,255,0.03);
      border-radius: 8px;
    }

    .stat-item {
      flex: 1;
      text-align: center;
    }

    .stat-label {
      font-size: 12px;
      color: #888;
      margin-bottom: 4px;
    }

    .stat-value {
      font-size: 20px;
      font-weight: 700;
    }
  </style>
</head>
<body>
  <div class="image-container"></div>

  <nav class="navbar">
    <div class="nav-links">
      <a onclick="showPage('home')">Home</a>
      <a onclick="showPage('about')">About</a>
      <a onclick="showPage('configs')">Configs</a>
    </div>
    <div style="display: flex; gap: 20px; align-items: center;">
      <img src="https://img.icons8.com/?size=100&id=30888&format=png&color=FFFFFF" alt="Discord" style="width: 22px; height: 22px; cursor: pointer; opacity: 0.9;" onclick="window.open('https://discord.gg/yourserver', '_blank')">
      <div id="userArea"></div>
    </div>
  </nav>

  <div class="content">
    <!-- Home -->
    <div id="home" class="page active">
      <div class="title-wrapper">
        <span class="title-word" style="color:#ffffff;">WELCOME</span>
        <span class="title-word" style="color:#ffffff;">TO</span>
        <span class="title-word" style="color:#888888;">AXION</span>
      </div>
    </div>

    <!-- About -->
    <div id="about" class="page about-page">
      <div class="title-wrapper">
        <span class="title-word" style="color:#ffffff;">About</span>
        <span class="title-word" style="color:#888888;">Axion</span>
      </div>
      <div class="description">
        Axion is a Da Hood external designed to integrate seamlessly in-game. It delivers smooth, reliable performance while bypassing PC checks, giving you a consistent edge during star tryouts and competitive play.
      </div>
    </div>

    <!-- Configs -->
    <div id="configs" class="page configs-page">
      <div class="title-wrapper">
        <span class="title-word" style="color:#ffffff;">Community</span>
        <span class="title-word" style="color:#888888;">Configs</span>
      </div>
      
      <div class="configs-container" id="configsContent"></div>
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
        <input type="text" class="form-input" id="configName" placeholder="e.g., Smooth Headshot V2">
      </div>

      <div class="form-group">
        <label class="form-label">Author Name</label>
        <input type="text" class="form-input" id="authorName" placeholder="Your name or alias">
      </div>

      <div class="form-group">
        <label class="form-label">Game</label>
        <input type="text" class="form-input" id="gameName" placeholder="e.g., Da Hood, Hood Modded, etc.">
      </div>

      <div class="form-group">
        <label class="form-label">Description</label>
        <textarea class="form-textarea" id="configDescription" placeholder="Describe your config settings..."></textarea>
      </div>

      <div class="modal-actions">
        <button class="modal-btn modal-btn-cancel" onclick="closeCreateModal()">Cancel</button>
        <button class="modal-btn modal-btn-submit" onclick="submitConfig()">Publish Config</button>
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

      <div class="form-group">
        <label class="form-label">Description</label>
        <p id="viewDescription" style="color: #aaa; line-height: 1.6;">-</p>
      </div>

      <div class="modal-actions">
        <button class="modal-btn modal-btn-cancel" onclick="closeViewModal()">Close</button>
        <button class="modal-btn modal-btn-submit" onclick="saveConfigToMenu()">Save to My Menu</button>
      </div>
    </div>
  </div>

  <script>
    let currentUser = null;
    let currentViewConfig = null;

    function showPage(pageId) {
      document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
      document.getElementById(pageId).classList.add('active');
      
      if (pageId === 'configs') {
        checkAuth();
      }
    }

    async function checkAuth() {
      const licenseKey = localStorage.getItem('license_key');
      if (licenseKey) {
        currentUser = { license_key: licenseKey };
        updateUI();
        loadConfigs();
      } else {
        showLogin();
      }
    }

    function updateUI() {
      document.getElementById('userArea').innerHTML = `
        <div class="user-info" onclick="logout()">
          <span>${currentUser.license_key.substring(0, 12)}...</span>
        </div>
      `;
    }

    function showLogin() {
      document.getElementById('configsContent').innerHTML = `
        <div class="login-box">
          <h2 style="margin-bottom: 12px;">Login Required</h2>
          <p style="color: #888; margin-bottom: 20px;">Enter your license key to view configs</p>
          <input type="text" id="licenseInput" class="login-input" placeholder="AXION-XXXX-XXXX-XXXX">
          <button class="btn" onclick="submitLogin()">Login</button>
        </div>
      `;
    }

    async function submitLogin() {
      const licenseKey = document.getElementById('licenseInput').value.trim();
      if (!licenseKey) {
        alert('Please enter your license key');
        return;
      }

      try {
        console.log('Logging in...');
        
        const res = await fetch('/auth/login', {
          method: 'POST',
          headers: { 
            'Content-Type': 'application/json',
            'Accept': 'application/json'
          },
          body: JSON.stringify({ license_key: licenseKey })
        });

        console.log('Response status:', res.status);
        
        if (!res.ok) {
          const text = await res.text();
          console.error('Error response:', text);
          alert('Login failed: ' + text);
          return;
        }

        const data = await res.json();
        console.log('Login successful:', data);

        localStorage.setItem('session_id', data.session_id);
        localStorage.setItem('license_key', data.license_key);
        currentUser = { license_key: data.license_key };
        updateUI();
        loadConfigs();
      } catch (e) {
        console.error('Login error:', e);
        alert('Error: ' + e.message);
      }
    }

    function logout() {
      localStorage.removeItem('session_id');
      localStorage.removeItem('license_key');
      currentUser = null;
      location.reload();
    }

    async function loadConfigs() {
      try {
        const res = await fetch('/api/public-configs');
        const data = await res.json();
        
        let html = '<button class="create-btn" onclick="openCreateModal()">+ Create Config</button>';
        html += '<div class="config-grid">';
        
        if (data.configs && data.configs.length > 0) {
          data.configs.forEach(config => {
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
        document.getElementById('configsContent').innerHTML = html;
      } catch (e) {
        console.error('Load error:', e);
        document.getElementById('configsContent').innerHTML = '<p>Error loading configs</p>';
      }
    }

    async function openCreateModal() {
      document.getElementById('createModal').classList.add('active');
      
      // Load user's saved configs
      try {
        const res = await fetch(`/api/configs/${currentUser.license_key}/list`);
        const data = await res.json();
        
        const select = document.getElementById('savedConfigSelect');
        select.innerHTML = '<option value="">Select a config...</option>';
        
        if (data.configs && data.configs.length > 0) {
          data.configs.forEach(config => {
            const option = document.createElement('option');
            option.value = config.name;
            option.textContent = config.name;
            select.appendChild(option);
          });
        } else {
          select.innerHTML = '<option value="">No saved configs found</option>';
        }
      } catch (e) {
        console.error('Error loading configs:', e);
        alert('Error loading your configs');
      }
    }

    function closeCreateModal() {
      document.getElementById('createModal').classList.remove('active');
    }

    async function submitConfig() {
      const savedConfigName = document.getElementById('savedConfigSelect').value;
      const configName = document.getElementById('configName').value.trim();
      const authorName = document.getElementById('authorName').value.trim();
      const gameName = document.getElementById('gameName').value;
      const description = document.getElementById('configDescription').value.trim();

      if (!savedConfigName) {
        alert('Please select a saved config');
        return;
      }

      if (!configName || !authorName || !description) {
        alert('Please fill all fields');
        return;
      }

      try {
        // Load the actual config data
        const configRes = await fetch(`/api/configs/${currentUser.license_key}/load/${savedConfigName}`);
        const configData = await configRes.json();

        // Create public config
        const sessionId = localStorage.getItem('session_id');
        const res = await fetch('/api/public-configs/create', {
          method: 'POST',
          headers: { 
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${sessionId}`
          },
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
          alert('Error: ' + error.detail);
        }
      } catch (e) {
        console.error('Error:', e);
        alert('Error creating config');
      }
    }

    async function viewConfig(configId) {
      try {
        const res = await fetch('/api/public-configs');
        const data = await res.json();
        const config = data.configs.find(c => c.id === configId);
        
        if (!config) return;

        currentViewConfig = config;
        
        document.getElementById('viewConfigName').textContent = config.config_name;
        document.getElementById('viewGame').textContent = config.game_name;
        document.getElementById('viewAuthor').textContent = config.author_name;
        document.getElementById('viewDownloads').textContent = config.downloads;
        document.getElementById('viewDescription').textContent = config.description;
        
        document.getElementById('viewModal').classList.add('active');
        
        // Increment download count
        await fetch(`/api/public-configs/${configId}/download`, { method: 'POST' });
      } catch (e) {
        console.error('Error:', e);
      }
    }

    function closeViewModal() {
      document.getElementById('viewModal').classList.remove('active');
      currentViewConfig = null;
      loadConfigs(); // Refresh to show updated download count
    }

    async function saveConfigToMenu() {
      if (!currentViewConfig) return;

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
          alert(`Config "${currentViewConfig.config_name}" saved to your menu!`);
          closeViewModal();
        } else {
          alert('Error saving config');
        }
      } catch (e) {
        alert('Error saving config');
      }
    }

    // Close modals on Escape
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        closeCreateModal();
        closeViewModal();
      }
    });
  </script>
</body>
</html>
"""

@app.get("/{key}", response_class=HTMLResponse)
def serve_ui(key: str):
    # Validate license key exists
    db = get_db()
    cur = db.cursor()
    cur.execute(q("SELECT key, redeemed_by, active FROM keys WHERE key=?"), (key,))
    result = cur.fetchone()
    db.close()
    
    if not result:
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Invalid License</title>
            <style>
                body {
                    margin: 0;
                    padding: 0;
                    height: 100vh;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    background: #0c0c0c;
                    color: #fff;
                    font-family: system-ui, sans-serif;
                }
                .error-box {
                    text-align: center;
                    padding: 40px;
                    background: rgba(255,255,255,0.05);
                    border: 1px solid rgba(255,255,255,0.1);
                    border-radius: 12px;
                }
                h1 { margin: 0 0 20px 0; color: #ff4444; }
                p { margin: 0; color: #888; }
            </style>
        </head>
        <body>
            <div class="error-box">
                <h1>❌ Invalid License Key</h1>
                <p>The license key you entered does not exist.</p>
            </div>
        </body>
        </html>
        """
    
    return f"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<title>Axion - {key}</title>
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
.toggle.active+.enable-text{{color:#e0e0e0}}
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
<div class="slider-container" id="triggerbotFovSlider" style="top:264px" data-setting="triggerbot.FOV">
<div class="slider-track">
<div class="slider-fill" id="triggerbotFovFill"></div>
<div class="slider-value" id="triggerbotFovValue">25</div>
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
let config={json.dumps(DEFAULT_CONFIG)};

document.querySelectorAll('.tab').forEach(tab=>{{
tab.addEventListener('click',()=>{{
document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
document.querySelectorAll('.tab-content').forEach(tc=>tc.classList.remove('active'));
tab.classList.add('active');
document.getElementById(tab.getAttribute('data-tab')).classList.add('active');
}});
}});

async function saveConfig(){{try{{await fetch(`/api/config/{key}`,{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify(config)}});}}catch(e){{console.error('Save failed:',e);}}}}

async function loadConfig(){{try{{const res=await fetch(`/api/config/{key}`);config=await res.json();applyConfigToUI();}}catch(e){{console.error('Load failed:',e);}}}}

function applyConfigToUI(){{
document.querySelectorAll('.toggle[data-setting]').forEach(toggle=>{{
const setting=toggle.dataset.setting;
const[section,key]=setting.split('.');
if(config[section]&&config[section][key]!==undefined)toggle.classList.toggle('active',config[section][key]);
}});

document.querySelectorAll('.keybind-picker[data-setting]').forEach(picker=>{{
const setting=picker.dataset.setting;
const[section,key]=setting.split('.');
if(config[section]&&config[section][key]!==undefined)picker.textContent=config[section][key];
}});

if(sliders.delay){{sliders.delay.current=config.triggerbot.Delay;sliders.delay.update();}}
if(sliders.maxStuds){{sliders.maxStuds.current=config.triggerbot.MaxStuds;sliders.maxStuds.update();}}
if(sliders.pred){{sliders.pred.current=config.triggerbot.Prediction;sliders.pred.update();}}
if(sliders.triggerbotFov){{sliders.triggerbotFov.current=config.triggerbot.FOV;sliders.triggerbotFov.update();}}
if(sliders.fov){{sliders.fov.current=config.camlock.FOV;sliders.fov.update();}}
if(sliders.smoothX){{sliders.smoothX.current=config.camlock.SmoothX;sliders.smoothX.update();}}
if(sliders.smoothY){{sliders.smoothY.current=config.camlock.SmoothY;sliders.smoothY.update();}}
if(sliders.camlockPred){{sliders.camlockPred.current=config.camlock.Prediction;sliders.camlockPred.update();}}
if(sliders.camlockMaxStuds){{sliders.camlockMaxStuds.current=config.camlock.MaxStuds;sliders.camlockMaxStuds.update();}}
if(sliders.scale){{sliders.scale.current=config.camlock.Scale;sliders.scale.update();}}

if(config.camlock.BodyPart){{
document.getElementById('bodyPartHeader').textContent=config.camlock.BodyPart;
document.querySelectorAll('#bodyPartList .dropdown-item').forEach(item=>{{
item.classList.toggle('selected',item.dataset.value===config.camlock.BodyPart);
}});
}}

if(config.camlock.EasingStyle){{
document.getElementById('easingHeader').textContent=config.camlock.EasingStyle;
document.querySelectorAll('#easingList .dropdown-item').forEach(item=>{{
item.classList.toggle('selected',item.dataset.value===config.camlock.EasingStyle);
}});
}}
}}

document.querySelectorAll('.toggle[data-setting]').forEach(toggle=>{{
toggle.addEventListener('click',()=>{{
toggle.classList.toggle('active');
const setting=toggle.dataset.setting;
const[section,key]=setting.split('.');
config[section][key]=toggle.classList.contains('active');
saveConfig();
}});
}});

document.querySelectorAll('.keybind-picker[data-setting]').forEach(picker=>{{
picker.addEventListener('click',()=>{{
picker.textContent='...';
const listener=(e)=>{{
e.preventDefault();
let keyName='';
if(e.button!==undefined){{
keyName=e.button===0?'Left Mouse':e.button===2?'Right Mouse':e.button===1?'Middle Mouse':`Mouse${{e.button}}`;
}}else if(e.key){{
keyName=e.key.toUpperCase();
if(keyName===' ')keyName='SPACE';
}}
picker.textContent=keyName||'NONE';
const setting=picker.dataset.setting;
const[section,key]=setting.split('.');
config[section][key]=keyName;
saveConfig();
document.removeEventListener('keydown',listener);
document.removeEventListener('mousedown',listener);
}};
document.addEventListener('keydown',listener,{{once:true}});
document.addEventListener('mousedown',listener,{{once:true}});
}});
}});

document.getElementById('bodyPartHeader').addEventListener('click',()=>{{
document.getElementById('bodyPartList').classList.toggle('open');
}});

document.querySelectorAll('#bodyPartList .dropdown-item').forEach(item=>{{
item.addEventListener('click',()=>{{
const value=item.dataset.value;
document.getElementById('bodyPartHeader').textContent=value;
document.querySelectorAll('#bodyPartList .dropdown-item').forEach(i=>i.classList.remove('selected'));
item.classList.add('selected');
document.getElementById('bodyPartList').classList.remove('open');
config.camlock.BodyPart=value;
saveConfig();
}});
}});

document.getElementById('easingHeader').addEventListener('click',()=>{{
document.getElementById('easingList').classList.toggle('open');
}});

document.querySelectorAll('#easingList .dropdown-item').forEach(item=>{{
item.addEventListener('click',()=>{{
const value=item.dataset.value;
document.getElementById('easingHeader').textContent=value;
document.querySelectorAll('#easingList .dropdown-item').forEach(i=>i.classList.remove('selected'));
item.classList.add('selected');
document.getElementById('easingList').classList.remove('open');
config.camlock.EasingStyle=value;
saveConfig();
}});
}});

const sliders={{}};

function createDecimalSlider(id,fillId,valueId,defaultVal,min,max,step,setting){{
const slider=document.getElementById(id);
if(!slider)return null;
const fill=document.getElementById(fillId);
const valueText=document.getElementById(valueId);

const obj={{
current:defaultVal,min:min,max:max,step:step,setting:setting,
update:function(){{
const percent=((this.current-this.min)/(this.max-this.min))*100;
fill.style.width=percent+'%';
valueText.textContent=this.current.toFixed(2);
valueText.style.color=this.current>=0.5?'#000':'#fff';
}}
}};

slider.addEventListener('mousedown',(e)=>{{
const rect=slider.getBoundingClientRect();
function move(e){{
const x=e.clientX-rect.left;
let percent=Math.max(0,Math.min(100,(x/rect.width)*100));
obj.current=obj.min+(percent/100)*(obj.max-obj.min);
obj.current=Math.round(obj.current/obj.step)*obj.step;
obj.current=Math.max(obj.min,Math.min(obj.max,obj.current));
obj.update();
const[section,key]=obj.setting.split('.');
config[section][key]=obj.current;
saveConfig();
}}
function up(){{
document.removeEventListener('mousemove',move);
document.removeEventListener('mouseup',up);
}}
document.addEventListener('mousemove',move);
document.addEventListener('mouseup',up);
move(e);
}});
obj.update();
return obj;
}}

function createIntSlider(id,fillId,valueId,defaultVal,min,max,blackThreshold,setting){{
const slider=document.getElementById(id);
if(!slider)return null;
const fill=document.getElementById(fillId);
const valueText=document.getElementById(valueId);

const obj={{
current:defaultVal,min:min,max:max,blackThreshold:blackThreshold,setting:setting,
update:function(){{
const percent=((this.current-this.min)/(this.max-this.min))*100;
fill.style.width=percent+'%';
valueText.textContent=Math.round(this.current);
valueText.style.color=this.current>=this.blackThreshold?'#000':'#fff';
}}
}};

slider.addEventListener('mousedown',(e)=>{{
const rect=slider.getBoundingClientRect();
function move(e){{
const x=e.clientX-rect.left;
const percent=Math.max(0,Math.min(100,(x/rect.width)*100));
obj.current=obj.min+(percent/100)*(obj.max-obj.min);
obj.current=Math.round(obj.current);
obj.current=Math.max(obj.min,Math.min(obj.max,obj.current));
obj.update();
const[section,key]=obj.setting.split('.');
config[section][key]=Math.round(obj.current);
saveConfig();
}}
function up(){{
document.removeEventListener('mousemove',move);
document.removeEventListener('mouseup',up);
}}
document.addEventListener('mousemove',move);
document.addEventListener('mouseup',up);
move(e);
}});
obj.update();
return obj;
}}

sliders.delay=createDecimalSlider('delaySlider','delayFill','delayValue',0.05,0.01,1.00,0.01,'triggerbot.Delay');
sliders.maxStuds=createIntSlider('maxStudsSlider','maxStudsFill','maxStudsValue',120,0,300,150,'triggerbot.MaxStuds');
sliders.pred=createDecimalSlider('predSlider','predFill','predValue',0.10,0.01,1.00,0.01,'triggerbot.Prediction');
sliders.triggerbotFov=createIntSlider('triggerbotFovSlider','triggerbotFovFill','triggerbotFovValue',25,1,100,50,'triggerbot.FOV');
sliders.fov=createIntSlider('fovSlider','fovFill','fovValue',280,0,500,250,'camlock.FOV');
sliders.smoothX=createIntSlider('smoothXSlider','smoothXFill','smoothXValue',14,0,30,15,'camlock.SmoothX');
sliders.smoothY=createIntSlider('smoothYSlider','smoothYFill','smoothYValue',14,0,30,15,'camlock.SmoothY');
sliders.camlockPred=createDecimalSlider('camlockPredSlider','camlockPredFill','camlockPredValue',0.14,0.01,1.00,0.01,'camlock.Prediction');
sliders.camlockMaxStuds=createIntSlider('camlockMaxStudsSlider','camlockMaxStudsFill','camlockMaxStudsValue',120,0,300,150,'camlock.MaxStuds');
sliders.scale=createDecimalSlider('scaleSlider','scaleFill','scaleValue',1.0,0.5,2.0,0.1,'camlock.Scale');

async function loadSavedConfigs(){{
try{{
const res=await fetch(`/api/configs/{key}/list`);
const data=await res.json();
const list=document.getElementById('configList');
list.innerHTML='';
data.configs.forEach((cfg,idx)=>{{
const div=document.createElement('div');
div.className='config-item';
div.innerHTML=`
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
}}catch(e){{console.error(e);}}
}}

function toggleConfigMenu(e, idx){{
e.stopPropagation();
const menu=document.getElementById(`configMenu${{idx}}`);
document.querySelectorAll('.config-menu').forEach(m=>{{
if(m!==menu)m.classList.remove('open');
}});
menu.classList.toggle('open');
}}

document.addEventListener('click',()=>{{
document.querySelectorAll('.config-menu').forEach(m=>m.classList.remove('open'));
}});

async function saveCurrentConfig(){{
const name=document.getElementById('saveConfigInput').value.trim();
if(!name)return alert('Enter config name');
try{{
await fetch(`/api/configs/{key}/save`,{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{config_name:name,config_data:config}})}});
document.getElementById('saveConfigInput').value='';
await loadSavedConfigs();
}}catch(e){{alert('Failed to save');}}
}}

async function loadConfigByName(name){{
try{{
const res=await fetch(`/api/configs/{key}/load/${{name}}`);
config=await res.json();
applyConfigToUI();
await saveConfig();
}}catch(e){{alert('Failed to load');}}
}}

let currentRenameConfig=null;

function renameConfigPrompt(oldName){{
currentRenameConfig=oldName;
document.getElementById('renameInput').value=oldName;
document.getElementById('renameModal').classList.add('active');
document.getElementById('renameInput').focus();
document.getElementById('renameInput').select();
}}

function closeRenameModal(){{
document.getElementById('renameModal').classList.remove('active');
currentRenameConfig=null;
}}

async function confirmRename(){{
const newName=document.getElementById('renameInput').value.trim();
if(!newName||newName===currentRenameConfig){{
closeRenameModal();
return;
}}
try{{
await fetch(`/api/configs/{key}/rename`,{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{old_name:currentRenameConfig,new_name:newName}})}});
await loadSavedConfigs();
closeRenameModal();
}}catch(e){{
alert('Failed to rename');
closeRenameModal();
}}
}}

document.getElementById('renameInput').addEventListener('keypress',(e)=>{{
if(e.key==='Enter')confirmRename();
if(e.key==='Escape')closeRenameModal();
}});

async function deleteConfigByName(name){{
try{{
await fetch(`/api/configs/{key}/delete/${{name}}`,{{method:'DELETE'}});
await loadSavedConfigs();
}}catch(e){{alert('Failed to delete');}}
}}

loadSavedConfigs();
loadConfig();
setInterval(loadConfig,1000);
</script>
</body>
</html>
"""
