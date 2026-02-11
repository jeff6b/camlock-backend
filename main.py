from fastapi import FastAPI, HTTPException, Cookie, Response, Request
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
import time
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
import hashlib
import hmac

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)

app = FastAPI()

# Add rate limiting middleware
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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
    # For SQLite, replace %s with ?
    import re
    # Replace %s but not %%s (escaped percent signs)
    return re.sub(r'(?<!%)%s(?!%)', '?', query)

# Password hashing functions
def hash_password(password: str, salt: str = None) -> tuple:
    """Hash password with salt"""
    if salt is None:
        salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return f"{salt}:{key.hex()}", salt

def verify_password(stored_hash: str, password: str) -> bool:
    """Verify password against stored hash"""
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
        
        # Create keys table with lifetime support
        if USE_POSTGRES:
            # Drop tables if they exist to recreate them
            cur.execute("DROP TABLE IF EXISTS login_sessions CASCADE")
            cur.execute("DROP TABLE IF EXISTS user_accounts CASCADE")
            cur.execute("DROP TABLE IF EXISTS user_sessions CASCADE")
            cur.execute("DROP TABLE IF EXISTS settings CASCADE")
            cur.execute("DROP TABLE IF EXISTS public_configs CASCADE")
            cur.execute("DROP TABLE IF EXISTS saved_configs CASCADE")
            cur.execute("DROP TABLE IF EXISTS keys CASCADE")
            
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
            
            cur.execute("""CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                config TEXT NOT NULL
            )""")
            
            # Add user accounts table
            cur.execute("""CREATE TABLE IF NOT EXISTS user_accounts (
                id SERIAL PRIMARY KEY,
                license_key TEXT UNIQUE NOT NULL,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT,
                created_at TEXT NOT NULL,
                last_login TEXT,
                FOREIGN KEY (license_key) REFERENCES keys(key) ON DELETE CASCADE
            )""")
            
            cur.execute("""CREATE TABLE IF NOT EXISTS login_sessions (
                session_id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                license_key TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                ip_address TEXT
            )""")
            
        else:
            # For SQLite, we need to handle tables differently
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
            
            # Add user accounts table
            cur.execute("""CREATE TABLE IF NOT EXISTS user_accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                license_key TEXT UNIQUE NOT NULL,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT,
                created_at TEXT NOT NULL,
                last_login TEXT,
                FOREIGN KEY (license_key) REFERENCES keys(key) ON DELETE CASCADE
            )""")
            
            cur.execute("""CREATE TABLE IF NOT EXISTS login_sessions (
                session_id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                license_key TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                ip_address TEXT
            )""")
        
        db.commit()
        print(f"Database initialized successfully. Using: {'PostgreSQL' if USE_POSTGRES else 'SQLite'}")
        
        # Test the tables
        cur.execute("SELECT * FROM keys LIMIT 1")
        print("Keys table: OK")
        
        cur.execute("SELECT * FROM user_accounts LIMIT 1")
        print("User accounts table: OK")
        
    except Exception as e:
        print(f"Database initialization error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        try:
            db.close()
        except:
            pass

# Initialize database on startup
init_db()

# Helper function to create web sessions
def create_web_session(license_key):
    """Create a web session record when user logs in via website"""
    db = get_db()
    cur = db.cursor()
    
    session_id = secrets.token_hex(16)
    created_at = datetime.now().isoformat()
    expires_at = (datetime.now() + timedelta(minutes=10)).isoformat()
    
    if USE_POSTGRES:
        cur.execute("""
            INSERT INTO user_sessions (session_id, license_key, created_at, expires_at)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (license_key) DO UPDATE 
            SET session_id = EXCLUDED.session_id, 
                created_at = EXCLUDED.created_at, 
                expires_at = EXCLUDED.expires_at
        """, (session_id, license_key, created_at, expires_at))
    else:
        cur.execute("""
            INSERT OR REPLACE INTO user_sessions 
            (session_id, license_key, created_at, expires_at)
            VALUES (?, ?, ?, ?)
        """, (session_id, license_key, created_at, expires_at))
    
    db.commit()
    db.close()
    
    return session_id

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

class CreateAccount(BaseModel):
    license_key: str
    username: str
    password: str
    email: Optional[str] = None

class UserLogin(BaseModel):
    username: str
    password: str

# Security middleware
@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response

ENHANCED_ANTI_DEVTOOLS_JS = """
<script>
(function() {
    'use strict';
    
    document.addEventListener('keydown', function(e) {
        if (e.key === 'F12' || e.keyCode === 123) {
            e.preventDefault();
            e.stopPropagation();
            startDebuggerSpam();
            return false;
        }
        
        if (e.ctrlKey && e.shiftKey && (e.key === 'I' || e.keyCode === 73)) {
            e.preventDefault();
            e.stopPropagation();
            startDebuggerSpam();
            return false;
        }
        
        if (e.ctrlKey && e.shiftKey && (e.key === 'J' || e.keyCode === 74)) {
            e.preventDefault();
            e.stopPropagation();
            startDebuggerSpam();
            return false;
        }
        
        if (e.ctrlKey && e.shiftKey && (e.key === 'C' || e.keyCode === 67)) {
            e.preventDefault();
            e.stopPropagation();
            startDebuggerSpam();
            return false;
        }
        
        if (e.ctrlKey && (e.key === 'U' || e.keyCode === 85)) {
            e.preventDefault();
            e.stopPropagation();
            startDebuggerSpam();
            return false;
        }
    });
    
    document.addEventListener('contextmenu', function(e) {
        e.preventDefault();
        e.stopPropagation();
        return false;
    });
    
    function startDebuggerSpam() {
        setInterval(() => {
            try {
                debugger;
                eval("debugger");
                Function("debugger")();
            } catch(e) {}
        }, 50);
        
        setInterval(() => {
            if (typeof console !== 'undefined') {
                console.clear();
                console.log('%c Stop', 'color: red; font-size: 30px; font-weight: bold;');
            }
        }, 100);
    }
    
    let lastWidth = window.innerWidth;
    let lastHeight = window.innerHeight;
    
    setInterval(() => {
        const widthDiff = Math.abs(window.outerWidth - window.innerWidth);
        const heightDiff = Math.abs(window.outerHeight - window.innerHeight);
        
        if (widthDiff > 150 || heightDiff > 150) {
            startDebuggerSpam();
        }
        
        lastWidth = window.innerWidth;
        lastHeight = window.innerHeight;
    }, 1000);
})();
</script>
"""

# ========== API ENDPOINTS ==========

@app.post("/api/validate")
@limiter.limit("10/minute")
async def validate_user(request: Request, data: KeyValidate):
    """Validate license key"""
    db = get_db()
    cur = db.cursor()
    
    try:
        cur.execute(q("SELECT key, active, expires_at, hwid FROM keys WHERE key=%s"), (data.key,))
        result = cur.fetchone()
        
        if not result:
            db.close()
            return {"valid": False, "error": "Invalid license key"}
        
        key, active, expires_at, hwid = result
        
        if active == 0:
            db.close()
            return {"valid": False, "error": "License inactive"}
        
        # Check if license is lifetime (no expiration) or expired
        if expires_at:
            try:
                if datetime.now() > datetime.fromisoformat(expires_at):
                    db.close()
                    return {"valid": False, "error": "License expired"}
            except:
                pass
        
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
        
        # Web login - create session
        db.close()
        create_web_session(data.key)
        return {"valid": True, "message": "Web login successful", "license_key": data.key}
        
    except Exception as e:
        db.close()
        return {"valid": False, "error": f"Server error: {str(e)}"}

@app.post("/api/create-account")
@limiter.limit("5/minute")
async def create_account(request: Request, data: CreateAccount):
    """Create username/password account for license"""
    db = get_db()
    cur = db.cursor()
    
    try:
        # Check if license exists and is active
        cur.execute(q("SELECT key, active, expires_at FROM keys WHERE key=%s"), (data.license_key,))
        license_result = cur.fetchone()
        
        if not license_result:
            db.close()
            return {"success": False, "error": "Invalid license key"}
        
        key, active, expires_at = license_result
        
        if active == 0:
            db.close()
            return {"success": False, "error": "License inactive"}
        
        # Check if license is expired (except lifetime)
        if expires_at:
            try:
                if datetime.now() > datetime.fromisoformat(expires_at):
                    db.close()
                    return {"success": False, "error": "License expired"}
            except:
                pass
        
        # Check if username already exists
        cur.execute(q("SELECT username FROM user_accounts WHERE username=%s"), (data.username,))
        if cur.fetchone():
            db.close()
            return {"success": False, "error": "Username already exists"}
        
        # Check if license already has an account
        cur.execute(q("SELECT license_key FROM user_accounts WHERE license_key=%s"), (data.license_key,))
        if cur.fetchone():
            db.close()
            return {"success": False, "error": "Account already exists for this license"}
        
        # Hash password
        password_hash, salt = hash_password(data.password)
        
        # Create account
        cur.execute(q("""
            INSERT INTO user_accounts (license_key, username, password_hash, email, created_at)
            VALUES (%s, %s, %s, %s, %s)
        """), (data.license_key, data.username, password_hash, data.email, datetime.now().isoformat()))
        
        db.commit()
        db.close()
        
        return {"success": True, "message": "Account created successfully"}
        
    except Exception as e:
        db.close()
        return {"success": False, "error": f"Server error: {str(e)}"}

@app.post("/api/user-login")
@limiter.limit("10/minute")
async def user_login(request: Request, data: UserLogin):
    """Login with username/password"""
    db = get_db()
    cur = db.cursor()
    
    try:
        # Get user account
        cur.execute(q("""
            SELECT ua.username, ua.password_hash, ua.license_key, k.active, k.expires_at
            FROM user_accounts ua
            JOIN keys k ON ua.license_key = k.key
            WHERE ua.username=%s
        """), (data.username,))
        
        result = cur.fetchone()
        
        if not result:
            db.close()
            return {"valid": False, "error": "Invalid username or password"}
        
        username, password_hash, license_key, active, expires_at = result
        
        # Check license status
        if active == 0:
            db.close()
            return {"valid": False, "error": "License inactive"}
        
        # Check if license is expired (except lifetime)
        if expires_at:
            try:
                if datetime.now() > datetime.fromisoformat(expires_at):
                    db.close()
                    return {"valid": False, "error": "License expired"}
            except:
                pass
        
        # Verify password
        if not verify_password(password_hash, data.password):
            db.close()
            return {"valid": False, "error": "Invalid username or password"}
        
        # Update last login
        cur.execute(q("UPDATE user_accounts SET last_login=%s WHERE username=%s"),
                   (datetime.now().isoformat(), username))
        
        # Create session
        session_id = secrets.token_hex(16)
        created_at = datetime.now().isoformat()
        expires_at_session = (datetime.now() + timedelta(days=30)).isoformat()
        
        cur.execute(q("""
            INSERT INTO login_sessions (session_id, username, license_key, created_at, expires_at, ip_address)
            VALUES (%s, %s, %s, %s, %s, %s)
        """), (session_id, username, license_key, created_at, expires_at_session, request.client.host))
        
        db.commit()
        db.close()
        
        # Also create web session for backward compatibility
        create_web_session(license_key)
        
        return {
            "valid": True, 
            "message": "Login successful",
            "username": username,
            "license_key": license_key,
            "session_id": session_id
        }
        
    except Exception as e:
        db.close()
        return {"valid": False, "error": f"Server error: {str(e)}"}

@app.get("/api/account-info/{license_key}")
@limiter.limit("30/minute")
def get_account_info(request: Request, license_key: str):
    """Get account info for a license key"""
    db = get_db()
    cur = db.cursor()
    
    try:
        cur.execute(q("""
            SELECT username, email, created_at, last_login 
            FROM user_accounts 
            WHERE license_key=%s
        """), (license_key,))
        
        result = cur.fetchone()
        db.close()
        
        if not result:
            return {"exists": False}
        
        username, email, created_at, last_login = result
        
        return {
            "exists": True,
            "username": username,
            "email": email,
            "created_at": created_at,
            "last_login": last_login
        }
        
    except Exception as e:
        db.close()
        return {"exists": False, "error": str(e)}

@app.get("/api/config/{key}")
@limiter.limit("30/minute")
def get_config(request: Request, key: str):
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
        return DEFAULT_CONFIG

@app.post("/api/config/{key}")
@limiter.limit("20/minute")
async def set_config(request: Request, key: str, data: dict):
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
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")

@app.get("/api/configs/{license_key}/list")
@limiter.limit("30/minute")
def list_configs(request: Request, license_key: str):
    """List saved configs"""
    db = get_db()
    cur = db.cursor()
    cur.execute(q("SELECT config_name, created_at FROM saved_configs WHERE license_key=%s ORDER BY created_at DESC"), (license_key,))
    rows = cur.fetchall()
    db.close()
    
    configs = [{"name": row[0], "created_at": row[1]} for row in rows]
    return {"configs": configs}

@app.post("/api/configs/{license_key}/save")
@limiter.limit("20/minute")
async def save_config(request: Request, license_key: str, data: SavedConfigRequest):
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
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")

@app.get("/api/configs/{license_key}/load/{config_name}")
@limiter.limit("30/minute")
def load_config(request: Request, license_key: str, config_name: str):
    """Load a saved config"""
    db = get_db()
    cur = db.cursor()
    cur.execute(q("SELECT config_data FROM saved_configs WHERE license_key=%s AND config_name=%s"), (license_key, config_name))
    row = cur.fetchone()
    db.close()
    
    if not row:
        raise HTTPException(status_code=404, detail="Config not found")
    
    return json.loads(row[0])

@app.post("/api/keys/create")
@limiter.limit("5/minute")
async def create_key(request: Request, data: KeyCreate):
    """Create a license key"""
    key = f"{secrets.randbelow(10000):04d}-{secrets.randbelow(10000):04d}-{secrets.randbelow(10000):04d}-{secrets.randbelow(10000):04d}"
    
    db = get_db()
    cur = db.cursor()
    
    try:
        expires_at = None
        if data.duration != "lifetime":
            now = datetime.now()
            if data.duration == "monthly":
                expires_at = (now + timedelta(days=30)).isoformat()
            elif data.duration == "weekly":
                expires_at = (now + timedelta(days=7)).isoformat()
            elif data.duration == "3monthly":
                expires_at = (now + timedelta(days=90)).isoformat()
        
        cur.execute(q("INSERT INTO keys (key, duration, created_at, expires_at, active, created_by) VALUES (%s, %s, %s, %s, 0, %s)"),
                   (key, data.duration, datetime.now().isoformat(), expires_at, data.created_by))
        db.commit()
        db.close()
        return {"key": key, "duration": data.duration, "expires_at": expires_at}
    except Exception as e:
        db.close()
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")

@app.post("/api/redeem")
@limiter.limit("5/minute")
async def redeem_key(request: Request, data: RedeemRequest):
    """Redeem a key"""
    db = get_db()
    cur = db.cursor()
    
    try:
        cur.execute(q("SELECT key, duration, redeemed_at, expires_at FROM keys WHERE key=%s"), (data.key,))
        result = cur.fetchone()
        
        if not result:
            db.close()
            raise HTTPException(status_code=404, detail="Invalid key")
        
        key, duration, redeemed_at, existing_expires = result
        
        if redeemed_at:
            db.close()
            raise HTTPException(status_code=400, detail="Already redeemed")
        
        now = datetime.now()
        expires_at = existing_expires
        
        if not expires_at:
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
    except Exception as e:
        db.close()
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")

@app.get("/api/users/{user_id}/license")
@limiter.limit("30/minute")
def get_user_license(request: Request, user_id: str):
    """Get user's license by Discord ID"""
    db = get_db()
    cur = db.cursor()
    
    try:
        cur.execute(q("SELECT key, duration, expires_at, redeemed_at, hwid, active FROM keys WHERE redeemed_by=%s"), (user_id,))
        result = cur.fetchone()
        db.close()
        
        if not result:
            return {"active": False, "message": "No license found"}
        
        key, duration, expires_at, redeemed_at, hwid, active = result
        
        if active == 0:
            return {"active": False, "message": "License inactive"}
        
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
    except Exception as e:
        db.close()
        return {"active": False, "error": f"Server error: {str(e)}"}

@app.get("/api/test/{license_key}")
@limiter.limit("30/minute")
def test_license(request: Request, license_key: str):
    """Test if license key exists"""
    try:
        db = get_db()
        cur = db.cursor()
        
        query = q("SELECT key, duration, expires_at, active FROM keys WHERE key=%s")
        cur.execute(query, (license_key,))
        result = cur.fetchone()
        db.close()
        
        if not result:
            return {
                "exists": False,
                "key_provided": license_key
            }
        
        key, duration, expires_at, active = result
        
        return {
            "exists": True,
            "key": key,
            "duration": duration,
            "expires_at": expires_at,
            "active": active,
            "is_lifetime": expires_at is None
        }
    except Exception as e:
        return {"error": str(e)}

@app.get("/api/keepalive")
@limiter.limit("60/minute")
def keepalive(request: Request):
    """Keep server awake"""
    return {"status": "alive", "timestamp": datetime.now().isoformat()}

@app.get("/api/debug/db")
@limiter.limit("10/minute")
def debug_db(request: Request):
    """Debug database connection"""
    try:
        db = get_db()
        cur = db.cursor()
        
        if USE_POSTGRES:
            cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'")
        else:
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        
        tables = cur.fetchall()
        
        cur.execute(q("SELECT COUNT(*) FROM keys"))
        count = cur.fetchone()
        
        cur.execute(q("SELECT COUNT(*) FROM user_accounts"))
        account_count = cur.fetchone()
        
        db.close()
        
        return {
            "database_type": "PostgreSQL" if USE_POSTGRES else "SQLite",
            "tables_found": [t[0] for t in tables],
            "keys_count": count[0] if count else 0,
            "accounts_count": account_count[0] if account_count else 0,
        }
    except Exception as e:
        return {"error": str(e), "type": type(e).__name__}

# ========== HTML PAGES ==========

MINIMAL_LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login • Axion</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: #0a0a0a;
            color: #fff;
            height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .login-container {
            width: 360px;
            padding: 40px 30px;
            background: #111;
            border-radius: 8px;
            border: 1px solid #222;
            box-shadow: 0 4px 20px rgba(0,0,0,0.5);
        }
        
        .logo {
            text-align: center;
            margin-bottom: 30px;
        }
        
        .logo h1 {
            font-size: 24px;
            font-weight: 300;
            color: #fff;
            letter-spacing: 1px;
        }
        
        .input-group {
            margin-bottom: 20px;
        }
        
        .input-group label {
            display: block;
            margin-bottom: 6px;
            font-size: 13px;
            color: #999;
            font-weight: 500;
        }
        
        .input-group input {
            width: 100%;
            padding: 12px 14px;
            background: #0a0a0a;
            border: 1px solid #333;
            border-radius: 4px;
            color: #fff;
            font-size: 14px;
            transition: border-color 0.2s;
        }
        
        .input-group input:focus {
            outline: none;
            border-color: #666;
        }
        
        .login-btn {
            width: 100%;
            padding: 12px;
            background: #1a1a1a;
            border: 1px solid #333;
            color: #fff;
            font-size: 14px;
            font-weight: 500;
            border-radius: 4px;
            cursor: pointer;
            transition: background 0.2s;
            margin-top: 10px;
        }
        
        .login-btn:hover {
            background: #222;
        }
        
        .login-btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
        
        .error-message {
            color: #ff4444;
            font-size: 13px;
            margin-top: 10px;
            text-align: center;
            min-height: 18px;
        }
        
        .success-message {
            color: #44ff44;
            font-size: 13px;
            margin-top: 10px;
            text-align: center;
            min-height: 18px;
        }
        
        .back-link {
            display: block;
            text-align: center;
            margin-top: 20px;
            font-size: 13px;
            color: #666;
            text-decoration: none;
        }
        
        .back-link:hover {
            color: #999;
        }
        
        .loader {
            display: inline-block;
            width: 16px;
            height: 16px;
            border: 2px solid #333;
            border-top-color: #fff;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            vertical-align: middle;
            margin-right: 8px;
        }
        
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">
            <h1>AXION</h1>
        </div>
        
        <form id="loginForm">
            <div class="input-group">
                <label>Username</label>
                <input type="text" id="username" placeholder="Enter username" autofocus>
            </div>
            
            <div class="input-group">
                <label>Password</label>
                <input type="password" id="password" placeholder="Enter password">
            </div>
            
            <button type="submit" class="login-btn" id="loginBtn">
                Login
            </button>
        </form>
        
        <div class="error-message" id="errorMsg"></div>
        <div class="success-message" id="successMsg"></div>
        
        <a href="/community" class="back-link">← Community</a>
    </div>

    <script>
        const form = document.getElementById('loginForm');
        const username = document.getElementById('username');
        const password = document.getElementById('password');
        const loginBtn = document.getElementById('loginBtn');
        const errorMsg = document.getElementById('errorMsg');
        const successMsg = document.getElementById('successMsg');

        async function handleLogin(e) {
            e.preventDefault();
            
            const usernameVal = username.value.trim();
            const passwordVal = password.value;
            
            if (!usernameVal || !passwordVal) {
                errorMsg.textContent = 'All fields are required';
                return;
            }
            
            errorMsg.textContent = '';
            successMsg.textContent = '';
            loginBtn.disabled = true;
            loginBtn.innerHTML = '<span class="loader"></span> Logging in...';
            
            try {
                const response = await fetch('/api/user-login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ 
                        username: usernameVal, 
                        password: passwordVal 
                    })
                });
                
                const data = await response.json();
                
                if (data.valid) {
                    successMsg.textContent = 'Login successful';
                    
                    setTimeout(() => {
                        if (data.license_key) {
                            window.location.href = `/config/${data.license_key}`;
                        }
                    }, 800);
                } else {
                    errorMsg.textContent = data.error || 'Login failed';
                    loginBtn.disabled = false;
                    loginBtn.textContent = 'Login';
                }
            } catch (error) {
                errorMsg.textContent = 'Connection error';
                loginBtn.disabled = false;
                loginBtn.textContent = 'Login';
            }
        }

        form.addEventListener('submit', handleLogin);
        
        username.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') handleLogin(e);
        });
        
        password.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') handleLogin(e);
        });
    </script>
""" + ENHANCED_ANTI_DEVTOOLS_JS + """
</body>
</html>
"""

MINIMAL_COMMUNITY_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Community • Axion</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: #0a0a0a;
            color: #fff;
            line-height: 1.5;
        }
        
        .header {
            background: #111;
            border-bottom: 1px solid #222;
            padding: 20px 30px;
            position: sticky;
            top: 0;
            z-index: 100;
        }
        
        .header-content {
            max-width: 1200px;
            margin: 0 auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .logo {
            font-size: 18px;
            font-weight: 300;
            letter-spacing: 1px;
            color: #fff;
        }
        
        .nav {
            display: flex;
            gap: 20px;
        }
        
        .nav a {
            color: #999;
            text-decoration: none;
            font-size: 14px;
            transition: color 0.2s;
        }
        
        .nav a:hover {
            color: #fff;
        }
        
        .container {
            max-width: 1200px;
            margin: 40px auto;
            padding: 0 30px;
        }
        
        .page-header {
            margin-bottom: 30px;
        }
        
        .page-title {
            font-size: 28px;
            font-weight: 300;
            margin-bottom: 10px;
            color: #fff;
        }
        
        .page-subtitle {
            color: #999;
            font-size: 14px;
            font-weight: 400;
        }
        
        .search-container {
            margin-bottom: 30px;
        }
        
        .search-input {
            width: 100%;
            max-width: 400px;
            padding: 12px 16px;
            background: #0a0a0a;
            border: 1px solid #333;
            border-radius: 4px;
            color: #fff;
            font-size: 14px;
        }
        
        .search-input:focus {
            outline: none;
            border-color: #666;
        }
        
        .search-input::placeholder {
            color: #666;
        }
        
        .stats-bar {
            display: flex;
            gap: 30px;
            margin-bottom: 40px;
            padding: 20px;
            background: #111;
            border: 1px solid #222;
            border-radius: 8px;
        }
        
        .stat-item {
            flex: 1;
        }
        
        .stat-value {
            font-size: 24px;
            font-weight: 300;
            color: #fff;
            margin-bottom: 4px;
        }
        
        .stat-label {
            color: #999;
            font-size: 12px;
        }
        
        .config-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 20px;
        }
        
        .config-card {
            background: #111;
            border: 1px solid #222;
            border-radius: 8px;
            padding: 24px;
            transition: border-color 0.2s;
        }
        
        .config-card:hover {
            border-color: #444;
        }
        
        .config-name {
            font-size: 16px;
            font-weight: 500;
            color: #fff;
            margin-bottom: 8px;
        }
        
        .config-game {
            font-size: 12px;
            color: #666;
            margin-bottom: 12px;
        }
        
        .config-description {
            font-size: 13px;
            color: #999;
            margin-bottom: 20px;
            line-height: 1.5;
            min-height: 60px;
        }
        
        .config-footer {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-top: 20px;
            padding-top: 20px;
            border-top: 1px solid #222;
        }
        
        .config-author {
            font-size: 12px;
            color: #999;
        }
        
        .config-downloads {
            font-size: 12px;
            color: #999;
        }
        
        .load-btn {
            width: 100%;
            padding: 10px;
            background: #0a0a0a;
            border: 1px solid #333;
            color: #fff;
            font-size: 13px;
            border-radius: 4px;
            cursor: pointer;
            transition: background 0.2s;
            margin-top: 16px;
        }
        
        .load-btn:hover {
            background: #1a1a1a;
        }
        
        .empty-state {
            text-align: center;
            padding: 60px 20px;
            color: #999;
            font-size: 14px;
            grid-column: 1 / -1;
        }
        
        .loading {
            text-align: center;
            padding: 60px 20px;
            color: #999;
            font-size: 14px;
            grid-column: 1 / -1;
        }
        
        .loading:after {
            content: '';
            display: inline-block;
            width: 14px;
            height: 14px;
            border: 2px solid #333;
            border-top-color: #fff;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin-left: 8px;
            vertical-align: middle;
        }
        
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        
        .error-state {
            text-align: center;
            padding: 60px 20px;
            color: #ff4444;
            font-size: 14px;
            grid-column: 1 / -1;
        }
        
        .create-btn {
            position: fixed;
            bottom: 30px;
            right: 30px;
            background: #1a1a1a;
            border: 1px solid #333;
            color: #fff;
            padding: 12px 24px;
            border-radius: 30px;
            font-size: 14px;
            cursor: pointer;
            transition: background 0.2s;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .create-btn:hover {
            background: #222;
        }
        
        .modal-overlay {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0,0,0,0.9);
            display: none;
            align-items: center;
            justify-content: center;
            z-index: 1000;
        }
        
        .modal-overlay.active {
            display: flex;
        }
        
        .modal-content {
            width: 380px;
            background: #111;
            border: 1px solid #333;
            border-radius: 8px;
            padding: 30px;
        }
        
        .modal-title {
            font-size: 18px;
            font-weight: 400;
            color: #fff;
            margin-bottom: 20px;
        }
        
        .modal-input {
            width: 100%;
            padding: 12px;
            margin-bottom: 16px;
            background: #0a0a0a;
            border: 1px solid #333;
            border-radius: 4px;
            color: #fff;
            font-size: 14px;
        }
        
        .modal-input:focus {
            outline: none;
            border-color: #666;
        }
        
        .modal-btn {
            width: 100%;
            padding: 12px;
            background: #1a1a1a;
            border: 1px solid #333;
            color: #fff;
            border-radius: 4px;
            cursor: pointer;
            transition: background 0.2s;
            font-size: 14px;
        }
        
        .modal-btn:hover {
            background: #222;
        }
        
        .modal-error {
            color: #ff4444;
            font-size: 13px;
            margin-top: 12px;
            text-align: center;
        }
        
        .modal-success {
            color: #44ff44;
            font-size: 13px;
            margin-top: 12px;
            text-align: center;
        }
        
        .close-modal {
            position: absolute;
            top: 15px;
            right: 15px;
            background: none;
            border: none;
            color: #666;
            font-size: 20px;
            cursor: pointer;
        }
        
        .close-modal:hover {
            color: #fff;
        }
        
        @media (max-width: 768px) {
            .header-content {
                flex-direction: column;
                gap: 15px;
            }
            
            .nav {
                width: 100%;
                justify-content: center;
            }
            
            .config-grid {
                grid-template-columns: 1fr;
            }
            
            .stats-bar {
                flex-direction: column;
                gap: 15px;
            }
            
            .container {
                padding: 0 20px;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="header-content">
            <div class="logo">AXION</div>
            <div class="nav">
                <a href="/menu">Login</a>
                <a href="#" onclick="refreshConfigs()">Refresh</a>
                <a href="#" onclick="showStats()">Stats</a>
            </div>
        </div>
    </div>
    
    <div class="container">
        <div class="page-header">
            <div class="page-title">Community</div>
            <div class="page-subtitle">Shared configurations</div>
        </div>
        
        <div class="search-container">
            <input type="text" class="search-input" id="searchInput" placeholder="Search configs...">
        </div>
        
        <div class="stats-bar" id="statsBar" style="display: none;">
            <div class="stat-item">
                <div class="stat-value" id="totalConfigs">0</div>
                <div class="stat-label">Total</div>
            </div>
            <div class="stat-item">
                <div class="stat-value" id="totalDownloads">0</div>
                <div class="stat-label">Downloads</div>
            </div>
            <div class="stat-item">
                <div class="stat-value" id="topGame">-</div>
                <div class="stat-label">Top Game</div>
            </div>
        </div>
        
        <div class="config-grid" id="configsList">
            <div class="loading">Loading</div>
        </div>
    </div>
    
    <button class="create-btn" onclick="showLoginModal()">
        + Share Config
    </button>
    
    <div class="modal-overlay" id="loginModal">
        <div class="modal-content">
            <button class="close-modal" onclick="hideLoginModal()">&times;</button>
            <div class="modal-title">Login</div>
            <input type="text" class="modal-input" id="modalUsername" placeholder="Username">
            <input type="password" class="modal-input" id="modalPassword" placeholder="Password">
            <button class="modal-btn" onclick="modalLogin()">Login</button>
            <div class="modal-error" id="modalError"></div>
            <div class="modal-success" id="modalSuccess"></div>
        </div>
    </div>
    
    <script>
        let allConfigs = [];
        let currentSearch = '';
        
        const configsList = document.getElementById('configsList');
        const loginModal = document.getElementById('loginModal');
        const modalUsername = document.getElementById('modalUsername');
        const modalPassword = document.getElementById('modalPassword');
        const modalError = document.getElementById('modalError');
        const modalSuccess = document.getElementById('modalSuccess');
        const searchInput = document.getElementById('searchInput');
        const statsBar = document.getElementById('statsBar');
        const totalConfigs = document.getElementById('totalConfigs');
        const totalDownloads = document.getElementById('totalDownloads');
        const topGame = document.getElementById('topGame');
        
        function showLoginModal() {
            loginModal.classList.add('active');
            modalUsername.focus();
        }
        
        function hideLoginModal() {
            loginModal.classList.remove('active');
            modalError.textContent = '';
            modalSuccess.textContent = '';
            modalUsername.value = '';
            modalPassword.value = '';
        }
        
        loginModal.addEventListener('click', function(e) {
            if (e.target === loginModal) {
                hideLoginModal();
            }
        });
        
        async function modalLogin() {
            const username = modalUsername.value.trim();
            const password = modalPassword.value;
            
            if (!username || !password) {
                modalError.textContent = 'All fields required';
                return;
            }
            
            modalError.textContent = '';
            modalSuccess.textContent = '';
            
            const btn = document.querySelector('.modal-btn');
            btn.disabled = true;
            btn.textContent = 'Logging in...';
            
            try {
                const res = await fetch('/api/user-login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });
                
                const data = await res.json();
                
                if (data.valid) {
                    modalSuccess.textContent = 'Success';
                    
                    setTimeout(() => {
                        if (data.license_key) {
                            window.location.href = `/config/${data.license_key}`;
                        }
                    }, 800);
                } else {
                    modalError.textContent = data.error || 'Login failed';
                    btn.disabled = false;
                    btn.textContent = 'Login';
                }
            } catch (e) {
                modalError.textContent = 'Connection error';
                btn.disabled = false;
                btn.textContent = 'Login';
            }
        }
        
        async function loadConfigs() {
            try {
                configsList.innerHTML = '<div class="loading">Loading</div>';
                
                const res = await fetch('/api/public-configs');
                const data = await res.json();
                
                allConfigs = data.configs || [];
                
                if (allConfigs.length === 0) {
                    configsList.innerHTML = '<div class="empty-state">No configs yet</div>';
                    updateStats();
                    return;
                }
                
                filterConfigs();
                updateStats();
                
            } catch(error) {
                configsList.innerHTML = '<div class="error-state">Failed to load</div>';
            }
        }
        
        function filterConfigs() {
            const filtered = allConfigs.filter(config => {
                if (!currentSearch) return true;
                
                const searchLower = currentSearch.toLowerCase();
                return (
                    (config.config_name || '').toLowerCase().includes(searchLower) ||
                    (config.game_name || '').toLowerCase().includes(searchLower) ||
                    (config.author_name || '').toLowerCase().includes(searchLower)
                );
            });
            
            displayConfigs(filtered);
        }
        
        function displayConfigs(configs) {
            if (configs.length === 0) {
                configsList.innerHTML = '<div class="empty-state">No matches</div>';
                return;
            }
            
            configsList.innerHTML = '';
            
            configs.forEach(config => {
                const card = document.createElement('div');
                card.className = 'config-card';
                card.innerHTML = `
                    <div class="config-name">${escapeHtml(config.config_name)}</div>
                    <div class="config-game">${escapeHtml(config.game_name)}</div>
                    <div class="config-description">${escapeHtml(config.description || 'No description')}</div>
                    <div class="config-footer">
                        <span class="config-author">${escapeHtml(config.author_name)}</span>
                        <span class="config-downloads">${config.downloads || 0} downloads</span>
                    </div>
                    <button class="load-btn" onclick="viewConfig(${config.id})">View</button>
                `;
                configsList.appendChild(card);
            });
        }
        
        function updateStats() {
            if (allConfigs.length === 0) {
                statsBar.style.display = 'none';
                return;
            }
            
            statsBar.style.display = 'flex';
            totalConfigs.textContent = allConfigs.length;
            
            const downloads = allConfigs.reduce((sum, c) => sum + (c.downloads || 0), 0);
            totalDownloads.textContent = downloads;
            
            const games = {};
            allConfigs.forEach(c => {
                const game = c.game_name || 'Unknown';
                games[game] = (games[game] || 0) + 1;
            });
            
            let topGameName = 'None';
            let maxCount = 0;
            for (const [game, count] of Object.entries(games)) {
                if (count > maxCount) {
                    maxCount = count;
                    topGameName = game;
                }
            }
            topGame.textContent = topGameName;
        }
        
        function viewConfig(configId) {
            showLoginModal();
            localStorage.setItem('pendingConfigId', configId);
        }
        
        function refreshConfigs() {
            loadConfigs();
        }
        
        function showStats() {
            statsBar.style.display = statsBar.style.display === 'none' ? 'flex' : 'none';
        }
        
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        
        searchInput.addEventListener('input', function() {
            currentSearch = this.value.trim();
            filterConfigs();
        });
        
        loadConfigs();
        setInterval(loadConfigs, 60000);
    </script>
""" + ENHANCED_ANTI_DEVTOOLS_JS + """
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
def serve_home():
    return HTMLResponse(content=MINIMAL_LOGIN_HTML)

@app.get("/menu", response_class=HTMLResponse)
def serve_menu_login():
    return HTMLResponse(content=MINIMAL_LOGIN_HTML)

@app.get("/community", response_class=HTMLResponse)
def serve_community():
    return HTMLResponse(content=MINIMAL_COMMUNITY_HTML)

@app.get("/config/{license_key}", response_class=HTMLResponse)
def serve_config_dashboard(license_key: str):
    """Config dashboard page"""
    try:
        db = get_db()
        cur = db.cursor()
        
        query = q("SELECT * FROM keys WHERE key=%s")
        cur.execute(query, (license_key,))
        result = cur.fetchone()
        db.close()
        
        if not result:
            return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Invalid • Axion</title>
<style>
body{{background:#0a0a0a;color:#fff;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}}
.container{{text-align:center;padding:40px;background:#111;border-radius:8px;border:1px solid #222}}
h1{{color:#ff4444;font-size:24px;font-weight:400;margin-bottom:20px}}
p{{color:#999;margin-bottom:20px}}
button{{padding:12px 30px;background:#1a1a1a;border:1px solid #333;color:#fff;border-radius:4px;cursor:pointer;font-size:14px}}
button:hover{{background:#222}}
</style>
</head>
<body>
<div class="container">
<h1>Invalid License</h1>
<p>License key not found or has expired</p>
<button onclick="window.location.href='/menu'">Return</button>
</div>
{ENHANCED_ANTI_DEVTOOLS_JS}
</body>
</html>"""
        
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<title>Axion Config</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box;user-select:none}}
body{{height:100vh;background:#0a0a0a;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#cfcfcf;display:flex;align-items:center;justify-content:center}}
.window{{width:760px;height:520px;background:#111;border:1px solid #222;box-shadow:0 0 40px rgba(0,0,0,0.8);display:flex;flex-direction:column;overflow:hidden}}
.topbar{{height:38px;background:#0a0a0a;border-bottom:1px solid #222;display:flex;align-items:center;padding:0 12px;gap:16px}}
.title{{font-size:13px;color:#bfbfbf;padding-right:16px;border-right:1px solid #222}}
.tabs{{display:flex;gap:18px;font-size:12px}}
.tab{{color:#9a9a9a;cursor:pointer;transition:color 0.2s}}
.tab:hover,.tab.active{{color:#ffffff}}
.topbar-right{{margin-left:auto;display:flex;align-items:center}}
.search-container{{position:relative;width:180px}}
.search-bar{{width:100%;height:26px;background:#0a0a0a;border:1px solid #222;color:#cfcfcf;font-size:11px;padding:0 10px;outline:none}}
.search-bar::placeholder{{color:#666}}
.search-bar:focus{{border-color:#444}}
.content{{flex:1;padding:10px;background:#0a0a0a;display:flex;align-items:center;justify-content:center;position:relative}}
.tab-content{{width:100%;height:100%;display:none}}
.tab-content.active{{display:block}}
.merged-panel{{width:100%;height:100%;background:#0a0a0a;border:1px solid #222;overflow:hidden;display:flex;align-items:center;justify-content:center}}
.inner-container{{width:98%;height:96%;display:flex;gap:14px;overflow:hidden}}
.half-panel{{flex:1;background:#111;border:1px solid #222;overflow-y:auto;padding:14px 16px;position:relative}}
.panel-header{{position:absolute;top:10px;left:16px;color:#bfbfbf;font-size:11px;font-weight:normal;pointer-events:none;z-index:1}}
.toggle-row{{position:absolute;left:16px;display:flex;align-items:center;gap:12px;z-index:1}}
.toggle-text{{display:flex;align-items:center;gap:12px}}
.toggle{{width:14px;height:14px;background:transparent;border:1px solid #1a1a1a;cursor:pointer;transition:background 0.2s;flex-shrink:0}}
.toggle.active{{background:#ccc}}
.enable-text{{color:#9a9a9a;font-size:11px;line-height:1;transition:color 0.25s;pointer-events:none}}
.toggle.active + .enable-text{{color:#e0e0e0}}
.keybind-picker{{width:80px;height:20px;background:#0a0a0a;border:1px solid #222;color:#cfcfcf;font-size:10px;display:flex;align-items:center;justify-content:center;cursor:pointer}}
.slider-label{{position:absolute;left:16px;color:#bfbfbf;font-size:11px;font-weight:normal;z-index:1}}
.slider-container{{position:absolute;left:16px;width:210px;height:14px;background:#0a0a0a;border:1px solid #222;overflow:hidden;z-index:10}}
.slider-track{{position:absolute;top:0;left:0;width:100%;height:100%;background:#0a0a0a}}
.slider-fill{{position:absolute;top:0;left:0;height:100%;background:#ccc;width:50%;transition:width 0.1s}}
.slider-value{{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);font-size:9px;font-weight:bold;pointer-events:none;z-index:3}}
.half-panel::-webkit-scrollbar{{width:5px}}
.half-panel::-webkit-scrollbar-track{{background:#0a0a0a}}
.half-panel::-webkit-scrollbar-thumb{{background:#222}}
.half-panel::-webkit-scrollbar-thumb:hover{{background:#333}}
.custom-dropdown{{position:absolute;left:16px;width:210px;height:16px;z-index:100}}
.dropdown-header{{width:100%;height:100%;background:#0a0a0a;border:1px solid #222;display:flex;align-items:center;padding:0 8px;cursor:pointer;font-size:10px;color:#cfcfcf}}
.dropdown-list{{position:absolute;top:100%;left:0;width:100%;max-height:160px;background:#0a0a0a;border:1px solid #222;border-top:none;overflow-y:auto;display:none;z-index:101}}
.dropdown-list.open{{display:block}}
.dropdown-item{{padding:5px 10px;font-size:11px;color:#cfcfcf;cursor:pointer;transition:background 0.15s}}
.dropdown-item:hover{{background:#1a1a1a}}
.dropdown-item.selected{{background:#222;color:#fff}}
.config-list{{position:absolute;top:32px;left:16px;right:16px;bottom:16px;overflow-y:auto}}
.config-list::-webkit-scrollbar{{width:6px}}
.config-list::-webkit-scrollbar-track{{background:#0a0a0a}}
.config-list::-webkit-scrollbar-thumb{{background:#333;border-radius:3px}}
.config-list::-webkit-scrollbar-thumb:hover{{background:#444}}
.config-item{{background:#0a0a0a;border:1px solid #222;padding:6px 10px;margin-bottom:6px;display:flex;align-items:center;gap:10px;position:relative}}
.config-item:hover{{background:#111}}
.config-name{{flex:1;font-size:10px;color:#fff;font-weight:normal}}
.config-dots{{width:20px;height:20px;display:flex;align-items:center;justify-content:center;cursor:pointer;color:#9a9a9a;font-size:16px;font-weight:bold;transition:color 0.2s;flex-shrink:0}}
.config-dots:hover{{color:#fff}}
.config-menu{{position:absolute;right:8px;top:28px;background:#0a0a0a;border:1px solid #222;display:none;z-index:200;min-width:100px}}
.config-menu.open{{display:block}}
.config-menu-item{{padding:6px 12px;font-size:10px;color:#cfcfcf;cursor:pointer;transition:background 0.2s;border-bottom:1px solid #1a1a1a;white-space:nowrap}}
.config-menu-item:last-child{{border-bottom:none}}
.config-menu-item:hover{{background:#1a1a1a;color:#fff}}
.input-box{{width:100%;height:24px;background:#0a0a0a;border:1px solid #222;color:#cfcfcf;font-size:11px;padding:0 8px;outline:none}}
.config-btn{{background:#0a0a0a;border:1px solid #222;padding:6px 12px;font-size:11px;color:#cfcfcf;cursor:pointer;transition:background 0.2s;width:100%;margin-top:6px}}
.config-btn:hover{{background:#111}}
.modal-overlay{{position:fixed;top:0;left:0;width:100vw;height:100vh;background:rgba(0,0,0,0.7);display:none;align-items:center;justify-content:center;z-index:9999}}
.modal-overlay.active{{display:flex}}
.modal-box{{background:#111;border:1px solid #222;padding:24px;min-width:300px}}
.modal-title{{color:#fff;font-size:13px;margin-bottom:16px;font-weight:normal}}
.modal-input{{width:100%;height:28px;background:#0a0a0a;border:1px solid #222;color:#cfcfcf;font-size:11px;padding:0 10px;outline:none;margin-bottom:12px}}
.modal-input:focus{{border-color:#444}}
.modal-buttons{{display:flex;gap:8px}}
.modal-btn{{flex:1;height:28px;background:#0a0a0a;border:1px solid #222;color:#cfcfcf;font-size:11px;cursor:pointer;transition:background 0.2s}}
.modal-btn:hover{{background:#111}}
.modal-btn.primary{{background:#1a1a1a}}
.modal-btn.primary:hover{{background:#252525}}
</style>
</head>
<body>
<div class="window">
    <div class="topbar">
        <div class="title">Axion</div>
        <div class="tabs">
            <div class="tab active" data-tab="aimbot">Aimbot</div>
            <div class="tab" data-tab="triggerbot">Triggerbot</div>
            <div class="tab" data-tab="settings">Configs</div>
        </div>
    </div>
    <div class="content">
        <div class="tab-content active" id="aimbot">
            <div class="merged-panel">
                <div class="inner-container">
                    <div class="half-panel">
                        <div class="panel-header">Aimbot</div>
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
                        <div class="panel-header">Aimbot Settings</div>
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
                        <div class="panel-header">Triggerbot</div>
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
                        <div class="panel-header">Triggerbot Settings</div>
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
                        <div class="panel-header">Saved Configs</div>
                        <div class="config-list" id="configList"></div>
                    </div>
                    <div class="half-panel">
                        <div class="panel-header">Actions</div>
                        <div style="position:absolute;top:32px;left:16px;right:16px">
                            <div style="margin-bottom:12px">
                                <div style="font-size:11px;color:#bfbfbf;margin-bottom:4px">Save Current Config</div>
                                <input type="text" id="saveConfigInput" class="input-box" placeholder="Config name...">
                                <button class="config-btn" style="margin-top:4px;width:100%" onclick="saveCurrentConfig()">Save</button>
                            </div>
                            <div style="margin-top:20px">
                                <div style="font-size:11px;color:#bfbfbf;margin-bottom:4px">Quick Actions</div>
                                <button class="config-btn" onclick="loadDefaultConfig()">Load Default</button>
                                <button class="config-btn" style="margin-top:8px" onclick="window.location.href='/menu'">Logout</button>
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
        const data = await res.json();
        config = data;
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

async function loadDefaultConfig() {{
    config = {json.dumps(DEFAULT_CONFIG)};
    applyConfigToUI();
    await saveConfig();
    alert('Default config loaded');
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

{ENHANCED_ANTI_DEVTOOLS_JS}
</body>
</html>"""
    
    except Exception as e:
        return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Error • Axion</title>
<style>
body{{background:#0a0a0a;color:#fff;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}}
.container{{text-align:center;padding:40px;background:#111;border-radius:8px;border:1px solid #222}}
h1{{color:#ff4444;font-size:24px;font-weight:400;margin-bottom:20px}}
.error-details{{color:#ff8888;font-size:13px;margin-top:20px;padding:15px;background:rgba(255,0,0,0.1);border-radius:4px}}
button{{margin-top:20px;padding:12px 30px;background:#1a1a1a;border:1px solid #333;color:#fff;border-radius:4px;cursor:pointer;font-size:14px}}
button:hover{{background:#222}}
</style>
</head>
<body>
<div class="container">
<h1>Error</h1>
<p>Failed to load config</p>
<div class="error-details">{str(e)}</div>
<button onclick="window.location.href='/menu'">Return</button>
</div>
{ENHANCED_ANTI_DEVTOOLS_JS}
</body>
</html>"""

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
