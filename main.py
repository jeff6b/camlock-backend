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
        
    except Exception as e:
        print(f"Database initialization error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        try:
            db.close()
        except:
            pass

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

class UserAuth(BaseModel):
    username: Optional[str] = None
    license_key: Optional[str] = None
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
                console.log('%c dm inlination on discord if u manage to harm the website and lmk how u did it so i can improve thanks', 'color: red; font-size: 30px; font-weight: bold;');
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

# ========== API ENDPOINTS WITH RATE LIMITING ==========

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
        print(f"Error in validate_user: {e}")
        import traceback
        traceback.print_exc()
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
        print(f"Error in create_account: {e}")
        import traceback
        traceback.print_exc()
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
        print(f"Error in user_login: {e}")
        import traceback
        traceback.print_exc()
        return {"valid": False, "error": f"Server error: {str(e)}"}

@app.post("/api/auth-validate")
@limiter.limit("10/minute")
async def auth_validate(request: Request, data: UserAuth):
    """Validate either license key or username/password"""
    db = get_db()
    cur = db.cursor()
    
    try:
        # First try username/password login
        if data.username:
            cur.execute(q("""
                SELECT ua.username, ua.password_hash, ua.license_key, k.active, k.expires_at
                FROM user_accounts ua
                JOIN keys k ON ua.license_key = k.key
                WHERE ua.username=%s
            """), (data.username,))
            
            result = cur.fetchone()
            
            if result:
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
                if verify_password(password_hash, data.password):
                    # Create web session
                    create_web_session(license_key)
                    
                    # Update last login
                    cur.execute(q("UPDATE user_accounts SET last_login=%s WHERE username=%s"),
                               (datetime.now().isoformat(), username))
                    db.commit()
                    
                    db.close()
                    return {
                        "valid": True,
                        "message": "Login successful",
                        "username": username,
                        "license_key": license_key,
                        "auth_method": "username"
                    }
        
        # Fall back to license key only
        if data.license_key:
            cur.execute(q("SELECT key, active, expires_at FROM keys WHERE key=%s"), (data.license_key,))
            result = cur.fetchone()
            
            if not result:
                db.close()
                return {"valid": False, "error": "Invalid credentials"}
            
            key, active, expires_at = result
            
            if active == 0:
                db.close()
                return {"valid": False, "error": "License inactive"}
            
            if expires_at:
                try:
                    if datetime.now() > datetime.fromisoformat(expires_at):
                        db.close()
                        return {"valid": False, "error": "License expired"}
                except:
                    pass
            
            # Create web session
            db.close()
            create_web_session(data.license_key)
            return {"valid": True, "message": "License login successful", "auth_method": "license"}
        
        db.close()
        return {"valid": False, "error": "Please provide username or license key"}
        
    except Exception as e:
        db.close()
        print(f"Error in auth_validate: {e}")
        import traceback
        traceback.print_exc()
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
        print(f"Error in get_account_info: {e}")
        import traceback
        traceback.print_exc()
        return {"exists": False, "error": str(e)}

@app.get("/api/check-active-session")
@limiter.limit("10/minute")
async def check_active_session(request: Request, hwid: str = None):
    """Check if there's an active web session for HWID"""
    if not hwid:
        return {"has_active_session": False}
    
    db = get_db()
    cur = db.cursor()
    
    # Check user_sessions table (created when user logs in via website)
    # Find sessions created in the last 2 minutes
    two_minutes_ago = (datetime.now() - timedelta(minutes=2)).isoformat()
    
    cur.execute(q("""
        SELECT us.license_key 
        FROM user_sessions us
        JOIN keys k ON us.license_key = k.key
        WHERE k.hwid = %s 
        AND us.created_at > %s
        ORDER BY us.created_at DESC
        LIMIT 1
    """), (hwid, two_minutes_ago))
    
    result = cur.fetchone()
    db.close()
    
    if result:
        return {
            "has_active_session": True,
            "license_key": result[0],
            "message": "Active website session found"
        }
    
    return {"has_active_session": False, "message": "No active session"}

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
        print(f"Error in get_config: {e}")
        import traceback
        traceback.print_exc()
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
        print(f"Error in set_config: {e}")
        import traceback
        traceback.print_exc()
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
        print(f"Error in save_config: {e}")
        import traceback
        traceback.print_exc()
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

@app.post("/api/configs/{license_key}/rename")
@limiter.limit("20/minute")
async def rename_config(request: Request, license_key: str, data: dict):
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
@limiter.limit("20/minute")
async def delete_config(request: Request, license_key: str, config_name: str):
    """Delete a config"""
    db = get_db()
    cur = db.cursor()
    cur.execute(q("DELETE FROM saved_configs WHERE license_key=%s AND config_name=%s"), (license_key, config_name))
    db.commit()
    db.close()
    
    return {"success": True}

@app.get("/api/public-configs")
@limiter.limit("60/minute")
def get_public_configs(request: Request):
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
        print(f"Error in get_public_configs: {e}")
        import traceback
        traceback.print_exc()
        return {"configs": []}

@app.post("/api/public-configs/create")
@limiter.limit("10/minute")
async def create_public_config(request: Request, data: PublicConfig):
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
        print(f"Error in create_public_config: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")

@app.get("/api/public-configs/{config_id}")
@limiter.limit("30/minute")
def get_public_config(request: Request, config_id: int):
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
@limiter.limit("30/minute")
async def download_config(request: Request, config_id: int):
    """Increment downloads"""
    db = get_db()
    cur = db.cursor()
    cur.execute(q("UPDATE public_configs SET downloads = downloads + 1 WHERE id=%s"), (config_id,))
    db.commit()
    db.close()
    return {"success": True}

@app.post("/api/keys/create")
@limiter.limit("5/minute")
async def create_key(request: Request, data: KeyCreate):
    """Create a license key"""
    # Generate key in format: XXXX-XXXX-XXXX-XXXX
    key = f"{secrets.randbelow(10000):04d}-{secrets.randbelow(10000):04d}-{secrets.randbelow(10000):04d}-{secrets.randbelow(10000):04d}"
    
    db = get_db()
    cur = db.cursor()
    
    try:
        # For lifetime keys, don't set expires_at
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
        print(f"Error in create_key: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")

@app.delete("/api/keys/{license_key}")
@limiter.limit("10/minute")
async def delete_key(request: Request, license_key: str):
    """Delete a key"""
    db = get_db()
    cur = db.cursor()
    cur.execute(q("DELETE FROM keys WHERE key=%s"), (license_key,))
    db.commit()
    db.close()
    return {"success": True}

@app.get("/api/dashboard/{license_key}")
@limiter.limit("30/minute")
def get_dashboard_data(request: Request, license_key: str):
    """Get dashboard data"""
    db = get_db()
    cur = db.cursor()
    
    try:
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
    except Exception as e:
        db.close()
        print(f"Error in get_dashboard_data: {e}")
        import traceback
        traceback.print_exc()
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
        expires_at = existing_expires  # Use existing expires_at (for lifetime keys it will be None)
        
        # Only calculate expires_at if not already set (for lifetime keys)
        if not expires_at:
            if duration == "monthly":
                expires_at = (now + timedelta(days=30)).isoformat()
            elif duration == "weekly":
                expires_at = (now + timedelta(days=7)).isoformat()
            elif duration == "3monthly":
                expires_at = (now + timedelta(days=90)).isoformat()
            # For lifetime keys, expires_at remains None
        
        cur.execute(q("UPDATE keys SET redeemed_at=%s, redeemed_by=%s, expires_at=%s, active=1 WHERE key=%s"),
                   (now.isoformat(), data.discord_id, expires_at, data.key))
        db.commit()
        db.close()
        
        return {"success": True, "duration": duration, "expires_at": expires_at, "message": "Key redeemed successfully"}
    except Exception as e:
        db.close()
        print(f"Error in redeem_key: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")

@app.post("/api/reset-hwid/{license_key}")
@limiter.limit("5/minute")
async def reset_hwid(request: Request, license_key: str):
    """Reset HWID"""
    db = get_db()
    cur = db.cursor()
    
    try:
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
    except Exception as e:
        db.close()
        print(f"Error in reset_hwid: {e}")
        import traceback
        traceback.print_exc()
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
        print(f"Error in get_user_license: {e}")
        import traceback
        traceback.print_exc()
        return {"active": False, "error": f"Server error: {str(e)}"}

@app.delete("/api/users/{user_id}/license")
@limiter.limit("10/minute")
async def delete_user_license(request: Request, user_id: str):
    """Delete user's license by Discord ID"""
    db = get_db()
    cur = db.cursor()
    
    try:
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
    except Exception as e:
        db.close()
        print(f"Error in delete_user_license: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")

@app.post("/api/users/{user_id}/reset-hwid")
@limiter.limit("5/minute")
async def reset_user_hwid(request: Request, user_id: str):
    """Reset HWID for user's license"""
    db = get_db()
    cur = db.cursor()
    
    try:
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
    except Exception as e:
        db.close()
        print(f"Error in reset_user_hwid: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")

@app.post("/api/check-login")
@limiter.limit("10/minute")
async def check_login(request: Request, data: dict):
    """Check if user is logged in (for Python cheat)"""
    hwid = data.get("hwid")
    
    db = get_db()
    cur = db.cursor()
    
    try:
        # Find if any key is bound to this HWID
        cur.execute(q("SELECT key FROM keys WHERE hwid=%s AND active=1"), (hwid,))
        result = cur.fetchone()
        db.close()
        
        if result:
            return {
                "logged_in": True,
                "username": result[0],
                "message": "User is logged in"
            }
        
        return {
            "logged_in": False,
            "message": "User not logged in"
        }
    except Exception as e:
        db.close()
        print(f"Error in check_login: {e}")
        import traceback
        traceback.print_exc()
        return {"logged_in": False, "error": f"Server error: {str(e)}"}

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
            # For PostgreSQL
            cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'")
        else:
            # For SQLite
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        
        tables = cur.fetchall()
        
        # Test keys table
        cur.execute(q("SELECT COUNT(*) FROM keys"))
        count = cur.fetchone()
        
        # Test user_accounts table
        cur.execute(q("SELECT COUNT(*) FROM user_accounts"))
        account_count = cur.fetchone()
        
        db.close()
        
        return {
            "database_type": "PostgreSQL" if USE_POSTGRES else "SQLite",
            "tables_found": [t[0] for t in tables],
            "keys_count": count[0] if count else 0,
            "accounts_count": account_count[0] if account_count else 0,
            "use_postgres": USE_POSTGRES,
            "database_url": DATABASE_URL if DATABASE_URL else "local.db"
        }
    except Exception as e:
        print(f"Error in debug_db: {e}")
        import traceback
        traceback.print_exc()
        return {"error": str(e), "type": type(e).__name__}

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
        print(f"Error in test_license: {e}")
        import traceback
        traceback.print_exc()
        return {"error": str(e)}

# ========== HTML PAGES ==========

ENHANCED_LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login • Axion</title>
    <meta name="theme-color" content="#0c0c0c">
    <style>
        html, body {
            margin: 0;
            padding: 0;
            height: 100vh;
            overflow: hidden;
            background: rgb(12,12,12);
            color: rgb(180,180,180);
            font-family: Arial, Helvetica, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            position: relative;
        }

        .particles {
            position: fixed;
            inset: 0;
            pointer-events: none;
            z-index: 1;
        }

        .particle {
            position: absolute;
            background: rgba(140,140,140, 0.35);
            border-radius: 50%;
            pointer-events: none;
            will-change: transform;
            animation: fall linear infinite;
        }

        @keyframes fall {
            0% {
                transform: translateY(-10vh) translateX(0) rotate(0deg);
                opacity: 0;
            }
            10% { opacity: 0.6; }
            90% { opacity: 0.6; }
            100% {
                transform: translateY(110vh) translateX(var(--drift)) rotate(720deg);
                opacity: 0;
            }
        }

        .container {
            width: 380px;
            max-width: 90%;
            background: rgb(12,12,12);
            background-image:
                radial-gradient(circle at 3px 3px, rgb(15,15,15) 1px, transparent 0);
            background-size: 6px 6px;
            padding: 30px 30px;
            box-sizing: border-box;
            border-radius: 4px;
            border: 1px solid rgb(28,28,28);
            position: relative;
            z-index: 10;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            min-height: 280px;
        }

        .loader {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            width: 40px;
            height: 40px;
            z-index: 20;
            display: none;
        }

        .arc-spinner {
            width: 40px;
            height: 40px;
            position: relative;
        }

        .arc-spinner::before,
        .arc-spinner::after {
            content: "";
            position: absolute;
            inset: 0;
            border: 4px solid transparent;
            border-radius: 50%;
            border-right-color: transparent;
            border-bottom-color: transparent;
            border-left-color: transparent;
            animation: spin-clockwise 1.2s linear infinite;
        }

        .arc-spinner::before,
        .arc-spinner::after {
            border-top-color: #888888;
        }

        .arc-spinner::after {
            animation-delay: 0.2s;
        }

        @keyframes spin-clockwise {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
        }

        .form-content {
            width: 100%;
            display: flex;
            flex-direction: column;
            align-items: center;
        }

        .logo-container {
            margin-bottom: 20px;
            text-align: center;
        }

        .logo-image {
            width: 100px;
            height: 100px;
            object-fit: contain;
            filter: brightness(1.1) contrast(1.1);
        }

        .login-form {
            width: 100%;
            display: flex;
            flex-direction: column;
            align-items: center;
        }

        .input-group {
            width: 100%;
            max-width: 320px;
            margin-bottom: 15px;
            display: flex;
            flex-direction: column;
        }

        .input-label {
            font-size: 12px;
            color: rgb(120,120,120);
            margin-bottom: 5px;
            margin-left: 2px;
        }

        .input-field {
            width: 100%;
            padding: 12px 14px;
            background: linear-gradient(145deg, rgb(24,24,24), rgb(20,20,20));
            border: 1px solid rgba(40,40,40,0.8);
            color: rgb(200,200,200);
            font-size: 14px;
            outline: none;
            box-sizing: border-box;
            border-radius: 4px;
            transition: border-color 0.4s ease, box-shadow 0.4s ease;
        }

        .input-field::placeholder {
            color: rgb(120,120,120);
        }

        .input-field:focus {
            border-color: #888888;
            box-shadow: 0 0 10px rgba(136,136,136,0.25);
        }

        .login-btn {
            width: 100%;
            max-width: 320px;
            padding: 12px;
            margin-top: 10px;
            background: linear-gradient(90deg, rgb(14,14,14), rgb(20,20,20));
            border: 1px solid rgba(40,40,40,0.8);
            color: rgb(200,200,200);
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            border-radius: 4px;
            transition: background 0.3s ease, border-color 0.3s ease;
            box-shadow: 0 0 8px rgba(0,0,0,0.5);
        }

        .login-btn:hover {
            background: linear-gradient(90deg, rgb(18,18,18), rgb(28,28,28));
            border-color: rgba(40,40,40,1);
        }

        .login-btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }

        .error-message {
            color: rgb(255, 80, 80);
            font-size: 12px;
            margin-top: 10px;
            text-align: center;
            min-height: 20px;
            max-width: 320px;
            word-wrap: break-word;
        }

        .success-message {
            color: rgb(80, 255, 80);
            font-size: 12px;
            margin-top: 10px;
            text-align: center;
            min-height: 20px;
        }

        .forgot-link {
            font-size: 12px;
            color: rgb(120,120,120);
            margin-top: 15px;
            text-decoration: none;
            cursor: pointer;
        }

        .forgot-link:hover {
            color: rgb(180,180,180);
            text-decoration: underline;
        }
        
        .info-note {
            font-size: 11px;
            color: rgb(120,120,120);
            margin-top: 15px;
            text-align: center;
            line-height: 1.4;
        }
        
        .back-link {
            position: absolute;
            top: 15px;
            left: 15px;
            color: #666;
            font-size: 12px;
            text-decoration: none;
        }
        
        .back-link:hover {
            color: #888;
        }
    </style>
</head>
<body>
    <div class="particles" id="particles"></div>

    <div class="container" id="container">
        <div class="loader" id="loader">
            <div class="arc-spinner"></div>
        </div>
        
        <div class="form-content" id="form">
            <a href="/community" class="back-link">← Community</a>
            
            <div class="logo-container">
                <img src="https://image2url.com/r2/default/images/1770423268822-32a09791-acb6-41e0-b8f9-1b159be9dc14.blob" alt="Axion" class="logo-image">
            </div>
            
            <div class="login-form" id="loginForm">
                <div class="input-group">
                    <div class="input-label">Username</div>
                    <input type="text" class="input-field" id="usernameInput" placeholder="Your username">
                    <div class="input-label" style="margin-top: 10px;">Password</div>
                    <input type="password" class="input-field" id="passwordInput" placeholder="Your password">
                </div>
                
                <button class="login-btn" id="loginBtn">Login</button>
                
                <div class="error-message" id="errorMsg"></div>
                <div class="success-message" id="successMsg"></div>
                
                <div class="info-note">
                    Login with the username and password you created<br>when redeeming your license key.
                </div>
                
                <a class="forgot-link" href="https://discord.gg/axion" target="_blank">
                    Need help? Join our Discord
                </a>
            </div>
        </div>
    </div>

    <script>
        // Create particles
        function createParticles() {
            const particlesContainer = document.getElementById('particles');
            const count = 70;

            for (let i = 0; i < count; i++) {
                const particle = document.createElement('div');
                particle.className = 'particle';

                const size = Math.random() * 1.6 + 0.6;
                const duration = Math.random() * 80 + 65;
                const delay = Math.random() * -90;
                const left = Math.random() * 100;
                const drift = (Math.random() - 0.5) * 50 + 'vw';

                particle.style.width = size + 'px';
                particle.style.height = size + 'px';
                particle.style.left = left + 'vw';
                particle.style.setProperty('--drift', drift);
                particle.style.animationDuration = duration + 's';
                particle.style.animationDelay = delay + 's';

                particlesContainer.appendChild(particle);
            }
        }

        // Clear error/success messages
        function clearMessages() {
            document.getElementById('errorMsg').textContent = '';
            document.getElementById('successMsg').textContent = '';
        }

        // Show loading
        function showLoading() {
            document.getElementById('loader').style.display = 'block';
            document.getElementById('form').style.opacity = '0.5';
            document.getElementById('loginBtn').disabled = true;
            document.getElementById('loginBtn').textContent = 'Logging in...';
        }

        // Hide loading
        function hideLoading() {
            document.getElementById('loader').style.display = 'none';
            document.getElementById('form').style.opacity = '1';
            document.getElementById('loginBtn').disabled = false;
            document.getElementById('loginBtn').textContent = 'Login';
        }

        // Login function
        async function performLogin() {
            const username = document.getElementById('usernameInput').value.trim();
            const password = document.getElementById('passwordInput').value;
            
            if (!username || !password) {
                document.getElementById('errorMsg').textContent = 'Please enter both username and password';
                return;
            }
            
            clearMessages();
            showLoading();
            
            try {
                const response = await fetch('/api/user-login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username: username, password: password })
                });
                
                const data = await response.json();
                
                if (data.valid) {
                    document.getElementById('successMsg').textContent = data.message || 'Login successful!';
                    
                    // Redirect to config page
                    setTimeout(() => {
                        if (data.license_key) {
                            window.location.href = `/config/${data.license_key}`;
                        } else {
                            document.getElementById('errorMsg').textContent = 'No license key found';
                            hideLoading();
                        }
                    }, 1000);
                } else {
                    document.getElementById('errorMsg').textContent = data.error || 'Login failed';
                    hideLoading();
                }
            } catch (error) {
                console.error('Login error:', error);
                document.getElementById('errorMsg').textContent = 'Connection error. Please try again.';
                hideLoading();
            }
        }

        // Event listeners
        document.getElementById('loginBtn').addEventListener('click', performLogin);
        
        // Allow Enter key to submit
        document.getElementById('usernameInput').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') performLogin();
        });
        
        document.getElementById('passwordInput').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') performLogin();
        });

        // Initialize
        createParticles();
        
        // Auto-focus username input
        setTimeout(() => {
            document.getElementById('usernameInput').focus();
        }, 100);
    </script>
""" + ENHANCED_ANTI_DEVTOOLS_JS + """
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
def serve_home():
    """Redirect to login"""
    response = HTMLResponse(content=ENHANCED_LOGIN_HTML)
    return response

@app.get("/menu", response_class=HTMLResponse)
def serve_menu_login():
    """Login page"""
    return ENHANCED_LOGIN_HTML

# Community page remains the same as before
@app.get("/community", response_class=HTMLResponse)
def serve_community():
    """Community configs page with popup login"""
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<title>Community Configs - Axion</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
}
body {
    background: #0a0a0a;
    color: #e0e0e0;
    min-height: 100vh;
    overflow-x: hidden;
}
.header {
    background: linear-gradient(135deg, #0f0f0f 0%, #1a1a1a 100%);
    padding: 20px 30px;
    border-bottom: 1px solid #2a2a2a;
    display: flex;
    justify-content: space-between;
    align-items: center;
    position: sticky;
    top: 0;
    z-index: 100;
    box-shadow: 0 4px 20px rgba(0,0,0,0.5);
}
.logo {
    font-size: 24px;
    font-weight: 700;
    background: linear-gradient(90deg, #fff, #aaa);
    -webkit-background-clip: text;
    background-clip: text;
    color: transparent;
    letter-spacing: 1px;
}
.nav {
    display: flex;
    gap: 25px;
    align-items: center;
}
.nav a {
    color: #aaa;
    text-decoration: none;
    font-weight: 500;
    font-size: 15px;
    transition: all 0.3s ease;
    padding: 8px 15px;
    border-radius: 6px;
    position: relative;
    overflow: hidden;
}
.nav a::before {
    content: '';
    position: absolute;
    bottom: 0;
    left: 0;
    width: 0;
    height: 2px;
    background: linear-gradient(90deg, #6a11cb 0%, #2575fc 100%);
    transition: width 0.3s ease;
}
.nav a:hover {
    color: #fff;
    background: rgba(255,255,255,0.05);
}
.nav a:hover::before {
    width: 100%;
}
.container {
    padding: 30px;
    max-width: 1400px;
    margin: 0 auto;
}
.page-title {
    font-size: 32px;
    font-weight: 700;
    margin-bottom: 10px;
    background: linear-gradient(90deg, #fff, #888);
    -webkit-background-clip: text;
    background-clip: text;
    color: transparent;
}
.page-subtitle {
    color: #888;
    font-size: 16px;
    margin-bottom: 30px;
    font-weight: 300;
}
.config-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
    gap: 25px;
    margin-top: 20px;
}
.config-card {
    background: linear-gradient(145deg, #121212, #0d0d0d);
    border: 1px solid #2a2a2a;
    border-radius: 12px;
    padding: 25px;
    transition: all 0.3s ease;
    position: relative;
    overflow: hidden;
    box-shadow: 0 8px 25px rgba(0,0,0,0.3);
}
.config-card::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    height: 3px;
    background: linear-gradient(90deg, #6a11cb 0%, #2575fc 100%);
}
.config-card:hover {
    transform: translateY(-8px);
    border-color: #3a3a3a;
    box-shadow: 0 15px 35px rgba(0,0,0,0.5);
}
.config-name {
    font-size: 20px;
    color: #fff;
    margin-bottom: 15px;
    font-weight: 600;
    line-height: 1.3;
}
.config-game {
    display: inline-block;
    background: rgba(106, 17, 203, 0.15);
    color: #9d6afc;
    padding: 6px 14px;
    border-radius: 20px;
    font-size: 13px;
    font-weight: 500;
    margin-bottom: 15px;
    border: 1px solid rgba(106, 17, 203, 0.3);
}
.config-description {
    color: #bbb;
    line-height: 1.6;
    font-size: 14.5px;
    margin: 15px 0;
    min-height: 70px;
}
.config-footer {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-top: 20px;
    padding-top: 15px;
    border-top: 1px solid #2a2a2a;
}
.config-author {
    color: #9a9a9a;
    font-size: 13px;
    font-weight: 500;
}
.config-author span {
    color: #ccc;
    font-weight: 600;
}
.config-downloads {
    display: flex;
    align-items: center;
    gap: 8px;
    color: #888;
    font-size: 13px;
    font-weight: 500;
}
.config-downloads img {
    width: 16px;
    height: 16px;
    filter: invert(0.6);
}
.load-btn {
    width: 100%;
    padding: 14px;
    margin-top: 15px;
    background: linear-gradient(90deg, #1a1a1a 0%, #222 100%);
    border: 1px solid #333;
    color: #ddd;
    cursor: pointer;
    border-radius: 8px;
    font-size: 15px;
    font-weight: 500;
    transition: all 0.3s ease;
    letter-spacing: 0.5px;
}
.load-btn:hover {
    background: linear-gradient(90deg, #222 0%, #2a2a2a 100%);
    border-color: #444;
    color: #fff;
    transform: translateY(-2px);
}
.load-btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
    transform: none;
}
.empty-state {
    text-align: center;
    padding: 60px 20px;
    color: #666;
    font-size: 18px;
    grid-column: 1 / -1;
}
.loading {
    text-align: center;
    padding: 60px 20px;
    color: #888;
    font-size: 16px;
    grid-column: 1 / -1;
}
.loading::after {
    content: '';
    display: inline-block;
    width: 20px;
    height: 20px;
    border: 3px solid #333;
    border-top-color: #6a11cb;
    border-radius: 50%;
    animation: spin 1s linear infinite;
    margin-left: 10px;
    vertical-align: middle;
}
@keyframes spin {
    to { transform: rotate(360deg); }
}
.error-state {
    text-align: center;
    padding: 60px 20px;
    color: #ff4444;
    font-size: 16px;
    grid-column: 1 / -1;
}
.create-btn {
    position: fixed;
    bottom: 30px;
    right: 30px;
    background: linear-gradient(90deg, #6a11cb 0%, #2575fc 100%);
    color: #fff;
    padding: 15px 25px;
    border-radius: 50px;
    cursor: pointer;
    font-size: 15px;
    font-weight: 600;
    transition: all 0.3s ease;
    border: none;
    box-shadow: 0 8px 25px rgba(106, 17, 203, 0.4);
    z-index: 100;
    display: flex;
    align-items: center;
    gap: 10px;
}
.create-btn:hover {
    transform: translateY(-3px);
    box-shadow: 0 12px 30px rgba(106, 17, 203, 0.6);
}
.create-btn i {
    font-size: 18px;
}

/* Modal Styles */
.modal-overlay {
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: rgba(0, 0, 0, 0.85);
    backdrop-filter: blur(10px);
    display: none;
    align-items: center;
    justify-content: center;
    z-index: 1000;
    opacity: 0;
    transition: opacity 0.3s ease;
}
.modal-overlay.active {
    display: flex;
    opacity: 1;
}
.modal-content {
    background: linear-gradient(145deg, #121212, #0d0d0d);
    border: 1px solid #2a2a2a;
    border-radius: 16px;
    padding: 40px;
    width: 90%;
    max-width: 420px;
    box-shadow: 0 25px 50px rgba(0,0,0,0.5);
    transform: scale(0.9);
    transition: transform 0.3s ease;
}
.modal-overlay.active .modal-content {
    transform: scale(1);
}
.modal-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 25px;
}
.modal-title {
    font-size: 24px;
    font-weight: 700;
    color: #fff;
    margin: 0;
}
.close-modal {
    background: none;
    border: none;
    color: #888;
    font-size: 28px;
    cursor: pointer;
    transition: color 0.3s;
    line-height: 1;
    padding: 0;
    width: 30px;
    height: 30px;
    display: flex;
    align-items: center;
    justify-content: center;
    border-radius: 50%;
}
.close-modal:hover {
    color: #fff;
    background: rgba(255,255,255,0.1);
}
.modal-input {
    width: 100%;
    padding: 15px;
    margin-bottom: 20px;
    background: #0a0a0a;
    border: 1px solid #333;
    border-radius: 8px;
    color: #fff;
    font-size: 15px;
    transition: all 0.3s;
}
.modal-input:focus {
    outline: none;
    border-color: #6a11cb;
    box-shadow: 0 0 0 2px rgba(106, 17, 203, 0.3);
}
.modal-input::placeholder {
    color: #666;
}
.modal-button {
    width: 100%;
    padding: 16px;
    background: linear-gradient(90deg, #6a11cb 0%, #2575fc 100%);
    border: none;
    border-radius: 8px;
    color: #fff;
    font-size: 16px;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.3s;
    letter-spacing: 0.5px;
}
.modal-button:hover {
    transform: translateY(-2px);
    box-shadow: 0 8px 20px rgba(106, 17, 203, 0.4);
}
.modal-button:disabled {
    opacity: 0.6;
    cursor: not-allowed;
    transform: none;
}
.modal-error {
    color: #ff4444;
    font-size: 14px;
    margin-top: 10px;
    text-align: center;
    min-height: 20px;
}
.modal-success {
    color: #44ff44;
    font-size: 14px;
    margin-top: 10px;
    text-align: center;
    min-height: 20px;
}

/* Stats Section */
.stats-bar {
    display: flex;
    gap: 30px;
    margin-bottom: 30px;
    padding: 20px;
    background: linear-gradient(145deg, #121212, #0d0d0d);
    border: 1px solid #2a2a2a;
    border-radius: 12px;
}
.stat-item {
    display: flex;
    flex-direction: column;
    align-items: center;
    flex: 1;
}
.stat-value {
    font-size: 28px;
    font-weight: 700;
    color: #fff;
    margin-bottom: 5px;
}
.stat-label {
    color: #888;
    font-size: 14px;
    font-weight: 500;
}

/* Search Bar */
.search-container {
    position: relative;
    width: 100%;
    max-width: 500px;
    margin: 0 auto 30px;
}
.search-input {
    width: 100%;
    padding: 16px 50px 16px 20px;
    background: #0a0a0a;
    border: 1px solid #333;
    border-radius: 50px;
    color: #fff;
    font-size: 15px;
    transition: all 0.3s;
}
.search-input:focus {
    outline: none;
    border-color: #6a11cb;
    box-shadow: 0 0 0 2px rgba(106, 17, 203, 0.3);
}
.search-icon {
    position: absolute;
    right: 20px;
    top: 50%;
    transform: translateY(-50%);
    color: #666;
    font-size: 18px;
}

/* Responsive */
@media (max-width: 768px) {
    .header {
        flex-direction: column;
        gap: 15px;
        padding: 20px;
    }
    .nav {
        width: 100%;
        justify-content: center;
        flex-wrap: wrap;
        gap: 10px;
    }
    .config-grid {
        grid-template-columns: 1fr;
    }
    .stats-bar {
        flex-direction: column;
        gap: 20px;
    }
    .container {
        padding: 20px;
    }
    .create-btn {
        bottom: 20px;
        right: 20px;
        padding: 12px 20px;
        font-size: 14px;
    }
}
</style>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>
<body>
<div class="header">
    <div class="logo">Axion Community</div>
    <div class="nav">
        <a href="/menu"><i class="fas fa-sign-in-alt"></i> Login</a>
        <a href="#" onclick="refreshConfigs()"><i class="fas fa-sync-alt"></i> Refresh</a>
        <a href="#" onclick="showStats()"><i class="fas fa-chart-bar"></i> Stats</a>
    </div>
</div>

<div class="container">
    <div class="page-title">Community Configurations</div>
    <div class="page-subtitle">Browse and download configs shared by the community</div>
    
    <div class="search-container">
        <input type="text" class="search-input" id="searchInput" placeholder="Search configs...">
        <i class="fas fa-search search-icon"></i>
    </div>
    
    <div class="stats-bar" id="statsBar" style="display: none;">
        <div class="stat-item">
            <div class="stat-value" id="totalConfigs">0</div>
            <div class="stat-label">Total Configs</div>
        </div>
        <div class="stat-item">
            <div class="stat-value" id="totalDownloads">0</div>
            <div class="stat-label">Total Downloads</div>
        </div>
        <div class="stat-item">
            <div class="stat-value" id="topGame">-</div>
            <div class="stat-label">Top Game</div>
        </div>
    </div>
    
    <div class="config-grid" id="configsList">
        <div class="loading">Loading community configs</div>
    </div>
</div>

<button class="create-btn" onclick="showLoginModal()">
    <i class="fas fa-plus"></i> Share Config
</button>

<!-- Login Modal -->
<div class="modal-overlay" id="loginModal">
    <div class="modal-content">
        <div class="modal-header">
            <div class="modal-title">Login Required</div>
            <button class="close-modal" onclick="hideLoginModal()">&times;</button>
        </div>
        <p style="color: #aaa; margin-bottom: 25px; line-height: 1.6;">
            Please login to download or share configurations. If you don't have an account, contact the administrator.
        </p>
        <input type="text" class="modal-input" id="modalUsernameInput" placeholder="Enter your username">
        <input type="password" class="modal-input" id="modalPasswordInput" placeholder="Enter your password">
        <button class="modal-button" id="modalLoginBtn" onclick="modalLogin()">
            <i class="fas fa-sign-in-alt"></i> Login
        </button>
        <div class="modal-error" id="modalError"></div>
        <div class="modal-success" id="modalSuccess"></div>
        <div style="margin-top: 20px; text-align: center;">
            <a href="/menu" style="color: #6a11cb; text-decoration: none; font-weight: 500;">
                <i class="fas fa-external-link-alt"></i> Open Full Login Page
            </a>
        </div>
    </div>
</div>

<script>
// Global variables
let allConfigs = [];
let currentSearch = '';

// DOM Elements
const configsList = document.getElementById('configsList');
const loginModal = document.getElementById('loginModal');
const modalUsernameInput = document.getElementById('modalUsernameInput');
const modalPasswordInput = document.getElementById('modalPasswordInput');
const modalLoginBtn = document.getElementById('modalLoginBtn');
const modalError = document.getElementById('modalError');
const modalSuccess = document.getElementById('modalSuccess');
const searchInput = document.getElementById('searchInput');
const statsBar = document.getElementById('statsBar');
const totalConfigs = document.getElementById('totalConfigs');
const totalDownloads = document.getElementById('totalDownloads');
const topGame = document.getElementById('topGame');

// Show/hide login modal
function showLoginModal() {
    loginModal.classList.add('active');
    modalUsernameInput.focus();
}

function hideLoginModal() {
    loginModal.classList.remove('active');
    modalError.textContent = '';
    modalSuccess.textContent = '';
    modalUsernameInput.value = '';
    modalPasswordInput.value = '';
}

// Close modal on overlay click
loginModal.addEventListener('click', function(e) {
    if (e.target === loginModal) {
        hideLoginModal();
    }
});

// Modal login function
async function modalLogin() {
    const username = modalUsernameInput.value.trim();
    const password = modalPasswordInput.value;
    
    if (!username || !password) {
        modalError.textContent = 'Please enter both username and password';
        return;
    }
    
    modalError.textContent = '';
    modalSuccess.textContent = '';
    modalLoginBtn.disabled = true;
    modalLoginBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Logging in...';
    
    try {
        const res = await fetch('/api/user-login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: username, password: password })
        });
        
        const data = await res.json();
        
        if (data.valid) {
            modalSuccess.textContent = 'Login successful!';
            
            // Redirect after short delay
            setTimeout(() => {
                if (data.license_key) {
                    window.location.href = `/config/${data.license_key}`;
                }
            }, 1000);
        } else {
            modalError.textContent = data.error || 'Invalid username or password';
        }
    } catch (e) {
        console.error('Login error:', e);
        modalError.textContent = 'Connection error. Please try again.';
    } finally {
        modalLoginBtn.disabled = false;
        modalLoginBtn.innerHTML = '<i class="fas fa-sign-in-alt"></i> Login';
    }
}

// Load configs from API
async function loadConfigs() {
    try {
        configsList.innerHTML = '<div class="loading">Loading community configs</div>';
        
        const res = await fetch('/api/public-configs');
        const data = await res.json();
        
        allConfigs = data.configs || [];
        
        if (allConfigs.length === 0) {
            configsList.innerHTML = '<div class="empty-state">No community configs yet. Be the first to share one!</div>';
            updateStats();
            return;
        }
        
        filterConfigs();
        updateStats();
        
    } catch(error) {
        console.error('Error loading configs:', error);
        configsList.innerHTML = '<div class="error-state">Error loading configs. Please try again later.</div>';
    }
}

// Filter configs based on search
function filterConfigs() {
    const filtered = allConfigs.filter(config => {
        if (!currentSearch) return true;
        
        const searchLower = currentSearch.toLowerCase();
        return (
            config.config_name.toLowerCase().includes(searchLower) ||
            config.game_name.toLowerCase().includes(searchLower) ||
            config.description.toLowerCase().includes(searchLower) ||
            config.author_name.toLowerCase().includes(searchLower)
        );
    });
    
    displayConfigs(filtered);
}

// Display configs in grid
function displayConfigs(configs) {
    if (configs.length === 0) {
        configsList.innerHTML = '<div class="empty-state">No configs found matching your search.</div>';
        return;
    }
    
    configsList.innerHTML = '';
    
    configs.forEach(config => {
        const card = document.createElement('div');
        card.className = 'config-card';
        card.innerHTML = `
            <div class="config-name">${escapeHtml(config.config_name)}</div>
            <div class="config-game">${escapeHtml(config.game_name)}</div>
            <div class="config-description">${escapeHtml(config.description || 'No description provided')}</div>
            <div class="config-footer">
                <div class="config-author">
                    <i class="fas fa-user"></i> <span>${escapeHtml(config.author_name)}</span>
                </div>
                <div class="config-downloads">
                    <i class="fas fa-download"></i>
                    <span>${config.downloads || 0}</span>
                </div>
            </div>
            <button class="load-btn" onclick="viewConfig(${config.id})" title="View and download this config">
                <i class="fas fa-eye"></i> View Details
            </button>
        `;
        configsList.appendChild(card);
    });
}

// Update statistics
function updateStats() {
    if (allConfigs.length === 0) {
        statsBar.style.display = 'none';
        return;
    }
    
    statsBar.style.display = 'flex';
    totalConfigs.textContent = allConfigs.length;
    
    // Calculate total downloads
    const downloads = allConfigs.reduce((sum, config) => sum + (config.downloads || 0), 0);
    totalDownloads.textContent = downloads.toLocaleString();
    
    // Find top game
    const gameCounts = {};
    allConfigs.forEach(config => {
        const game = config.game_name;
        gameCounts[game] = (gameCounts[game] || 0) + 1;
    });
    
    const topGameName = Object.keys(gameCounts).reduce((a, b) => 
        gameCounts[a] > gameCounts[b] ? a : b, 'N/A'
    );
    topGame.textContent = topGameName;
}

// View config details
function viewConfig(configId) {
    showLoginModal();
    // You could store the configId to auto-download after login
    localStorage.setItem('pendingConfigId', configId);
}

// Refresh configs
function refreshConfigs() {
    loadConfigs();
}

// Show stats
function showStats() {
    statsBar.style.display = statsBar.style.display === 'none' ? 'flex' : 'none';
}

// Utility function to escape HTML
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Search functionality
searchInput.addEventListener('input', function() {
    currentSearch = this.value.trim();
    filterConfigs();
});

// Auto-refresh every 60 seconds
setInterval(loadConfigs, 60000);

// Load configs on page load
document.addEventListener('DOMContentLoaded', loadConfigs);

// Check for pending config after login
const pendingConfigId = localStorage.getItem('pendingConfigId');
if (pendingConfigId) {
    // You could implement auto-redirect to config page after login
    localStorage.removeItem('pendingConfigId');
}
</script>
</body>
</html>"""
    
    return HTMLResponse(content=html_content + ENHANCED_ANTI_DEVTOOLS_JS)

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
<title>Invalid License - Axion</title>
<style>
body{{background:rgb(12,12,12);color:white;font-family:Arial;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}}
.container{{text-align:center;padding:40px;background:rgba(0,0,0,0.5);border-radius:10px;border:1px solid rgba(255,255,255,0.1)}}
h1{{color:rgb(255,68,68);margin-bottom:20px}}
button{{margin-top:20px;padding:12px 30px;background:#333;color:white;border:none;border-radius:5px;cursor:pointer;font-size:16px}}
button:hover{{background:#444}}
</style>
</head>
<body>
<div class="container">
<h1>Invalid License</h1>
<p>License key not found or has expired</p>
<button onclick="window.location.href='/menu'">Return to Login</button>
</div>
{ENHANCED_ANTI_DEVTOOLS_JS}
</body>
</html>"""
        
        # Return the full HTML page for valid license
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<title>Axion Config</title>
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
        <div class="title">Axion Config</div>
        <div class="tabs">
            <div class="tab active" data-tab="aimbot">Aimbot</div>
            <div class="tab" data-tab="triggerbot">Triggerbot</div>
            <div class="tab" data-tab="settings">Configs</div>
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
        print(f"Error in serve_config_dashboard: {e}")
        import traceback
        traceback.print_exc()
        return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Error - Axion</title>
<style>
body{{background:rgb(12,12,12);color:white;font-family:Arial;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}}
.container{{text-align:center;padding:40px;background:rgba(0,0,0,0.5);border-radius:10px;border:1px solid rgba(255,255,255,0.1)}}
h1{{color:rgb(255,68,68);margin-bottom:20px}}
.error-details{{color:rgb(255,120,120);font-size:14px;margin-top:20px;word-wrap:break-word;max-width:600px;text-align:left;padding:15px;background:rgba(255,0,0,0.1);border-radius:5px;border:1px solid rgba(255,0,0,0.3)}}
button{{margin-top:20px;padding:12px 30px;background:#333;color:white;border:none;border-radius:5px;cursor:pointer;font-size:16px}}
button:hover{{background:#444}}
</style>
</head>
<body>
<div class="container">
<h1>Server Error</h1>
<p>An error occurred while loading the config dashboard.</p>
<div class="error-details">
<strong>Error Details:</strong><br>
{str(e)}
</div>
<button onclick="window.location.href='/menu'">Return to Login</button>
</div>
{ENHANCED_ANTI_DEVTOOLS_JS}
</body>
</html>"""

if __name__ == "__main__":
    init_db()
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
