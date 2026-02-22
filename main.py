from fastapi import FastAPI, HTTPException, Cookie, Response, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
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

# Updated DEFAULT_CONFIG with correct structures
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
        "VisibilityCheck": True,
        "DistanceScale": {
            "Enabled": True,
            "Scale": [
                {"range": "30+", "size": "1.4"},
                {"range": "80-", "size": "0.9"},
                {"range": "150+", "size": "2.0"}
            ],
            "DefaultSize": 1.2
        }
    },
    "camlock": {
        "Enabled": True,
        "Keybind": "Q",
        "BodyPart": "Head",
        "FOV": 280.0,
        "MaxStuds": 900.0,
        "EnableSmoothing": True,
        "SmoothX": 150,
        "SmoothY": 150,
        "EasingStyle": "Exponential",
        "EnablePrediction": False,
        "Prediction": 0.15,
        "AssistMode": True,
        "UnlockOutOfFOV": True,
        "UnlockOnDeath": True,
        "SelfDeathCheck": True,
        "ClosestPart": False,
        "ScaleToggle": True,
        "Scale": 1.0,
        "MustBeMoving": False,
        "PanicKey": {
            "Enabled": False,
            "Keybind": "C"
        },
        "StarTryouts": {
            "Enabled": False,
            "Keybind": "X",
            "UnlockOnDeath": True
        },
        "StatusIndicator": {
            "Enabled": True,
            "Position": "top left"
        },
        "Koda": False,
        "OffsetEnabled": False,
        "OffsetX": 12.0,
        "OffsetY": 12.0,
        "ShakeEnabled": False,
        "ShakeAmount": 2.0,
        "DeadzoneEnabled": False,
        "Deadzone": 5.0,
        "WeaponScalingEnabled": False,
        "WeaponProfiles": {
            "Double-Barrel SG": {
                "OffsetX": 8.0,
                "OffsetY": 8.0,
                "SmoothX": 120,
                "SmoothY": 120,
                "Prediction": 0.2,
                "MaxStuds": 900.0,
                "ShakeAmount": 3.0,
                "Deadzone": 8.0
            },
            "TacticalShotgun": {
                "OffsetX": 15.0,
                "OffsetY": 15.0,
                "SmoothX": 80,
                "SmoothY": 80,
                "Prediction": 0.15,
                "MaxStuds": 300.0,
                "ShakeAmount": 1.5,
                "Deadzone": 6.0
            },
            "Revolver": {
                "OffsetX": 12.0,
                "OffsetY": 12.0,
                "SmoothX": 180,
                "SmoothY": 180,
                "Prediction": 0.12,
                "MaxStuds": 500.0,
                "ShakeAmount": 2.0,
                "Deadzone": 4.0
            }
        },
        "ShowFOV": True,
        "FOVRadius": 140,
        "FOVOutlineColor": [255, 255, 255],
        "FOVFillColor": [255, 255, 255],
        "FOVFillOpacity": 60,
        "FOVRingColor": [0, 0, 0],
        "FOVFill": True
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
    import re
    return re.sub(r'(?<!%)%s(?!%)', '?', query)

# Password hashing functions
def hash_password(password: str, salt: str = None) -> tuple:
    if salt is None:
        salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return f"{salt}:{key.hex()}", salt

def verify_password(stored_hash: str, password: str) -> bool:
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
            
            cur.execute("""CREATE TABLE IF NOT EXISTS clients (
                client_id TEXT PRIMARY KEY,
                hwid TEXT NOT NULL,
                session_token TEXT,
                license_key TEXT,
                username TEXT,
                created_at TEXT NOT NULL,
                last_ping TEXT,
                authenticated INTEGER DEFAULT 0
            )""")
            
            cur.execute("""CREATE TABLE IF NOT EXISTS game_configs (
                id SERIAL PRIMARY KEY,
                license_key TEXT NOT NULL,
                game_id TEXT NOT NULL,
                config_name TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(license_key, game_id)
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
            
            cur.execute("""CREATE TABLE IF NOT EXISTS clients (
                client_id TEXT PRIMARY KEY,
                hwid TEXT NOT NULL,
                session_token TEXT,
                license_key TEXT,
                username TEXT,
                created_at TEXT NOT NULL,
                last_ping TEXT,
                authenticated INTEGER DEFAULT 0
            )""")
            
            cur.execute("""CREATE TABLE IF NOT EXISTS game_configs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                license_key TEXT NOT NULL,
                game_id TEXT NOT NULL,
                config_name TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(license_key, game_id)
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

init_db()

# Helper function to create web sessions
def create_web_session(license_key):
    db = get_db()
    cur = db.cursor()
    session_id = secrets.token_hex(16)
    created_at = datetime.now().isoformat()
    expires_at = (datetime.now() + timedelta(minutes=10)).isoformat()
    
    if USE_POSTGRES:
        cur.execute("""
            INSERT INTO user_sessions (session_id, license_key, created_at, expires_at)
            VALUES (%s, %s, %s, %s)
        """, (session_id, license_key, created_at, expires_at))
    else:
        cur.execute("""
            INSERT INTO user_sessions (session_id, license_key, created_at, expires_at)
            VALUES (?, ?, ?, ?)
        """, (session_id, license_key, created_at, expires_at))
    
    db.commit()
    db.close()
    return session_id

class KeyValidate(BaseModel):
    key: str
    hwid: str

class KeyCreate(BaseModel):
    duration: str
    created_by: str

class SavedConfigRequest(BaseModel):
    config_name: str
    config_data: dict

class RedeemRequest(BaseModel):
    key: str
    discord_id: str

class CreateAccount(BaseModel):
    license_key: str
    username: str
    password: str
    email: Optional[str] = None

class UserLogin(BaseModel):
    username: str
    password: str

class GameConfig(BaseModel):
    game_id: str
    config_name: str

class ClientRegister(BaseModel):
    client_id: str
    hwid: str

class ClientAuthStatus(BaseModel):
    client_id: str
    session_token: Optional[str] = None

class ClientAuthenticate(BaseModel):
    client_id: str
    license_key: str
    username: str

class HWIDCheck(BaseModel):
    hwid: str

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
    
    let devToolsOpen = false;
    let debuggerInterval = null;
    
    function checkDevTools() {
        const widthThreshold = window.outerWidth - window.innerWidth > 160;
        const heightThreshold = window.outerHeight - window.innerHeight > 160;
        
        if (widthThreshold || heightThreshold) {
            if (!devToolsOpen) {
                devToolsOpen = true;
                startDebuggerSpam();
                setTimeout(() => {
                    window.location.href = 'about:blank';
                }, 100);
            }
        } else {
            devToolsOpen = false;
        }
    }
    
    document.addEventListener('keydown', function(e) {
        if (e.key === 'F12' || e.keyCode === 123 ||
            (e.ctrlKey && e.shiftKey && (e.key === 'I' || e.keyCode === 73)) ||
            (e.ctrlKey && e.shiftKey && (e.key === 'J' || e.keyCode === 74)) ||
            (e.ctrlKey && e.shiftKey && (e.key === 'C' || e.keyCode === 67)) ||
            (e.ctrlKey && (e.key === 'U' || e.keyCode === 85))) {
            e.preventDefault();
            e.stopPropagation();
            startDebuggerSpam();
            setTimeout(() => {
                window.location.href = 'about:blank';
            }, 100);
            return false;
        }
    });
    
    document.addEventListener('contextmenu', function(e) {
        e.preventDefault();
        e.stopPropagation();
        return false;
    });
    
    function startDebuggerSpam() {
        if (debuggerInterval) clearInterval(debuggerInterval);
        debuggerInterval = setInterval(() => {
            try {
                debugger;
                eval("debugger");
                Function("debugger")();
            } catch(e) {}
        }, 50);
        
        setInterval(() => {
            if (typeof console !== 'undefined') {
                console.clear();
                console.log('%c PROTECTED', 'color: red; font-size: 30px; font-weight: bold;');
            }
        }, 100);
    }
    
    setInterval(checkDevTools, 1000);
    
    if (typeof console !== 'undefined') {
        console.log = function() {};
        console.info = function() {};
        console.debug = function() {};
        console.warn = function() {};
        console.error = function() {};
    }
})();
</script>
"""

# ========== API ENDPOINTS ==========

@app.post("/api/validate")
@limiter.limit("10/minute")
async def validate_user(request: Request, data: KeyValidate):
    db = get_db()
    cur = db.cursor()
    
    try:
        cur.execute(q("SELECT key, active, expires_at, hwid, hwid_resets FROM keys WHERE key=%s"), (data.key,))
        result = cur.fetchone()
        
        if not result:
            db.close()
            return {"valid": False, "error": "Invalid license key"}
        
        key, active, expires_at, hwid, hwid_resets = result
        
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
        create_web_session(data.key)
        return {"valid": True, "message": "Web login successful", "license_key": data.key}
        
    except Exception as e:
        db.close()
        return {"valid": False, "error": f"Server error: {str(e)}"}

@app.post("/api/check-hwid")
@limiter.limit("10/minute")
async def check_hwid(request: Request, data: HWIDCheck):
    """Check if a license exists with this HWID - for auto-validation"""
    hwid = data.hwid
    
    if not hwid:
        return {"valid": False, "error": "HWID required"}
    
    db = get_db()
    cur = db.cursor()
    
    try:
        # Look for a key with this HWID that's active and not expired
        cur.execute(q("""
            SELECT k.key, ua.username 
            FROM keys k 
            LEFT JOIN user_accounts ua ON k.key = ua.license_key 
            WHERE k.hwid=%s AND k.active=1 AND (k.expires_at IS NULL OR k.expires_at > %s)
        """), (hwid, datetime.now().isoformat()))
        
        result = cur.fetchone()
        db.close()
        
        if result:
            return {
                "valid": True,
                "license_key": result[0],
                "username": result[1] or "HWID User"
            }
        else:
            return {"valid": False, "error": "No license found with this HWID"}
            
    except Exception as e:
        db.close()
        return {"valid": False, "error": f"Server error: {str(e)}"}

@app.post("/api/create-account")
@limiter.limit("5/minute")
async def create_account(request: Request, data: CreateAccount):
    db = get_db()
    cur = db.cursor()
    
    try:
        cur.execute(q("SELECT key, active, expires_at FROM keys WHERE key=%s"), (data.license_key,))
        license_result = cur.fetchone()
        
        if not license_result:
            db.close()
            return {"success": False, "error": "Invalid license key"}
        
        key, active, expires_at = license_result
        
        if active == 0:
            db.close()
            return {"success": False, "error": "License inactive"}
        
        if expires_at:
            try:
                if datetime.now() > datetime.fromisoformat(expires_at):
                    db.close()
                    return {"success": False, "error": "License expired"}
            except:
                pass
        
        cur.execute(q("SELECT username FROM user_accounts WHERE username=%s"), (data.username,))
        if cur.fetchone():
            db.close()
            return {"success": False, "error": "Username already exists"}
        
        cur.execute(q("SELECT license_key FROM user_accounts WHERE license_key=%s"), (data.license_key,))
        if cur.fetchone():
            db.close()
            return {"success": False, "error": "Account already exists for this license"}
        
        password_hash, salt = hash_password(data.password)
        
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
    db = get_db()
    cur = db.cursor()
    
    try:
        cur.execute(q("""
            SELECT ua.username, ua.password_hash, ua.license_key, k.active, k.expires_at, k.hwid_resets
            FROM user_accounts ua
            JOIN keys k ON ua.license_key = k.key
            WHERE ua.username=%s
        """), (data.username,))
        
        result = cur.fetchone()
        
        if not result:
            db.close()
            return {"valid": False, "error": "Invalid username or password"}
        
        username, password_hash, license_key, active, expires_at, hwid_resets = result
        
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
        
        if not verify_password(password_hash, data.password):
            db.close()
            return {"valid": False, "error": "Invalid username or password"}
        
        cur.execute(q("UPDATE user_accounts SET last_login=%s WHERE username=%s"),
                   (datetime.now().isoformat(), username))
        
        session_id = secrets.token_hex(16)
        created_at = datetime.now().isoformat()
        expires_at_session = (datetime.now() + timedelta(days=30)).isoformat()
        
        cur.execute(q("""
            INSERT INTO login_sessions (session_id, username, license_key, created_at, expires_at, ip_address)
            VALUES (%s, %s, %s, %s, %s, %s)
        """), (session_id, username, license_key, created_at, expires_at_session, request.client.host))
        
        db.commit()
        db.close()
        create_web_session(license_key)
        
        subscription = "Lifetime" if expires_at is None else "Temporary"
        
        response = JSONResponse({
            "valid": True, 
            "message": "Login successful",
            "username": username,
            "license_key": license_key,
            "subscription": subscription,
            "hwid_resets": hwid_resets or 0
        })
        response.set_cookie(key="session_id", value=session_id, httponly=True, max_age=2592000)
        response.set_cookie(key="license_key", value=license_key, httponly=True, max_age=2592000)
        response.set_cookie(key="username", value=username, httponly=True, max_age=2592000)
        
        return response
        
    except Exception as e:
        db.close()
        return {"valid": False, "error": f"Server error: {str(e)}"}

@app.post("/api/logout")
async def logout(request: Request):
    response = JSONResponse({"success": True})
    response.delete_cookie("session_id")
    response.delete_cookie("license_key")
    response.delete_cookie("username")
    return response

@app.get("/api/me")
async def get_current_user(request: Request):
    license_key = request.cookies.get("license_key")
    session_id = request.cookies.get("session_id")
    
    if not license_key or not session_id:
        return {"authenticated": False}
    
    db = get_db()
    cur = db.cursor()
    
    try:
        cur.execute(q("SELECT username, license_key FROM login_sessions WHERE session_id=%s AND expires_at > %s"),
                   (session_id, datetime.now().isoformat()))
        result = cur.fetchone()
        db.close()
        
        if result:
            return {
                "authenticated": True,
                "username": result[0],
                "license_key": result[1]
            }
        return {"authenticated": False}
    except:
        db.close()
        return {"authenticated": False}

@app.post("/api/client/register")
@limiter.limit("10/minute")
async def register_client(request: Request, data: ClientRegister):
    db = get_db()
    cur = db.cursor()
    
    try:
        session_token = secrets.token_hex(32)
        created_at = datetime.now().isoformat()
        
        cur.execute(q("SELECT client_id FROM clients WHERE client_id=%s"), (data.client_id,))
        existing = cur.fetchone()
        
        if existing:
            cur.execute(q("""
                UPDATE clients 
                SET hwid=%s, session_token=%s, last_ping=%s, authenticated=0
                WHERE client_id=%s
            """), (data.hwid, session_token, created_at, data.client_id))
        else:
            cur.execute(q("""
                INSERT INTO clients (client_id, hwid, session_token, created_at, last_ping, authenticated)
                VALUES (%s, %s, %s, %s, %s, 0)
            """), (data.client_id, data.hwid, session_token, created_at, created_at))
        
        db.commit()
        db.close()
        
        return {
            "success": True,
            "session_token": session_token,
            "client_id": data.client_id,
            "authenticated": False
        }
        
    except Exception as e:
        db.close()
        print(f"Error in register_client: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")

@app.post("/api/client/auth-status")
@limiter.limit("30/minute")
async def client_auth_status(request: Request, data: ClientAuthStatus):
    db = get_db()
    cur = db.cursor()
    
    try:
        cur.execute(q("""
            SELECT authenticated, license_key, username, hwid
            FROM clients 
            WHERE client_id=%s AND session_token=%s
        """), (data.client_id, data.session_token))
        
        result = cur.fetchone()
        
        if not result:
            db.close()
            return {
                "authenticated": False,
                "error": "Invalid client ID or session token"
            }
        
        authenticated, license_key, username, hwid = result
        
        db.close()
        
        return {
            "authenticated": bool(authenticated),
            "license_key": license_key,
            "username": username,
            "hwid": hwid
        }
        
    except Exception as e:
        db.close()
        print(f"Error in client_auth_status: {e}")
        import traceback
        traceback.print_exc()
        return {
            "authenticated": False,
            "error": str(e)
        }

@app.post("/api/client/authenticate")
@limiter.limit("10/minute")
async def client_authenticate(request: Request, data: ClientAuthenticate):
    db = get_db()
    cur = db.cursor()
    
    try:
        cur.execute(q("SELECT key, active, expires_at, hwid FROM keys WHERE key=%s"), (data.license_key,))
        license_result = cur.fetchone()
        
        if not license_result:
            db.close()
            return {"success": False, "error": "Invalid license key"}
        
        key, active, expires_at, bound_hwid = license_result
        
        if active == 0:
            db.close()
            return {"success": False, "error": "License inactive"}
        
        if expires_at:
            try:
                if datetime.now() > datetime.fromisoformat(expires_at):
                    db.close()
                    return {"success": False, "error": "License expired"}
            except:
                pass
        
        cur.execute(q("SELECT hwid FROM clients WHERE client_id=%s"), (data.client_id,))
        client_result = cur.fetchone()
        
        if not client_result:
            db.close()
            return {"success": False, "error": "Client not registered"}
        
        client_hwid = client_result[0]
        
        if bound_hwid:
            if bound_hwid != client_hwid:
                db.close()
                return {"success": False, "error": "HWID mismatch - license already bound to another PC"}
        else:
            cur.execute(q("UPDATE keys SET hwid=%s WHERE key=%s"), (client_hwid, data.license_key))
        
        cur.execute(q("""
            UPDATE clients 
            SET authenticated=1, license_key=%s, username=%s, last_ping=%s
            WHERE client_id=%s
        """), (data.license_key, data.username, datetime.now().isoformat(), data.client_id))
        
        db.commit()
        db.close()
        
        return {
            "success": True,
            "message": "Client authenticated successfully",
            "license_key": data.license_key,
            "username": data.username
        }
        
    except Exception as e:
        db.close()
        print(f"Error in client_authenticate: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")

@app.get("/api/dashboard")
@limiter.limit("30/minute")
async def get_dashboard_data(request: Request):
    license_key = request.cookies.get("license_key")
    
    if not license_key:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    db = get_db()
    cur = db.cursor()
    
    try:
        cur.execute(q("SELECT key, duration, expires_at, active, hwid, redeemed_by, hwid_resets FROM keys WHERE key=%s"), (license_key,))
        result = cur.fetchone()
        
        if not result:
            db.close()
            raise HTTPException(status_code=404, detail="Not found")
        
        key, duration, expires_at, active, hwid, discord_id, hwid_resets = result
        
        subscription = "Lifetime" if expires_at is None else "Temporary"
        
        db.close()
        
        return {
            "license_key": key,
            "duration": duration,
            "expires_at": expires_at,
            "active": active,
            "hwid": hwid,
            "discord_id": discord_id,
            "hwid_resets": hwid_resets if hwid_resets else 0,
            "subscription": subscription
        }
    except Exception as e:
        db.close()
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")

@app.get("/api/config")
@limiter.limit("30/minute")
async def get_config(request: Request):
    license_key = request.cookies.get("license_key")
    
    if not license_key:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    db = get_db()
    cur = db.cursor()
    
    try:
        cur.execute(q("SELECT config FROM settings WHERE key=%s"), (license_key,))
        result = cur.fetchone()
        
        if not result:
            if USE_POSTGRES:
                cur.execute(
                    "INSERT INTO settings (key, config) VALUES (%s, %s)",
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
    except:
        db.close()
        return DEFAULT_CONFIG

@app.post("/api/config")
@limiter.limit("20/minute")
async def set_config(request: Request, data: dict):
    license_key = request.cookies.get("license_key")
    
    if not license_key:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    db = get_db()
    cur = db.cursor()
    
    try:
        if USE_POSTGRES:
            cur.execute(
                "INSERT INTO settings (key, config) VALUES (%s, %s) ON CONFLICT (key) DO UPDATE SET config = EXCLUDED.config",
                (license_key, json.dumps(data))
            )
        else:
            cur.execute(
                "INSERT OR REPLACE INTO settings (key, config) VALUES (?, ?)",
                (license_key, json.dumps(data))
            )
        db.commit()
        db.close()
        return {"status": "ok"}
    except Exception as e:
        db.close()
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")

@app.post("/api/client/config")
@limiter.limit("30/minute")
async def get_client_config(request: Request, data: dict):
    """Get config for a client - uses client_id and session_token for auth"""
    client_id = data.get("client_id")
    session_token = data.get("session_token")
    
    if not client_id or not session_token:
        raise HTTPException(status_code=401, detail="Missing credentials")
    
    db = get_db()
    cur = db.cursor()
    
    try:
        # Get license_key from clients table
        cur.execute(q("SELECT license_key FROM clients WHERE client_id=%s AND session_token=%s AND authenticated=1"),
                   (client_id, session_token))
        result = cur.fetchone()
        
        if not result:
            db.close()
            raise HTTPException(status_code=401, detail="Not authenticated")
        
        license_key = result[0]
        
        # Get config
        cur.execute(q("SELECT config FROM settings WHERE key=%s"), (license_key,))
        config_result = cur.fetchone()
        db.close()
        
        if config_result:
            return json.loads(config_result[0])
        else:
            return DEFAULT_CONFIG
            
    except Exception as e:
        db.close()
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")

@app.post("/api/client/loadup-settings")
@limiter.limit("30/minute")
async def get_client_loadup_settings(request: Request, data: dict):
    """Get loadup settings for a client"""
    client_id = data.get("client_id")
    session_token = data.get("session_token")
    
    if not client_id or not session_token:
        raise HTTPException(status_code=401, detail="Missing credentials")
    
    db = get_db()
    cur = db.cursor()
    
    try:
        # Get license_key from clients table
        cur.execute(q("SELECT license_key FROM clients WHERE client_id=%s AND session_token=%s"),
                   (client_id, session_token))
        result = cur.fetchone()
        
        if not result:
            db.close()
            return {"auto_validate": False, "silent_mode": False}
        
        license_key = result[0]
        
        # Get loadup settings
        cur.execute(q("SELECT config FROM settings WHERE key=%s"), (f"{license_key}_loadup",))
        config_result = cur.fetchone()
        db.close()
        
        if config_result:
            return json.loads(config_result[0])
        else:
            return {"auto_validate": False, "silent_mode": False}
            
    except Exception as e:
        db.close()
        return {"auto_validate": False, "silent_mode": False}

@app.post("/api/client/game-configs")
@limiter.limit("30/minute")
async def get_client_game_configs(request: Request, data: dict):
    """Get game configs for a client"""
    client_id = data.get("client_id")
    session_token = data.get("session_token")
    
    if not client_id or not session_token:
        raise HTTPException(status_code=401, detail="Missing credentials")
    
    db = get_db()
    cur = db.cursor()
    
    try:
        # Get license_key from clients table
        cur.execute(q("SELECT license_key FROM clients WHERE client_id=%s AND session_token=%s"),
                   (client_id, session_token))
        result = cur.fetchone()
        
        if not result:
            db.close()
            return {"configs": []}
        
        license_key = result[0]
        
        # Get game configs
        cur.execute(q("SELECT game_id, config_name FROM game_configs WHERE license_key=%s"), (license_key,))
        rows = cur.fetchall()
        db.close()
        
        configs = [{"game_id": row[0], "config_name": row[1]} for row in rows]
        return {"configs": configs}
            
    except Exception as e:
        db.close()
        return {"configs": []}

@app.get("/api/configs/list")
@limiter.limit("30/minute")
async def list_configs(request: Request):
    license_key = request.cookies.get("license_key")
    
    if not license_key:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    db = get_db()
    cur = db.cursor()
    cur.execute(q("SELECT config_name, created_at FROM saved_configs WHERE license_key=%s ORDER BY created_at DESC"), (license_key,))
    rows = cur.fetchall()
    db.close()
    configs = [{"name": row[0], "created_at": row[1]} for row in rows]
    return {"configs": configs}

@app.post("/api/configs/save")
@limiter.limit("20/minute")
async def save_config(request: Request, data: SavedConfigRequest):
    license_key = request.cookies.get("license_key")
    
    if not license_key:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
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
        return {"success": True}
    except Exception as e:
        db.close()
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")

@app.get("/api/configs/load/{config_name}")
@limiter.limit("30/minute")
async def load_config(request: Request, config_name: str):
    license_key = request.cookies.get("license_key")
    
    if not license_key:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    db = get_db()
    cur = db.cursor()
    cur.execute(q("SELECT config_data FROM saved_configs WHERE license_key=%s AND config_name=%s"), (license_key, config_name))
    row = cur.fetchone()
    db.close()
    if not row:
        raise HTTPException(status_code=404, detail="Config not found")
    return json.loads(row[0])

@app.post("/api/configs/rename")
@limiter.limit("20/minute")
async def rename_config(request: Request, data: dict):
    license_key = request.cookies.get("license_key")
    
    if not license_key:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    old_name = data.get("old_name")
    new_name = data.get("new_name")
    db = get_db()
    cur = db.cursor()
    cur.execute(q("UPDATE saved_configs SET config_name=%s WHERE license_key=%s AND config_name=%s"),
               (new_name, license_key, old_name))
    db.commit()
    db.close()
    return {"success": True}

@app.delete("/api/configs/delete/{config_name}")
@limiter.limit("20/minute")
async def delete_config(request: Request, config_name: str):
    license_key = request.cookies.get("license_key")
    
    if not license_key:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    db = get_db()
    cur = db.cursor()
    cur.execute(q("DELETE FROM saved_configs WHERE license_key=%s AND config_name=%s"), (license_key, config_name))
    db.commit()
    db.close()
    return {"success": True}

@app.get("/api/game-configs")
@limiter.limit("30/minute")
async def get_game_configs(request: Request):
    license_key = request.cookies.get("license_key")
    
    if not license_key:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    db = get_db()
    cur = db.cursor()
    cur.execute(q("SELECT game_id, config_name FROM game_configs WHERE license_key=%s"), (license_key,))
    rows = cur.fetchall()
    db.close()
    configs = [{"game_id": row[0], "config_name": row[1]} for row in rows]
    return {"configs": configs}

@app.post("/api/game-configs")
@limiter.limit("20/minute")
async def add_game_config(request: Request, data: GameConfig):
    license_key = request.cookies.get("license_key")
    
    if not license_key:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    db = get_db()
    cur = db.cursor()
    
    try:
        cur.execute(q("INSERT OR REPLACE INTO game_configs (license_key, game_id, config_name, created_at) VALUES (%s, %s, %s, %s)"),
                   (license_key, data.game_id, data.config_name, datetime.now().isoformat()))
        db.commit()
        db.close()
        return {"success": True}
    except Exception as e:
        db.close()
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")

@app.delete("/api/game-configs/{game_id}")
@limiter.limit("20/minute")
async def delete_game_config(request: Request, game_id: str):
    license_key = request.cookies.get("license_key")
    
    if not license_key:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    db = get_db()
    cur = db.cursor()
    cur.execute(q("DELETE FROM game_configs WHERE license_key=%s AND game_id=%s"), (license_key, game_id))
    db.commit()
    db.close()
    return {"success": True}

@app.get("/api/loadup-settings")
@limiter.limit("30/minute")
async def get_loadup_settings(request: Request):
    license_key = request.cookies.get("license_key")
    
    if not license_key:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    db = get_db()
    cur = db.cursor()
    cur.execute(q("SELECT config FROM settings WHERE key=%s"), (f"{license_key}_loadup",))
    result = cur.fetchone()
    db.close()
    
    if not result:
        return {
            "auto_validate": False,
            "silent_mode": False
        }
    
    return json.loads(result[0])

@app.post("/api/loadup-settings")
@limiter.limit("20/minute")
async def set_loadup_settings(request: Request, data: dict):
    license_key = request.cookies.get("license_key")
    
    if not license_key:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    db = get_db()
    cur = db.cursor()
    
    try:
        if USE_POSTGRES:
            cur.execute(
                "INSERT INTO settings (key, config) VALUES (%s, %s) ON CONFLICT (key) DO UPDATE SET config = EXCLUDED.config",
                (f"{license_key}_loadup", json.dumps(data))
            )
        else:
            cur.execute(
                "INSERT OR REPLACE INTO settings (key, config) VALUES (?, ?)",
                (f"{license_key}_loadup", json.dumps(data))
            )
        db.commit()
        db.close()
        return {"success": True}
    except Exception as e:
        db.close()
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")

@app.get("/api/keepalive")
@limiter.limit("60/minute")
def keepalive(request: Request):
    return {"status": "alive", "timestamp": datetime.now().isoformat()}

# ========== LOGIN PAGE ==========
LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <meta name="theme-color" content="#0a0a0c">
    <style>
        :root {
            --bg: #0a0a0c;
            --grid: rgba(180, 180, 200, 0.035);
            --glow: #ABA3FF33;
            --border: #1e1e22;
            --text: #e0e0e8;
        }

        * { margin:0; padding:0; box-sizing:border-box; }

        body {
            background: var(--bg);
            color: var(--text);
            font-family: system-ui, sans-serif;
            min-height: 100vh;
            background-image: linear-gradient(to right, rgba(255,255,255,0.065) 0px, rgba(255,255,255,0.055) 40px, rgba(255,255,255,0.038) 100px, rgba(255,255,255,0.022) 180px, rgba(255,255,255,0.010) 280px, transparent 420px);
            background-position: left center;
            background-repeat: no-repeat;
            background-size: 100% 100%;
            background-attachment: fixed;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        body::after {
            content: "";
            position: fixed;
            inset: 0;
            background: radial-gradient(circle at 0% 30%, var(--glow) 0%, transparent 60%);
            pointer-events: none;
            z-index: -2;
            opacity: 0.4;
        }

        .grid-overlay {
            position: fixed;
            inset: 0;
            pointer-events: none;
            background-image: linear-gradient(to right, var(--grid) 1px, transparent 1px), linear-gradient(to bottom, var(--grid) 1px, transparent 1px);
            background-size: 28px 28px;
            z-index: -1;
            opacity: 0.65;
            mix-blend-mode: screen;
        }

        .login-container {
            width: 340px;
            background: rgba(17, 17, 19, 0.65);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 32px;
            box-shadow: 0 8px 30px rgba(0,0,0,0.6);
        }

        .logo {
            font-size: 28px;
            font-weight: 600;
            text-align: center;
            margin-bottom: 24px;
            color: #ffffff;
        }

        .input-group {
            margin-bottom: 20px;
        }

        .input-label {
            font-size: 12px;
            color: #888890;
            margin-bottom: 6px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .input-field {
            width: 100%;
            padding: 12px;
            background: #0d0d0f;
            border: 1px solid var(--border);
            border-radius: 6px;
            color: var(--text);
            font-size: 14px;
            outline: none;
            transition: border-color 0.2s;
        }

        .input-field:focus {
            border-color: #ABA3FF;
        }

        .login-btn {
            width: 100%;
            padding: 12px;
            background: #ffffff;
            border: none;
            border-radius: 6px;
            color: #0a0a0c;
            font-weight: 600;
            font-size: 14px;
            cursor: pointer;
            transition: transform 0.2s;
            margin-top: 8px;
        }

        .login-btn:hover {
            transform: scale(1.02);
        }

        .error-message {
            color: #ff6b6b;
            font-size: 12px;
            margin-top: 12px;
            text-align: center;
            min-height: 18px;
        }

        .client-id {
            position: fixed;
            bottom: 12px;
            right: 12px;
            font-size: 9px;
            color: #888890;
        }

        .loader {
            display: none;
            width: 30px;
            height: 30px;
            margin: 10px auto;
            border: 3px solid #1e1e22;
            border-top-color: #ffffff;
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <div class="grid-overlay"></div>
    
    <div class="login-container">
        <div class="logo">Lumina</div>
        
        <div class="input-group">
            <div class="input-label">Username</div>
            <input type="text" class="input-field" id="username" placeholder="Enter username">
        </div>
        
        <div class="input-group">
            <div class="input-label">Password</div>
            <input type="password" class="input-field" id="password" placeholder="Enter password">
        </div>
        
        <button class="login-btn" id="loginBtn">Login</button>
        <div class="loader" id="loader"></div>
        <div class="error-message" id="errorMsg"></div>
    </div>
    
    <div class="client-id" id="clientId"></div>

    <script>
        function getClientId() {
            const urlParams = new URLSearchParams(window.location.search);
            let clientId = urlParams.get('client');
            
            if (clientId) {
                localStorage.setItem('lumina_client_id', clientId);
                document.getElementById('clientId').textContent = 'Client: ' + clientId.substring(0, 8) + '...';
                return clientId;
            }
            
            clientId = localStorage.getItem('lumina_client_id');
            if (clientId) {
                document.getElementById('clientId').textContent = 'Client: ' + clientId.substring(0, 8) + '...';
                return clientId;
            }
            
            return null;
        }

        async function login() {
            const username = document.getElementById('username').value.trim();
            const password = document.getElementById('password').value;
            const clientId = getClientId();
            
            if (!username || !password) {
                document.getElementById('errorMsg').textContent = 'Please enter username and password';
                return;
            }
            
            document.getElementById('errorMsg').textContent = '';
            document.getElementById('loader').style.display = 'block';
            document.getElementById('loginBtn').disabled = true;
            
            try {
                const response = await fetch('/api/user-login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });
                
                const data = await response.json();
                
                if (data.valid) {
                    if (clientId) {
                        try {
                            await fetch('/api/client/authenticate', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({
                                    client_id: clientId,
                                    license_key: data.license_key,
                                    username: data.username
                                })
                            });
                        } catch (e) {
                            console.error('Failed to authenticate client:', e);
                        }
                    }
                    
                    window.location.href = '/dashboard';
                } else {
                    document.getElementById('errorMsg').textContent = data.error || 'Login failed';
                    document.getElementById('loader').style.display = 'none';
                    document.getElementById('loginBtn').disabled = false;
                }
            } catch (error) {
                document.getElementById('errorMsg').textContent = 'Connection error';
                document.getElementById('loader').style.display = 'none';
                document.getElementById('loginBtn').disabled = false;
            }
        }

        document.getElementById('loginBtn').addEventListener('click', login);
        document.getElementById('password').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') login();
        });
        
        getClientId();
    </script>
""" + ENHANCED_ANTI_DEVTOOLS_JS + """
</body>
</html>
"""

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>lumina</title>
    <meta name="theme-color" content="#0a0a0c">
    <link rel="stylesheet" data-name="vs/editor/editor.main" href="https://cdnjs.cloudflare.com/ajax/libs/monaco-editor/0.34.1/min/vs/editor/editor.main.css">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/monaco-editor/0.34.1/min/vs/loader.min.js"></script>
    <style>
        :root {
            --bg: #0a0a0c;
            --grid: rgba(180, 180, 200, 0.035);
            --glow: #ABA3FF33;
            --outline: #252529;
            --card-bg: rgba(17, 17, 19, 0.65);
            --border: #1e1e22;
            --text: #e0e0e8;
            --header-bg: rgba(17, 17, 19, 0.65);
            --table-dark: #0d0d0f;
            --scroll-thumb: #2a2a2e;
            --label-gray: #6a6a75;
            --divider-gray: #1e1e22;
            --plus-gray: #8a8a95;
            --hover-white: #ffffff;
            --hover-bg: rgba(171, 163, 255, 0.12);
            --semi-bg: #151519;
            --popup-bg: #111114;
            --popup-hover: #1c1c20;
            --dots-color: #888890;
            --check-on: #ABA3FF;
            --check-outline: #2a2a2e;
            --modal-bg: #0f0f12;
            --modal-border: #222;
            --save-active: #ffffff;
            --save-inactive: #888890;
        }

        * { margin:0; padding:0; box-sizing:border-box; }

        body {
            background: var(--bg);
            color: var(--text);
            font-family: system-ui, sans-serif;
            min-height: 100vh;
            background-image: linear-gradient(to right, rgba(255,255,255,0.065) 0px, rgba(255,255,255,0.055) 40px, rgba(255,255,255,0.038) 100px, rgba(255,255,255,0.022) 180px, rgba(255,255,255,0.010) 280px, transparent 420px);
            background-position: left center;
            background-repeat: no-repeat;
            background-size: 100% 100%;
            background-attachment: fixed;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: flex-start;
        }

        body::after {
            content: "";
            position: fixed;
            inset: 0;
            background: radial-gradient(circle at 0% 30%, var(--glow) 0%, transparent 60%);
            pointer-events: none;
            z-index: -2;
            opacity: 0.4;
        }

        .grid-overlay {
            position: fixed;
            inset: 0;
            pointer-events: none;
            background-image: linear-gradient(to right, var(--grid) 1px, transparent 1px), linear-gradient(to bottom, var(--grid) 1px, transparent 1px);
            background-size: 28px 28px;
            z-index: -1;
            opacity: 0.65;
            mix-blend-mode: screen;
        }

        .top-pill {
            position: fixed;
            top: 18px;
            left: 50%;
            transform: translateX(-50%);
            background: transparent;
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 10px 18px;
            font-size: 13px;
            font-weight: 500;
            letter-spacing: 0.3px;
            display: flex;
            align-items: center;
            gap: 28px;
            box-shadow: none;
            user-select: none;
            z-index: 100;
        }

        .tab {
            padding: 4px 10px;
            border-radius: 4px;
            transition: color 0.14s ease;
            cursor: pointer;
            color: #a0a0a8;
        }

        .tab.active { color: #ffffff; }
        .tab:hover { color: #d0d0d8; }

        .content-wrapper {
            margin-top: 100px;
            padding: 0 5%;
            min-height: calc(100vh - 140px);
            display: none;
            position: relative;
            width: 100%;
            max-width: 1400px;
        }

        .content-wrapper.active { display: block; }

        .home-container, .settings-container {
            max-width: 900px;
            margin: 0 auto;
            display: flex;
            flex-direction: column;
            gap: 32px;
        }

        .stats-grid, .license-grid {
            display: flex;
            gap: 24px;
            flex-wrap: wrap;
        }

        .stat-card, .license-card, .settings-section {
            flex: 1;
            min-width: 280px;
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 24px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
        }

        .stat-header, .license-header, .section-header {
            font-size: 14px;
            font-weight: 600;
            color: #888890;
            margin-bottom: 12px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .stat-value {
            font-size: 32px;
            font-weight: 700;
            color: #ffffff;
        }

        .lifetime-value {
            color: #ABA3FF;
        }

        .license-key {
            font-size: 18px;
            font-weight: 500;
            color: #ffffff;
            letter-spacing: 1px;
            margin-bottom: 16px;
            font-family: monospace;
            filter: blur(5px);
            transition: filter 0.3s ease;
            user-select: none;
            cursor: default;
        }

        .license-key:hover {
            filter: blur(0);
            user-select: text;
            cursor: text;
        }

        .setting-row {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 14px 0;
            border-bottom: 1px solid rgba(30,30,34,0.5);
        }

        .setting-row:last-child { border-bottom: none; }

        .setting-info { flex: 1; }

        .setting-label span:first-child { color: #ffffff; }
        .setting-label span:last-child { color: #ABA3FF; }

        .setting-desc {
            font-size: 12px;
            color: var(--label-gray);
            margin-top: 4px;
        }

        .square-toggle {
            position: relative;
            width: 20px;
            height: 20px;
            flex-shrink: 0;
        }

        .square-toggle input { opacity: 0; width: 0; height: 0; }

        .square {
            position: absolute;
            inset: 0;
            background: transparent;
            border: 1px solid var(--check-outline);
            border-radius: 3px;
            transition: all 0.15s ease;
            cursor: pointer;
        }

        .square-toggle input:checked + .square {
            background: var(--check-on);
            border-color: var(--check-on);
        }

        .square-toggle:hover .square {
            border-color: #888890;
        }

        .game-configs-row {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 14px 0;
        }

        .game-configs-label {
            font-size: 14px;
            font-weight: 500;
            color: var(--text);
        }

        .game-configs-desc {
            font-size: 12px;
            color: var(--label-gray);
            margin-top: 4px;
        }

        .big-plus {
            font-size: 32px;
            font-weight: 500;
            color: #ffffff;
            cursor: pointer;
        }

        .big-plus:hover { opacity: 0.85; }

        .external-container {
            width: 100%;
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 20px;
        }

        .header-panel {
            width: 90%;
            max-width: 1100px;
            height: 110px;
            background: var(--header-bg);
            border: 1px solid var(--border);
            border-radius: 0;
            overflow: hidden;
            box-shadow: none;
            display: flex;
            flex-direction: column;
            justify-content: center;
            padding: 0 28px;
            margin: 160px auto 0;
        }

        .top-row {
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .title {
            font-size: 20px;
            font-weight: 600;
            color: #ffffff;
        }

        .version {
            font-size: 13px;
            color: #888890;
            margin-top: 6px;
        }

        .buttons { display: flex; gap: 12px; margin-right: -20px; }

        .btn {
            height: 42px;
            padding: 0 20px;
            font-size: 13px;
            font-weight: 600;
            border-radius: 6px;
            cursor: pointer;
            transition: border-color 0.2s ease;
            display: flex;
            align-items: center;
        }

        .btn-download {
            background: transparent;
            color: #ffffff;
            border: 1px solid var(--outline);
        }

        .btn-download:hover { border-color: #3a3a40; }

        .table-section {
            display: flex;
            flex-direction: column;
            align-items: center;
            width: 100%;
            margin-top: 60px;
        }

        .table-container {
            display: flex;
            flex-direction: row;
            align-items: center;
            justify-content: center;
            gap: 25px;
            width: 100%;
            position: relative;
        }

        .save-btn-container {
            width: 100%;
            display: flex;
            justify-content: flex-end;
            margin-bottom: 10px;
            padding-right: calc((100% - 780px - 280px - 25px) / 2);
        }

        .save-mask-btn {
            padding: 10px 24px;
            background: var(--save-active);
            color: #0a0a0c;
            border: none;
            border-radius: 6px;
            font-weight: 600;
            font-size: 14px;
            cursor: pointer;
            transition: all 0.2s ease;
            box-shadow: 0 2px 8px rgba(0,0,0,0.3);
        }

        .save-mask-btn.disabled {
            background: var(--save-inactive);
            color: #444;
            cursor: not-allowed;
            pointer-events: none;
            box-shadow: none;
        }

        .save-mask-btn:hover:not(.disabled) {
            transform: scale(1.05);
            box-shadow: 0 4px 12px rgba(0,0,0,0.4);
        }

        .floating-panel {
            width: 280px;
            height: 480px;
            background: #0d0d0f;
            border: 1px solid var(--border);
            border-radius: 10px;
            box-shadow: 0 8px 30px rgba(0,0,0,0.6);
            position: relative;
            overflow: hidden;
            flex-shrink: 0;
        }

        .header-area {
            position: absolute;
            top: 8px;
            left: 0;
            right: 0;
            height: 32px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0 16px;
            transition: color 0.15s ease;
            z-index: 5;
        }

        .configs-label {
            font-size: 11px;
            font-weight: 500;
            color: var(--label-gray);
            letter-spacing: 0.4px;
            user-select: none;
        }

        .plus-button {
            font-size: 24px;
            font-weight: 500;
            color: #ffffff;
            line-height: 1;
            width: 28px;
            height: 28px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 6px;
            transition: opacity 0.15s ease;
            cursor: pointer;
        }

        .plus-button:hover { opacity: 0.85; }

        .configs-divider {
            position: absolute;
            top: 48px;
            left: 0;
            right: 0;
            height: 1px;
            background: var(--divider-gray);
            opacity: 0.7;
        }

        .configs-list {
            position: absolute;
            top: 56px;
            left: 0;
            right: 0;
            bottom: 0;
            overflow-y: auto;
            padding: 8px 0;
        }

        .config-item {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 10px 16px;
            transition: background 0.15s ease;
            cursor: pointer;
            position: relative;
        }

        .config-item:hover { background: var(--semi-bg); }

        .config-name {
            font-size: 12px;
            color: var(--text);
        }

        .config-dots {
            display: none;
            flex-direction: column;
            align-items: center;
            gap: 2px;
            color: var(--dots-color);
            font-size: 9px;
            line-height: 0.7;
            cursor: pointer;
            padding: 4px 8px;
            border-radius: 4px;
            z-index: 10;
        }

        .config-item:hover .config-dots { display: flex; }

        .popup-menu {
            position: fixed;
            background: var(--popup-bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.5);
            opacity: 0;
            transform: scale(0.95);
            transition: opacity 0.2s ease, transform 0.2s ease;
            pointer-events: none;
            z-index: 1000;
            min-width: 120px;
        }

        .popup-menu.visible {
            opacity: 1;
            transform: scale(1);
            pointer-events: auto;
        }

        .popup-item {
            padding: 10px 16px;
            font-size: 12px;
            color: var(--text);
            cursor: pointer;
            transition: background 0.15s ease;
        }

        .popup-item:hover { background: var(--popup-hover); }

        .big-table-box {
            width: 780px;
            height: 480px;
            background: #0d0d0f;
            border: 1px solid var(--border);
            border-radius: 10px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.5);
            overflow: hidden;
            flex-shrink: 0;
        }

        #monacoContainer { width: 100%; height: 100%; }

        .modal-overlay {
            position: fixed;
            inset: 0;
            background: rgba(0,0,0,0.85);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 9999;
            opacity: 0;
            visibility: hidden;
            transition: opacity 0.25s ease;
        }

        .modal-overlay.show {
            opacity: 1;
            visibility: visible;
        }

        .modal-content {
            background: var(--modal-bg);
            border: 1px solid var(--modal-border);
            border-radius: 12px;
            width: 90%;
            max-width: 500px;
            max-height: 80vh;
            overflow-y: auto;
            padding: 24px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.7);
        }

        .modal-title {
            color: #ffffff;
            font-size: 18px;
            margin-bottom: 20px;
        }

        .config-slot {
            display: flex;
            align-items: center;
            gap: 16px;
            margin-bottom: 16px;
            padding: 12px 0;
            border-bottom: 1px solid rgba(30,30,34,0.3);
        }

        .config-dropdown, .config-gameid {
            flex: 1;
            padding: 10px;
            background: #0d0d0f;
            border: 1px solid var(--border);
            border-radius: 6px;
            color: var(--text);
            font-size: 14px;
        }

        .config-dropdown:focus, .config-gameid:focus {
            outline: none;
            border-color: #ABA3FF;
        }

        .new-slot-btn {
            width: 100%;
            padding: 12px;
            background: transparent;
            border: none;
            color: #ffffff;
            font-size: 24px;
            font-weight: bold;
            cursor: pointer;
            margin: 16px 0 24px;
            transition: opacity 0.2s ease;
            text-align: center;
        }

        .new-slot-btn:hover { opacity: 0.85; }

        .save-btn {
            width: 100%;
            padding: 14px;
            background: #ffffff;
            color: #0a0a0c;
            border: 1px solid #e0e0e8;
            border-radius: 8px;
            font-weight: 600;
            font-size: 15px;
            cursor: pointer;
            transition: transform 0.2s ease;
            text-align: center;
        }

        .save-btn:hover { transform: scale(1.05); }

        .modal-buttons {
            display: flex;
            gap: 10px;
            margin-top: 20px;
        }

        .modal-btn {
            flex: 1;
            padding: 12px;
            border: none;
            border-radius: 6px;
            font-weight: 600;
            font-size: 14px;
            cursor: pointer;
            transition: transform 0.2s ease;
        }

        .modal-btn-primary {
            background: #ffffff;
            color: #0a0a0c;
        }

        .modal-btn-secondary {
            background: transparent;
            color: #ffffff;
            border: 1px solid var(--border);
        }

        .modal-btn:hover {
            transform: scale(1.02);
        }

        .logout-btn {
            position: fixed;
            top: 18px;
            right: 20px;
            padding: 8px 16px;
            background: transparent;
            border: 1px solid var(--border);
            border-radius: 6px;
            color: #888890;
            font-size: 12px;
            cursor: pointer;
            transition: all 0.2s ease;
            z-index: 101;
        }

        .logout-btn:hover {
            color: #ffffff;
            border-color: #ffffff;
        }
    </style>
</head>
<body>
    <div class="grid-overlay"></div>

    <div class="top-pill">
        <div class="tab active" data-tab="home">Home</div>
        <div class="tab" data-tab="external">External</div>
        <div class="tab" data-tab="table">Table</div>
        <div class="tab" data-tab="settings">Settings</div>
    </div>

    <button class="logout-btn" onclick="logout()">Logout</button>

    <div id="home" class="content-wrapper active">
        <div class="home-container">
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-header">Total HWID Resets</div>
                    <div class="stat-value" id="hwidResets">0</div>
                </div>
                <div class="stat-card">
                    <div class="stat-header">Subscription</div>
                    <div class="stat-value lifetime-value" id="subscription">Lifetime</div>
                </div>
            </div>
            <div class="license-grid">
                <div class="license-card">
                    <div class="license-header">EXTERNAL LICENSE</div>
                    <div class="license-key" id="licenseKey">Loading...</div>
                </div>
                <div class="license-card">
                    <div class="license-header">HWID</div>
                    <div class="license-key" id="hwid">Loading...</div>
                </div>
            </div>
        </div>
    </div>

    <div id="external" class="content-wrapper">
        <div class="external-container">
            <div class="header-panel">
                <div class="top-row">
                    <div>
                        <div class="title">Lumina External</div>
                        <div class="version">Version 0.1.0</div>
                    </div>
                    <div class="buttons">
                        <button class="btn btn-download" onclick="window.open('https://example.com/download', '_blank')">DOWNLOAD</button>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div id="table" class="content-wrapper">
        <div class="table-section">
            <div class="save-btn-container">
                <button class="save-mask-btn" id="saveMaskBtn">Save</button>
            </div>
            <div class="table-container">
                <div class="floating-panel">
                    <div class="header-area">
                        <div class="configs-label">configs</div>
                        <div class="plus-button" id="createConfigBtn">+</div>
                    </div>
                    <div class="configs-divider"></div>
                    <div class="configs-list" id="configsList"></div>
                    <div class="popup-menu" id="configMenu">
                        <div class="popup-item" onclick="loadSelectedConfig()">Load</div>
                        <div class="popup-item" onclick="renameSelectedConfig()">Rename</div>
                        <div class="popup-item" onclick="deleteSelectedConfig()">Delete</div>
                    </div>
                </div>
                <div class="big-table-box">
                    <div id="monacoContainer"></div>
                </div>
            </div>
        </div>
    </div>

    <div id="settings" class="content-wrapper">
        <div class="settings-container">
            <div class="settings-section">
                <div class="section-header">Loadup Settings</div>

                <div class="setting-row">
                    <div class="setting-info">
                        <div class="setting-label"><span>Auto</span> <span>Validate</span></div>
                        <div class="setting-desc">Automatically validate your license based on HWID</div>
                    </div>
                    <label class="square-toggle">
                        <input type="checkbox" id="autoValidateToggle" checked>
                        <span class="square"></span>
                    </label>
                </div>

                <div class="game-configs-row">
                    <div class="setting-info">
                        <div class="setting-label"><span>Game</span> <span>Configs</span></div>
                        <div class="game-configs-desc">Add a game specific config </div>
                    </div>
                    <div class="big-plus" id="openGameConfigs">+</div>
                </div>
            </div>
        </div>
    </div>

    <div class="modal-overlay" id="gameConfigsModal">
        <div class="modal-content">
            <div class="modal-title">Game Configs</div>
            <div id="gameConfigSlots"></div>
            <button class="new-slot-btn" id="newGameConfigBtn">+</button>
            <button class="save-btn" onclick="saveGameConfigs()">Save</button>
        </div>
    </div>

    <div class="modal-overlay" id="createConfigModal">
        <div class="modal-content">
            <div class="modal-title">Create Config</div>
            <input type="text" class="config-gameid" id="newConfigName" placeholder="Config name" style="width: 100%;">
            <div class="modal-buttons">
                <button class="modal-btn modal-btn-primary" onclick="createNewConfig()">Create</button>
                <button class="modal-btn modal-btn-secondary" onclick="closeCreateModal()">Cancel</button>
            </div>
        </div>
    </div>

    <script>
        let currentConfig = {};
        let editor = null;
        let selectedConfig = null;
        let configMenu = document.getElementById('configMenu');
        let gameConfigs = [];

        
        require.config({ paths: { 'vs': 'https://cdnjs.cloudflare.com/ajax/libs/monaco-editor/0.34.1/min/vs' }});
        require(['vs/editor/editor.main'], function () {
            monaco.editor.defineTheme('customDark', {
                base: 'vs-dark',
                inherit: true,
                rules: [
                    { token: 'string', foreground: 'CE9178' },
                    { token: 'number', foreground: 'B5CEA8' },
                    { token: 'keyword', foreground: '569CD6' },
                ],
                colors: {
                    'editor.background': '#0d0d0f',
                    'editor.foreground': '#d4d4d8',
                    'editorLineNumber.foreground': '#444',
                }
            });

            editor = monaco.editor.create(document.getElementById('monacoContainer'), {
                value: JSON.stringify(currentConfig, null, 2),
                language: 'json',
                theme: 'customDark',
                automaticLayout: true,
                fontSize: 14,
                minimap: { enabled: false }
            });

            editor.onDidChangeModelContent(() => {
                document.getElementById('saveMaskBtn').classList.remove('disabled');
            });
        });

        document.querySelectorAll('.tab').forEach(tab => {
            tab.addEventListener('click', () => {
                document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
                document.querySelectorAll('.content-wrapper').forEach(w => w.classList.remove('active'));
                tab.classList.add('active');
                document.getElementById(tab.dataset.tab).classList.add('active');
            });
        });

       
        async function checkAuth() {
            try {
                const res = await fetch('/api/me');
                const data = await res.json();
                
                if (!data.authenticated) {
                    window.location.href = '/menu';
                    return false;
                }
                
                return data;
            } catch (e) {
                window.location.href = '/menu';
                return false;
            }
        }

        
        async function logout() {
            await fetch('/api/logout', { method: 'POST' });
            window.location.href = '/menu';
        }

        
        
        async function loadDashboard() {
            const auth = await checkAuth();
            if (!auth) return;
            
            try {
                const res = await fetch('/api/dashboard');
                const data = await res.json();
                
                document.getElementById('hwidResets').textContent = data.hwid_resets || 0;
                document.getElementById('subscription').textContent = data.subscription || 'Lifetime';
                document.getElementById('licenseKey').textContent = data.license_key;
                document.getElementById('hwid').textContent = data.hwid || 'Not bound';
                
                
                
                const configRes = await fetch('/api/config');
                currentConfig = await configRes.json();
                if (editor) {
                    editor.setValue(JSON.stringify(currentConfig, null, 2));
                }
                
                
                
                loadConfigsList();
                
               
                
                loadGameConfigs();
                
                
                
                const loadupRes = await fetch('/api/loadup-settings');
                const loadupData = await loadupRes.json();
                
                document.getElementById('autoValidateToggle').checked = loadupData.auto_validate;
                
            } catch (e) {
                console.error('Failed to load dashboard:', e);
            }
        }

        
        async function loadConfigsList() {
            try {
                const res = await fetch('/api/configs/list');
                const data = await res.json();
                
                const list = document.getElementById('configsList');
                list.innerHTML = '';
                
                data.configs.forEach((config, index) => {
                    const div = document.createElement('div');
                    div.className = 'config-item';
                    div.id = `config-item-${index}`;
                    div.innerHTML = `
                        <div class="config-name">${config.name}</div>
                        <div class="config-dots">•••</div>
                    `;
                    
                    div.addEventListener('click', (e) => {
                        if (!e.target.classList.contains('config-dots')) {
                            loadConfigByName(config.name);
                        }
                    });
                    
                    const dots = div.querySelector('.config-dots');
                    dots.addEventListener('click', (e) => {
                        e.stopPropagation();
                        showConfigMenu(e, config.name);
                    });
                    
                    list.appendChild(div);
                });
            } catch (e) {
                console.error('Failed to load configs list:', e);
            }
        }

        
        function showConfigMenu(event, configName) {
            
            configMenu.classList.remove('visible');
            
            
            const rect = event.target.getBoundingClientRect();
            configMenu.style.top = (rect.bottom + window.scrollY + 5) + 'px';
            configMenu.style.left = (rect.left + window.scrollX - 100) + 'px';
            
            
            configMenu.classList.add('visible');
            selectedConfig = configName;
            
            
            setTimeout(() => {
                document.addEventListener('click', function closeMenu(e) {
                    if (!configMenu.contains(e.target) && !e.target.classList.contains('config-dots')) {
                        configMenu.classList.remove('visible');
                        document.removeEventListener('click', closeMenu);
                    }
                });
            }, 10);
        }

        
        async function loadConfigByName(name) {
            try {
                const res = await fetch(`/api/configs/load/${name}`);
                const config = await res.json();
                currentConfig = config;
                editor.setValue(JSON.stringify(config, null, 2));
                document.getElementById('saveMaskBtn').classList.remove('disabled');
                configMenu.classList.remove('visible');
            } catch (e) {
                console.error('Failed to load config:', e);
            }
        }

        function loadSelectedConfig() {
            if (selectedConfig) {
                loadConfigByName(selectedConfig);
            }
        }

        async function renameSelectedConfig() {
            if (!selectedConfig) return;
            
            const newName = prompt('Enter new name:', selectedConfig);
            if (newName && newName !== selectedConfig) {
                try {
                    await fetch('/api/configs/rename', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ old_name: selectedConfig, new_name: newName })
                    });
                    await loadConfigsList();
                    configMenu.classList.remove('visible');
                } catch (e) {
                    console.error('Failed to rename config:', e);
                }
            }
        }

        async function deleteSelectedConfig() {
            if (!selectedConfig) return;
            
            if (confirm(`Delete config "${selectedConfig}"?`)) {
                try {
                    await fetch(`/api/configs/delete/${selectedConfig}`, {
                        method: 'DELETE'
                    });
                    await loadConfigsList();
                    configMenu.classList.remove('visible');
                } catch (e) {
                    console.error('Failed to delete config:', e);
                }
            }
        }

        
        document.getElementById('saveMaskBtn').addEventListener('click', async () => {
            if (document.getElementById('saveMaskBtn').classList.contains('disabled')) return;
            
            try {
                const newConfig = JSON.parse(editor.getValue());
                await fetch('/api/config', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(newConfig)
                });
                
                document.getElementById('saveMaskBtn').classList.add('disabled');
                currentConfig = newConfig;
            } catch (e) {
                alert('Invalid JSON');
            }
        });

        
        document.getElementById('createConfigBtn').addEventListener('click', () => {
            document.getElementById('createConfigModal').classList.add('show');
        });

        window.closeCreateModal = function() {
            document.getElementById('createConfigModal').classList.remove('show');
            document.getElementById('newConfigName').value = '';
        };

        window.createNewConfig = async function() {
            const name = document.getElementById('newConfigName').value.trim();
            if (!name) return;
            
            try {
                await fetch('/api/configs/save', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        config_name: name,
                        config_data: currentConfig
                    })
                });
                
                closeCreateModal();
                await loadConfigsList();
            } catch (e) {
                console.error('Failed to create config:', e);
            }
        };

        
        document.getElementById('openGameConfigs').addEventListener('click', () => {
            document.getElementById('gameConfigsModal').classList.add('show');
        });

        document.getElementById('gameConfigsModal').addEventListener('click', (e) => {
            if (e.target === document.getElementById('gameConfigsModal')) {
                document.getElementById('gameConfigsModal').classList.remove('show');
            }
        });

        async function loadGameConfigs() {
            try {
                const res = await fetch('/api/game-configs');
                const data = await res.json();
                gameConfigs = data.configs || [];
                renderGameConfigs();
            } catch (e) {
                console.error('Failed to load game configs:', e);
            }
        }

        async function renderGameConfigs() {
            const configsRes = await fetch('/api/configs/list');
            const configsData = await configsRes.json();
            const availableConfigs = configsData.configs || [];
            
            const slots = document.getElementById('gameConfigSlots');
            slots.innerHTML = '';
            
            gameConfigs.forEach((config, index) => {
                const slot = document.createElement('div');
                slot.className = 'config-slot';
                
                const select = document.createElement('select');
                select.className = 'config-dropdown';
                select.id = `gameConfigSelect_${index}`;
                
                availableConfigs.forEach(c => {
                    const option = document.createElement('option');
                    option.value = c.name;
                    option.textContent = c.name;
                    if (c.name === config.config_name) option.selected = true;
                    select.appendChild(option);
                });
                
                const input = document.createElement('input');
                input.type = 'text';
                input.className = 'config-gameid';
                input.value = config.game_id;
                input.placeholder = 'Game ID';
                input.id = `gameConfigId_${index}`;
                
                slot.appendChild(select);
                slot.appendChild(input);
                slots.appendChild(slot);
            });
        }

        document.getElementById('newGameConfigBtn').addEventListener('click', async () => {
            const slots = document.getElementById('gameConfigSlots');
            const index = gameConfigs.length;
            
            const configsRes = await fetch('/api/configs/list');
            const configsData = await configsRes.json();
            
            const slot = document.createElement('div');
            slot.className = 'config-slot';
            
            const select = document.createElement('select');
            select.className = 'config-dropdown';
            select.id = `gameConfigSelect_${index}`;
            
            configsData.configs.forEach(c => {
                const option = document.createElement('option');
                option.value = c.name;
                option.textContent = c.name;
                select.appendChild(option);
            });
            
            const input = document.createElement('input');
            input.type = 'text';
            input.className = 'config-gameid';
            input.id = `gameConfigId_${index}`;
            input.placeholder = 'Game ID';
            
            slot.appendChild(select);
            slot.appendChild(input);
            slots.appendChild(slot);
            
            gameConfigs.push({ game_id: '', config_name: configsData.configs[0]?.name || '' });
        });

        window.saveGameConfigs = async function() {
            const newConfigs = [];
            for (let i = 0; i <= gameConfigs.length; i++) {
                const select = document.getElementById(`gameConfigSelect_${i}`);
                const input = document.getElementById(`gameConfigId_${i}`);
                
                if (select && input && input.value.trim()) {
                    newConfigs.push({
                        game_id: input.value.trim(),
                        config_name: select.value
                    });
                }
            }
            
            try {
                
                for (const config of gameConfigs) {
                    if (config.game_id) {
                        await fetch(`/api/game-configs/${config.game_id}`, {
                            method: 'DELETE'
                        });
                    }
                }
                
                
                for (const config of newConfigs) {
                    await fetch('/api/game-configs', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(config)
                    });
                }
                
                gameConfigs = newConfigs;
                document.getElementById('gameConfigsModal').classList.remove('show');
            } catch (e) {
                console.error('Failed to save game configs:', e);
            }
        };

        
        async function saveLoadupSettings() {
            const settings = {
                auto_validate: document.getElementById('autoValidateToggle').checked,
                silent_mode: false
            };
            
            try {
                await fetch('/api/loadup-settings', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(settings)
                });
            } catch (e) {
                console.error('Failed to save loadup settings:', e);
            }
        }

        document.getElementById('autoValidateToggle').addEventListener('change', saveLoadupSettings);

        
        loadDashboard();
    </script>
    """ + ENHANCED_ANTI_DEVTOOLS_JS + """
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
def serve_home():
    return HTMLResponse(content=LOGIN_HTML)

@app.get("/menu", response_class=HTMLResponse)
def serve_menu():
    return HTMLResponse(content=LOGIN_HTML)

@app.get("/dashboard", response_class=HTMLResponse)
async def serve_dashboard(request: Request):
    license_key = request.cookies.get("license_key")
    session_id = request.cookies.get("session_id")
    
    if not license_key or not session_id:
        return RedirectResponse(url="/menu")
    
    db = get_db()
    cur = db.cursor()
    
    try:
        cur.execute(q("SELECT username FROM login_sessions WHERE session_id=%s AND license_key=%s AND expires_at > %s"),
                   (session_id, license_key, datetime.now().isoformat()))
        result = cur.fetchone()
        db.close()
        
        if not result:
            return RedirectResponse(url="/menu")
        
        return HTMLResponse(content=DASHBOARD_HTML)
    except:
        db.close()
        return RedirectResponse(url="/menu")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
