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
import bcrypt
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
        # Users table with username/password
        cur.execute("""CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            license_key TEXT NOT NULL,
            discord_id TEXT,
            created_at TEXT NOT NULL,
            hwid TEXT,
            hwid_reset_count INTEGER DEFAULT 0
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
            username TEXT NOT NULL,
            config_name TEXT NOT NULL,
            config_data TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(username, config_name)
        )""")
        
        cur.execute("""CREATE TABLE IF NOT EXISTS public_configs (
            id SERIAL PRIMARY KEY,
            config_name TEXT NOT NULL,
            author_name TEXT NOT NULL,
            game_name TEXT NOT NULL,
            description TEXT,
            config_data TEXT NOT NULL,
            username TEXT NOT NULL,
            created_at TEXT NOT NULL,
            downloads INTEGER DEFAULT 0
        )""")
        
        cur.execute("""CREATE TABLE IF NOT EXISTS user_sessions (
            session_id TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        )""")
        
    else:
        # SQLite
        cur.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            license_key TEXT NOT NULL,
            discord_id TEXT,
            created_at TEXT NOT NULL,
            hwid TEXT,
            hwid_reset_count INTEGER DEFAULT 0
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
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            config_name TEXT NOT NULL,
            config_data TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(username, config_name)
        )""")
        
        cur.execute("""CREATE TABLE IF NOT EXISTS public_configs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            config_name TEXT NOT NULL,
            author_name TEXT NOT NULL,
            game_name TEXT NOT NULL,
            description TEXT,
            config_data TEXT NOT NULL,
            username TEXT NOT NULL,
            created_at TEXT NOT NULL,
            downloads INTEGER DEFAULT 0
        )""")
        
        cur.execute("""CREATE TABLE IF NOT EXISTS user_sessions (
            session_id TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        )""")
    
    db.commit()
    db.close()
    print("✅ Database initialized")

# Pydantic models
class UserRegister(BaseModel):
    username: str
    password: str
    license_key: str
    discord_id: Optional[str] = None

class UserLogin(BaseModel):
    username: str
    password: str

class KeyValidate(BaseModel):
    username: str
    password: str
    hwid: str

class ConfigData(BaseModel):
    config_name: str
    config_data: dict

class PublicConfig(BaseModel):
    config_name: str
    author_name: str
    game_name: str
    description: str
    config_data: dict

class KeyCreate(BaseModel):
    duration: str
    created_by: str

# Password hashing
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password: str, hash: str) -> bool:
    return bcrypt.checkpw(password.encode(), hash.encode())

# === AUTH ENDPOINTS ===

@app.post("/api/auth/register")
def register_user(data: UserRegister):
    """Register new user (called by Discord bot)"""
    db = get_db()
    cur = db.cursor()
    
    # Check if license exists and not redeemed
    cur.execute(q("SELECT * FROM keys WHERE key=?"), (data.license_key,))
    key_result = cur.fetchone()
    
    if not key_result:
        db.close()
        raise HTTPException(status_code=404, detail="Invalid license key")
    
    _, duration, created_at, expires_at, redeemed_at, redeemed_by, hwid, active, created_by = key_result
    
    if redeemed_by:
        db.close()
        raise HTTPException(status_code=400, detail="License already redeemed")
    
    # Check if username exists
    cur.execute(q("SELECT * FROM users WHERE username=?"), (data.username,))
    if cur.fetchone():
        db.close()
        raise HTTPException(status_code=400, detail="Username already exists")
    
    # Hash password
    password_hash = hash_password(data.password)
    
    # Create user
    cur.execute(q("INSERT INTO users (username, password_hash, license_key, discord_id, created_at, hwid_reset_count) VALUES (?, ?, ?, ?, ?, 0)"),
               (data.username, password_hash, data.license_key, data.discord_id, datetime.now().isoformat()))
    
    # Mark key as redeemed
    cur.execute(q("UPDATE keys SET redeemed_by=?, redeemed_at=?, active=1 WHERE key=?"),
               (data.username, datetime.now().isoformat(), data.license_key))
    
    db.commit()
    db.close()
    
    return {"success": True, "username": data.username}

@app.post("/api/auth/login")
def login_user(data: UserLogin):
    """Login with username/password"""
    db = get_db()
    cur = db.cursor()
    
    cur.execute(q("SELECT password_hash FROM users WHERE username=?"), (data.username,))
    result = cur.fetchone()
    
    if not result:
        db.close()
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    password_hash = result[0]
    
    if not verify_password(data.password, password_hash):
        db.close()
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Create session
    session_id = secrets.token_urlsafe(32)
    expires_at = (datetime.now() + timedelta(days=30)).isoformat()
    
    cur.execute(q("INSERT INTO user_sessions (session_id, username, created_at, expires_at) VALUES (?, ?, ?, ?)"),
               (session_id, data.username, datetime.now().isoformat(), expires_at))
    db.commit()
    db.close()
    
    response = JSONResponse({"success": True, "username": data.username})
    response.set_cookie(
        key="session_id",
        value=session_id,
        max_age=30 * 24 * 60 * 60,
        httponly=False,
        samesite="none",
        secure=True,
        path="/"
    )
    
    return response

@app.post("/api/validate")
def validate_user(data: KeyValidate):
    """Validate user for test.py login"""
    db = get_db()
    cur = db.cursor()
    
    cur.execute(q("SELECT password_hash, hwid, license_key FROM users WHERE username=?"), (data.username,))
    result = cur.fetchone()
    
    if not result:
        db.close()
        return {"valid": False, "error": "Invalid username"}, 401
    
    password_hash, hwid, license_key = result
    
    if not verify_password(data.password, password_hash):
        db.close()
        return {"valid": False, "error": "Invalid password"}, 401
    
    # Check license status
    cur.execute(q("SELECT active, expires_at FROM keys WHERE key=?"), (license_key,))
    key_result = cur.fetchone()
    
    if not key_result or key_result[0] == 0:
        db.close()
        return {"valid": False, "error": "License inactive"}, 401
    
    expires_at = key_result[1]
    if expires_at and datetime.now() > datetime.fromisoformat(expires_at):
        db.close()
        return {"valid": False, "error": "License expired"}, 401
    
    # HWID check
    if hwid is None:
        cur.execute(q("UPDATE users SET hwid=? WHERE username=?"), (data.hwid, data.username))
        db.commit()
        db.close()
        return {"valid": True, "message": "HWID bound successfully"}
    elif hwid == data.hwid:
        db.close()
        return {"valid": True, "message": "Authentication successful"}
    else:
        db.close()
        return {"valid": False, "error": "HWID mismatch"}, 401

@app.get("/api/dashboard/{username}")
def get_dashboard_data(username: str):
    """Get dashboard data for user"""
    db = get_db()
    cur = db.cursor()
    
    cur.execute(q("SELECT license_key, hwid, hwid_reset_count, created_at, discord_id FROM users WHERE username=?"), (username,))
    user_result = cur.fetchone()
    
    if not user_result:
        db.close()
        raise HTTPException(status_code=404, detail="User not found")
    
    license_key, hwid, hwid_reset_count, created_at, discord_id = user_result
    
    # Get license info
    cur.execute(q("SELECT duration, expires_at, active FROM keys WHERE key=?"), (license_key,))
    key_result = cur.fetchone()
    
    db.close()
    
    if not key_result:
        subscription_status = "Inactive"
        subscription_type = "None"
        expires_at = None
    else:
        duration, expires_at, active = key_result
        subscription_status = "Active" if active == 1 else "Inactive"
        subscription_type = duration.capitalize() if duration else "Lifetime"
    
    return {
        "username": username,
        "license_key": license_key[:8] + "..." if license_key else "N/A",
        "license_key_full": license_key,
        "hwid": hwid if hwid else "Not bound",
        "hwid_reset_count": hwid_reset_count,
        "subscription_status": subscription_status,
        "subscription_type": subscription_type,
        "expires_at": expires_at,
        "created_at": created_at,
        "discord_id": discord_id
    }

@app.post("/api/hwid/reset")
def reset_hwid(data: dict):
    """Reset HWID for user"""
    username = data.get("username")
    
    db = get_db()
    cur = db.cursor()
    
    cur.execute(q("SELECT hwid_reset_count FROM users WHERE username=?"), (username,))
    result = cur.fetchone()
    
    if not result:
        db.close()
        raise HTTPException(status_code=404, detail="User not found")
    
    reset_count = result[0]
    
    # Reset HWID and increment counter
    cur.execute(q("UPDATE users SET hwid=NULL, hwid_reset_count=? WHERE username=?"),
               (reset_count + 1, username))
    db.commit()
    db.close()
    
    return {
        "success": True,
        "reset_count": reset_count + 1,
        "message": "HWID reset successfully"
    }

# === CONFIG ENDPOINTS ===

@app.get("/api/configs/{username}/list")
def list_configs(username: str):
    """Get user's saved configs"""
    db = get_db()
    cur = db.cursor()
    cur.execute(q("SELECT config_name, config_data FROM saved_configs WHERE username=? ORDER BY created_at DESC"), (username,))
    results = cur.fetchall()
    db.close()
    
    return {
        "configs": [
            {"name": r[0], "data": json.loads(r[1])}
            for r in results
        ]
    }

@app.post("/api/configs/{username}/save")
def save_config(username: str, data: ConfigData):
    """Save config for user"""
    db = get_db()
    cur = db.cursor()
    
    try:
        cur.execute(q("INSERT INTO saved_configs (username, config_name, config_data, created_at) VALUES (?, ?, ?, ?) ON CONFLICT(username, config_name) DO UPDATE SET config_data=?, created_at=?"),
                   (username, data.config_name, json.dumps(data.config_data), datetime.now().isoformat(), json.dumps(data.config_data), datetime.now().isoformat()))
        db.commit()
        db.close()
        return {"success": True}
    except Exception as e:
        db.close()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/public-configs")
def get_public_configs():
    """Get all public configs"""
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute(q("SELECT id, config_name, author_name, game_name, description, config_data, username, created_at, downloads FROM public_configs ORDER BY created_at DESC"))
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
                    "created_by": r[6][:8] + "...",
                    "created_at": r[7],
                    "downloads": r[8]
                } for r in results
            ]
        }
    except:
        return {"configs": []}

@app.post("/api/public-configs/create")
def create_public_config(data: PublicConfig, session_id: Optional[str] = Cookie(None)):
    """Create public config"""
    username = "website-user"
    
    if session_id:
        db = get_db()
        cur = db.cursor()
        try:
            cur.execute(q("SELECT username FROM user_sessions WHERE session_id=?"), (session_id,))
            result = cur.fetchone()
            if result:
                username = result[0]
            db.close()
        except:
            pass
    
    db = get_db()
    cur = db.cursor()
    
    try:
        cur.execute(q("INSERT INTO public_configs (config_name, author_name, game_name, description, config_data, username, created_at, downloads) VALUES (?, ?, ?, ?, ?, ?, ?, 0)"),
                   (data.config_name, data.author_name, data.game_name, data.description, json.dumps(data.config_data), username, datetime.now().isoformat()))
        db.commit()
        db.close()
        return {"success": True}
    except Exception as e:
        db.close()
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/public-configs/{config_id}/download")
def download_config(config_id: int):
    """Increment download count"""
    db = get_db()
    cur = db.cursor()
    cur.execute(q("UPDATE public_configs SET downloads = downloads + 1 WHERE id=?"), (config_id,))
    db.commit()
    db.close()
    return {"success": True}

# === KEY MANAGEMENT ===

@app.post("/api/keys/create")
def create_key(data: KeyCreate):
    """Create new license key"""
    key = f"{secrets.token_hex(2).upper()}-{secrets.token_hex(2).upper()}-{secrets.token_hex(2).upper()}-{secrets.token_hex(2).upper()}"
    
    expires_at = None
    if data.duration != "lifetime":
        days = int(data.duration.replace("days", ""))
        expires_at = (datetime.now() + timedelta(days=days)).isoformat()
    
    db = get_db()
    cur = db.cursor()
    cur.execute(q("INSERT INTO keys (key, duration, created_at, expires_at, active, created_by) VALUES (?, ?, ?, ?, 0, ?)"),
               (key, data.duration, datetime.now().isoformat(), expires_at, data.created_by))
    db.commit()
    db.close()
    
    return {"key": key, "duration": data.duration, "expires_at": expires_at}

@app.get("/users/{discord_id}/info")
def get_user_info(discord_id: str):
    """Get user info by Discord ID"""
    db = get_db()
    cur = db.cursor()
    
    cur.execute(q("SELECT username, license_key, hwid FROM users WHERE discord_id=?"), (discord_id,))
    result = cur.fetchone()
    db.close()
    
    if not result:
        raise HTTPException(status_code=404, detail="No user found")
    
    return {
        "username": result[0],
        "license_key": result[1],
        "hwid": result[2]
    }

@app.post("/users/{discord_id}/reset-hwid")
def admin_reset_hwid(discord_id: str):
    """Admin reset HWID"""
    db = get_db()
    cur = db.cursor()
    
    cur.execute(q("SELECT hwid, hwid_reset_count, username FROM users WHERE discord_id=?"), (discord_id,))
    result = cur.fetchone()
    
    if not result:
        db.close()
        raise HTTPException(status_code=404, detail="No user found")
    
    old_hwid, reset_count, username = result
    
    cur.execute(q("UPDATE users SET hwid=NULL, hwid_reset_count=? WHERE discord_id=?"),
               (reset_count + 1, discord_id))
    db.commit()
    db.close()
    
    return {"success": True, "old_hwid": old_hwid, "reset_count": reset_count + 1}

# Initialize DB
init_db()

# === HTML PAGES ===

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - Axion</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
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
            text-align: center;
        }
        .logo {
            font-size: 24px;
            font-weight: bold;
            color: white;
            margin-bottom: 40px;
        }
        nav ul { list-style: none; }
        nav li { margin: 12px 0; }
        nav a {
            display: block;
            color: #888;
            text-decoration: none;
            padding: 10px 14px;
            border-radius: 6px;
            transition: color 0.2s;
            cursor: pointer;
        }
        nav a:hover { color: white; }
        nav a.active { color: white; }
        .main-content {
            margin-left: 180px;
            flex: 1;
            padding: 32px 24px 40px 200px;
        }
        .container { max-width: 1300px; margin: 0 auto; }
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
        .tab-content { display: none; }
        .tab-content.active { display: block; }
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
        .card {
            background: rgb(18,18,18);
            border: 1px solid rgb(35,35,35);
            border-radius: 12px;
            padding: 28px;
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
        .info-item { margin-bottom: 24px; }
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
        }
        .info-value:hover { filter: blur(0); }
        
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
        .modal.active { display: flex; }
        .modal-content {
            background: #1a1a1f;
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 12px;
            padding: 32px;
            width: 90%;
            max-width: 450px;
            text-align: center;
        }
        .modal-title {
            font-size: 22px;
            font-weight: 600;
            color: white;
            margin-bottom: 12px;
        }
        .modal-text {
            font-size: 15px;
            color: #aaa;
            margin-bottom: 28px;
            line-height: 1.5;
        }
        .modal-actions {
            display: flex;
            gap: 12px;
        }
        .modal-btn {
            flex: 1;
            padding: 12px;
            border-radius: 8px;
            font-size: 15px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
        }
        .modal-btn-cancel {
            background: transparent;
            border: 1px solid rgb(45,45,45);
            color: #ccc;
        }
        .modal-btn-cancel:hover {
            background: rgb(25,25,25);
        }
        .modal-btn-confirm {
            background: #d32f2f;
            border: 1px solid #d32f2f;
            color: white;
        }
        .modal-btn-confirm:hover {
            background: #b71c1c;
        }
    </style>
</head>
<body>
    <aside class="sidebar">
        <div class="logo">Axion</div>
        <nav>
            <ul>
                <li><a href="#subscriptions" class="active">Subscriptions</a></li>
                <li><a href="#security">Security</a></li>
            </ul>
        </nav>
    </aside>

    <main class="main-content">
        <div class="container">
            <h1 id="page-title">Subscriptions</h1>
            <div class="subtitle">Manage and view your active subscriptions</div>
            <div class="divider"></div>

            <!-- Subscriptions Tab -->
            <div id="subscriptions" class="tab-content active">
                <div class="stats">
                    <div class="stat-card">
                        <div class="stat-label">Active</div>
                        <div class="stat-value" id="stat-active">1</div>
                        <div class="stat-sub">subscriptions</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Total HWID Resets</div>
                        <div class="stat-value" id="stat-resets">0</div>
                        <div class="stat-sub">All time</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Subscription</div>
                        <div class="stat-value" id="stat-status">Active</div>
                        <div class="stat-sub" id="stat-type">Lifetime</div>
                    </div>
                </div>
            </div>

            <!-- Security Tab -->
            <div id="security" class="tab-content">
                <div class="card">
                    <div class="card-title">Account Information</div>
                    <div class="card-subtitle">View and manage your account details</div>

                    <div class="info-item">
                        <div class="info-label">Username</div>
                        <div class="info-value" id="display-username">Loading...</div>
                    </div>

                    <div class="info-item">
                        <div class="info-label">License Key</div>
                        <div class="info-value" id="display-license">Loading...</div>
                    </div>

                    <div class="info-item">
                        <div class="info-label">HWID (Click to reset)</div>
                        <div class="info-value" id="display-hwid" style="cursor:pointer;" onclick="openResetModal()">Loading...</div>
                    </div>
                </div>
            </div>
        </div>
    </main>

    <!-- Reset HWID Modal -->
    <div class="modal" id="resetModal">
        <div class="modal-content">
            <div class="modal-title">⚠️ Reset HWID</div>
            <div class="modal-text">
                Are you sure you want to reset your HWID? This will unbind your account from the current device.
            </div>
            <div class="modal-actions">
                <button class="modal-btn modal-btn-cancel" onclick="closeResetModal()">Cancel</button>
                <button class="modal-btn modal-btn-confirm" onclick="confirmReset()">Reset HWID</button>
            </div>
        </div>
    </div>

    <script>
        let currentUsername = null;

        // Tab switching
        document.querySelectorAll('nav a').forEach(link => {
            link.addEventListener('click', function(e) {
                e.preventDefault();
                const targetId = this.getAttribute('href').substring(1);
                
                document.querySelectorAll('.tab-content').forEach(tab => {
                    tab.classList.remove('active');
                });
                
                document.getElementById(targetId).classList.add('active');
                
                document.querySelectorAll('nav a').forEach(a => a.classList.remove('active'));
                this.classList.add('active');
                
                document.getElementById('page-title').textContent = this.textContent;
                
                const subtitleEl = document.querySelector('.subtitle');
                if (targetId === 'subscriptions') {
                    subtitleEl.textContent = 'Manage and view your active subscriptions';
                } else if (targetId === 'security') {
                    subtitleEl.textContent = 'Manage account security and HWID';
                }
            });
        });

        // Load dashboard data
        async function loadDashboard() {
            // Get username from URL
            const urlParams = new URLSearchParams(window.location.search);
            currentUsername = urlParams.get('user');
            
            if (!currentUsername) {
                alert('No user specified');
                return;
            }

            try {
                const res = await fetch(`/api/dashboard/${currentUsername}`);
                const data = await res.json();

                // Update stats
                document.getElementById('stat-active').textContent = data.subscription_status === 'Active' ? '1' : '0';
                document.getElementById('stat-resets').textContent = data.hwid_reset_count;
                document.getElementById('stat-status').textContent = data.subscription_status;
                document.getElementById('stat-type').textContent = data.subscription_type;

                // Update security info
                document.getElementById('display-username').textContent = data.username;
                document.getElementById('display-license').textContent = data.license_key_full;
                document.getElementById('display-hwid').textContent = data.hwid || 'Not bound';
            } catch (e) {
                console.error('Error loading dashboard:', e);
                alert('Error loading dashboard');
            }
        }

        function openResetModal() {
            document.getElementById('resetModal').classList.add('active');
        }

        function closeResetModal() {
            document.getElementById('resetModal').classList.remove('active');
        }

        async function confirmReset() {
            try {
                const res = await fetch('/api/hwid/reset', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username: currentUsername })
                });

                const data = await res.json();

                if (res.ok) {
                    alert('HWID reset successfully!');
                    closeResetModal();
                    loadDashboard(); // Reload data
                } else {
                    alert('Error resetting HWID');
                }
            } catch (e) {
                alert('Error resetting HWID');
            }
        }

        // Load on page load
        loadDashboard();
    </script>
</body>
</html>
"""

@app.get("/dashboard", response_class=HTMLResponse)
def serve_dashboard():
    """Serve dashboard page"""
    return DASHBOARD_HTML

# Home page HTML continues in next message due to length...

# === DASHBOARD HTML ===

@app.get("/dashboard", response_class=HTMLResponse)
def serve_dashboard():
    """Serve dashboard page"""
    return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - Axion</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
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
            text-align: center;
        }
        .logo {
            font-size: 24px;
            font-weight: bold;
            color: white;
            margin-bottom: 40px;
        }
        nav ul { list-style: none; }
        nav li { margin: 12px 0; }
        nav a {
            display: block;
            color: #888;
            text-decoration: none;
            padding: 10px 14px;
            border-radius: 6px;
            transition: color 0.2s;
            cursor: pointer;
        }
        nav a:hover { color: white; }
        nav a.active { color: white; }
        .main-content {
            margin-left: 180px;
            flex: 1;
            padding: 32px 24px 40px 200px;
        }
        .container { max-width: 1300px; margin: 0 auto; }
        h1 { font-size: 28px; font-weight: 600; color: white; margin-bottom: 8px; }
        .subtitle { font-size: 15px; color: #888; margin-bottom: 28px; }
        .divider { height: 1px; background: rgb(35,35,35); margin: 0 0 36px 0; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
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
        .stat-label { font-size: 14px; color: #777; margin-bottom: 12px; }
        .stat-value { font-size: 32px; font-weight: bold; color: white; }
        .stat-sub { font-size: 13px; color: #666; margin-top: 6px; }
        .card {
            background: rgb(18,18,18);
            border: 1px solid rgb(35,35,35);
            border-radius: 12px;
            padding: 28px;
        }
        .card-title { font-size: 20px; font-weight: 600; color: white; margin-bottom: 8px; }
        .card-subtitle { font-size: 14px; color: #888; margin-bottom: 28px; }
        .info-item { margin-bottom: 24px; }
        .info-label { font-size: 14px; color: #aaa; margin-bottom: 8px; display: block; }
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
        }
        .info-value:hover { filter: blur(0); }
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
        .modal.active { display: flex; }
        .modal-content {
            background: #1a1a1f;
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 12px;
            padding: 32px;
            width: 90%;
            max-width: 450px;
            text-align: center;
        }
        .modal-title { font-size: 22px; font-weight: 600; color: white; margin-bottom: 12px; }
        .modal-text { font-size: 15px; color: #aaa; margin-bottom: 28px; line-height: 1.5; }
        .modal-actions { display: flex; gap: 12px; }
        .modal-btn {
            flex: 1;
            padding: 12px;
            border-radius: 8px;
            font-size: 15px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            border: none;
        }
        .modal-btn-cancel {
            background: transparent;
            border: 1px solid rgb(45,45,45);
            color: #ccc;
        }
        .modal-btn-cancel:hover { background: rgb(25,25,25); }
        .modal-btn-confirm {
            background: #d32f2f;
            border: 1px solid #d32f2f;
            color: white;
        }
        .modal-btn-confirm:hover { background: #b71c1c; }
        @media (max-width: 900px) {
            .sidebar {
                width: 100%;
                height: auto;
                position: relative;
                border-right: none;
                border-bottom: 1px solid rgb(35,35,35);
            }
            .main-content { margin-left: 0; padding: 24px 16px; }
            .stats { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <aside class="sidebar">
        <div class="logo">Axion</div>
        <nav>
            <ul>
                <li><a href="#subscriptions" class="active">Subscriptions</a></li>
                <li><a href="#security">Security</a></li>
            </ul>
        </nav>
    </aside>
    <main class="main-content">
        <div class="container">
            <h1 id="page-title">Subscriptions</h1>
            <div class="subtitle">Manage and view your active subscriptions</div>
            <div class="divider"></div>
            <div id="subscriptions" class="tab-content active">
                <div class="stats">
                    <div class="stat-card">
                        <div class="stat-label">Active</div>
                        <div class="stat-value" id="stat-active">1</div>
                        <div class="stat-sub">subscriptions</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Total HWID Resets</div>
                        <div class="stat-value" id="stat-resets">0</div>
                        <div class="stat-sub">All time</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Subscription</div>
                        <div class="stat-value" id="stat-status">Active</div>
                        <div class="stat-sub" id="stat-type">Lifetime</div>
                    </div>
                </div>
            </div>
            <div id="security" class="tab-content">
                <div class="card">
                    <div class="card-title">Account Information</div>
                    <div class="card-subtitle">View and manage your account details</div>
                    <div class="info-item">
                        <div class="info-label">Username</div>
                        <div class="info-value" id="display-username">Loading...</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">License Key</div>
                        <div class="info-value" id="display-license">Loading...</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">HWID (Click to reset)</div>
                        <div class="info-value" id="display-hwid" onclick="openResetModal()">Loading...</div>
                    </div>
                </div>
            </div>
        </div>
    </main>
    <div class="modal" id="resetModal">
        <div class="modal-content">
            <div class="modal-title">⚠️ Reset HWID</div>
            <div class="modal-text">Are you sure you want to reset your HWID? This will unbind your account from the current device.</div>
            <div class="modal-actions">
                <button class="modal-btn modal-btn-cancel" onclick="closeResetModal()">Cancel</button>
                <button class="modal-btn modal-btn-confirm" onclick="confirmReset()">Reset HWID</button>
            </div>
        </div>
    </div>
    <script>
        let currentUsername = null;
        document.querySelectorAll('nav a').forEach(link => {
            link.addEventListener('click', function(e) {
                e.preventDefault();
                const targetId = this.getAttribute('href').substring(1);
                document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
                document.getElementById(targetId).classList.add('active');
                document.querySelectorAll('nav a').forEach(a => a.classList.remove('active'));
                this.classList.add('active');
                document.getElementById('page-title').textContent = this.textContent;
                const subtitleEl = document.querySelector('.subtitle');
                if (targetId === 'subscriptions') {
                    subtitleEl.textContent = 'Manage and view your active subscriptions';
                } else if (targetId === 'security') {
                    subtitleEl.textContent = 'Manage account security and HWID';
                }
            });
        });
        async function loadDashboard() {
            const urlParams = new URLSearchParams(window.location.search);
            currentUsername = urlParams.get('user');
            if (!currentUsername) { alert('No user specified'); return; }
            try {
                const res = await fetch(`/api/dashboard/${currentUsername}`);
                const data = await res.json();
                document.getElementById('stat-active').textContent = data.subscription_status === 'Active' ? '1' : '0';
                document.getElementById('stat-resets').textContent = data.hwid_reset_count;
                document.getElementById('stat-status').textContent = data.subscription_status;
                document.getElementById('stat-type').textContent = data.subscription_type;
                document.getElementById('display-username').textContent = data.username;
                document.getElementById('display-license').textContent = data.license_key_full;
                document.getElementById('display-hwid').textContent = data.hwid || 'Not bound';
            } catch (e) {
                console.error('Error loading dashboard:', e);
                alert('Error loading dashboard');
            }
        }
        function openResetModal() { document.getElementById('resetModal').classList.add('active'); }
        function closeResetModal() { document.getElementById('resetModal').classList.remove('active'); }
        async function confirmReset() {
            try {
                const res = await fetch('/api/hwid/reset', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username: currentUsername })
                });
                const data = await res.json();
                if (res.ok) {
                    alert('HWID reset successfully!');
                    closeResetModal();
                    loadDashboard();
                } else {
                    alert('Error resetting HWID');
                }
            } catch (e) {
                alert('Error resetting HWID');
            }
        }
        loadDashboard();
    </script>
</body>
</html>
"""
