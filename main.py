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
            hwid_resets INTEGER DEFAULT 0,
            active INTEGER DEFAULT 0,
            created_by TEXT
        )""")
        
        # Add hwid_resets column if it doesn't exist
        try:
            cur.execute("ALTER TABLE keys ADD COLUMN IF NOT EXISTS hwid_resets INTEGER DEFAULT 0")
            db.commit()
        except:
            pass
        
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
            hwid_resets INTEGER DEFAULT 0,
            active INTEGER DEFAULT 0,
            created_by TEXT
        )""")
        
        # Add hwid_resets column if it doesn't exist
        try:
            cur.execute("ALTER TABLE keys ADD COLUMN hwid_resets INTEGER DEFAULT 0")
            db.commit()
        except:
            pass
        
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

class RedeemRequest(BaseModel):
    key: str
    discord_id: str

class KeyValidate(BaseModel):
    key: str
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
    """Validate license key"""
    db = get_db()
    cur = db.cursor()
    
    # Check if key exists and is active
    cur.execute(q("SELECT key, active, expires_at, hwid FROM keys WHERE key=%s"), (data.key,))
    result = cur.fetchone()
    
    if not result:
        db.close()
        return {"valid": False, "error": "Invalid license key"}
    
    key, active, expires_at, hwid = result
    
    # Check if active
    if active == 0:
        db.close()
        return {"valid": False, "error": "License inactive"}
    
    # Check expiry
    if expires_at and datetime.now() > datetime.fromisoformat(expires_at):
        db.close()
        return {"valid": False, "error": "License expired"}
    
    # HWID check (for test.py, not web)
    if data.hwid != 'web-login':
        if hwid is None:
            # Bind HWID
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

@app.get("/api/public-configs/{config_id}")
def get_public_config(config_id: int):
    """Get a single public config"""
    db = get_db()
    cur = db.cursor()
    cur.execute(q("SELECT id, config_name, author_name, game_name, description, config_data, downloads FROM public_configs WHERE id=?"), (config_id,))
    row = cur.fetchone()
    db.close()
    
    if not row:
        raise HTTPException(status_code=404, detail="Config not found")
    
    return {
        "id": row[0],
        "config_name": row[1],
        "author_name": row[2],
        "game_name": row[3],
        "description": row[4],
        "config_data": json.loads(row[5]) if row[5] else {},
        "downloads": row[6]
    }

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

# === DASHBOARD API ENDPOINTS ===

@app.get("/api/dashboard/{license_key}")
def get_dashboard_data_by_license(license_key: str):
    """Get dashboard data by license key"""
    db = get_db()
    cur = db.cursor()
    
    cur.execute(q("SELECT key, duration, expires_at, active, hwid, redeemed_by, hwid_resets FROM keys WHERE key=%s"), (license_key,))
    result = cur.fetchone()
    
    db.close()
    
    if not result:
        raise HTTPException(status_code=404, detail="License not found")
    
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
def redeem_license_key(data: RedeemRequest):
    """Redeem a license key with Discord ID"""
    db = get_db()
    cur = db.cursor()
    
    # Check if key exists and is not redeemed
    cur.execute(q("SELECT key, duration, redeemed_at, active FROM keys WHERE key=%s"), (data.key,))
    result = cur.fetchone()
    
    if not result:
        db.close()
        raise HTTPException(status_code=404, detail="Invalid key")
    
    key, duration, redeemed_at, active = result
    
    if redeemed_at:
        db.close()
        raise HTTPException(status_code=400, detail="Key already redeemed")
    
    # Calculate expiry
    now = datetime.now()
    if duration == "lifetime":
        expires_at = None
    elif duration == "monthly":
        expires_at = (now + timedelta(days=30)).isoformat()
    elif duration == "weekly":
        expires_at = (now + timedelta(days=7)).isoformat()
    else:
        expires_at = None
    
    # Redeem key
    cur.execute(q("UPDATE keys SET redeemed_at=%s, redeemed_by=%s, expires_at=%s, active=1 WHERE key=%s"),
               (now.isoformat(), data.discord_id, expires_at, data.key))
    db.commit()
    db.close()
    
    return {
        "success": True,
        "message": "Key redeemed successfully",
        "license_key": data.key
    }

@app.post("/api/reset-hwid/{license_key}")
def reset_hwid_by_license(license_key: str):
    """Reset HWID for a license key"""
    db = get_db()
    cur = db.cursor()
    
    # Get current hwid_resets count
    cur.execute(q("SELECT hwid_resets FROM keys WHERE key=%s"), (license_key,))
    result = cur.fetchone()
    
    if not result:
        db.close()
        raise HTTPException(status_code=404, detail="License not found")
    
    hwid_resets = result[0] if result[0] else 0
    
    # Reset HWID and increment counter
    cur.execute(q("UPDATE keys SET hwid=NULL, hwid_resets=%s WHERE key=%s"),
               (hwid_resets + 1, license_key))
    db.commit()
    db.close()
    
    return {
        "success": True,
        "hwid_resets": hwid_resets + 1,
        "message": "HWID reset successfully"
    }

# === DASHBOARD HTML ===

@app.get("/dashboard/{license_key}", response_class=HTMLResponse)
def serve_dashboard_page(license_key: str):
    """Serve dashboard HTML"""
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
        const licenseKey = window.location.pathname.split('/dashboard/')[1];

        if (!licenseKey) {
            alert('No license key provided');
            window.location.href = '/home';
        }

        // Load user data
        async function loadUserData() {
            try {
                const res = await fetch(`/api/dashboard/${licenseKey}`);
                if (res.status === 404) {
                    alert('License not found');
                    window.location.href = '/home';
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
                const res = await fetch('/api/redeem', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ key, discord_id: discordId })
                });

                const data = await res.json();
                
                if (res.ok) {
                    alert('Key redeemed successfully!');
                    // Reload to new license key dashboard
                    window.location.href = `/dashboard/${key}`;
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
                const res = await fetch(`/api/reset-hwid/${licenseKey}`, {
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

# Run the app
if __name__ == "__main__":
    init_db()
