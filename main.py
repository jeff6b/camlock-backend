# main.py - FULL BACKEND ON RENDER (camlock-backend.onrender.com)
from fastapi import FastAPI, Path, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import sqlite3
import json
import random
from datetime import datetime, timedelta

app = FastAPI()

# ============== DATABASE ==============
def get_db():
    return sqlite3.connect("database.db")

def init_db():
    db = get_db()
    cur = db.cursor()
   
    # Settings table (uses key as identifier)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            config TEXT
        )
    """)
    
    # Keys table with user tracking
    cur.execute("""
        CREATE TABLE IF NOT EXISTS keys (
            key TEXT PRIMARY KEY,
            duration TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT,
            redeemed_at TEXT,
            redeemed_by TEXT,
            hwid TEXT,
            active INTEGER DEFAULT 0,
            created_by TEXT
        )
    """)
   
    db.commit()
    db.close()

init_db()

# Default configuration with BOTH triggerbot and camlock
DEFAULT_CONFIG = {
    "triggerbot": {
        "Enabled": True,
        "Keybind": "Right Mouse",
        "Delay": 0.05,
        "MaxStuds": 120,
        "StudCheck": True,
        "DeathCheck": True,
        "KnifeCheck": True,
        "TeamCheck": True,
        "TargetMode": False,
        "TargetKeybind": "Middle Mouse",
        "Prediction": 0.1,
    },
    "camlock": {
        "Enabled": True,
        "Keybind": "Q",
        "FOV": 280.0,
        "SmoothX": 14.0,
        "SmoothY": 14.0,
        "Prediction": 0.14,
        "MaxStuds": 120.0,
        "UnlockOnDeath": True,
        "SelfDeathCheck": True,
        "BodyPart": "Head",
        "ClosestPart": False,
        "ScaleToggle": False,
        "Scale": 1.0,
    }
}

# ============== PYDANTIC MODELS ==============
class KeyCreate(BaseModel):
    duration: str
    created_by: str

class KeyRedeem(BaseModel):
    key: str
    user_id: str

class KeyValidate(BaseModel):
    key: str
    hwid: str

# ============== HELPER FUNCTIONS ==============
def generate_key():
    """Generate key in format: XXXX-XXXX-XXXX-XXXX"""
    parts = []
    for _ in range(4):
        part = ''.join([str(random.randint(0, 9)) for _ in range(4)])
        parts.append(part)
    return '-'.join(parts)

def get_expiry_date(duration, from_date=None):
    """Calculate expiry from specific date (for countdown on redemption)"""
    base = from_date if from_date else datetime.now()
    if duration == "weekly":
        return (base + timedelta(weeks=1)).isoformat()
    elif duration == "monthly":
        return (base + timedelta(days=30)).isoformat()
    elif duration == "3monthly":
        return (base + timedelta(days=90)).isoformat()
    return None

# ============== CONFIG API (Dashboard) ==============
@app.get("/api/config/{key}")
def get_config(key: str = Path(..., description="License Key")):
    db = get_db()
    cur = db.cursor()
   
    cur.execute("INSERT OR IGNORE INTO settings (key, config) VALUES (?, ?)", 
                (key, json.dumps(DEFAULT_CONFIG)))
    db.commit()
   
    cur.execute("SELECT config FROM settings WHERE key=?", (key,))
    result = cur.fetchone()
    db.close()
    
    config = json.loads(result[0]) if result else DEFAULT_CONFIG
    return config

@app.post("/api/config/{key}")
def set_config(key: str, data: dict):
    db = get_db()
    cur = db.cursor()
    
    cur.execute("""
        INSERT INTO settings(key, config) VALUES(?, ?)
        ON CONFLICT(key) DO UPDATE SET config=excluded.config
    """, (key, json.dumps(data)))
    
    db.commit()
    db.close()
    return {"status": "ok"}

# ============== KEYSYSTEM API ==============

@app.post("/api/keys/create")
def create_key(data: KeyCreate):
    """Create a new license key (not active until redeemed)"""
    db = get_db()
    cur = db.cursor()
    
    key = generate_key()
    
    try:
        cur.execute("""
            INSERT INTO keys (key, duration, created_at, active, created_by)
            VALUES (?, ?, ?, 0, ?)
        """, (key, data.duration, datetime.now().isoformat(), data.created_by))
        
        db.commit()
        db.close()
        
        return {
            "key": key,
            "duration": data.duration,
            "status": "awaiting_redemption"
        }
    except Exception as e:
        db.close()
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/keys/redeem")
def redeem_key(data: KeyRedeem):
    """Redeem a key - starts countdown and binds to user"""
    db = get_db()
    cur = db.cursor()
    
    # Check if key exists
    cur.execute("SELECT * FROM keys WHERE key=?", (data.key,))
    result = cur.fetchone()
    
    if not result:
        db.close()
        raise HTTPException(status_code=404, detail="Invalid key")
    
    key, duration, created_at, expires_at, redeemed_at, redeemed_by, hwid, active, created_by = result
    
    # Check if already redeemed
    if redeemed_by:
        db.close()
        raise HTTPException(status_code=400, detail="Key already redeemed by another user")
    
    # Start countdown NOW
    now = datetime.now()
    expiry = get_expiry_date(duration, now)
    
    cur.execute("""
        UPDATE keys 
        SET redeemed_at=?, redeemed_by=?, expires_at=?, active=1
        WHERE key=?
    """, (now.isoformat(), data.user_id, expiry, data.key))
    
    db.commit()
    db.close()
    
    return {
        "success": True,
        "key": data.key,
        "duration": duration,
        "expires_at": expiry,
        "message": "Key redeemed successfully"
    }

@app.delete("/api/users/{user_id}/license")
def delete_user_license(user_id: str):
    """Delete a user's license"""
    db = get_db()
    cur = db.cursor()
    
    cur.execute("SELECT key FROM keys WHERE redeemed_by=?", (user_id,))
    result = cur.fetchone()
    
    if not result:
        db.close()
        raise HTTPException(status_code=404, detail="No license found for this user")
    
    key = result[0]
    cur.execute("DELETE FROM keys WHERE redeemed_by=?", (user_id,))
    db.commit()
    db.close()
    
    return {"status": "deleted", "key": key, "user_id": user_id}

@app.get("/api/users/{user_id}/license")
def get_user_license(user_id: str):
    """Get license info for a user"""
    db = get_db()
    cur = db.cursor()
    
    cur.execute("SELECT * FROM keys WHERE redeemed_by=?", (user_id,))
    result = cur.fetchone()
    db.close()
    
    if not result:
        return {"active": False, "message": "No license found"}
    
    key, duration, created_at, expires_at, redeemed_at, redeemed_by, hwid, active, created_by = result
    
    # Check if expired
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

@app.post("/api/users/{user_id}/reset-hwid")
def reset_user_hwid(user_id: str):
    """Reset HWID for a user's license"""
    db = get_db()
    cur = db.cursor()
    
    cur.execute("SELECT hwid FROM keys WHERE redeemed_by=?", (user_id,))
    result = cur.fetchone()
    
    if not result:
        db.close()
        raise HTTPException(status_code=404, detail="No license found for this user")
    
    old_hwid = result[0]
    cur.execute("UPDATE keys SET hwid=NULL WHERE redeemed_by=?", (user_id,))
    db.commit()
    db.close()
    
    return {"status": "reset", "user_id": user_id, "old_hwid": old_hwid}

@app.get("/api/keys/{key}")
def get_key_info(key: str):
    """Get information about a key"""
    db = get_db()
    cur = db.cursor()
    
    cur.execute("SELECT * FROM keys WHERE key=?", (key,))
    result = cur.fetchone()
    db.close()
    
    if not result:
        raise HTTPException(status_code=404, detail="Key not found")
    
    return {
        "key": result[0],
        "duration": result[1],
        "created_at": result[2],
        "expires_at": result[3],
        "redeemed_at": result[4],
        "redeemed_by": result[5],
        "hwid": result[6],
        "active": result[7],
        "created_by": result[8]
    }

@app.get("/api/keys/list")
def list_keys():
    """List all keys"""
    db = get_db()
    cur = db.cursor()
    
    cur.execute("SELECT * FROM keys ORDER BY created_at DESC")
    results = cur.fetchall()
    db.close()
    
    keys = []
    for result in results:
        keys.append({
            "key": result[0],
            "duration": result[1],
            "created_at": result[2],
            "expires_at": result[3],
            "redeemed_at": result[4],
            "redeemed_by": result[5],
            "hwid": result[6],
            "active": result[7],
            "created_by": result[8]
        })
    
    return {"keys": keys}

@app.post("/api/validate")
def validate_key(data: KeyValidate):
    """Validate a key and bind HWID (NO USERNAME NEEDED)"""
    db = get_db()
    cur = db.cursor()
    
    cur.execute("SELECT * FROM keys WHERE key=?", (data.key,))
    result = cur.fetchone()
    
    if not result:
        db.close()
        return {"valid": False, "error": "Invalid key"}, 401
    
    key, duration, created_at, expires_at, redeemed_at, redeemed_by, hwid, active, created_by = result
    
    # Check if redeemed
    if not redeemed_by:
        db.close()
        return {"valid": False, "error": "Key not redeemed yet"}, 401
    
    # Check if expired
    if expires_at and datetime.now() > datetime.fromisoformat(expires_at):
        db.close()
        return {"valid": False, "error": "Key expired"}, 401
    
    # Check HWID binding
    if hwid is None:
        # First time use - bind HWID
        cur.execute("UPDATE keys SET hwid=? WHERE key=?", (data.hwid, data.key))
        db.commit()
        db.close()
        
        return {
            "valid": True,
            "message": "HWID bound successfully",
            "key": key,
            "expires_at": expires_at
        }
    
    elif hwid == data.hwid:
        # HWID matches - allow access
        db.close()
        return {
            "valid": True,
            "message": "Authentication successful",
            "key": key,
            "expires_at": expires_at
        }
    
    else:
        # HWID mismatch
        db.close()
        return {"valid": False, "error": "HWID mismatch"}, 401

# ============== DASHBOARD UI ==============
@app.get("/{key}", response_class=HTMLResponse)
def serve_ui(key: str):
    return f"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<title>Axion - {key}</title>
<style>
    * {{
        margin: 0;
        padding: 0;
        box-sizing: border-box;
        user-select: none;
    }}
    body {{
        height: 100vh;
        background: radial-gradient(circle at top, #0f0f0f, #050505);
        font-family: Arial, Helvetica, sans-serif;
        color: #cfcfcf;
        display: flex;
        align-items: center;
        justify-content: center;
    }}
    .window {{
        width: 760px;
        height: 520px;
        background: linear-gradient(#111, #0a0a0a);
        border: 1px solid #2a2a2a;
        box-shadow: 0 0 40px rgba(0,0,0,0.8);
        display: flex;
        flex-direction: column;
        overflow: hidden;
    }}
    .topbar {{
        height: 38px;
        background: linear-gradient(#1a1a1a, #0e0e0e);
        border-bottom: 1px solid #2b2b2b;
        display: flex;
        align-items: center;
        padding: 0 12px;
        gap: 16px;
    }}
    .title {{
        font-size: 13px;
        color: #bfbfbf;
        padding-right: 16px;
        border-right: 1px solid #2a2a2a;
    }}
    .tabs {{
        display: flex;
        gap: 18px;
        font-size: 12px;
    }}
    .tab {{
        color: #9a9a9a;
        cursor: pointer;
        transition: color 0.2s;
    }}
    .tab:hover,
    .tab.active {{
        color: #ffffff;
        text-shadow: 0 0 4px rgba(255,255,255,0.3);
    }}
    .topbar-right {{
        margin-left: auto;
        display: flex;
        align-items: center;
    }}
    .search-container {{
        position: relative;
        width: 180px;
    }}
    .search-bar {{
        width: 100%;
        height: 26px;
        background: #0f0f0f;
        border: 1px solid #2a2a2a;
        color: #cfcfcf;
        font-size: 11px;
        padding: 0 10px 0 32px;
        outline: none;
        transition: border-color 0.2s ease;
    }}
    .search-bar::placeholder {{
        color: #666666;
    }}
    .search-bar:focus {{
        border-color: #555555;
    }}
    .search-icon {{
        position: absolute;
        left: 10px;
        top: 50%;
        transform: translateY(-50%);
        width: 14px;
        height: 14px;
        pointer-events: none;
    }}
    .content {{
        flex: 1;
        padding: 10px;
        background: #0c0c0c;
        display: flex;
        align-items: center;
        justify-content: center;
        position: relative;
    }}
    .tab-content {{
        width: 100%;
        height: 100%;
        display: none;
    }}
    .tab-content.active {{
        display: block;
    }}
    .merged-panel {{
        width: 100%;
        height: 100%;
        background: #0c0c0c;
        border: 1px solid #222;
        overflow: hidden;
        display: flex;
        align-items: center;
        justify-content: center;
    }}
    .inner-container {{
        width: 98%;
        height: 96%;
        display: flex;
        gap: 14px;
        overflow: hidden;
    }}
    .half-panel {{
        flex: 1;
        background: #111111;
        border: 1px solid #2a2a2a;
        box-shadow: 0 0 25px rgba(0,0,0,0.6) inset;
        overflow-y: auto;
        border-radius: 0;
        padding: 14px 16px;
        position: relative;
    }}
    .panel-header {{
        position: absolute;
        top: 10px;
        left: 16px;
        color: #bfbfbf;
        font-size: 11px;
        font-weight: normal;
        pointer-events: none;
        z-index: 1;
    }}
    .toggle-row {{
        position: absolute;
        left: 16px;
        display: flex;
        align-items: center;
        gap: 12px;
        z-index: 1;
    }}
    .toggle-text {{
        display: flex;
        align-items: center;
        gap: 12px;
    }}
    .toggle {{
        width: 14px;
        height: 14px;
        background: transparent;
        border: 0.8px solid #1a1a1a;
        border-radius: 0;
        cursor: pointer;
        transition: background 0.2s ease;
        flex-shrink: 0;
    }}
    .toggle.active {{
        background: #cccccc;
        box-shadow: inset 0 0 4px rgba(0,0,0,0.5);
    }}
    .enable-text {{
        color: #9a9a9a;
        font-size: 11px;
        line-height: 1;
        transition: color 0.25s ease;
        pointer-events: none;
    }}
    .toggle.active + .enable-text {{
        color: #e0e0e0;
    }}
    .underline-highlight {{
        text-decoration: underline;
        text-decoration-color: #cccccc;
        text-decoration-thickness: 1.5px;
        text-underline-offset: 2px;
    }}
    .keybind-picker {{
        width: 80px;
        height: 20px;
        background: #0f0f0f;
        border: 1px solid #2a2a2a;
        color: #cfcfcf;
        font-size: 10px;
        display: flex;
        align-items: center;
        justify-content: center;
        cursor: pointer;
        user-select: none;
    }}
    .slider-label {{
        position: absolute;
        left: 16px;
        color: #bfbfbf;
        font-size: 11px;
        font-weight: normal;
        z-index: 1;
    }}
    .slider-container {{
        position: absolute;
        left: 16px;
        width: 210px;
        height: 14px;
        background: #0f0f0f;
        border: 1px solid #2a2a2a;
        overflow: hidden;
        z-index: 10;
    }}
    .slider-track {{
        position: absolute;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: #0f0f0f;
    }}
    .slider-fill {{
        position: absolute;
        top: 0;
        left: 0;
        height: 100%;
        background: #cccccc;
        width: 50%;
        transition: width 0.1s ease;
    }}
    .slider-value {{
        position: absolute;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        font-size: 9px;
        font-weight: bold;
        pointer-events: none;
        z-index: 3;
        transition: color 0.2s;
    }}
    .half-panel::-webkit-scrollbar {{
        width: 5px;
    }}
    .half-panel::-webkit-scrollbar-track {{
        background: #0a0a0a;
        border-left: 1px solid #111;
    }}
    .half-panel::-webkit-scrollbar-thumb {{
        background: #222222;
        border-radius: 0;
    }}
    .half-panel::-webkit-scrollbar-thumb:hover {{
        background: #444444;
    }}
    .custom-dropdown {{
        position: absolute;
        left: 16px;
        width: 210px;
        height: 16px;
        z-index: 100;
    }}
    .dropdown-header {{
        width: 100%;
        height: 100%;
        background: #0f0f0f;
        border: 1px solid #2a2a2a;
        display: flex;
        align-items: center;
        padding: 0 8px;
        cursor: pointer;
        font-size: 10px;
        color: #cfcfcf;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
    }}
    .dropdown-list {{
        position: absolute;
        top: 100%;
        left: 0;
        width: 100%;
        max-height: 160px;
        background: #0f0f0f;
        border: 1px solid #2a2a2a;
        border-top: none;
        overflow-y: auto;
        display: none;
        z-index: 101;
        box-shadow: 0 8px 16px rgba(0,0,0,0.6);
    }}
    .dropdown-list.open {{
        display: block;
    }}
    .dropdown-item {{
        padding: 5px 10px;
        font-size: 11px;
        color: #cfcfcf;
        cursor: pointer;
        transition: background 0.15s;
    }}
    .dropdown-item:hover {{
        background: #1a1a1a;
    }}
    .dropdown-item.selected {{
        background: #222;
        color: #ffffff;
    }}
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
        <!-- AIMBOT TAB -->
        <div class="tab-content active" id="aimbot">
            <div class="merged-panel">
                <div class="inner-container">
                    <div class="half-panel">
                        <div class="panel-header">aimbot</div>
                        <div class="toggle-row" style="top: 32px;">
                            <div class="toggle-text">
                                <div class="toggle active" data-setting="camlock.Enabled"></div>
                                <span class="enable-text">Enable Aimbot</span>
                            </div>
                            <div class="keybind-picker" data-setting="camlock.Keybind">Q</div>
                        </div>
                        <div class="toggle-row" style="top: 58px;">
                            <div class="toggle" data-setting="camlock.UnlockOnDeath"></div>
                            <span class="enable-text">Unlock On Death</span>
                        </div>
                        <div class="toggle-row" style="top: 82px;">
                            <div class="toggle" data-setting="camlock.SelfDeathCheck"></div>
                            <span class="enable-text">Self Death Check</span>
                        </div>
                        <div class="toggle-row" style="top: 106px;">
                            <div class="toggle" data-setting="camlock.ClosestPart"></div>
                            <span class="enable-text">Closest Part</span>
                        </div>
                    </div>
                    <div class="half-panel">
                        <div class="panel-header">aimbot settings</div>
                        <div class="slider-label" style="top: 32px;">FOV</div>
                        <div class="slider-container" id="fovSlider" style="top: 46px;" data-setting="camlock.FOV">
                            <div class="slider-track">
                                <div class="slider-fill" id="fovFill"></div>
                                <div class="slider-value" id="fovValue">280</div>
                            </div>
                        </div>
                        <div class="slider-label" style="top: 72px;">Smooth X</div>
                        <div class="slider-container" id="smoothXSlider" style="top: 86px;" data-setting="camlock.SmoothX">
                            <div class="slider-track">
                                <div class="slider-fill" id="smoothXFill"></div>
                                <div class="slider-value" id="smoothXValue">14</div>
                            </div>
                        </div>
                        <div class="slider-label" style="top: 112px;">Smooth Y</div>
                        <div class="slider-container" id="smoothYSlider" style="top: 126px;" data-setting="camlock.SmoothY">
                            <div class="slider-track">
                                <div class="slider-fill" id="smoothYFill"></div>
                                <div class="slider-value" id="smoothYValue">14</div>
                            </div>
                        </div>
                        <div class="slider-label" style="top: 152px;">Prediction</div>
                        <div class="slider-container" id="camlockPredSlider" style="top: 166px;" data-setting="camlock.Prediction">
                            <div class="slider-track">
                                <div class="slider-fill" id="camlockPredFill"></div>
                                <div class="slider-value" id="camlockPredValue">0.14</div>
                            </div>
                        </div>
                        <div class="slider-label" style="top: 192px;">Max Studs</div>
                        <div class="slider-container" id="camlockMaxStudsSlider" style="top: 206px;" data-setting="camlock.MaxStuds">
                            <div class="slider-track">
                                <div class="slider-fill" id="camlockMaxStudsFill"></div>
                                <div class="slider-value" id="camlockMaxStudsValue">120</div>
                            </div>
                        </div>
                        <div class="slider-label" style="top: 232px;">Body Part</div>
                        <div class="custom-dropdown" style="top: 246px;" id="bodyPartDropdown" data-setting="camlock.BodyPart">
                            <div class="dropdown-header" id="bodyPartHeader">Head</div>
                            <div class="dropdown-list" id="bodyPartList">
                                <div class="dropdown-item selected" data-value="Head">Head</div>
                                <div class="dropdown-item" data-value="UpperTorso">UpperTorso</div>
                                <div class="dropdown-item" data-value="LowerTorso">LowerTorso</div>
                                <div class="dropdown-item" data-value="HumanoidRootPart">HumanoidRootPart</div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- TRIGGERBOT TAB -->
        <div class="tab-content" id="triggerbot">
            <div class="merged-panel">
                <div class="inner-container">
                    <div class="half-panel">
                        <div class="panel-header">triggerbot</div>
                        <div class="toggle-row" style="top: 32px;" data-search="enable triggerbot">
                            <div class="toggle-text">
                                <div class="toggle active" data-setting="triggerbot.Enabled"></div>
                                <span class="enable-text">Enable Triggerbot</span>
                            </div>
                            <div class="keybind-picker" data-setting="triggerbot.Keybind">Right Mouse</div>
                        </div>
                        <div class="toggle-row" style="top: 58px;" data-search="target mode">
                            <div class="toggle-text">
                                <div class="toggle" data-setting="triggerbot.TargetMode"></div>
                                <span class="enable-text">Target Mode</span>
                            </div>
                            <div class="keybind-picker" data-setting="triggerbot.TargetKeybind">Middle Mouse</div>
                        </div>
                    </div>
                    <div class="half-panel">
                        <div class="panel-header">triggerbot settings</div>
                        <div class="toggle-row" style="top: 32px;" data-search="stud check distance">
                            <div class="toggle active" data-setting="triggerbot.StudCheck"></div>
                            <span class="enable-text">Stud Check</span>
                        </div>
                        <div class="toggle-row" style="top: 56px;" data-search="death check">
                            <div class="toggle active" data-setting="triggerbot.DeathCheck"></div>
                            <span class="enable-text">Death Check</span>
                        </div>
                        <div class="toggle-row" style="top: 80px;" data-search="knife check">
                            <div class="toggle active" data-setting="triggerbot.KnifeCheck"></div>
                            <span class="enable-text">Knife Check</span>
                        </div>
                        <div class="toggle-row" style="top: 104px;" data-search="team check">
                            <div class="toggle active" data-setting="triggerbot.TeamCheck"></div>
                            <span class="enable-text">Team Check</span>
                        </div>
                        <div class="slider-label" style="top: 130px;">Delay (s)</div>
                        <div class="slider-container" id="delaySlider" style="top: 144px;" data-setting="triggerbot.Delay">
                            <div class="slider-track">
                                <div class="slider-fill" id="delayFill"></div>
                                <div class="slider-value" id="delayValue">0.05</div>
                            </div>
                        </div>
                        <div class="slider-label" style="top: 170px;">Max Studs</div>
                        <div class="slider-container" id="maxStudsSlider" style="top: 184px;" data-setting="triggerbot.MaxStuds">
                            <div class="slider-track">
                                <div class="slider-fill" id="maxStudsFill"></div>
                                <div class="slider-value" id="maxStudsValue">120</div>
                            </div>
                        </div>
                        <div class="slider-label" style="top: 210px;">Prediction</div>
                        <div class="slider-container" id="predSlider" style="top: 224px;" data-setting="triggerbot.Prediction">
                            <div class="slider-track">
                                <div class="slider-fill" id="predFill"></div>
                                <div class="slider-value" id="predValue">0.10</div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- SETTINGS TAB -->
        <div class="tab-content" id="settings">
            <div class="merged-panel">
                <div style="color: #666666; text-align: center; padding: 40px;">
                    Settings coming soon...
                </div>
            </div>
        </div>
    </div>
</div>

<script>
let config = {json.dumps(DEFAULT_CONFIG)};

// Tab switching
document.querySelectorAll('.tab').forEach(tab => {{
    tab.addEventListener('click', () => {{
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(tc => tc.classList.remove('active'));
        tab.classList.add('active');
        const tabId = tab.getAttribute('data-tab');
        document.getElementById(tabId).classList.add('active');
    }});
}});

async function saveConfig() {{
    try {{
        await fetch(`/api/config/{key}`, {{
            method: 'POST',
            headers: {{ 'Content-Type': 'application/json' }},
            body: JSON.stringify(config)
        }});
    }} catch(e) {{
        console.error('Save failed:', e);
    }}
}}

async function loadConfig() {{
    try {{
        const res = await fetch(`/api/config/{key}`);
        config = await res.json();
        applyConfigToUI();
    }} catch(e) {{
        console.error('Load failed:', e);
    }}
}}

function applyConfigToUI() {{
    document.querySelectorAll('.toggle[data-setting]').forEach(toggle => {{
        const setting = toggle.dataset.setting;
        const [section, settingKey] = setting.split('.');
        if (config[section] && config[section][settingKey] !== undefined) {{
            toggle.classList.toggle('active', config[section][settingKey]);
        }}
    }});
    
    document.querySelectorAll('.keybind-picker[data-setting]').forEach(picker => {{
        const setting = picker.dataset.setting;
        const [section, settingKey] = setting.split('.');
        if (config[section] && config[section][settingKey] !== undefined) {{
            picker.textContent = config[section][settingKey];
        }}
    }});
    
    // Update all sliders
    if (sliders.delay) {{ sliders.delay.current = config.triggerbot.Delay; sliders.delay.update(); }}
    if (sliders.maxStuds) {{ sliders.maxStuds.current = config.triggerbot.MaxStuds; sliders.maxStuds.update(); }}
    if (sliders.pred) {{ sliders.pred.current = config.triggerbot.Prediction; sliders.pred.update(); }}
    if (sliders.fov) {{ sliders.fov.current = config.camlock.FOV; sliders.fov.update(); }}
    if (sliders.smoothX) {{ sliders.smoothX.current = config.camlock.SmoothX; sliders.smoothX.update(); }}
    if (sliders.smoothY) {{ sliders.smoothY.current = config.camlock.SmoothY; sliders.smoothY.update(); }}
    if (sliders.camlockPred) {{ sliders.camlockPred.current = config.camlock.Prediction; sliders.camlockPred.update(); }}
    if (sliders.camlockMaxStuds) {{ sliders.camlockMaxStuds.current = config.camlock.MaxStuds; sliders.camlockMaxStuds.update(); }}
    
    // Update dropdown
    if (config.camlock.BodyPart) {{
        document.getElementById('bodyPartHeader').textContent = config.camlock.BodyPart;
        document.querySelectorAll('#bodyPartList .dropdown-item').forEach(item => {{
            item.classList.toggle('selected', item.dataset.value === config.camlock.BodyPart);
        }});
    }}
}}

document.querySelectorAll('.toggle[data-setting]').forEach(toggle => {{
    toggle.addEventListener('click', () => {{
        toggle.classList.toggle('active');
        const setting = toggle.dataset.setting;
        const [section, settingKey] = setting.split('.');
        config[section][settingKey] = toggle.classList.contains('active');
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
                keyName = e.button === 0 ? 'Left Mouse' : e.button === 2 ? 'Right Mouse' : e.button === 1 ? 'Middle Mouse' : `Mouse${{e.button}}`;
            }} else if (e.key) {{
                keyName = e.key.toUpperCase();
                if (keyName === ' ') keyName = 'SPACE';
            }}
            picker.textContent = keyName || 'NONE';
            const setting = picker.dataset.setting;
            const [section, settingKey] = setting.split('.');
            config[section][settingKey] = keyName;
            saveConfig();
            document.removeEventListener('keydown', listener);
            document.removeEventListener('mousedown', listener);
        }};
        document.addEventListener('keydown', listener, {{ once: true }});
        document.addEventListener('mousedown', listener, {{ once: true }});
    }});
}});

// Dropdown
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

const sliders = {{}};

function createDecimalSlider(id, fillId, valueId, defaultVal, min, max, step, setting) {{
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
        update: function() {{
            const percent = ((this.current - this.min) / (this.max - this.min)) * 100;
            fill.style.width = percent + '%';
            valueText.textContent = this.current.toFixed(2);
            valueText.style.color = this.current >= 0.5 ? '#000000' : '#ffffff';
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
            const [section, settingKey] = obj.setting.split('.');
            config[section][settingKey] = obj.current;
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
            valueText.style.color = this.current >= this.blackThreshold ? '#000000' : '#ffffff';
        }}
    }};
    
    slider.addEventListener('mousedown', (e) => {{
        const rect = slider.getBoundingClientRect();
        function move(e) {{
            const x = e.clientX - rect.left;
            const percent = Math.max(0, Math.min(100, (x / rect.width) * 100));
            obj.current = (percent / 100) * obj.max;
            obj.update();
            const [section, settingKey] = obj.setting.split('.');
            config[section][settingKey] = Math.round(obj.current);
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

// Triggerbot sliders
sliders.delay = createDecimalSlider('delaySlider', 'delayFill', 'delayValue', 0.05, 0.01, 1.00, 0.01, 'triggerbot.Delay');
sliders.maxStuds = createIntSlider('maxStudsSlider', 'maxStudsFill', 'maxStudsValue', 120, 300, 150, 'triggerbot.MaxStuds');
sliders.pred = createDecimalSlider('predSlider', 'predFill', 'predValue', 0.10, 0.01, 1.00, 0.01, 'triggerbot.Prediction');

// Camlock sliders
sliders.fov = createIntSlider('fovSlider', 'fovFill', 'fovValue', 280, 500, 250, 'camlock.FOV');
sliders.smoothX = createIntSlider('smoothXSlider', 'smoothXFill', 'smoothXValue', 14, 30, 15, 'camlock.SmoothX');
sliders.smoothY = createIntSlider('smoothYSlider', 'smoothYFill', 'smoothYValue', 14, 30, 15, 'camlock.SmoothY');
sliders.camlockPred = createDecimalSlider('camlockPredSlider', 'camlockPredFill', 'camlockPredValue', 0.14, 0.01, 1.00, 0.01, 'camlock.Prediction');
sliders.camlockMaxStuds = createIntSlider('camlockMaxStudsSlider', 'camlockMaxStudsFill', 'camlockMaxStudsValue', 120, 300, 150, 'camlock.MaxStuds');

loadConfig();
setInterval(loadConfig, 1000);
</script>
</body>
</html>
"""
