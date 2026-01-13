# main.py - FULL BACKEND ON RENDER (camlock-backend.onrender.com)
from fastapi import FastAPI, Path, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import sqlite3
import json
import uuid
from datetime import datetime, timedelta

app = FastAPI()

# ============== DATABASE ==============
def get_db():
    return sqlite3.connect("database.db")

def init_db():
    db = get_db()
    cur = db.cursor()
   
    # Settings table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            username TEXT PRIMARY KEY,
            config TEXT
        )
    """)
    
    # Keys table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS keys (
            key TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            duration TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            hwid TEXT,
            active INTEGER DEFAULT 1,
            created_by TEXT
        )
    """)
   
    db.commit()
    db.close()

init_db()

# Default configuration
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
    username: str
    duration: str
    created_by: str

class KeyValidate(BaseModel):
    key: str
    hwid: str
    username: str

# ============== HELPER FUNCTIONS ==============
def generate_key(prefix="PHASE"):
    return f"{prefix}-{uuid.uuid4().hex[:8].upper()}-{uuid.uuid4().hex[:8].upper()}"

def get_expiry_date(duration):
    if duration == "weekly":
        return (datetime.now() + timedelta(weeks=1)).isoformat()
    elif duration == "monthly":
        return (datetime.now() + timedelta(days=30)).isoformat()
    elif duration == "3monthly":
        return (datetime.now() + timedelta(days=90)).isoformat()
    return None

# ============== CONFIG API (Dashboard) ==============
@app.get("/api/config/{username}")
def get_config(username: str = Path(..., description="Username")):
    db = get_db()
    cur = db.cursor()
   
    cur.execute("INSERT OR IGNORE INTO settings (username, config) VALUES (?, ?)", 
                (username, json.dumps(DEFAULT_CONFIG)))
    db.commit()
   
    cur.execute("SELECT config FROM settings WHERE username=?", (username,))
    result = cur.fetchone()
    db.close()
    
    config = json.loads(result[0]) if result else DEFAULT_CONFIG
    return config

@app.post("/api/config/{username}")
def set_config(username: str, data: dict):
    db = get_db()
    cur = db.cursor()
    
    cur.execute("""
        INSERT INTO settings(username, config) VALUES(?, ?)
        ON CONFLICT(username) DO UPDATE SET config=excluded.config
    """, (username, json.dumps(data)))
    
    db.commit()
    db.close()
    return {"status": "ok"}

# ============== KEYSYSTEM API ==============

@app.post("/api/keys/create")
def create_key(data: KeyCreate):
    """Create a new license key"""
    db = get_db()
    cur = db.cursor()
    
    key = generate_key()
    expires_at = get_expiry_date(data.duration)
    
    if not expires_at:
        raise HTTPException(status_code=400, detail="Invalid duration")
    
    try:
        cur.execute("""
            INSERT INTO keys (key, username, duration, created_at, expires_at, created_by)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (key, data.username, data.duration, datetime.now().isoformat(), expires_at, data.created_by))
        
        db.commit()
        db.close()
        
        return {
            "key": key,
            "username": data.username,
            "duration": data.duration,
            "expires_at": expires_at
        }
    except Exception as e:
        db.close()
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/keys/{key}")
def delete_key(key: str):
    """Delete a license key"""
    db = get_db()
    cur = db.cursor()
    
    cur.execute("SELECT username FROM keys WHERE key=?", (key,))
    result = cur.fetchone()
    
    if not result:
        db.close()
        raise HTTPException(status_code=404, detail="Key not found")
    
    username = result[0]
    cur.execute("DELETE FROM keys WHERE key=?", (key,))
    db.commit()
    db.close()
    
    return {"status": "deleted", "username": username}

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
        "username": result[1],
        "duration": result[2],
        "created_at": result[3],
        "expires_at": result[4],
        "hwid": result[5],
        "active": result[6],
        "created_by": result[7]
    }

@app.get("/api/keys/list")
def list_keys():
    """List all keys"""
    db = get_db()
    cur = db.cursor()
    
    cur.execute("SELECT * FROM keys")
    results = cur.fetchall()
    db.close()
    
    keys = []
    for result in results:
        keys.append({
            "key": result[0],
            "username": result[1],
            "duration": result[2],
            "created_at": result[3],
            "expires_at": result[4],
            "hwid": result[5],
            "active": result[6],
            "created_by": result[7]
        })
    
    return {"keys": keys}

@app.post("/api/keys/{key}/reset")
def reset_hwid(key: str):
    """Reset HWID binding for a key"""
    db = get_db()
    cur = db.cursor()
    
    cur.execute("SELECT username, hwid FROM keys WHERE key=?", (key,))
    result = cur.fetchone()
    
    if not result:
        db.close()
        raise HTTPException(status_code=404, detail="Key not found")
    
    username, old_hwid = result
    cur.execute("UPDATE keys SET hwid=NULL WHERE key=?", (key,))
    db.commit()
    db.close()
    
    return {"status": "reset", "username": username, "old_hwid": old_hwid}

@app.post("/api/validate")
def validate_key(data: KeyValidate):
    """Validate a key and bind HWID"""
    db = get_db()
    cur = db.cursor()
    
    cur.execute("SELECT * FROM keys WHERE key=?", (data.key,))
    result = cur.fetchone()
    
    if not result:
        db.close()
        return {"valid": False, "error": "Invalid key"}, 401
    
    key, username, duration, created_at, expires_at, hwid, active, created_by = result
    
    # Check if expired
    if datetime.now() > datetime.fromisoformat(expires_at):
        db.close()
        return {"valid": False, "error": "Key expired"}, 401
    
    # Check username match
    if username != data.username:
        db.close()
        return {"valid": False, "error": "Username mismatch"}, 401
    
    # Check HWID binding
    if hwid is None:
        # First time use - bind HWID
        cur.execute("UPDATE keys SET hwid=? WHERE key=?", (data.hwid, data.key))
        db.commit()
        db.close()
        
        return {
            "valid": True,
            "message": "HWID bound successfully",
            "username": username,
            "expires_at": expires_at
        }
    
    elif hwid == data.hwid:
        # HWID matches - allow access
        db.close()
        return {
            "valid": True,
            "message": "Authentication successful",
            "username": username,
            "expires_at": expires_at
        }
    
    else:
        # HWID mismatch
        db.close()
        return {"valid": False, "error": "HWID mismatch"}, 401

# ============== DASHBOARD UI ==============
@app.get("/{username}", response_class=HTMLResponse)
def serve_ui(username: str):
    return f"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<title>Axion - {username}</title>
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
    .slider-thumb {{
        position: absolute;
        top: 50%;
        transform: translateY(-50%);
        width: 12px;
        height: 12px;
        background: #ffffff;
        cursor: ew-resize;
        pointer-events: none;
        z-index: 2;
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
</style>
</head>
<body>
<div class="window">
    <div class="topbar">
        <div class="title">Axion</div>
        <div class="tabs">
            <div class="tab">aimbot</div>
            <div class="tab active">triggerbot</div>
            <div class="tab">settings</div>
            <div class="tab">configs</div>
        </div>
        <div class="topbar-right">
            <div class="search-container">
                <img src="https://img.icons8.com/?size=100&id=14079&format=png&color=FFFFFF" alt="Search" class="search-icon">
                <input type="text" id="searchInput" class="search-bar" placeholder="Search...">
            </div>
        </div>
    </div>
    <div class="content">
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
</div>

<script>
let config = {json.dumps(DEFAULT_CONFIG)};

async function saveConfig() {{
    try {{
        await fetch(`/api/config/{username}`, {{
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
        const res = await fetch(`/api/config/{username}`);
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
    
    if (config.triggerbot.Delay !== undefined) {{
        sliders.delay.current = config.triggerbot.Delay;
        sliders.delay.update();
    }}
    if (config.triggerbot.MaxStuds !== undefined) {{
        sliders.maxStuds.current = config.triggerbot.MaxStuds;
        sliders.maxStuds.update();
    }}
    if (config.triggerbot.Prediction !== undefined) {{
        sliders.pred.current = config.triggerbot.Prediction;
        sliders.pred.update();
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
                keyName = e.button === 0 ? 'Left Mouse' : e.button === 2 ? 'Right Mouse' : e.button === 1 ? 'Middle Mouse' : `Mouse${{e.button}}`;
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
        document.addEventListener('keydown', listener, {{ once: true }});
        document.addEventListener('mousedown', listener, {{ once: true }});
    }});
}});

const searchInput = document.getElementById('searchInput');
const toggleRows = document.querySelectorAll('.toggle-row[data-search]');
searchInput.addEventListener('input', () => {{
    const query = searchInput.value.toLowerCase().trim();
    toggleRows.forEach(row => {{
        const textSpan = row.querySelector('.enable-text');
        const originalText = textSpan.dataset.original || textSpan.textContent;
        if (!textSpan.dataset.original) textSpan.dataset.original = originalText;
        textSpan.innerHTML = originalText;
        if (query === '') return;
        const searchTerm = row.getAttribute('data-search').toLowerCase();
        if (searchTerm.includes(query)) {{
            textSpan.innerHTML = `<span class="underline-highlight">${{originalText}}</span>`;
        }}
    }});
}});

const sliders = {{}};

function createDecimalSlider(id, fillId, valueId, defaultVal, min, max, step, setting) {{
    const slider = document.getElementById(id);
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

sliders.delay = createDecimalSlider('delaySlider', 'delayFill', 'delayValue', 0.05, 0.01, 1.00, 0.01, 'triggerbot.Delay');
sliders.maxStuds = createIntSlider('maxStudsSlider', 'maxStudsFill', 'maxStudsValue', 120, 300, 150, 'triggerbot.MaxStuds');
sliders.pred = createDecimalSlider('predSlider', 'predFill', 'predValue', 0.10, 0.01, 1.00, 0.01, 'triggerbot.Prediction');

loadConfig();
setInterval(loadConfig, 1000);
</script>
</body>
</html>
"""
