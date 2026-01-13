# main.py
from fastapi import FastAPI, Path
from fastapi.responses import HTMLResponse
import sqlite3
import json

app = FastAPI()

# ---------------- Database ----------------
def get_db():
    return sqlite3.connect("database.db")

def init_db():
    db = get_db()
    cur = db.cursor()
   
    # Settings table (stores entire config as JSON per user)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            username TEXT PRIMARY KEY,
            config TEXT
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

# ---------------- API ----------------
@app.get("/api/config/{username}")
def get_config(username: str = Path(..., description="Username")):
    db = get_db()
    cur = db.cursor()
   
    # Create entry if user doesn't exist
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
    
    # Update or create user config
    cur.execute("""
        INSERT INTO settings(username, config) VALUES(?, ?)
        ON CONFLICT(username) DO UPDATE SET config=excluded.config
    """, (username, json.dumps(data)))
    
    db.commit()
    db.close()
    return {"status": "ok"}

# ---------------- HTML UI ----------------
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

// Save config to backend
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

// Load config from backend
async function loadConfig() {{
    try {{
        const res = await fetch(`/api/config/{username}`);
        config = await res.json();
        applyConfigToUI();
    }} catch(e) {{
        console.error('Load failed:', e);
    }}
}}

// Apply config to UI
function applyConfigToUI() {{
    // Toggles
    document.querySelectorAll('.toggle[data-setting]').forEach(toggle => {{
        const setting = toggle.dataset.setting;
        const [section, key] = setting.split('.');
        if (config[section] && config[section][key] !== undefined) {{
            toggle.classList.toggle('active', config[section][key]);
        }}
    }});
    
    // Keybinds
    document.querySelectorAll('.keybind-picker[data-setting]').forEach(picker => {{
        const setting = picker.dataset.setting;
        const [section, key] = setting.split('.');
        if (config[section] && config[section][key] !== undefined) {{
            picker.textContent = config[section][key];
        }}
    }});
    
    // Sliders
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

// Toggle click handlers
document.querySelectorAll('.toggle[data-setting]').forEach(toggle => {{
    toggle.addEventListener('click', () => {{
        toggle.classList.toggle('active');
        const setting = toggle.dataset.setting;
        const [section, key] = setting.split('.');
        config[section][key] = toggle.classList.contains('active');
        saveConfig();
    }});
}});

// Keybind picker
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

// Search functionality
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

// Slider system
const sliders = {{}};

// Decimal slider (Delay, Prediction)
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

// Integer slider (Max Studs)
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

// Initialize sliders
sliders.delay = createDecimalSlider('delaySlider', 'delayFill', 'delayValue', 0.05, 0.01, 1.00, 0.01, 'triggerbot.Delay');
sliders.maxStuds = createIntSlider('maxStudsSlider', 'maxStudsFill', 'maxStudsValue', 120, 300, 150, 'triggerbot.MaxStuds');
sliders.pred = createDecimalSlider('predSlider', 'predFill', 'predValue', 0.10, 0.01, 1.00, 0.01, 'triggerbot.Prediction');

// Load initial config
loadConfig();

// Poll for updates every 1 second
setInterval(loadConfig, 1000);
</script>
</body>
</html>
"""
