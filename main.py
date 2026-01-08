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
        "Delay": 0.0,
        "MaxStuds": 120,
        "LimitStuds": True,
        "DeathCheck": True,
        "KnifeCheck": True,
        "TeamCheck": True,
        "TargetMode": False,
        "TargetKeybind": "Middle Mouse",
        "Prediction": 0.1,
    },
    "esp": {
        "Enabled": False,
        "Animation": True,
        "BaseColor": [255, 255, 255, 255],
        "WaveColor": [0, 0, 0, 255],
        "TextColor": [200, 200, 200, 255],
        "StudCheck": False,
        "MaxStuds": 500,
        "TeamCheck": True,
        "Skeleton": False,
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
    return {"success": True, "username": username}

# ---------------- Web Panel ----------------
@app.get("/{username}", response_class=HTMLResponse)
def web_panel(username: str = Path(..., description="Username")):
    return f"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>UI Remake - {username}</title>
<style>
/* ================= RESET ================= */
* {{
    box-sizing: border-box;
    margin: 0;
    padding: 0;
}}
/* ================= COLORS ================= */
:root {{
    --bg-main: #0d0f12;
    --bg-panel: #111418;
    --bg-panel-soft: #15191e;
    --bg-top: #0b0d10;
    --border-main: #2a2f36;
    --border-soft: #1f242b;
    --text-main: #e6e6e6;
    --text-dim: #9aa0a6;
    --text-faint: #6f7680;
    --accent: #7fd1ff;
    --accent-soft: rgba(127,209,255,0.25);
    --toggle-off: transparent;
    --toggle-on: #a78bfa;
}}
/* ================= BODY ================= */
body {{
    background: radial-gradient(circle at top, #141821, #0b0d10 60%);
    font-family: "Segoe UI", Inter, system-ui, sans-serif;
    color: var(--text-main);
    height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
}}
/* ================= WINDOW ================= */
.window {{
    width: 820px;
    height: 540px;
    background: linear-gradient(#0f1216, #0b0d10);
    border: 1px solid var(--border-main);
    border-radius: 6px;
    box-shadow:
        0 0 0 1px rgba(255,255,255,0.02),
        0 20px 50px rgba(0,0,0,0.6);
    overflow: hidden;
}}
/* ================= TOP BAR ================= */
.topbar {{
    height: 48px;
    background: linear-gradient(#101419, #0b0e12);
    border-bottom: 1px solid var(--border-soft);
    display: flex;
    align-items: center;
    padding: 0 14px;
    gap: 18px;
}}
.logo {{
    width: 24px;
    height: 24px;
    object-fit: contain;
}}
.tabs {{
    display: flex;
    gap: 18px;
}}
.tab {{
    font-size: 13px;
    color: var(--text-dim);
    cursor: pointer;
    transition: color 0.2s;
}}
.tab:hover {{
    color: var(--text-main);
}}
.tab.active {{
    color: var(--text-main);
}}
.search-container {{
    margin-left: auto;
    display: flex;
    align-items: center;
    gap: 8px;
    background: #0c0f13;
    border: 1px solid var(--border-soft);
    border-radius: 4px;
    padding: 6px 10px;
}}
.search-icon {{
    width: 14px;
    height: 14px;
    opacity: 0.5;
}}
.search {{
    background: transparent;
    border: none;
    outline: none;
    font-size: 12px;
    color: var(--text-faint);
    width: 180px;
}}
.search::placeholder {{
    color: var(--text-faint);
}}
/* ================= CONTENT ================= */
.content {{
    display: flex;
    gap: 14px;
    padding: 14px;
    height: calc(100% - 48px);
}}
.tab-content {{
    display: none;
    width: 100%;
}}
.tab-content.active {{
    display: flex;
    gap: 14px;
}}
/* ================= PANELS ================= */
.panel {{
    background:
        linear-gradient(180deg, #12161b, #0e1116);
    border: 1px solid var(--border-soft);
    border-radius: 4px;
    padding: 10px;
    overflow-y: auto;
}}
.panel::-webkit-scrollbar {{
    width: 6px;
}}
.panel::-webkit-scrollbar-track {{
    background: #0c0f13;
    border-radius: 3px;
}}
.panel::-webkit-scrollbar-thumb {{
    background: var(--border-main);
    border-radius: 3px;
}}
.panel-title {{
    font-size: 12px;
    text-transform: lowercase;
    color: var(--text-dim);
    margin-bottom: 8px;
}}
/* ================= LEFT SIDE ================= */
.left {{
    width: 240px;
    display: flex;
    flex-direction: column;
    gap: 14px;
}}
/* ================= RIGHT SIDE ================= */
.right {{
    flex: 1;
}}
/* ================= ROW ================= */
.row {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 6px 4px;
    font-size: 12px;
    color: var(--text-dim);
}}
.row + .row {{
    border-top: 1px solid rgba(255,255,255,0.03);
}}
.row.highlight {{
    background: rgba(167, 139, 250, 0.2);
    animation: highlight-fade 2s ease-out;
}}
@keyframes highlight-fade {{
    0% {{ background: rgba(167, 139, 250, 0.4); }}
    100% {{ background: transparent; }}
}}
/* ================= ROW CONTROLS ================= */
.row-controls {{
    display: flex;
    align-items: center;
    gap: 6px;
}}
/* ================= TOGGLE ================= */
.toggle {{
    width: 16px;
    height: 16px;
    background: var(--toggle-off);
    border: 1px solid var(--border-soft);
    border-radius: 2px;
    cursor: pointer;
    transition: background-color 0.3s ease;
}}
.toggle.on {{
    background: var(--toggle-on);
    border-color: var(--toggle-on);
}}
/* ================= CUSTOM INPUT ================= */
.custom-input-wrapper {{
    display: flex;
    align-items: center;
    background: #0c0f13;
    border: 1px solid var(--border-soft);
    border-radius: 4px;
    padding: 4px 8px;
    width: 80px;
}}
.custom-input {{
    background: transparent;
    border: none;
    outline: none;
    font-size: 11px;
    color: var(--text-dim);
    width: 100%;
    text-align: right;
}}
.custom-input-small {{
    width: 60px;
}}
/* ================= SLIDER ================= */
.slider-container {{
    width: 120px;
    position: relative;
}}
.slider-wrapper {{
    position: relative;
    height: 20px;
    background: transparent;
    border: 1px solid var(--border-soft);
    border-radius: 3px;
    overflow: hidden;
}}
.slider-fill {{
    position: absolute;
    left: 0;
    top: 0;
    height: 100%;
    background: var(--toggle-on);
    transition: width 0.1s;
    pointer-events: none;
}}
.slider-label {{
    position: absolute;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    font-size: 9px;
    color: #ffffff;
    pointer-events: none;
    z-index: 2;
    font-weight: 600;
    transition: color 0.1s;
}}
.slider {{
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    opacity: 0;
    cursor: pointer;
    z-index: 1;
}}
/* ================= COLOR SWATCH ================= */
.color {{
    width: 28px;
    height: 14px;
    background: linear-gradient(45deg,#9aa0a6,#e6e6e6);
    border-radius: 2px;
    border: 1px solid rgba(0,0,0,0.6);
    cursor: pointer;
}}
/* ================= CUSTOM DROPDOWN ================= */
.custom-select {{
    position: relative;
    width: 120px;
}}
.select-selected {{
    background: #0c0f13;
    border: 1px solid var(--border-soft);
    padding: 4px 8px;
    border-radius: 3px;
    font-size: 11px;
    color: var(--text-dim);
    cursor: pointer;
    display: flex;
    justify-content: space-between;
    align-items: center;
}}
.select-selected:hover {{
    background: #12161b;
}}
.select-selected::after {{
    content: "▼";
    font-size: 8px;
    color: var(--text-faint);
}}
.select-items {{
    position: absolute;
    background: #0c0f13;
    border: 1px solid var(--border-soft);
    border-radius: 3px;
    top: 100%;
    left: 0;
    right: 0;
    z-index: 99;
    margin-top: 2px;
    display: none;
    max-height: 150px;
    overflow-y: auto;
}}
.select-items::-webkit-scrollbar {{
    width: 4px;
}}
.select-items::-webkit-scrollbar-track {{
    background: #0c0f13;
}}
.select-items::-webkit-scrollbar-thumb {{
    background: var(--border-main);
    border-radius: 2px;
}}
.select-items.show {{
    display: block;
}}
.select-item {{
    padding: 6px 8px;
    font-size: 11px;
    color: var(--text-dim);
    cursor: pointer;
    transition: all 0.15s;
}}
.select-item:hover {{
    background: var(--toggle-on);
    color: var(--text-main);
}}
.select-item.selected {{
    background: rgba(167, 139, 250, 0.2);
    color: var(--text-main);
}}
/* ================= BUTTON ================= */
.button {{
    margin-top: 10px;
    width: 100%;
    background: linear-gradient(#151a20,#0e1116);
    border: 1px solid var(--border-soft);
    border-radius: 3px;
    padding: 8px;
    text-align: center;
    font-size: 12px;
    color: var(--text-dim);
    cursor: pointer;
    transition: background 0.2s;
}}
.button:hover {{
    background: linear-gradient(#1a1f26,#12161b);
}}
.keybind-btn {{
    background: #0c0f13;
    border: 1px solid var(--border-soft);
    padding: 2px 6px;
    border-radius: 2px;
    font-size: 9px;
    color: var(--text-dim);
    cursor: pointer;
    min-width: 40px;
    text-align: center;
}}
.keybind-btn:hover {{
    background: #12161b;
}}
.keybind-btn.listening {{
    color: #ffffff;
}}
</style>
</head>
<body>
<div class="window">
    <div class="topbar">
        <img src="https://image2url.com/r2/bucket1/images/1767835198897-45b69784-a6ec-4151-947a-7d633e4797b8.png" alt="logo" class="logo">
        <div class="tabs">
            <div class="tab active" data-tab="aimbot">aimbot</div>
            <div class="tab" data-tab="visuals">visuals</div>
            <div class="tab" data-tab="misc">misc</div>
            <div class="tab" data-tab="settings">settings</div>
        </div>
        <div class="search-container">
            <img src="https://img.icons8.com/?size=100&id=7695&format=png&color=FFFFFF" alt="search" class="search-icon">
            <input type="text" class="search" id="searchInput" placeholder="search">
        </div>
    </div>
    <div class="content">
        <!-- AIMBOT TAB (CAMLOCK) -->
        <div class="tab-content active" id="aimbot">
            <div class="left">
                <div class="panel">
                    <div class="panel-title">camlock</div>
                    <div class="row" data-search="enabled keybind camlock aimbot">
                        <span>enabled</span>
                        <div class="row-controls">
                            <div class="toggle on" data-setting="camlock.Enabled"></div>
                            <div class="keybind-btn" data-setting="camlock.Keybind">Q</div>
                        </div>
                    </div>
                    <div class="row" data-search="fov field of view camlock aimbot"><span>fov</span><div class="custom-input-wrapper"><input type="number" class="custom-input" value="280.0" step="1" data-setting="camlock.FOV"></div></div>
                    <div class="row" data-search="smooth x smoothing camlock aimbot"><span>smooth x</span><div class="custom-input-wrapper custom-input-small"><input type="number" class="custom-input" value="14.0" step="0.1" data-setting="camlock.SmoothX"></div></div>
                    <div class="row" data-search="smooth y smoothing camlock aimbot"><span>smooth y</span><div class="custom-input-wrapper custom-input-small"><input type="number" class="custom-input" value="14.0" step="0.1" data-setting="camlock.SmoothY"></div></div>
                    <div class="row" data-search="prediction camlock aimbot"><span>prediction</span><div class="custom-input-wrapper custom-input-small"><input type="number" class="custom-input" value="0.14" step="0.01" data-setting="camlock.Prediction"></div></div>
                    <div class="row" data-search="max studs distance camlock aimbot"><span>max studs</span><div class="custom-input-wrapper"><input type="number" class="custom-input" value="120.0" step="1" data-setting="camlock.MaxStuds"></div></div>
                </div>
            </div>
            <div class="right panel">
                <div class="panel-title">settings</div>
                <div class="row" data-search="unlock death camlock aimbot"><span>unlock on death</span><div class="toggle on" data-setting="camlock.UnlockOnDeath"></div></div>
                <div class="row" data-search="self death check camlock aimbot"><span>self death check</span><div class="toggle on" data-setting="camlock.SelfDeathCheck"></div></div>
                <div class="row" data-search="body part target camlock aimbot">
                    <span>body part</span>
                    <div class="custom-select" data-setting="camlock.BodyPart">
                        <div class="select-selected">Head</div>
                        <div class="select-items">
                            <div class="select-item selected" data-value="Head">Head</div>
                            <div class="select-item" data-value="Torso">Torso</div>
                            <div class="select-item" data-value="UpperTorso">UpperTorso</div>
                            <div class="select-item" data-value="LowerTorso">LowerTorso</div>
                        </div>
                    </div>
                </div>
                <div class="row" data-search="closest part camlock aimbot"><span>closest part</span><div class="toggle" data-setting="camlock.ClosestPart"></div></div>
                <div class="row" data-search="scale toggle camlock aimbot"><span>scale toggle</span><div class="toggle" data-setting="camlock.ScaleToggle"></div></div>
                <div class="row" data-search="scale camlock aimbot">
                    <span>scale</span>
                    <div class="slider-container">
                        <div class="slider-wrapper">
                            <div class="slider-fill" id="scaleFill"></div>
                            <div class="slider-label" id="scaleLabel">3/5</div>
                            <input type="range" class="slider" id="scaleSlider" min="1" max="5" step="1" value="3" data-setting="camlock.Scale">
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <!-- VISUALS TAB (ESP) -->
        <div class="tab-content" id="visuals">
            <div class="left">
                <div class="panel">
                    <div class="panel-title">esp</div>
                    <div class="row" data-search="enabled esp visuals"><span>enabled</span><div class="toggle" data-setting="esp.Enabled"></div></div>
                    <div class="row" data-search="animation esp visuals"><span>animation</span><div class="toggle on" data-setting="esp.Animation"></div></div>
                    <div class="row" data-search="skeleton esp visuals"><span>skeleton</span><div class="toggle" data-setting="esp.Skeleton"></div></div>
                    <div class="row" data-search="team check esp visuals"><span>team check</span><div class="toggle on" data-setting="esp.TeamCheck"></div></div>
                    <div class="row" data-search="stud check distance esp visuals"><span>stud check</span><div class="toggle" data-setting="esp.StudCheck"></div></div>
                    <div class="row" data-search="max studs distance esp visuals"><span>max studs</span><div class="custom-input-wrapper"><input type="number" class="custom-input" value="500" step="10" data-setting="esp.MaxStuds"></div></div>
                </div>
            </div>
            <div class="right panel">
                <div class="panel-title">colors</div>
                <div class="row" data-search="base color esp visuals"><span>base color</span><div class="color" style="background: rgb(255,255,255)" data-setting="esp.BaseColor"></div></div>
                <div class="row" data-search="wave color esp visuals"><span>wave color</span><div class="color" style="background: rgb(0,0,0)" data-setting="esp.WaveColor"></div></div>
                <div class="row" data-search="text color esp visuals"><span>text color</span><div class="color" style="background: rgb(200,200,200)" data-setting="esp.TextColor"></div></div>
            </div>
        </div>
        <!-- MISC TAB (TRIGGERBOT) -->
        <div class="tab-content" id="misc">
            <div class="left">
                <div class="panel">
                    <div class="panel-title">triggerbot</div>
                    <div class="row" data-search="enabled keybind triggerbot misc">
                        <span>enabled</span>
                        <div class="row-controls">
                            <div class="toggle on" data-setting="triggerbot.Enabled"></div>
                            <div class="keybind-btn" data-setting="triggerbot.Keybind">RMB</div>
                        </div>
                    </div>
                    <div class="row" data-search="delay triggerbot misc"><span>delay</span><div class="custom-input-wrapper custom-input-small"><input type="number" class="custom-input" value="0.0" step="0.01" min="0" data-setting="triggerbot.Delay"></div></div>
                    <div class="row" data-search="max studs distance triggerbot misc"><span>max studs</span><div class="custom-input-wrapper"><input type="number" class="custom-input" value="120" step="1" data-setting="triggerbot.MaxStuds"></div></div>
                    <div class="row" data-search="prediction triggerbot misc"><span>prediction</span><div class="custom-input-wrapper custom-input-small"><input type="number" class="custom-input" value="0.1" step="0.01" data-setting="triggerbot.Prediction"></div></div>
                </div>
            </div>
            <div class="right panel">
                <div class="panel-title">checks</div>
                <div class="row" data-search="limit studs distance triggerbot misc"><span>limit studs</span><div class="toggle on" data-setting="triggerbot.LimitStuds"></div></div>
                <div class="row" data-search="death check triggerbot misc"><span>death check</span><div class="toggle on" data-setting="triggerbot.DeathCheck"></div></div>
                <div class="row" data-search="knife check triggerbot misc"><span>knife check</span><div class="toggle on" data-setting="triggerbot.KnifeCheck"></div></div>
                <div class="row" data-search="team check triggerbot misc"><span>team check</span><div class="toggle on" data-setting="triggerbot.TeamCheck"></div></div>
                <div class="row" data-search="target mode keybind triggerbot misc">
                    <span>target mode</span>
                    <div class="row-controls">
                        <div class="toggle" data-setting="triggerbot.TargetMode"></div>
                        <div class="keybind-btn" data-setting="triggerbot.TargetKeybind">MMB</div>
                    </div>
                </div>
            </div>
        </div>
        <!-- SETTINGS TAB -->
        <div class="tab-content" id="settings">
            <div class="panel" style="width: 100%;">
                <div class="panel-title">settings</div>
                <div class="row"><span>coming soon</span></div>
            </div>
        </div>
    </div>
</div>
<script>
const USERNAME = "{username}";
const API_URL = `/api/config/${{USERNAME}}`;

// Configuration object
let config = {{}};

// Load config from server
async function loadConfig() {{
    try {{
        const res = await fetch(API_URL);
        const data = await res.json();
        config = data;
        applyConfigToUI();
    }} catch (err) {{
        console.error('Failed to load config:', err);
    }}
}}

// Apply config to UI elements
function applyConfigToUI() {{
    // Apply toggles
    document.querySelectorAll('.toggle').forEach(toggle => {{
        const setting = toggle.dataset.setting;
        if (setting) {{
            const [section, key] = setting.split('.');
            if (config[section] && config[section][key] !== undefined) {{
                toggle.classList.toggle('on', config[section][key]);
            }}
        }}
    }});
    
    // Apply inputs
    document.querySelectorAll('.custom-input').forEach(input => {{
        const setting = input.dataset.setting;
        if (setting) {{
            const [section, key] = setting.split('.');
            if (config[section] && config[section][key] !== undefined) {{
                input.value = config[section][key];
            }}
        }}
    }});
    
    // Apply keybinds
    document.querySelectorAll('.keybind-btn').forEach(btn => {{
        const setting = btn.dataset.setting;
        if (setting) {{
            const [section, key] = setting.split('.');
            if (config[section] && config[section][key] !== undefined) {{
                btn.textContent = config[section][key];
            }}
        }}
    }});
    
    // Apply dropdowns
    document.querySelectorAll('.custom-select').forEach(select => {{
        const setting = select.dataset.setting;
        if (setting) {{
            const [section, key] = setting.split('.');
            if (config[section] && config[section][key] !== undefined) {{
                const value = config[section][key];
                select.querySelector('.select-selected').textContent = value;
                select.querySelectorAll('.select-item').forEach(item => {{
                    item.classList.toggle('selected', item.dataset.value === value);
                }});
            }}
        }}
    }});
    
    // Apply slider
    if (config.camlock && config.camlock.Scale !== undefined) {{
        const slider = document.getElementById('scaleSlider');
        const value = Math.round(config.camlock.Scale * 5);
        slider.value = value;
        updateSlider();
    }}
    
    // Apply colors
    document.querySelectorAll('.color').forEach(color => {{
        const setting = color.dataset.setting;
        if (setting) {{
            const [section, key] = setting.split('.');
            if (config[section] && config[section][key] !== undefined) {{
                const [r, g, b] = config[section][key];
                color.style.background = `rgb(${{r}},${{g}},${{b}})`;
            }}
        }}
    }});
}}

// Save config to server
async function saveConfig() {{
    try {{
        await fetch(API_URL, {{
            method: 'POST',
            headers: {{ 'Content-Type': 'application/json' }},
            body: JSON.stringify(config)
        }});
    }} catch (err) {{
        console.error('Failed to save config:', err);
    }}
}}

// Search functionality
const searchInput = document.getElementById('searchInput');
searchInput.addEventListener('input', (e) => {{
    const query = e.target.value.toLowerCase().trim();
   
    if (query === '') {{
        document.querySelectorAll('.row.highlight').forEach(row => {{
            row.classList.remove('highlight');
        }});
        return;
    }}
   
    const allRows = document.querySelectorAll('.row[data-search]');
    let foundMatch = null;
   
    allRows.forEach(row => {{
        const searchTerms = row.getAttribute('data-search').toLowerCase();
        if (searchTerms.includes(query)) {{
            if (!foundMatch) foundMatch = row;
        }}
    }});
   
    if (foundMatch) {{
        const tabContent = foundMatch.closest('.tab-content');
        const tabId = tabContent.id;
       
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
       
        document.querySelector(`.tab[data-tab="${{tabId}}"]`).classList.add('active');
        tabContent.classList.add('active');
       
        document.querySelectorAll('.row.highlight').forEach(row => {{
            row.classList.remove('highlight');
        }});
       
        foundMatch.classList.add('highlight');
       
        setTimeout(() => {{
            foundMatch.scrollIntoView({{ behavior: 'smooth', block: 'center' }});
        }}, 100);
    }}
}});

// Tab switching
document.querySelectorAll('.tab').forEach(tab => {{
    tab.addEventListener('click', () => {{
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
       
        tab.classList.add('active');
        document.getElementById(tab.dataset.tab).classList.add('active');
    }});
}});

// Toggle handling
document.querySelectorAll('.toggle').forEach(toggle => {{
    toggle.addEventListener('click', () => {{
        toggle.classList.toggle('on');
        const setting = toggle.dataset.setting;
        if (setting) {{
            const [section, key] = setting.split('.');
            config[section][key] = toggle.classList.contains('on');
            saveConfig();
        }}
    }});
}});

// Custom input handling
document.querySelectorAll('.custom-input').forEach(input => {{
    input.addEventListener('change', () => {{
        const setting = input.dataset.setting;
        if (setting) {{
            const [section, key] = setting.split('.');
            config[section][key] = parseFloat(input.value);
            saveConfig();
        }}
    }});
}});

// Custom dropdown handling
document.querySelectorAll('.custom-select').forEach(select => {{
    const selected = select.querySelector('.select-selected');
    const itemsContainer = select.querySelector('.select-items');
    const items = select.querySelectorAll('.select-item');
   
    selected.addEventListener('click', (e) => {{
        e.stopPropagation();
        document.querySelectorAll('.select-items').forEach(s => {{
            if (s !== itemsContainer) s.classList.remove('show');
        }});
        itemsContainer.classList.toggle('show');
    }});
   
    items.forEach(item => {{
        item.addEventListener('click', () => {{
            const value = item.dataset.value;
            selected.textContent = value;
           
            items.forEach(i => i.classList.remove('selected'));
            item.classList.add('selected');
           
            itemsContainer.classList.remove('show');
           
            const setting = select.dataset.setting;
            if (setting) {{
                const [section, key] = setting.split('.');
                config[section][key] = value;
                saveConfig();
            }}
        }});
    }});
}});

// Close dropdowns when clicking outside
document.addEventListener('click', () => {{
    document.querySelectorAll('.select-items').forEach(s => s.classList.remove('show'));
}});

// Custom slider handling with dynamic label color
const scaleSlider = document.getElementById('scaleSlider');
const scaleFill = document.getElementById('scaleFill');
const scaleLabel = document.getElementById('scaleLabel');

function updateSlider() {{
    const value = parseInt(scaleSlider.value);
    const max = parseInt(scaleSlider.max);
    const percentage = ((value - 1) / (max - 1)) * 100;
   
    scaleFill.style.width = percentage + '%';
    scaleLabel.textContent = `${{value}}/5`;
   
    if (percentage >= 50) {{
        scaleLabel.style.color = '#000000';
    }} else {{
        scaleLabel.style.color = '#ffffff';
    }}
   
    const setting = scaleSlider.dataset.setting;
    if (setting) {{
        const [section, key] = setting.split('.');
        config[section][key] = value / 5;
        saveConfig();
    }}
}}

scaleSlider.addEventListener('input', updateSlider);

// Color picker handling
document.querySelectorAll('.color').forEach(color => {{
    color.addEventListener('click', () => {{
        const input = document.createElement('input');
        input.type = 'color';
        const rgb = color.style.background.match(/\\d+/g);
        if (rgb) {{
            const hex = '#' + rgb.slice(0, 3).map(x => {{
                const hex = parseInt(x).toString(16);
                return hex.length === 1 ? '0' + hex : hex;
            }}).join('');
            input.value = hex;
        }}
       
        input.addEventListener('change', () => {{
            const hex = input.value;
            const r = parseInt(hex.slice(1, 3), 16);
            const g = parseInt(hex.slice(3, 5), 16);
            const b = parseInt(hex.slice(5, 7), 16);
           
            color.style.background = `rgb(${{r}},${{g}},${{b}})`;
           
            const setting = color.dataset.setting;
            if (setting) {{
                const [section, key] = setting.split('.');
                config[section][key] = [r, g, b, 255];
                saveConfig();
            }}
        }});
       
        input.click();
    }});
}});

// Keybind handling
document.querySelectorAll('.keybind-btn').forEach(btn => {{
    btn.addEventListener('click', () => {{
        const oldText = btn.textContent;
        btn.textContent = '...';
        btn.classList.add('listening');
       
        const handleKey = (e) => {{
            e.preventDefault();
            let key = e.key;
           
            if (e.button === 0) key = 'LMB';
            else if (e.button === 1) key = 'MMB';
            else if (e.button === 2) key = 'RMB';
            else if (e.key.length === 1) key = e.key.toUpperCase();
           
            btn.textContent = key;
            btn.classList.remove('listening');
           
            const setting = btn.dataset.setting;
            if (setting) {{
                const [section, settingKey] = setting.split('.');
                config[section][settingKey] = key;
                saveConfig();
            }}
           
            document.removeEventListener('keydown', handleKey);
            document.removeEventListener('mousedown', handleKey);
        }};
       
        document.addEventListener('keydown', handleKey);
        document.addEventListener('mousedown', handleKey);
       
        setTimeout(() => {{
            document.removeEventListener('keydown', handleKey);
            document.removeEventListener('mousedown', handleKey);
            if (btn.textContent === '...') {{
                btn.textContent = oldText;
                btn.classList.remove('listening');
            }}
        }}, 5000);
    }});
}});

// Initialize
loadConfig();
setInterval(loadConfig, 2000); // Poll for updates every 2 seconds
</script>
</body>
</html>
    """
