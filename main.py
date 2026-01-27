from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import psycopg2
import sqlite3
import os
import json
import secrets
from datetime import datetime, timedelta
import re

app = FastAPI()

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
    return sqlite3.connect("local.db")

def q(query):
    return query if USE_POSTGRES else query.replace("%s", "?")

def init_db():
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
        try: cur.execute("ALTER TABLE keys ADD COLUMN IF NOT EXISTS hwid_resets INTEGER DEFAULT 0"); db.commit()
        except: pass
        
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
        
        cur.execute("""CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            config TEXT NOT NULL
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
        try: cur.execute("ALTER TABLE keys ADD COLUMN hwid_resets INTEGER DEFAULT 0"); db.commit()
        except: pass
        
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
        
        cur.execute("""CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            config TEXT NOT NULL
        )""")
    
    db.commit()
    db.close()
    print("✅ Database initialized")

# ────────────────────────────────────────────────
# Pydantic Models (all of them this time)
# ────────────────────────────────────────────────
class KeyValidate(BaseModel):
    key: str
    hwid: str

class SavedConfigRequest(BaseModel):
    config_name: str
    config_data: dict

class KeyCreate(BaseModel):
    duration: str
    created_by: str

class PublicConfig(BaseModel):
    config_name: str
    author_name: str
    game_name: str
    description: str
    config_data: dict

class RedeemRequest(BaseModel):
    key: str
    discord_id: str

# ────────────────────────────────────────────────
# Anti-DevTools Protection
# ────────────────────────────────────────────────
ANTI_DEVTOOLS_SCRIPT = """
<script>
(function(){
  'use strict';
  const BLOCK = '/blocked';
  document.addEventListener('contextmenu', e => { e.preventDefault(); location.replace(BLOCK); });
  document.addEventListener('keydown', e => {
    const k = e.key?.toLowerCase?.() || '';
    const c = e.keyCode || e.which;
    if (c === 123 || k === 'f12' ||
        (e.ctrlKey && e.shiftKey && (k==='i'||k==='j'||k==='c'||k==='u')) ||
        (e.ctrlKey && (k==='u'||k==='s'))) {
      e.preventDefault();
      location.replace(BLOCK);
    }
  });
  let devOpen = false;
  function checkDev() {
    if ((window.outerWidth - window.innerWidth > 100) || (window.outerHeight - window.innerHeight > 100)) {
      if (!devOpen) { devOpen = true; location.replace(BLOCK); }
    } else devOpen = false;
  }
  setInterval(checkDev, 400);
  setInterval(() => {
    const s = performance.now(); debugger; const e = performance.now();
    if (e - s > 60) location.replace(BLOCK);
  }, 800);
})();
</script>
"""

BLOCKED_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Blocked - Axion</title>
  <style>
    body{margin:0;height:100vh;background:#0a0a0a;color:#eee;font-family:Arial;display:flex;align-items:center;justify-content:center;}
    .box{text-align:center;padding:60px 40px;background:#111;border:1px solid #444;border-radius:12px;max-width:500px;}
    h1{font-size:48px;color:#f44;margin:0 0 20px;}
    p{font-size:18px;color:#aaa;line-height:1.6;}
    a{color:#4af;text-decoration:none;font-size:18px;}
    a:hover{text-decoration:underline;}
  </style>
</head>
<body>
  <div class="box">
    <h1>ACCESS BLOCKED</h1>
    <p>Developer tools detected.<br>Close them and return.</p>
    <br>
    <a href="/">← Back to Home</a>
  </div>
  <script>
    document.addEventListener('contextmenu',e=>e.preventDefault());
    document.addEventListener('keydown',e=>{
      if(e.key==='F12'||e.keyCode===123||
         (e.ctrlKey&&e.shiftKey&&(e.key==='I'||e.key==='J'||e.key==='C'||e.key==='U'))) e.preventDefault();
    });
    setTimeout(()=>location.href='/', 10000);
  </script>
</body>
</html>"""

@app.get("/blocked", response_class=HTMLResponse)
def blocked():
    return BLOCKED_HTML

def protect_html(html: str) -> str:
    if '</body>' in html:
        return html.replace('</body>', ANTI_DEVTOOLS_SCRIPT + '</body>')
    return html + ANTI_DEVTOOLS_SCRIPT

# ────────────────────────────────────────────────
# Homepage (full, no cut)
# ────────────────────────────────────────────────
_INDEX_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Axion — Home</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body, html { height: 100%; background-color: rgb(12, 12, 12); color: #fff; font-family: system-ui, -apple-system, sans-serif; overflow-x: hidden; }
    .image-container { width: 100%; height: 100vh; background-image: url('https://image2url.com/r2/default/images/1768674767693-4fff24d5-abfa-4be9-a3ee-bd44454bad9f.blob'); background-size: cover; background-position: center; opacity: 0.01; position: fixed; inset: 0; z-index: 1; }
    .navbar { position: fixed; top: 0; left: 0; right: 0; padding: 1.2rem 2rem; display: flex; justify-content: space-between; align-items: center; z-index: 100; backdrop-filter: blur(12px); background: rgba(12, 12, 12, 0.6); border-bottom: 1px solid rgba(255,255,255,0.08); }
    .nav-links { display: flex; gap: 2rem; }
    .nav-links a { color: rgba(255, 255, 255, 0.6); text-decoration: none; font-size: 0.95rem; font-weight: 500; transition: color 0.3s; cursor: pointer; }
    .nav-links a:hover { color: rgba(255, 255, 255, 1); }
    .nav-right { display: flex; gap: 1.5rem; align-items: center; }
    .nav-right a { color: rgba(255, 255, 255, 0.7); text-decoration: none; font-size: 0.95rem; font-weight: 500; transition: color 0.3s; }
    .nav-right a:hover { color: rgba(255, 255, 255, 1); }
    .login-btn { padding: 8px 20px; background: rgba(255,255,255,0.1); border: 1px solid rgba(255,255,255,0.2); border-radius: 6px; color: white; cursor: pointer; transition: all 0.2s; font-size: 0.9rem; }
    .login-btn:hover { background: rgba(255,255,255,0.15); }
    .user-info { padding: 8px 20px; background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.15); border-radius: 6px; color: white; cursor: pointer; transition: all 0.2s; font-size: 0.9rem; }
    .user-info:hover { background: rgba(255,255,255,0.1); }
    .content { position: fixed; inset: 0; z-index: 5; overflow-y: auto; pointer-events: none; }
    .content > * { pointer-events: auto; }
    .page { position: absolute; inset: 0; display: flex; flex-direction: column; justify-content: center; align-items: center; opacity: 0; pointer-events: none; transition: opacity 0.6s ease; }
    .page.active { opacity: 1; pointer-events: auto; }
    .configs-page { justify-content: flex-start; padding-top: 15vh; }
    .about-page { padding: 20px; }
    .about-page .description { max-width: 600px; text-align: center; font-size: 18px; line-height: 1.8; color: #aaa; margin-top: 40px; }
    .pricing-page { justify-content: flex-start; padding-top: 15vh; }
    .pricing-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 30px; width: 90%; max-width: 1000px; margin-top: 60px; }
    .pricing-card { background: rgba(18,18,22,0.6); border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; padding: 32px; text-align: center; transition: all 0.3s; }
    .pricing-card:hover { transform: translateY(-8px); border-color: rgba(255,255,255,0.2); background: rgba(22,22,26,0.7); }
    .pricing-card.featured { border-color: rgba(255,255,255,0.3); background: rgba(25,25,30,0.8); }
    .plan-name { font-size: 24px; font-weight: 700; color: #fff; margin-bottom: 16px; }
    .plan-price { font-size: 48px; font-weight: 900; color: #fff; margin-bottom: 8px; }
    .plan-duration { font-size: 14px; color: #888; margin-bottom: 24px; }
    .plan-features { list-style: none; text-align: left; margin-top: 24px; }
    .plan-features li { padding: 10px 0; color: #aaa; font-size: 15px; border-bottom: 1px solid rgba(255,255,255,0.05); }
    .plan-features li:last-child { border-bottom: none; }
    .title-wrapper { display: flex; gap: 0.8rem; flex-wrap: wrap; justify-content: center; }
    .title-word { font-size: 3.8rem; font-weight: 900; letter-spacing: -1.5px; text-shadow: 0 0 25px rgba(0,0,0,0.7); }
    .configs-container { width: 90%; max-width: 1200px; margin-top: 60px; }
    .login-required { text-align: center; padding: 60px 20px; background: rgba(18,18,22,0.5); border-radius: 12px; border: 1px solid rgba(255,255,255,0.08); }
    .create-btn { padding: 14px 32px; background: transparent; border: 1px solid rgba(255,255,255,0.15); border-radius: 8px; color: #fff; font-size: 15px; cursor: pointer; transition: all 0.3s ease; margin-bottom: 30px; backdrop-filter: blur(10px); -webkit-backdrop-filter: blur(10px); }
    .create-btn:hover { background: rgba(255,255,255,0.05); border-color: rgba(255,255,255,0.25); transform: translateY(-2px); }
    .pagination { display: flex; justify-content: center; gap: 10px; margin-top: 30px; margin-bottom: 60px; }
    .page-btn { padding: 8px 16px; background: transparent; border: 1px solid rgba(255,255,255,0.15); border-radius: 6px; color: #fff; font-size: 14px; cursor: pointer; transition: all 0.2s; backdrop-filter: blur(10px); }
    .page-btn:hover:not(:disabled) { background: rgba(255,255,255,0.05); border-color: rgba(255,255,255,0.25); }
    .page-btn.active { background: rgba(255,255,255,0.1); border-color: rgba(255,255,255,0.3); }
    .page-btn:disabled { opacity: 0.3; cursor: not-allowed; }
    .config-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(350px, 1fr)); gap: 20px; margin-bottom: 40px; }
    .config-card { background: rgba(25,25,30,0.6); border: 1px solid rgba(255,255,255,0.08); border-radius: 12px; padding: 24px; transition: all 0.3s; cursor: pointer; }
    .config-card:hover { background: rgba(30,30,35,0.7); border-color: rgba(255,255,255,0.15); transform: translateY(-4px); }
    .config-name { font-size: 20px; font-weight: 700; margin-bottom: 8px; }
    .config-game { font-size: 12px; color: #888; background: rgba(255,255,255,0.05); padding: 4px 10px; border-radius: 4px; display: inline-block; margin-bottom: 12px; }
    .config-description { font-size: 14px; color: #aaa; line-height: 1.5; margin: 12px 0; }
    .config-footer { display: flex; justify-content: space-between; align-items: center; margin-top: 16px; padding-top: 16px; border-top: 1px solid rgba(255,255,255,0.06); font-size: 13px; color: #666; }
    .modal { display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.85); backdrop-filter: blur(10px); z-index: 1000; justify-content: center; align-items: center; opacity: 0; transition: opacity 0.3s ease; }
    .modal.active { display: flex; animation: fadeIn 0.3s ease forwards; }
    @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
    .modal-content { background: #1a1a1f; border: 1px solid rgba(255,255,255,0.1); border-radius: 8px; padding: 24px; width: 90%; max-width: 460px; max-height: 80vh; overflow-y: auto; box-shadow: 0 20px 60px rgba(0,0,0,0.5); transform: scale(0.95); animation: modalZoom 0.3s ease forwards; }
    @keyframes modalZoom { from { transform: scale(0.95); } to { transform: scale(1); } }
    .modal-title { font-size: 20px; font-weight: 600; margin-bottom: 20px; color: #fff; }
    .form-group { margin-bottom: 16px; }
    .form-label { display: block; font-size: 13px; color: #888; margin-bottom: 6px; font-weight: 500; }
    .form-input, .form-select, .form-textarea { width: 100%; padding: 10px 14px; background: transparent; border: 1px solid rgba(255,255,255,0.12); border-radius: 6px; color: #fff; font-size: 14px; font-family: inherit; transition: all 0.2s; }
    .form-input:focus, .form-select:focus, .form-textarea:focus { outline: none; border-color: rgba(255,255,255,0.3); background: rgba(255,255,255,0.02); }
    .form-textarea { resize: vertical; min-height: 90px; }
    .form-select { cursor: pointer; }
    .form-select option { background: #1a1a1f; color: #fff; }
    .modal-actions { display: flex; gap: 10px; margin-top: 20px; }
    .modal-btn { flex: 1; padding: 11px; background: transparent; border: 1px solid rgba(255,255,255,0.15); border-radius: 6px; font-size: 14px; font-weight: 600; cursor: pointer; transition: all 0.2s; color: #fff; backdrop-filter: blur(5px); }
    .modal-btn:hover { background: rgba(255,255,255,0.05); border-color: rgba(255,255,255,0.25); }
    .config-detail-modal .modal-content { max-width: 600px; background: #16161a; padding: 28px; }
    .config-stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin: 20px 0; padding: 20px; background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.08); border-radius: 8px; }
    .stat-item { text-align: center; }
    .stat-label { font-size: 11px; color: #666; margin-bottom: 6px; text-transform: uppercase; letter-spacing: 0.5px; }
    .stat-value { font-size: 18px; font-weight: 700; color: #fff; }
    .detail-section { margin: 20px 0; }
    .detail-label { font-size: 12px; color: #666; margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.5px; }
    .detail-content { color: #aaa; line-height: 1.6; font-size: 14px; padding: 12px; background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.06); border-radius: 6px; }
    @media (max-width: 768px) { .title-word { font-size: 2.5rem; } .config-grid { grid-template-columns: 1fr; } .pricing-grid { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
  <div class="image-container"></div>
  <nav class="navbar">
    <div class="nav-links">
      <a onclick="showPage('home')">Home</a>
      <a onclick="showPage('about')">About</a>
      <a onclick="showPage('pricing')">Pricing</a>
      <a onclick="showPage('configs')">Configs</a>
    </div>
    <div class="nav-right">
      <a href="/dashboard" style="cursor:pointer">Dashboard</a>
      <div id="userArea"></div>
    </div>
  </nav>
  <div class="content">
    <div id="home" class="page active">
      <div class="title-wrapper">
        <span class="title-word" style="color:#ffffff;">WELCOME</span>
        <span class="title-word" style="color:#ffffff;">TO</span>
        <span class="title-word" style="color:#888888;">Axion</span>
      </div>
    </div>
    <div id="about" class="page about-page">
      <div class="title-wrapper">
        <span class="title-word" style="color:#ffffff;">About</span>
        <span class="title-word" style="color:#888888;">Axion</span>
      </div>
      <div class="description">
        Axion is a Da Hood external designed to integrate seamlessly in-game. It delivers smooth, reliable performance while bypassing PC checks, giving you a consistent edge during star tryouts and competitive play.
      </div>
    </div>
    <div id="pricing" class="page pricing-page">
      <div class="title-wrapper">
        <span class="title-word" style="color:#ffffff;">Pricing</span>
      </div>
      <div class="pricing-grid">
        <div class="pricing-card">
          <div class="plan-name">Weekly</div>
          <div class="plan-price">$5</div>
          <div class="plan-duration">7 days</div>
          <ul class="plan-features">
            <li>✓ Full access to Axion</li>
            <li>✓ All features unlocked</li>
            <li>✓ Discord support</li>
          </ul>
        </div>
        <div class="pricing-card">
          <div class="plan-name">Monthly</div>
          <div class="plan-price">$15</div>
          <div class="plan-duration">30 days</div>
          <ul class="plan-features">
            <li>✓ Full access to Axion</li>
            <li>✓ All features unlocked</li>
            <li>✓ Priority support</li>
          </ul>
        </div>
        <div class="pricing-card featured">
          <div class="plan-name">Lifetime</div>
          <div class="plan-price">$40</div>
          <div class="plan-duration">forever</div>
          <ul class="plan-features">
            <li>✓ Full access to Axion</li>
            <li>✓ All features unlocked</li>
            <li>✓ VIP support</li>
            <li>✓ Best value</li>
          </ul>
        </div>
      </div>
    </div>
    <div id="configs" class="page configs-page">
      <div class="title-wrapper">
        <span class="title-word" style="color:#ffffff;">Community</span>
        <span class="title-word" style="color:#888888;">Configs</span>
      </div>
      <div class="configs-container" id="configsContent">
        <div class="login-required">
          <h3 style="font-size: 24px; margin-bottom: 12px;">Login Required</h3>
          <p style="color: #888; margin-bottom: 20px;">Please login to view and create configs</p>
          <button class="login-btn" onclick="showLoginModal()">Login</button>
        </div>
      </div>
    </div>
  </div>
  <div class="modal" id="loginModal">
    <div class="modal-content">
      <h2 class="modal-title">Login to Axion</h2>
      <div class="form-group">
        <label class="form-label">License Key</label>
        <input type="text" class="form-input" id="licenseKeyInput" placeholder="XXXX-XXXX-XXXX-XXXX">
      </div>
      <div class="modal-actions">
        <button class="modal-btn" onclick="closeLoginModal()">Cancel</button>
        <button class="modal-btn" onclick="submitLogin()">Login</button>
      </div>
    </div>
  </div>
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
        <input type="text" class="form-input" id="configName" placeholder="e.g., Pro Camlock Settings">
      </div>
      <div class="form-group">
        <label class="form-label">Author Name</label>
        <input type="text" class="form-input" id="authorName" placeholder="Your name">
      </div>
      <div class="form-group">
        <label class="form-label">Game</label>
        <input type="text" class="form-input" id="gameName" placeholder="e.g., Da Hood, Hood Modded, etc.">
      </div>
      <div class="form-group">
        <label class="form-label">Description</label>
        <textarea class="form-textarea" id="configDescription" placeholder="Describe your config..."></textarea>
      </div>
      <div class="modal-actions">
        <button class="modal-btn" onclick="closeCreateModal()">Cancel</button>
        <button class="modal-btn" onclick="publishConfig()">Publish Config</button>
      </div>
    </div>
  </div>
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
      <div class="detail-section">
        <div class="detail-label">Description</div>
        <div class="detail-content" id="viewDescription">-</div>
      </div>
      <div class="modal-actions">
        <button class="modal-btn" onclick="closeViewModal()">Close</button>
        <button class="modal-btn" onclick="saveConfigToMenu()">Load to Menu</button>
      </div>
    </div>
  </div>
  <script>
    let currentUser = null;
    let allConfigs = [];
    let currentPage = 1;
    let currentViewConfig = null;
    const CONFIGS_PER_PAGE = 6;
    function showPage(pageId) {
      document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
      document.getElementById(pageId).classList.add('active');
      if (pageId === 'configs' && currentUser) loadConfigs();
    }
    function showLoginModal() { document.getElementById('loginModal').classList.add('active'); }
    function closeLoginModal() { document.getElementById('loginModal').classList.remove('active'); }
    async function submitLogin() {
      const licenseKey = document.getElementById('licenseKeyInput').value.trim();
      if (!licenseKey) return alert('Please enter your license key');
      try {
        const res = await fetch(`/api/validate`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ key: licenseKey, hwid: 'web-login' })
        });
        if (res.ok) {
          const data = await res.json();
          if (data.valid) {
            currentUser = { license_key: licenseKey };
            document.getElementById('userArea').innerHTML = `<div class="user-info" onclick="logout()"><span>${licenseKey.substring(0,12)}...</span></div>`;
            closeLoginModal();
            loadConfigs();
          } else alert('Invalid or expired license key');
        } else alert('Invalid license key');
      } catch (e) {
        alert('Connection error');
        console.error(e);
      }
    }
    function logout() {
      currentUser = null;
      document.getElementById('userArea').innerHTML = `<button class="login-btn" onclick="showLoginModal()">Login</button>`;
      document.getElementById('configsContent').innerHTML = `<div class="login-required"><h3 style="font-size:24px;margin-bottom:12px;">Login Required</h3><p style="color:#888;margin-bottom:20px;">Please login to view and create configs</p><button class="login-btn" onclick="showLoginModal()">Login</button></div>`;
    }
    async function loadConfigs() {
      try {
        const res = await fetch('/api/public-configs');
        const data = await res.json();
        allConfigs = data.configs || [];
        renderConfigsPage();
      } catch (e) {
        console.error('Load error:', e);
        document.getElementById('configsContent').innerHTML = '<p>Error loading configs</p>';
      }
    }
    function renderConfigsPage() {
      const start = (currentPage - 1) * CONFIGS_PER_PAGE;
      const end = start + CONFIGS_PER_PAGE;
      const pageConfigs = allConfigs.slice(start, end);
      const totalPages = Math.ceil(allConfigs.length / CONFIGS_PER_PAGE);
      let html = '<button class="create-btn" onclick="openCreateModal()">+ Create Config</button><div class="config-grid">';
      if (pageConfigs.length > 0) {
        pageConfigs.forEach(config => {
          html += `<div class="config-card" onclick="viewConfig(${config.id})"><div class="config-name">${config.config_name}</div><div class="config-game">${config.game_name}</div><div class="config-description">${config.description}</div><div class="config-footer"><div>by ${config.author_name}</div><div>${config.downloads} downloads</div></div></div>`;
        });
      } else {
        html += '<p style="color: #888; text-align: center; padding: 40px;">No configs yet! Be the first to create one.</p>';
      }
      html += '</div>';
      if (totalPages > 1) {
        html += '<div class="pagination">';
        html += `<button class="page-btn" onclick="changePage(${currentPage - 1})" ${currentPage === 1 ? 'disabled' : ''}>Previous</button>`;
        for (let i = 1; i <= totalPages; i++) {
          html += `<button class="page-btn ${i === currentPage ? 'active' : ''}" onclick="changePage(${i})">${i}</button>`;
        }
        html += `<button class="page-btn" onclick="changePage(${currentPage + 1})" ${currentPage === totalPages ? 'disabled' : ''}>Next</button>`;
        html += '</div>';
      }
      document.getElementById('configsContent').innerHTML = html;
    }
    function changePage(page) {
      const totalPages = Math.ceil(allConfigs.length / CONFIGS_PER_PAGE);
      if (page < 1 || page > totalPages) return;
      currentPage = page;
      renderConfigsPage();
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }
    async function openCreateModal() {
      document.getElementById('createModal').classList.add('active');
      try {
        const res = await fetch(`/api/configs/${currentUser.license_key}/list`);
        const data = await res.json();
        const select = document.getElementById('savedConfigSelect');
        select.innerHTML = '<option value="">Select a config...</option>';
        if (data.configs && data.configs.length > 0) {
          data.configs.forEach(cfg => select.innerHTML += `<option value="${cfg.name}">${cfg.name}</option>`);
        } else {
          select.innerHTML = '<option value="">No saved configs found</option>';
        }
      } catch (e) { console.error('Error loading configs:', e); }
    }
    function closeCreateModal() { document.getElementById('createModal').classList.remove('active'); }
    async function publishConfig() {
      const selected = document.getElementById('savedConfigSelect').value;
      const name = document.getElementById('configName').value.trim();
      const author = document.getElementById('authorName').value.trim();
      const game = document.getElementById('gameName').value.trim();
      const desc = document.getElementById('configDescription').value.trim();
      if (!selected) return alert('Please select a config');
      if (!name || !author || !game || !desc) return alert('Please fill in all fields');
      try {
        const configRes = await fetch(`/api/configs/${currentUser.license_key}/load/${selected}`);
        const configData = await configRes.json();
        const res = await fetch('/api/public-configs/create', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            config_name: name,
            author_name: author,
            game_name: game,
            description: desc,
            config_data: configData
          })
        });
        if (res.ok) {
          alert('Config published!');
          closeCreateModal();
          loadConfigs();
        } else {
          const error = await res.json();
          alert('Error: ' + (error.detail || 'Failed to publish'));
        }
      } catch (e) { alert('Error publishing config: ' + e.message); }
    }
    async function viewConfig(configId) {
      try {
        const res = await fetch(`/api/public-configs/${configId}`);
        const data = await res.json();
        currentViewConfig = data;
        document.getElementById('viewConfigName').textContent = data.config_name;
        document.getElementById('viewGame').textContent = data.game_name;
        document.getElementById('viewAuthor').textContent = data.author_name;
        document.getElementById('viewDownloads').textContent = data.downloads;
        document.getElementById('viewDescription').textContent = data.description;
        document.getElementById('viewModal').classList.add('active');
        fetch(`/api/public-configs/${configId}/download`, { method: 'POST' });
      } catch (e) { alert('Error loading config'); }
    }
    function closeViewModal() { document.getElementById('viewModal').classList.remove('active'); }
    async function saveConfigToMenu() {
      if (!currentUser || !currentViewConfig) return alert('Please login first');
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
          alert('Config loaded to your menu!');
          closeViewModal();
        } else alert('Failed to save config');
      } catch (e) { alert('Error saving config: ' + e.message); }
    }
    document.addEventListener('keydown', e => { if (e.key === 'Escape') { closeLoginModal(); closeCreateModal(); closeViewModal(); } });
    document.getElementById('userArea').innerHTML = `<button class="login-btn" onclick="showLoginModal()">Login</button>`;
  </script>
</body>
</html>"""

@app.get("/", response_class=HTMLResponse)
@app.get("/home", response_class=HTMLResponse)
def serve_home():
    return protect_html(_INDEX_HTML)

# Customer dashboard route (full)
@app.get("/dashboard", response_class=HTMLResponse)
def serve_customer_dashboard():
    dashboard_html = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Account - Axion</title>
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{background:rgb(12,12,12);background-image:radial-gradient(circle at 3px 3px,rgb(15,15,15) 1px,transparent 0);background-size:6px 6px;color:#ccc;font-family:'Segoe UI',system-ui,sans-serif;min-height:100vh;display:flex}
    .sidebar{width:180px;background:rgb(13,13,13);border-right:1px solid rgb(35,35,35);padding:32px 16px;position:fixed;top:0;bottom:0;overflow-y:auto;text-align:center}
    .logo{font-size:24px;font-weight:700;color:#fff;margin-bottom:40px;cursor:pointer}
    nav ul{list-style:none}
    nav li{margin:12px 0}
    nav a{display:block;color:#888;text-decoration:none;padding:10px 14px;border-radius:6px;transition:color .2s;cursor:pointer}
    nav a:hover,nav a.active{color:#fff}
    .main-content{margin-left:180px;flex:1;padding:32px 24px 40px 200px}
    .container{max-width:1300px;margin:0 auto}
    h1{font-size:28px;font-weight:600;color:#fff;margin-bottom:8px}
    .subtitle{font-size:15px;color:#888;margin-bottom:28px}
    .divider{height:1px;background:rgb(35,35,35);margin:0 0 36px}
    .tab-content{display:none}
    .tab-content.active{display:block}
    .stats{display:grid;grid-template-columns:repeat(3,1fr);gap:20px;margin-bottom:48px}
    .stat-card{background:rgb(18,18,18);border:1px solid rgb(35,35,35);border-radius:10px;padding:24px 20px;text-align:center}
    .stat-label{font-size:14px;color:#777;margin-bottom:12px}
    .stat-value{font-size:32px;font-weight:700;color:#fff}
    .stat-sub{font-size:13px;color:#666;margin-top:6px}
    .manage-grid,.security-grid{display:grid;grid-template-columns:1fr;gap:28px}
    .card{background:rgb(18,18,18);border:1px solid rgb(35,35,35);border-radius:12px;padding:28px;overflow:hidden}
    .card-title{font-size:20px;font-weight:600;color:#fff;margin-bottom:8px}
    .card-subtitle{font-size:14px;color:#888;margin-bottom:28px}
    .input-group{margin-bottom:20px}
    .input-label{font-size:14px;color:#aaa;margin-bottom:8px;display:block}
    input[type=text]{width:100%;padding:14px 16px;background:rgb(25,25,25);border:1px solid rgb(45,45,45);border-radius:8px;color:#fff;font-family:monospace;font-size:15px}
    input::placeholder{color:#666;opacity:1}
    .redeem-btn{width:100%;padding:14px;background:#fff;border:none;border-radius:8px;color:#000;font-size:15px;font-weight:600;cursor:pointer;transition:all .25s ease;transform:scale(1)}
    .redeem-btn:hover{transform:scale(1.03);background:rgb(240,240,240);box-shadow:0 4px 12px rgba(0,0,0,.4)}
    .info-item{margin-bottom:24px}
    .info-label{font-size:14px;color:#aaa;margin-bottom:8px;display:block}
    .info-value{width:100%;padding:14px 16px;background:rgb(25,25,25);border:1px solid rgb(45,45,45);border-radius:8px;color:#fff;font-family:monospace;font-size:15px;transition:filter .3s ease;user-select:none;cursor:pointer;position:relative}
    .info-value.blur{filter:blur(6px)}
    .info-value:hover{filter:blur(0)}
    .info-value.resetting::after{content:"Reset successful!";position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);background:rgba(0,0,0,.8);color:#4caf50;padding:8px 16px;border-radius:6px;font-size:14px;white-space:nowrap;pointer-events:none;opacity:0;animation:fadeOut 2s forwards}
    @keyframes fadeOut{0%{opacity:1}100%{opacity:0}}
    .empty-section{background:rgb(18,18,18);border:1px solid rgb(35,35,35);border-radius:12px;padding:80px 32px;text-align:center}
    #redeem-from-subs{background:transparent;border:1px solid rgb(35,35,35);color:#ddd;padding:12px 40px;border-radius:6px;font-size:15px;font-weight:500;cursor:pointer;transition:all .2s}
    #redeem-from-subs:hover{border-color:#777;color:#fff}
    .modal{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,.85);justify-content:center;align-items:center;z-index:1000;opacity:0;transition:opacity .3s ease}
    .modal.show{display:flex;opacity:1}
    .modal-content{background:rgb(18,18,18);border:1px solid rgb(35,35,35);border-radius:12px;padding:32px;max-width:420px;width:90%;text-align:center;transform:scale(.95);transition:transform .3s ease}
    .modal.show .modal-content{transform:scale(1)}
    .modal-title{font-size:20px;color:#fff;margin-bottom:24px}
    .modal-question{font-size:15px;color:#fff;margin-bottom:16px;text-align:left}
    .modal-buttons{display:flex;gap:12px;margin-top:20px}
    .modal-btn{flex:1;padding:12px;background:transparent;border:1px solid rgb(35,35,35);border-radius:8px;color:#fff;font-size:14px;font-weight:500;cursor:pointer;transition:all .2s}
    .modal-btn:hover{background:rgba(255,255,255,0.05);border-color:rgb(55,55,55)}
    @media (max-width:900px){.sidebar{width:100%;height:auto;position:relative;border-right:none;border-bottom:1px solid rgb(35,35,35);padding:20px;display:flex;flex-direction:column;align-items:center;text-align:center;background:rgb(13,13,13)}
      .logo{margin-bottom:20px}
      nav ul{display:flex;justify-content:center;gap:8px;flex-wrap:wrap}
      .main-content{margin-left:0;padding:24px 16px}
      .stats{grid-template-columns:repeat(auto-fit,minmax(140px,1fr))}}
    @media (max-width:500px){.card,.modal-content{padding:20px}}
  </style>
</head>
<body>
  <aside class="sidebar">
    <div class="logo" onclick="window.location.href='/'">Axion</div>
    <nav>
      <ul>
        <li><a href="#subscriptions" class="active">Subscriptions</a></li>
        <li><a href="#manage">Manage</a></li>
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
          <div class="stat-card"><div class="stat-label">Active</div><div class="stat-value" id="activeSubs">Unknown</div><div class="stat-sub">subscriptions</div></div>
          <div class="stat-card"><div class="stat-label">Total HWID Resets</div><div class="stat-value" id="totalResets">Unknown</div><div class="stat-sub">All time</div></div>
          <div class="stat-card"><div class="stat-label">Subscription</div><div class="stat-value" id="subStatus">Unknown</div><div class="stat-sub" id="subDuration">Unknown</div></div>
        </div>
        <div class="empty-section" id="subsSection">
          <div style="font-size:20px;color:#fff;margin-bottom:12px">No subscriptions yet</div>
          <div style="font-size:15px;color:#888;margin-bottom:32px">Redeem a key to get started</div>
          <button id="redeem-from-subs">Redeem Key</button>
        </div>
      </div>
      <div id="manage" class="tab-content">
        <div class="manage-grid">
          <div class="card">
            <div class="card-title">Redeem Key</div>
            <div class="card-subtitle">Activate a new subscription</div>
            <div class="input-group">
              <div class="input-label">Subscription Key</div>
              <input type="text" id="redeemKeyInput" placeholder="XXXXX-XXXXX-XXXXX-XXXXX">
            </div>
            <button class="redeem-btn" id="redeemBtn">Redeem Key</button>
          </div>
        </div>
      </div>
      <div id="security" class="tab-content">
        <div class="security-grid">
          <div class="card">
            <div class="card-title">Account Information</div>
            <div class="card-subtitle">View and manage your account details</div>
            <div class="info-item">
              <div class="info-label">License</div>
              <div class="info-value blur" id="licenseDisplay">Unknown</div>
            </div>
            <div class="info-item">
              <div class="info-label">HWID</div>
              <div class="info-value blur hwid-value" id="hwidDisplay">Unknown</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </main>
  <div id="loginModal" class="modal">
    <div class="modal-content">
      <div class="modal-title">Welcome to Axion Dashboard</div>
      <div class="modal-question">Do you have a License?</div>
      <div class="input-group">
        <input type="text" id="loginKeyInput" class="input-label" placeholder="Enter your license key" style="width:100%;margin-bottom:0">
      </div>
      <div class="modal-buttons">
        <button class="modal-btn" id="noLicenseBtn">No</button>
        <button class="modal-btn" id="yesLicenseBtn">Yes</button>
      </div>
    </div>
  </div>
  <div id="redeemModal" class="modal">
    <div class="modal-content">
      <div class="modal-title">Redeem Axion Key</div>
      <div class="input-group">
        <div class="input-label">Discord User ID</div>
        <input type="text" id="discordIdInput" placeholder="123456789012345678">
      </div>
      <button class="redeem-btn" id="continueBtn">Continue</button>
    </div>
  </div>
  <script>
    let licenseKey = localStorage.getItem('axion_license');
    let hasLicense = localStorage.getItem('axion_has_license') === 'true';
    if (!localStorage.getItem('axion_dashboard_visited')) document.getElementById('loginModal').classList.add('show');
    else if (hasLicense && licenseKey) loadDashboard();
    document.getElementById('noLicenseBtn').onclick = () => {
      localStorage.setItem('axion_dashboard_visited', 'true');
      localStorage.setItem('axion_has_license', 'false');
      hasLicense = false;
      licenseKey = null;
      document.getElementById('loginModal').classList.remove('show');
      setUnknownState();
    };
    document.getElementById('yesLicenseBtn').onclick = async () => {
      const key = document.getElementById('loginKeyInput').value.trim();
      if (!key) return alert('Please enter your license key');
      try {
        const res = await fetch(`/api/dashboard/${key}`);
        if (!res.ok) return alert('Invalid license key');
        const data = await res.json();
        licenseKey = key;
        hasLicense = true;
        localStorage.setItem('axion_license', key);
        localStorage.setItem('axion_has_license', 'true');
        localStorage.setItem('axion_dashboard_visited', 'true');
        document.getElementById('loginModal').classList.remove('show');
        loadDashboard();
      } catch (e) { alert('Error validating license: ' + e.message); }
    };
    function setUnknownState() {
      document.getElementById('activeSubs').textContent = 'Unknown';
      document.getElementById('totalResets').textContent = 'Unknown';
      document.getElementById('subStatus').textContent = 'Unknown';
      document.getElementById('subDuration').textContent = 'Unknown';
      document.getElementById('licenseDisplay').textContent = 'Unknown';
      document.getElementById('hwidDisplay').textContent = 'Unknown';
    }
    async function loadDashboard() {
      if (!hasLicense || !licenseKey) return setUnknownState();
      try {
        const res = await fetch(`/api/dashboard/${licenseKey}`);
        if (!res.ok) {
          alert('Invalid license key');
          localStorage.removeItem('axion_license');
          localStorage.setItem('axion_has_license', 'false');
          return setUnknownState();
        }
        const data = await res.json();
        document.getElementById('activeSubs').textContent = data.active ? '1' : '0';
        document.getElementById('totalResets').textContent = data.hwid_resets || 0;
        document.getElementById('subStatus').textContent = data.active ? 'Active' : 'Inactive';
        const durationMap = {'weekly':'Weekly','monthly':'Monthly','3monthly':'Quarterly','lifetime':'Lifetime'};
        document.getElementById('subDuration').textContent = durationMap[data.duration] || data.duration.toUpperCase();
        document.getElementById('licenseDisplay').textContent = data.license_key;
        document.getElementById('hwidDisplay').textContent = data.hwid || 'Not bound';
      } catch (e) {
        console.error('Error loading dashboard:', e);
        setUnknownState();
      }
    }
    document.querySelectorAll('nav a').forEach(link => {
      link.addEventListener('click', e => {
        e.preventDefault();
        const targetId = link.getAttribute('href').slice(1);
        document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
        document.getElementById(targetId).classList.add('active');
        document.querySelectorAll('nav a').forEach(a => a.classList.remove('active'));
        link.classList.add('active');
        document.getElementById('page-title').textContent = link.textContent;
        document.querySelector('.subtitle').textContent = targetId === 'subscriptions' ? 'Manage and view your active subscriptions' :
                                                          targetId === 'manage' ? 'Redeem keys and manage security information' :
                                                          'Manage account security and HWID';
      });
    });
    document.getElementById('redeem-from-subs').onclick = () => document.querySelector('a[href="#manage"]').click();
    document.getElementById('hwidDisplay').onclick = async () => {
      if (!hasLicense || !licenseKey) return alert('Please login with a license key to reset HWID');
      if (!confirm("Are you sure you want to reset your HWID? This action cannot be undone.")) return;
      try {
        const res = await fetch(`/api/reset-hwid/${licenseKey}`, { method: 'POST' });
        if (res.ok) {
          const data = await res.json();
          document.getElementById('hwidDisplay').textContent = 'Not bound';
          document.getElementById('totalResets').textContent = data.hwid_resets;
          const hwidEl = document.getElementById('hwidDisplay');
          hwidEl.classList.add('resetting');
          setTimeout(() => hwidEl.classList.remove('resetting'), 2200);
        } else alert('Failed to reset HWID');
      } catch (e) { alert('Error: ' + e.message); }
    };
    const redeemModal = document.getElementById('redeemModal');
    document.getElementById('redeemBtn').onclick = () => {
      const key = document.getElementById('redeemKeyInput').value.trim();
      if (!key) return alert('Please enter a key');
      redeemModal.style.display = 'flex';
      setTimeout(() => redeemModal.classList.add('show'), 10);
      document.getElementById('discordIdInput').value = '';
    };
    document.getElementById('continueBtn').onclick = async () => {
      const id = document.getElementById('discordIdInput').value.trim();
      const key = document.getElementById('redeemKeyInput').value.trim();
      if (!/^\d{17,19}$/.test(id)) return alert('Invalid Discord ID');
      try {
        const res = await fetch('/api/redeem', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ key, discord_id: id })
        });
        if (res.ok) {
          alert('Key redeemed successfully!');
          localStorage.setItem('axion_license', key);
          localStorage.setItem('axion_has_license', 'true');
          licenseKey = key;
          hasLicense = true;
          redeemModal.classList.remove('show');
          setTimeout(() => redeemModal.style.display = 'none', 300);
          document.getElementById('redeemKeyInput').value = '';
          loadDashboard();
        } else {
          const error = await res.json();
          alert('Error: ' + error.detail);
        }
      } catch (e) { alert('Error: ' + e.message); }
    };
    redeemModal.onclick = e => {
      if (e.target === redeemModal) {
        redeemModal.classList.remove('show');
        setTimeout(() => redeemModal.style.display = 'none', 300);
      }
    };
  </script>
</body>
</html>"""
    return protect_html(dashboard_html)

# Per-license personal dashboard (this is the full one — no cut)
@app.get("/{license_key}", response_class=HTMLResponse)
def serve_dashboard(license_key: str):
    if license_key in ["api", "favicon.ico", "home", "blocked"]:
        raise HTTPException(status_code=404)
    
    db = get_db()
    cur = db.cursor()
    cur.execute(q("SELECT * FROM keys WHERE key=%s"), (license_key,))
    result = cur.fetchone()
    db.close()
    
    if not result:
        error_html = "<html><body style='background:rgb(12,12,12);color:white;font-family:Arial;display:flex;align-items:center;justify-content:center;height:100vh'><div style='text-align:center'><h1 style='color:rgb(255,68,68)'>Invalid License</h1><p>License key not found</p></div></body></html>"
        return protect_html(error_html)
    
    dashboard_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<title>Axion Dashboard</title>
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
const key = "{license_key}";
let config = {json.dumps(DEFAULT_CONFIG)};
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
    }} catch(e) {{ console.error('Save failed:', e); }}
}}
async function loadConfig() {{
    try {{
        const res = await fetch(`/api/config/${{key}}`);
        config = await res.json();
        applyConfigToUI();
    }} catch(e) {{ console.error('Load failed:', e); }}
}}
function applyConfigToUI() {{
    document.querySelectorAll('.toggle[data-setting]').forEach(toggle => {{
        const [section, key] = toggle.dataset.setting.split('.');
        if (config[section]?.[key] !== undefined) toggle.classList.toggle('active', config[section][key]);
    }});
    document.querySelectorAll('.keybind-picker[data-setting]').forEach(picker => {{
        const [section, key] = picker.dataset.setting.split('.');
        if (config[section]?.[key] !== undefined) picker.textContent = config[section][key];
    }});
    if (sliders.delay) {{ sliders.delay.current = config.triggerbot.Delay ?? 0.05; sliders.delay.update(); }}
    if (sliders.maxStuds) {{ sliders.maxStuds.current = config.triggerbot.MaxStuds ?? 120; sliders.maxStuds.update(); }}
    if (sliders.pred) {{ sliders.pred.current = config.triggerbot.Prediction ?? 0.1; sliders.pred.update(); }}
    if (sliders.trigFov) {{ sliders.trigFov.current = config.triggerbot.FOV ?? 25; sliders.trigFov.update(); }}
    if (sliders.fov) {{ sliders.fov.current = config.camlock.FOV ?? 280; sliders.fov.update(); }}
    if (sliders.smoothX) {{ sliders.smoothX.current = config.camlock.SmoothX ?? 14; sliders.smoothX.update(); }}
    if (sliders.smoothY) {{ sliders.smoothY.current = config.camlock.SmoothY ?? 14; sliders.smoothY.update(); }}
    if (sliders.camlockPred) {{ sliders.camlockPred.current = config.camlock.Prediction ?? 0.14; sliders.camlockPred.update(); }}
    if (sliders.camlockMaxStuds) {{ sliders.camlockMaxStuds.current = config.camlock.MaxStuds ?? 120; sliders.camlockMaxStuds.update(); }}
    if (sliders.scale) {{ sliders.scale.current = config.camlock.Scale ?? 1.0; sliders.scale.update(); }}
    if (config.camlock?.BodyPart) {{
        document.getElementById('bodyPartHeader').textContent = config.camlock.BodyPart;
        document.querySelectorAll('#bodyPartList .dropdown-item').forEach(item => item.classList.toggle('selected', item.dataset.value === config.camlock.BodyPart));
    }}
    if (config.camlock?.EasingStyle) {{
        document.getElementById('easingHeader').textContent = config.camlock.EasingStyle;
        document.querySelectorAll('#easingList .dropdown-item').forEach(item => item.classList.toggle('selected', item.dataset.value === config.camlock.EasingStyle));
    }}
}}
document.querySelectorAll('.toggle[data-setting]').forEach(toggle => {{
    toggle.addEventListener('click', () => {{
        toggle.classList.toggle('active');
        const [section, key] = toggle.dataset.setting.split('.');
        config[section][key] = toggle.classList.contains('active');
        saveConfig();
    }});
}});
document.querySelectorAll('.keybind-picker[data-setting]').forEach(picker => {{
    picker.addEventListener('click', () => {{
        picker.textContent = '...';
        const listener = e => {{
            e.preventDefault();
            let name = '';
            if (e.button !== undefined) {{
                name = e.button === 0 ? 'Left Mouse' : e.button === 2 ? 'Right Mouse' : e.button === 1 ? 'Middle Mouse' : `Mouse${{e.button}}`;
            }} else if (e.key) {{
                name = e.key.toUpperCase();
                if (name === ' ') name = 'SPACE';
            }}
            picker.textContent = name || 'NONE';
            const [section, key] = picker.dataset.setting.split('.');
            config[section][key] = name;
            saveConfig();
            document.removeEventListener('keydown', listener);
            document.removeEventListener('mousedown', listener);
        }};
        document.addEventListener('keydown', listener, {{once:true}});
        document.addEventListener('mousedown', listener, {{once:true}});
    }});
}});
document.getElementById('bodyPartHeader').onclick = () => document.getElementById('bodyPartList').classList.toggle('open');
document.querySelectorAll('#bodyPartList .dropdown-item').forEach(item => {{
    item.onclick = () => {{
        const val = item.dataset.value;
        document.getElementById('bodyPartHeader').textContent = val;
        document.querySelectorAll('#bodyPartList .dropdown-item').forEach(i => i.classList.remove('selected'));
        item.classList.add('selected');
        document.getElementById('bodyPartList').classList.remove('open');
        config.camlock.BodyPart = val;
        saveConfig();
    }};
}});
document.getElementById('easingHeader').onclick = () => document.getElementById('easingList').classList.toggle('open');
document.querySelectorAll('#easingList .dropdown-item').forEach(item => {{
    item.onclick = () => {{
        const val = item.dataset.value;
        document.getElementById('easingHeader').textContent = val;
        document.querySelectorAll('#easingList .dropdown-item').forEach(i => i.classList.remove('selected'));
        item.classList.add('selected');
        document.getElementById('easingList').classList.remove('open');
        config.camlock.EasingStyle = val;
        saveConfig();
    }};
}});
const sliders = {{}};
function createDecimalSlider(id, fillId, valueId, def, min, max, step, setting, thresh=0.5) {{
    const el = document.getElementById(id);
    if (!el) return null;
    const fill = document.getElementById(fillId);
    const val = document.getElementById(valueId);
    const obj = {{ current: def, min, max, step, setting, threshold: thresh,
        update() {{
            const pct = ((this.current - this.min) / (this.max - this.min)) * 100;
            fill.style.width = pct + '%';
            val.textContent = this.current.toFixed(2);
            val.style.color = this.current < this.threshold ? '#fff' : '#000';
        }}
    }};
    el.onmousedown = e => {{
        const rect = el.getBoundingClientRect();
        const move = e => {{
            let pct = Math.max(0, Math.min(100, ((e.clientX - rect.left) / rect.width) * 100));
            obj.current = obj.min + (pct / 100) * (obj.max - obj.min);
            obj.current = Math.round(obj.current / obj.step) * obj.step;
            obj.current = Math.max(obj.min, Math.min(obj.max, obj.current));
            obj.update();
            const [s, k] = obj.setting.split('.');
            config[s][k] = obj.current;
            saveConfig();
        }};
        const up = () => { document.removeEventListener('mousemove', move); document.removeEventListener('mouseup', up); };
        document.addEventListener('mousemove', move);
        document.addEventListener('mouseup', up);
        move(e);
    }};
    obj.update();
    return obj;
}}
function createIntSlider(id, fillId, valueId, def, max, blackThresh, setting) {{
    const el = document.getElementById(id);
    if (!el) return null;
    const fill = document.getElementById(fillId);
    const val = document.getElementById(valueId);
    const obj = {{ current: def, max, blackThreshold: blackThresh, setting,
        update() {{
            const pct = (this.current / this.max) * 100;
            fill.style.width = pct + '%';
            val.textContent = Math.round(this.current);
            val.style.color = this.current >= this.blackThreshold ? '#000' : '#fff';
        }}
    }};
    el.onmousedown = e => {{
        const rect = el.getBoundingClientRect();
        const move = e => {{
            const pct = Math.max(0, Math.min(100, ((e.clientX - rect.left) / rect.width) * 100));
            obj.current = (pct / 100) * obj.max;
            obj.update();
            const [s, k] = obj.setting.split('.');
            config[s][k] = Math.round(obj.current);
            saveConfig();
        }};
        const up = () => { document.removeEventListener('mousemove', move); document.removeEventListener('mouseup', up); };
        document.addEventListener('mousemove', move);
        document.addEventListener('mouseup', up);
        move(e);
    }};
    obj.update();
    return obj;
}}
sliders.delay = createDecimalSlider('delaySlider','delayFill','delayValue',0.05,0.01,1,0.01,'triggerbot.Delay');
sliders.maxStuds = createIntSlider('maxStudsSlider','maxStudsFill','maxStudsValue',120,300,150,'triggerbot.MaxStuds');
sliders.pred = createDecimalSlider('predSlider','predFill','predValue',0.10,0.01,1,0.01,'triggerbot.Prediction');
sliders.trigFov = createIntSlider('trigFovSlider','trigFovFill','trigFovValue',25,100,50,'triggerbot.FOV');
sliders.fov = createIntSlider('fovSlider','fovFill','fovValue',280,500,250,'camlock.FOV');
sliders.smoothX = createIntSlider('smoothXSlider','smoothXFill','smoothXValue',14,30,15,'camlock.SmoothX');
sliders.smoothY = createIntSlider('smoothYSlider','smoothYFill','smoothYValue',14,30,15,'camlock.SmoothY');
sliders.camlockPred = createDecimalSlider('camlockPredSlider','camlockPredFill','camlockPredValue',0.14,0.01,1,0.01,'camlock.Prediction');
sliders.camlockMaxStuds = createIntSlider('camlockMaxStudsSlider','camlockMaxStudsFill','camlockMaxStudsValue',120,300,150,'camlock.MaxStuds');
sliders.scale = createDecimalSlider('scaleSlider','scaleFill','scaleValue',1.0,0.5,2.0,0.1,'camlock.Scale',1.2);
async function loadSavedConfigs() {{
    try {{
        const res = await fetch(`/api/configs/${{key}}/list`);
        const data = await res.json();
        const list = document.getElementById('configList');
        list.innerHTML = '';
        data.configs.forEach((cfg, i) => {{
            const item = document.createElement('div');
            item.className = 'config-item';
            item.innerHTML = `
                <div class="config-name">${cfg.name}</div>
                <div class="config-dots" onclick="toggleConfigMenu(event, ${i})">⋮</div>
                <div class="config-menu" id="menu${i}">
                    <div class="config-menu-item" onclick="loadConfigByName('${cfg.name}')">Load</div>
                    <div class="config-menu-item" onclick="renameConfigPrompt('${cfg.name}')">Rename</div>
                    <div class="config-menu-item" onclick="deleteConfigByName('${cfg.name}')">Delete</div>
                </div>`;
            list.appendChild(item);
        }});
    }} catch(e) {{ console.error(e); }}
}}
function toggleConfigMenu(e, idx) {{
    e.stopPropagation();
    document.querySelectorAll('.config-menu').forEach(m => m !== document.getElementById(`menu${idx}`) && m.classList.remove('open'));
    document.getElementById(`menu${idx}`).classList.toggle('open');
}}
document.addEventListener('click', () => document.querySelectorAll('.config-menu').forEach(m => m.classList.remove('open')));
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
        loadSavedConfigs();
    }} catch(e) {{ alert('Failed to save'); }}
}}
async function loadConfigByName(name) {{
    try {{
        const res = await fetch(`/api/configs/${{key}}/load/${{name}}`);
        config = await res.json();
        applyConfigToUI();
        saveConfig();
    }} catch(e) {{ alert('Failed to load'); }}
}}
let renameOld = null;
function renameConfigPrompt(old) {{
    renameOld = old;
    document.getElementById('renameInput').value = old;
    document.getElementById('renameModal').classList.add('active');
    document.getElementById('renameInput').focus();
}}
function closeRenameModal() {{
    document.getElementById('renameModal').classList.remove('active');
    renameOld = null;
}}
async function confirmRename() {{
    const newName = document.getElementById('renameInput').value.trim();
    if (!newName || newName === renameOld) return closeRenameModal();
    try {{
        await fetch(`/api/configs/${{key}}/rename`, {{
            method: 'POST',
            headers: {{'Content-Type': 'application/json'}},
            body: JSON.stringify({{old_name: renameOld, new_name: newName}})
        }});
        loadSavedConfigs();
        closeRenameModal();
    }} catch(e) {{ alert('Failed to rename'); closeRenameModal(); }}
}}
document.getElementById('renameInput').onkeypress = e => {{
    if (e.key === 'Enter') confirmRename();
    if (e.key === 'Escape') closeRenameModal();
}};
async function deleteConfigByName(name) {{
    try {{
        await fetch(`/api/configs/${{key}}/delete/${{name}}`, {{method: 'DELETE'}});
        loadSavedConfigs();
    }} catch(e) {{ alert('Failed to delete'); }}
}}
loadSavedConfigs();
loadConfig();
setInterval(loadConfig, 1500);
</script>
</body>
</html>"""
    return protect_html(dashboard_html)

# ────────────────────────────────────────────────
# API Endpoints (all of them)
# ────────────────────────────────────────────────
@app.post("/api/validate")
def validate_user(data: KeyValidate):
    db = get_db()
    cur = db.cursor()
    cur.execute(q("SELECT key, active, expires_at, hwid FROM keys WHERE key=%s"), (data.key,))
    row = cur.fetchone()
    db.close()
    if not row: return {"valid": False, "error": "Invalid license key"}
    key, active, expires, hwid = row
    if active == 0: return {"valid": False, "error": "License inactive"}
    if expires and datetime.now() > datetime.fromisoformat(expires): return {"valid": False, "error": "License expired"}
    if data.hwid != 'web-login':
        if hwid is None:
            db = get_db(); cur = db.cursor()
            cur.execute(q("UPDATE keys SET hwid=%s WHERE key=%s"), (data.hwid, data.key))
            db.commit(); db.close()
            return {"valid": True, "message": "HWID bound"}
        if hwid != data.hwid: return {"valid": False, "error": "HWID mismatch"}
    return {"valid": True}

@app.get("/api/config/{key}")
def get_config(key: str):
    db = get_db(); cur = db.cursor()
    cur.execute(q("SELECT config FROM settings WHERE key=%s"), (key,))
    row = cur.fetchone()
    if not row:
        if USE_POSTGRES:
            cur.execute("INSERT INTO settings (key, config) VALUES (%s, %s) ON CONFLICT (key) DO NOTHING", (key, json.dumps(DEFAULT_CONFIG)))
        else:
            cur.execute("INSERT OR IGNORE INTO settings (key, config) VALUES (?, ?)", (key, json.dumps(DEFAULT_CONFIG)))
        db.commit()
        db.close()
        return DEFAULT_CONFIG
    db.close()
    return json.loads(row[0])

@app.post("/api/config/{key}")
def set_config(key: str, data: dict):
    db = get_db(); cur = db.cursor()
    if USE_POSTGRES:
        cur.execute("INSERT INTO settings (key, config) VALUES (%s, %s) ON CONFLICT (key) DO UPDATE SET config = EXCLUDED.config", (key, json.dumps(data)))
    else:
        cur.execute("INSERT INTO settings (key, config) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET config = excluded.config", (key, json.dumps(data)))
    db.commit(); db.close()
    return {"status": "ok"}

@app.get("/api/configs/{license_key}/list")
def list_configs(license_key: str):
    db = get_db(); cur = db.cursor()
    cur.execute(q("SELECT config_name, created_at FROM saved_configs WHERE license_key=%s ORDER BY created_at DESC"), (license_key,))
    rows = cur.fetchall()
    db.close()
    return {"configs": [{"name": r[0], "created_at": r[1]} for r in rows]}

@app.post("/api/configs/{license_key}/save")
def save_config(license_key: str, data: SavedConfigRequest):
    db = get_db(); cur = db.cursor()
    cur.execute(q("SELECT id FROM saved_configs WHERE license_key=%s AND config_name=%s"), (license_key, data.config_name))
    if cur.fetchone():
        cur.execute(q("UPDATE saved_configs SET config_data=%s WHERE license_key=%s AND config_name=%s"),
                    (json.dumps(data.config_data), license_key, data.config_name))
    else:
        cur.execute(q("INSERT INTO saved_configs (license_key, config_name, config_data, created_at) VALUES (%s, %s, %s, %s)"),
                    (license_key, data.config_name, json.dumps(data.config_data), datetime.now().isoformat()))
    db.commit(); db.close()
    return {"success": True}

@app.get("/api/configs/{license_key}/load/{config_name}")
def load_config(license_key: str, config_name: str):
    db = get_db(); cur = db.cursor()
    cur.execute(q("SELECT config_data FROM saved_configs WHERE license_key=%s AND config_name=%s"), (license_key, config_name))
    row = cur.fetchone()
    db.close()
    if not row: raise HTTPException(404, "Config not found")
    return json.loads(row[0])

@app.post("/api/configs/{license_key}/rename")
def rename_config(license_key: str, data: dict):
    db = get_db(); cur = db.cursor()
    cur.execute(q("UPDATE saved_configs SET config_name=%s WHERE license_key=%s AND config_name=%s"),
                (data["new_name"], license_key, data["old_name"]))
    db.commit(); db.close()
    return {"success": True}

@app.delete("/api/configs/{license_key}/delete/{config_name}")
def delete_config(license_key: str, config_name: str):
    db = get_db(); cur = db.cursor()
    cur.execute(q("DELETE FROM saved_configs WHERE license_key=%s AND config_name=%s"), (license_key, config_name))
    db.commit(); db.close()
    return {"success": True}

@app.get("/api/public-configs")
def get_public_configs():
    db = get_db(); cur = db.cursor()
    cur.execute(q("SELECT id, config_name, author_name, game_name, description, downloads, created_at FROM public_configs ORDER BY created_at DESC"))
    rows = cur.fetchall()
    db.close()
    return {"configs": [{"id":r[0],"config_name":r[1],"author_name":r[2],"game_name":r[3],"description":r[4],"downloads":r[5],"created_at":r[6]} for r in rows]}

@app.post("/api/public-configs/create")
def create_public_config(data: PublicConfig):
    db = get_db(); cur = db.cursor()
    cur.execute(q("INSERT INTO public_configs (config_name, author_name, game_name, description, config_data, license_key, created_at, downloads) VALUES (%s,%s,%s,%s,%s,%s,%s,0)"),
                (data.config_name, data.author_name, data.game_name, data.description, json.dumps(data.config_data), "web", datetime.now().isoformat()))
    db.commit(); db.close()
    return {"success": True}

@app.get("/api/public-configs/{config_id}")
def get_public_config(config_id: int):
    db = get_db(); cur = db.cursor()
    cur.execute(q("SELECT * FROM public_configs WHERE id=%s"), (config_id,))
    row = cur.fetchone()
    db.close()
    if not row: raise HTTPException(404)
    return {
        "id": row[0], "config_name": row[1], "author_name": row[2], "game_name": row[3],
        "description": row[4], "config_data": json.loads(row[5]), "license_key": row[6],
        "created_at": row[7], "downloads": row[8]
    }

@app.post("/api/public-configs/{config_id}/download")
def increment_download(config_id: int):
    db = get_db(); cur = db.cursor()
    cur.execute(q("UPDATE public_configs SET downloads = downloads + 1 WHERE id=%s"), (config_id,))
    db.commit(); db.close()
    return {"success": True}

@app.post("/api/keys/create")
def create_key(data: KeyCreate):
    key = f"{secrets.randbelow(10000):04d}-{secrets.randbelow(10000):04d}-{secrets.randbelow(10000):04d}-{secrets.randbelow(10000):04d}"
    db = get_db(); cur = db.cursor()
    cur.execute(q("INSERT INTO keys (key, duration, created_at, active, created_by) VALUES (%s,%s,%s,0,%s)"),
                (key, data.duration, datetime.now().isoformat(), data.created_by))
    db.commit(); db.close()
    return {"key": key, "duration": data.duration}

@app.delete("/api/keys/{license_key}")
def delete_key(license_key: str):
    db = get_db(); cur = db.cursor()
    cur.execute(q("DELETE FROM keys WHERE key=%s"), (license_key,))
    db.commit(); db.close()
    return {"success": True}

@app.get("/api/dashboard/{license_key}")
def get_dashboard_data(license_key: str):
    db = get_db(); cur = db.cursor()
    cur.execute(q("SELECT key,duration,expires_at,active,hwid,redeemed_by,hwid_resets FROM keys WHERE key=%s"), (license_key,))
    row = cur.fetchone()
    db.close()
    if not row: raise HTTPException(404)
    return {
        "license_key": row[0], "duration": row[1], "expires_at": row[2], "active": row[3],
        "hwid": row[4], "discord_id": row[5], "hwid_resets": row[6] or 0
    }

@app.post("/api/redeem")
def redeem_key(data: RedeemRequest):
    db = get_db(); cur = db.cursor()
    cur.execute(q("SELECT duration, redeemed_at FROM keys WHERE key=%s"), (data.key,))
    row = cur.fetchone()
    if not row: raise HTTPException(404, "Invalid key")
    duration, redeemed = row
    if redeemed: raise HTTPException(400, "Already redeemed")
    now = datetime.now()
    expires = None
    if duration == "weekly": expires = (now + timedelta(days=7)).isoformat()
    elif duration == "monthly": expires = (now + timedelta(days=30)).isoformat()
    elif duration == "3monthly": expires = (now + timedelta(days=90)).isoformat()
    cur.execute(q("UPDATE keys SET redeemed_at=%s, redeemed_by=%s, expires_at=%s, active=1 WHERE key=%s"),
                (now.isoformat(), data.discord_id, expires, data.key))
    db.commit(); db.close()
    return {"success": True, "expires_at": expires}

@app.post("/api/reset-hwid/{license_key}")
def reset_hwid(license_key: str):
    db = get_db(); cur = db.cursor()
    cur.execute(q("SELECT hwid_resets FROM keys WHERE key=%s"), (license_key,))
    resets = cur.fetchone()[0] or 0
    cur.execute(q("UPDATE keys SET hwid=NULL, hwid_resets=%s WHERE key=%s"), (resets + 1, license_key))
    db.commit(); db.close()
    return {"success": True, "hwid_resets": resets + 1}

@app.get("/api/keepalive")
def keepalive():
    return {"status": "alive"}

if __name__ == "__main__":
    init_db()
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
