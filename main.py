from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse
import sqlite3

app = FastAPI()

API_KEY = "test_key_123"

# ---------------- Database ----------------
def get_db():
    return sqlite3.connect("database.db")

def init_db():
    db = get_db()
    cur = db.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)
    cur.execute("""
        INSERT OR IGNORE INTO settings (key, value)
        VALUES ('camlock', 'false')
    """)
    db.commit()
    db.close()

init_db()

def check_key(auth):
    if auth != API_KEY:
        raise HTTPException(status_code=401)

# ---------------- API ----------------
@app.get("/api/status")
def get_status(authorization: str = Header(None)):
    check_key(authorization)
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT value FROM settings WHERE key='camlock'")
    value = cur.fetchone()[0]
    db.close()
    return {"camlock": value == "true"}

@app.post("/api/status")
def set_status(data: dict, authorization: str = Header(None)):
    check_key(authorization)
    camlock = "true" if data.get("camlock") else "false"
    db = get_db()
    cur = db.cursor()
    cur.execute(
        "UPDATE settings SET value=? WHERE key='camlock'",
        (camlock,)
    )
    db.commit()
    db.close()
    return {"success": True}

# ---------------- Web Panel ----------------
@app.get("/", response_class=HTMLResponse)
def web_panel():
    return """
    <html>
    <head>
        <title>Camlock Control Panel</title>
    </head>
    <body>
        <h1>Camlock Control</h1>
        <button onclick="toggle(true)">Turn ON</button>
        <button onclick="toggle(false)">Turn OFF</button>
        <p id="status">Loading...</p>

        <script>
            const API_URL = '/api/status';
            const API_KEY = 'test_key_123';

            async function updateStatus() {
                try {
                    const res = await fetch(API_URL, {
                        headers: { 'Authorization': API_KEY }
                    });
                    const data = await res.json();
                    document.getElementById('status').innerText =
                        'Camlock is ' + (data.camlock ? 'ON' : 'OFF');
                } catch (err) {
                    document.getElementById('status').innerText = 'Error fetching status';
                }
            }

            async function toggle(state) {
                try {
                    await fetch(API_URL, {
                        method: 'POST',
                        headers: {
                            'Authorization': API_KEY,
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({ camlock: state })
                    });
                    updateStatus();
                } catch (err) {
                    alert('Failed to toggle state');
                }
            }

            setInterval(updateStatus, 2000);
            updateStatus();
        </script>
    </body>
    </html>
    """
