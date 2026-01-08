# main.py
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
import sqlite3

app = FastAPI()

# ---------------- Database ----------------
def get_db():
    return sqlite3.connect("database.db")

def init_db():
    db = get_db()
    cur = db.cursor()
    
    # Settings table (per-user, key format "camlock_<username>")
    cur.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)
    
    db.commit()
    db.close()

init_db()

# ---------------- API ----------------
@app.get("/api/status")
def get_status(user: str = "default"):
    db = get_db()
    cur = db.cursor()
    
    # create entry if user doesn't exist
    cur.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (f"camlock_{user}", "false"))
    db.commit()
    
    cur.execute("SELECT value FROM settings WHERE key=?", (f"camlock_{user}",))
    value = cur.fetchone()[0]
    db.close()
    return {"camlock": value == "true"}

@app.post("/api/status")
def set_status(data: dict):
    user = data.get("user", "default")
    camlock = "true" if data.get("camlock") else "false"

    db = get_db()
    cur = db.cursor()
    # create or update user-specific camlock
    cur.execute("""
        INSERT INTO settings(key, value) VALUES(?, ?)
        ON CONFLICT(key) DO UPDATE SET value=excluded.value
    """, (f"camlock_{user}", camlock))
    db.commit()
    db.close()

    return {"success": True, "user": user, "camlock": camlock == "true"}

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

        <label for="username">User:</label>
        <input type="text" id="username" value="lol">
        <br><br>

        <button onclick="toggle(true)">Turn ON</button>
        <button onclick="toggle(false)">Turn OFF</button>
        <p id="status">Loading...</p>

        <script>
            const API_URL = '/api/status';

            async function updateStatus() {
                const user = document.getElementById('username').value;
                try {
                    const res = await fetch(API_URL + '?user=' + encodeURIComponent(user));
                    const data = await res.json();
                    document.getElementById('status').innerText =
                        'Camlock for ' + user + ' is ' + (data.camlock ? 'ON' : 'OFF');
                } catch (err) {
                    document.getElementById('status').innerText = 'Error fetching status';
                }
            }

            async function toggle(state) {
                const user = document.getElementById('username').value;
                try {
                    await fetch(API_URL, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ user: user, camlock: state })
                    });
                    updateStatus();
                } catch (err) {
                    alert('Failed to toggle state for ' + user);
                }
            }

            setInterval(updateStatus, 2000);
            updateStatus();
        </script>
    </body>
    </html>
    """
