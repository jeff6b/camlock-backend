from fastapi import FastAPI, Header, HTTPException
import sqlite3

app = FastAPI()

API_KEY = "test_key_123"

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
