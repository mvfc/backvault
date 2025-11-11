import os
from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from db import db_connect, put_key
import logging
from sys import stdout

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
    handlers=[logging.StreamHandler(stdout)],
)
logger = logging.getLogger(__name__)

app = FastAPI()

# --- Constants ---
DATA_DIR = os.getenv("DATA_DIR", "/app")
DB_PATH = os.getenv("DB_PATH", "/app/db/backvault.db")
PRAGMA_KEY_FILE = os.getenv("PRAGMA_KEY_FILE", "/app/db/backvault.db.pragma")

# --- UI HTML ---
HTML_FORM = open("./form.html").read()

@app.get("/health")
def health_check():
    return {"status": "ok"}

@app.get("/", response_class=HTMLResponse)
def index():
    return HTML_FORM

@app.post("/init")
async def init(
    master_password: str = Form(...),
    client_id: str = Form(...),
    client_secret: str = Form(...),
    file_password: str = Form(...),
):
    conn, cursor = db_connect(DB_PATH, PRAGMA_KEY_FILE)
    if not conn or not cursor:
        return HTMLResponse("Database connection failed", status_code=500)
    
    # Store encrypted passwords and keys
    put_key(conn, "master_password", master_password.encode())
    put_key(conn, "client_id", client_id.encode())
    put_key(conn, "client_secret", client_secret.encode())
    put_key(conn, "file_password", file_password.encode())

    conn.close()

    return RedirectResponse("/done", status_code=302)

@app.get("/done", response_class=HTMLResponse)
def done():
    from threading import Thread
    import time, os, signal

    logging.info("Setup complete, shutting down UI...")
    def _shutdown():
        time.sleep(0.5)
        os.kill(os.getpid(), signal.SIGTERM)

    Thread(target=_shutdown).start()
    return """
    <html>
    <body style="background:#111; color:#eee; display:flex; justify-content:center; align-items:center; height:100vh; font-family:Segoe UI, sans-serif;">
      <div style="text-align:center;">
        <h3>Setup complete.</h3>
        <p>The UI will now stop and the container will enter normal mode. You can close this window.</p>
      </div>
    </body>
    </html>
    """
