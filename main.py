import csv
import json
import sqlite3
from datetime import datetime, timezone
from io import BytesIO, StringIO
from pathlib import Path
from typing import Optional

import qrcode
from better_profanity import profanity
from fastapi import Depends, FastAPI, Form, HTTPException, Request, status
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from filelock import FileLock
from passlib.context import CryptContext
from pydantic import BaseModel

# --- CONFIG ---
Path("data").mkdir(exist_ok=True)
DB_PATH_ACTIVITIES = "data/activities.db"
DB_PATH_ADMIN = "data/admin.db"
DB_PATH_ACTIVITIES_LOCK = DB_PATH_ACTIVITIES + ".lock"
DB_PATH_ADMIN_LOCK = DB_PATH_ADMIN + ".lock"
FAVICON_PATH = "data/favicon.ico"

# --- FAVICON ---
if not Path(FAVICON_PATH).exists():
    img = qrcode.make("Event Scanner")
    img.save(FAVICON_PATH)

# --- APP ---
app = FastAPI(
    title="QR Event Scanner",
    version="0.0.1",
    summary="Track event attendance via QR codes",
    description="A simple FastAPI app to track event attendance via QR codes, with an admin panel for management.",
    openapi_tags=[
        {"name": "Navigation", "description": "Navigation and event listing endpoints"},
        {"name": "Admin", "description": "Admin panel endpoints"},
        {"name": "QR", "description": "QR code generation endpoints"},
        {
            "name": "Scanning",
            "description": "Endpoints for scanning and tracking attendance",
        },
        {"name": "Events", "description": "Event listing endpoints"},
    ],
)

security = HTTPBasic()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# -------------------
# --- DATABASE INIT ---
# -------------------
def init_db():
    """Initialize the activities database if it doesn't exist."""
    conn = sqlite3.connect(DB_PATH_ACTIVITIES)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS activities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            attendee TEXT NOT NULL,
            description TEXT,
            timestamp TEXT NOT NULL,
            event TEXT NOT NULL,
            ip TEXT
        )
    """)
    conn.commit()
    conn.close()


init_db()


def init_admin_events():
    """Create table for admin-managed events."""
    print("Initializing admin-managed events...")
    with FileLock(DB_PATH_ADMIN_LOCK, timeout=5):
        db = get_admin_db()
        cur = db.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS managed_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL
            )
        """)

        cur.execute("SELECT COUNT(*) FROM managed_events")
        if cur.fetchone()[0] == 0:
            cur.executemany(
                "INSERT INTO managed_events (name) VALUES (?)",
                [("Main Hall",), ("Registration",), ("Lounge",)],
            )

        db.commit()
        db.close()


def get_admin_db():
    """Get a connection to the admin database, initializing if needed."""
    conn = sqlite3.connect(DB_PATH_ADMIN)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS authentication (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS prohibited_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_name TEXT UNIQUE NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE NOT NULL
        )
    """)
    conn.commit()
    return conn


get_admin_db()
init_admin_events()


# -------------------
# --- ADMIN UTILS ---
# -------------------
def init_admin_user():
    """Initialize default admin user if none exist."""
    db = get_admin_db()
    cur = db.cursor()
    cur.execute("SELECT COUNT(*) FROM authentication")
    if cur.fetchone()[0] == 0:
        hashed = pwd_context.hash("admin")
        cur.execute(
            "INSERT INTO authentication (username, password) VALUES (?, ?)",
            ("admin", hashed),
        )
        db.commit()
    db.close()
    init_prohibited_events()


init_admin_events()


def verify_credentials(credentials: HTTPBasicCredentials):
    """Verify provided HTTP Basic credentials."""
    db = get_admin_db()
    cur = db.cursor()
    cur.execute(
        "SELECT password FROM authentication WHERE username = ?",
        (credentials.username,),
    )
    row = cur.fetchone()
    db.close()
    if not row or not pwd_context.verify(credentials.password, row[0]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized",
            headers={"WWW-Authenticate": 'Basic realm="Admin Area"'},
        )
    return credentials.username


# -------------------
# --- PROHIBITED EVENTS / IPs ---
# -------------------
def init_prohibited_events():
    """Initialize default prohibited events and blocked IPs if none exist."""
    default_events = ["example_bad_event"]
    default_ips = ["x.x.x.x"]

    with FileLock(DB_PATH_ADMIN_LOCK, timeout=5):
        db = get_admin_db()
        cur = db.cursor()

        cur.execute("SELECT COUNT(*) FROM prohibited_events")
        if cur.fetchone()[0] == 0:
            cur.executemany(
                "INSERT INTO prohibited_events (event_name) VALUES (?)",
                [(e,) for e in default_events],
            )

        cur.execute("SELECT COUNT(*) FROM blocked_ips")
        if cur.fetchone()[0] == 0:
            cur.executemany(
                "INSERT INTO blocked_ips (ip) VALUES (?)", [(ip,) for ip in default_ips]
            )

        db.commit()
        cur.close()
        db.close()

    load_prohibited_filters()


def load_prohibited_filters():
    """Load prohibited event names into the profanity filter."""
    profanity.load_censor_words()
    db = get_admin_db()
    cur = db.cursor()
    cur.execute("SELECT event_name FROM prohibited_events")
    custom_words = [row[0] for row in cur.fetchall()]
    db.close()
    profanity.add_censor_words(custom_words)


def is_event_allowed(event_name: str) -> bool:
    """Check if the given event name is allowed (not profane or prohibited)."""
    return not profanity.contains_profanity(event_name)


def is_ip_allowed(ip: str) -> bool:
    """Check if the given IP is not in the blocked list."""
    db = get_admin_db()
    cur = db.cursor()
    cur.execute("SELECT 1 FROM blocked_ips WHERE ip = ?", (ip,))
    result = cur.fetchone()
    db.close()
    return result is None


# -------------------
# --- DATA MODEL ---
# -------------------
class ScanIn(BaseModel):
    """Input model for scan events."""

    attendee: str
    description: Optional[str] = None
    event: str


# -------------------
# --- API ENDPOINTS ---
# -------------------
@app.post("/api/scan", tags=["Scanning"])
async def receive_scan(payload: ScanIn, request: Request):
    """Receive a scan event with attendee, optional description, and event name."""
    attendee = payload.attendee.strip() if payload.attendee else ""
    if not attendee:
        raise HTTPException(status_code=400, detail="attendee is required")
    description = payload.description or ""
    event = payload.event.strip() if payload.event else ""
    timestamp = datetime.now(timezone.utc).isoformat()
    ip = request.client.host if request.client else "unknown"

    if not is_event_allowed(event):
        raise HTTPException(status_code=400, detail=f"Event '{event}' is prohibited")
    if not is_ip_allowed(ip):
        raise HTTPException(status_code=403, detail=f"IP '{ip}' is blocked")

    with FileLock(DB_PATH_ACTIVITIES_LOCK, timeout=5):
        conn = sqlite3.connect(DB_PATH_ACTIVITIES)
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO activities (attendee, description, timestamp, event, ip) VALUES (?, ?, ?, ?, ?)",
            (attendee, description, timestamp, event, ip),
        )
        conn.commit()
        conn.close()
    return {
        "status": "ok",
        "attendee": attendee,
        "event": event,
        "timestamp": timestamp,
        "ip": ip,
    }


@app.get("/api/recent", tags=["Scanning"])
async def recent(limit: int = 50, include_qr_generation: bool = False):
    """Return recent scans, optionally including QR generation events."""
    conn = sqlite3.connect(DB_PATH_ACTIVITIES)
    cur = conn.cursor()
    query = "SELECT id, attendee, description, timestamp, event FROM activities"
    if not include_qr_generation:
        query += " WHERE event != 'QR Generator'"
    query += " ORDER BY id DESC LIMIT ?"
    cur.execute(query, (limit,))
    rows = cur.fetchall()
    conn.close()
    return [
        {
            "id": r[0],
            "attendee": r[1],
            "description": r[2],
            "timestamp": r[3],
            "event": r[4],
        }
        for r in rows
    ]


@app.get("/api/qr-gen", tags=["QR"])
async def qr_gen(attendee: str, description: Optional[str] = ""):
    """Generate a QR code PNG for the given attendee and optional description."""
    payload = {"attendee": attendee, "description": description}
    payload_text = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    img = qrcode.make(payload_text)
    buf = BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return StreamingResponse(buf, media_type="image/png")


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    """Serve the favicon."""
    return FileResponse(FAVICON_PATH)


# -------------------
# --- HOMEPAGE ---
# -------------------
@app.get("/", response_class=HTMLResponse, tags=["Navigation"])
async def homepage():
    """Simple homepage for event selection."""
    html = """
    <!doctype html>
    <html>
      <head><meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Event Scanner - Home</title>
        <script src="https://cdn.tailwindcss.com"></script>
      </head>
      <body class="bg-gray-100 flex flex-col items-center justify-start min-h-screen p-4">
        <div class="bg-white shadow-xl rounded-2xl p-6 max-w-md w-full mx-auto text-center">
          <h1 class="text-2xl font-bold text-gray-800 mb-4">Event Scanner</h1>
          <p class="text-gray-600 mb-6">Select an event to start scanning QR codes for attendees.</p>
          <label for="eventSelect" class="block font-semibold text-gray-700 mb-2">Event</label>
          <select id="eventSelect" class="w-full border rounded-lg px-3 py-3 mb-4">
          </select>
          <button id="goBtn" class="w-full bg-blue-600 text-white font-semibold py-3 rounded-lg hover:bg-blue-700">Go to Event</button>
        </div>
        <script>
          document.getElementById('goBtn').addEventListener('click', () => {
            const ev = document.getElementById('eventSelect').value;
            window.location.href = '/events/' + encodeURIComponent(ev);
          });

          async function loadEvents() {
              const resp = await fetch('/api/managed-events'); // JSON API
              const data = await resp.json();
              const select = document.getElementById('eventSelect');
              select.innerHTML = '';
              data.events.forEach(e => {
                  const opt = document.createElement('option');
                  opt.value = e.name;
                  opt.textContent = e.name;
                  select.appendChild(opt);
              });
          }
          loadEvents();
        </script>
      </body>
    </html>
    """
    return HTMLResponse(html)


# -------------------
# --- ADMIN ENDPOINTS ---
# -------------------
@app.post("/admin/change-password", response_class=HTMLResponse, tags=["Admin"])
def change_password(
    username: str = Form(...),
    new_password: str = Form(...),
    credentials: HTTPBasicCredentials = Depends(security),
):
    """Change password for the given username."""
    verify_credentials(credentials)
    hashed = pwd_context.hash(new_password)

    with FileLock(DB_PATH_ADMIN_LOCK, timeout=5):
        db = get_admin_db()
        cur = db.cursor()
        cur.execute(
            "UPDATE authentication SET password = ? WHERE username = ?",
            (hashed, username),
        )
        db.commit()
        db.close()
    return HTMLResponse(
        f"<p>Password changed successfully for {username}.</p><a href='/admin'>Back to Admin</a>"
    )


@app.post("/admin/add-prohibited-event", response_class=HTMLResponse, tags=["Admin"])
def add_prohibited_event(
    event_name: str = Form(...), credentials: HTTPBasicCredentials = Depends(security)
):
    """Add a new prohibited event."""
    verify_credentials(credentials)
    with FileLock(DB_PATH_ADMIN_LOCK, timeout=5):
        db = get_admin_db()
        cur = db.cursor()
        cur.execute(
            "INSERT OR IGNORE INTO prohibited_events (event_name) VALUES (?)",
            (event_name,),
        )
        db.commit()
        db.close()

    load_prohibited_filters()
    return HTMLResponse(
        f"<p>Prohibited event '{event_name}' added.</p><a href='/admin'>Back</a>"
    )


@app.post("/admin/remove-prohibited-event", response_class=HTMLResponse, tags=["Admin"])
def remove_prohibited_event(
    event_id: int = Form(...), credentials: HTTPBasicCredentials = Depends(security)
):
    """Remove a prohibited event by its ID."""
    verify_credentials(credentials)
    with FileLock(DB_PATH_ADMIN_LOCK, timeout=5):
        db = get_admin_db()
        cur = db.cursor()
        cur.execute("DELETE FROM prohibited_events WHERE id = ?", (event_id,))
        db.commit()
        db.close()
    load_prohibited_filters()
    return HTMLResponse("<p>Prohibited event removed.</p><a href='/admin'>Back</a>")


@app.post("/admin/add-blocked-ip", response_class=HTMLResponse, tags=["Admin"])
def add_blocked_ip(
    ip: str = Form(...), credentials: HTTPBasicCredentials = Depends(security)
):
    """Add a blocked IP address."""
    verify_credentials(credentials)
    with FileLock(DB_PATH_ADMIN_LOCK, timeout=5):
        db = get_admin_db()
        cur = db.cursor()
        cur.execute("INSERT OR IGNORE INTO blocked_ips (ip) VALUES (?)", (ip,))
        db.commit()
        db.close()
    return HTMLResponse(f"<p>IP '{ip}' blocked.</p><a href='/admin'>Back</a>")


@app.post("/admin/remove-blocked-ip", response_class=HTMLResponse, tags=["Admin"])
def remove_blocked_ip(
    ip_id: int = Form(...), credentials: HTTPBasicCredentials = Depends(security)
):
    """Remove a blocked IP by its ID."""
    verify_credentials(credentials)
    with FileLock(DB_PATH_ADMIN_LOCK, timeout=5):
        db = get_admin_db()
        cur = db.cursor()
        cur.execute("DELETE FROM blocked_ips WHERE id = ?", (ip_id,))
        db.commit()
        db.close()
    return HTMLResponse("<p>Blocked IP removed.</p><a href='/admin'>Back</a>")


@app.get("/admin/export-scans", tags=["Admin"])
def export_scans(credentials: HTTPBasicCredentials = Depends(security)):
    """Export all scans as a CSV file."""
    user = verify_credentials(credentials)

    conn = sqlite3.connect(DB_PATH_ACTIVITIES)
    cur = conn.cursor()
    cur.execute(
        "SELECT id, attendee, description, timestamp, event, ip FROM activities ORDER BY id ASC"
    )
    rows = cur.fetchall()
    conn.close()

    # Prepare CSV in memory
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Attendee", "Description", "Timestamp", "Event", "IP"])
    writer.writerows(rows)
    output.seek(0)

    return StreamingResponse(
        output,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=scans.csv"},
    )


@app.get("/admin/scans", tags=["Admin"])
def get_recent_scans(
    limit: int = 50, credentials: HTTPBasicCredentials = Depends(security)
):
    """Return recent scans for admin panel."""
    verify_credentials(credentials)

    conn = sqlite3.connect(DB_PATH_ACTIVITIES)
    cur = conn.cursor()
    cur.execute(
        "SELECT id, attendee, description, event, ip, timestamp FROM activities ORDER BY id DESC LIMIT ?",
        (limit,),
    )
    rows = cur.fetchall()
    conn.close()
    return [
        {
            "id": r[0],
            "attendee": r[1],
            "description": r[2],
            "event": r[3],
            "ip": r[4],
            "timestamp": r[5],
        }
        for r in rows
    ]


@app.post("/admin/add-event", response_class=HTMLResponse, tags=["Admin"])
def add_event(
    event_name: str = Form(...), credentials: HTTPBasicCredentials = Depends(security)
):
    """Add a new event to the admin-managed list."""
    verify_credentials(credentials)
    with FileLock(DB_PATH_ADMIN_LOCK, timeout=5):
        db = get_admin_db()
        cur = db.cursor()
        cur.execute(
            "INSERT OR IGNORE INTO managed_events (name) VALUES (?)", (event_name,)
        )
        db.commit()
        db.close()
    return HTMLResponse(f"<p>Event '{event_name}' added.</p><a href='/admin'>Back</a>")


@app.post("/admin/remove-event", response_class=HTMLResponse, tags=["Admin"])
def remove_event(
    event_id: int = Form(...), credentials: HTTPBasicCredentials = Depends(security)
):
    """Remove an event by ID."""
    verify_credentials(credentials)
    with FileLock(DB_PATH_ADMIN_LOCK, timeout=5):
        db = get_admin_db()
        cur = db.cursor()
        cur.execute("DELETE FROM managed_events WHERE id = ?", (event_id,))
        db.commit()
        db.close()
    return HTMLResponse("<p>Event removed.</p><a href='/admin'>Back</a>")


@app.get("/api/managed-events", tags=["Events"])
def list_events():
    """List all managed events."""
    db = get_admin_db()
    cur = db.cursor()
    cur.execute("SELECT id, name FROM managed_events ORDER BY name")
    events = [{"id": row[0], "name": row[1]} for row in cur.fetchall()]
    db.close()
    return {"events": events}


@app.get("/admin", response_class=HTMLResponse, tags=["Admin"])
def admin_page(credentials: HTTPBasicCredentials = Depends(security)):
    """Admin panel for managing prohibited events, blocked IPs, changing password, and viewing recent scans."""
    init_admin_user()
    user = verify_credentials(credentials)

    db = get_admin_db()
    cur = db.cursor()
    cur.execute("SELECT id, event_name FROM prohibited_events")
    prohibited_events = cur.fetchall()
    cur.execute("SELECT id, ip FROM blocked_ips")
    blocked_ips = cur.fetchall()
    cur.execute("SELECT id, name FROM managed_events ORDER BY name")
    managed_events = cur.fetchall()
    db.close()

    html = f"""
    <!doctype html>
    <html lang="en">
    <head><meta charset="UTF-8"><title>Admin Area</title>
    <script src="https://cdn.tailwindcss.com"></script></head>
    <body class="bg-gray-100 p-6">
        <h1 class="text-2xl font-bold mb-4">Welcome, {user}</h1>

        <section class="mb-6">
            <h2 class="text-xl font-semibold mb-2">Change Password</h2>
            <form method="post" action="/admin/change-password" class="space-y-2">
                <input type="hidden" name="username" value="{user}">
                <input type="password" name="new_password" placeholder="New Password" required class="border px-2 py-1">
                <button type="submit" class="bg-blue-600 text-white px-3 py-1 rounded">Change Password</button>
            </form>
        </section>

        <section class="mb-6">
            <h2 class="text-xl font-semibold mb-2">Prohibited Events</h2>
            <form method="post" action="/admin/add-prohibited-event" class="space-y-2">
                <input type="text" name="event_name" placeholder="Event Name" required class="border px-2 py-1">
                <button type="submit" class="bg-red-600 text-white px-3 py-1 rounded">Add</button>
            </form>
            <ul class="mt-2">
                {"".join([f'<li>{e[1]} <form style="display:inline;" method="post" action="/admin/remove-prohibited-event"><input type="hidden" name="event_id" value="{e[0]}"><button type="submit" class="bg-gray-600 text-white px-2 py-1 rounded">Remove</button></form></li>' for e in prohibited_events])}
            </ul>
        </section>

        <section class="mb-6">
            <h2 class="text-xl font-semibold mb-2">Blocked IPs</h2>
            <form method="post" action="/admin/add-blocked-ip" class="space-y-2">
                <input type="text" name="ip" placeholder="IP Address" required class="border px-2 py-1">
                <button type="submit" class="bg-red-600 text-white px-3 py-1 rounded">Block</button>
            </form>
            <ul class="mt-2">
                {"".join([f'<li>{ip[1]} <form style="display:inline;" method="post" action="/admin/remove-blocked-ip"><input type="hidden" name="ip_id" value="{ip[0]}"><button type="submit" class="bg-gray-600 text-white px-2 py-1 rounded">Remove</button></form></li>' for ip in blocked_ips])}
            </ul>
        </section>

      <section class="mb-6">
          <h2 class="text-xl font-semibold mb-2">Managed Events</h2>
          <form method="post" action="/admin/add-event" class="space-y-2">
              <input type="text" name="event_name" placeholder="Event Name" required class="border px-2 py-1">
              <button type="submit" class="bg-blue-600 text-white px-3 py-1 rounded">Add</button>
          </form>
          <ul class="mt-2">
              {"".join([f'<li>{e[1]} <form style="display:inline;" method="post" action="/admin/remove-event"><input type="hidden" name="event_id" value="{e[0]}"><button type="submit" class="bg-gray-600 text-white px-2 py-1 rounded">Remove</button></form></li>' for e in managed_events])}
          </ul>
      </section>

        <h2 class="text-xl font-semibold mt-6">Recent Scans</h2>
        <table class="border border-gray-400 w-full text-left mb-4">
            <thead>
                <tr>
                    <th class="border px-2 py-1">ID</th>
                    <th class="border px-2 py-1">Attendee</th>
                    <th class="border px-2 py-1">Description</th>
                    <th class="border px-2 py-1">Event</th>
                    <th class="border px-2 py-1">IP</th>
                    <th class="border px-2 py-1">Timestamp</th>
                </tr>
            </thead>
            <tbody id="scanTableBody"></tbody>
        </table>
        <form method="get" action="/admin/export-scans">
            <button type="submit" class="bg-green-600 text-white px-3 py-1 rounded">Export All Scans (CSV)</button>
        </form>
        <script>
            async function loadScans() {{
                const resp = await fetch('/admin/scans');
                const data = await resp.json();
                const tbody = document.getElementById('scanTableBody');
                tbody.innerHTML = '';
                data.forEach(scan => {{
                    const tr = document.createElement('tr');
                    tr.innerHTML = `
                        <td class="border px-2 py-1">${{scan.id}}</td>
                        <td class="border px-2 py-1">${{scan.attendee}}</td>
                        <td class="border px-2 py-1">${{scan.description}}</td>
                        <td class="border px-2 py-1">${{scan.event}}</td>
                        <td class="border px-2 py-1">${{scan.ip}}</td>
                        <td class="border px-2 py-1">${{new Date(scan.timestamp).toLocaleString()}}</td>
                    `;
                    tbody.appendChild(tr);
                }});
            }}
            loadScans();
        </script>
    </body>
    </html>
    """
    return HTMLResponse(html)


# --- Events page ---
@app.get("/events/{name}", response_class=HTMLResponse, tags=["Scanning"])
async def events_page(name: str):
    """
    Display the scanning event page for tracking attendance against a given event.
    """
    event_name = name
    if not is_event_allowed(event_name):
        return HTMLResponse(
            f"<h1>Event '{event_name}' is prohibited.</h1>", status_code=400
        )

    html = f"""
    <!doctype html>
    <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Scanner — {event_name}</title>
        <script src="https://cdn.tailwindcss.com"></script>
      </head>
      <body class="bg-gray-900 text-white flex flex-col items-center justify-start min-h-screen p-4">
        <div id="flash" class="fixed inset-0 bg-green-500 bg-opacity-80 hidden items-center justify-center z-50">
          <div class="text-4xl font-bold text-green-900">SUCCESS</div>
        </div>
        <div class="w-full max-w-md space-y-4">
          <h2 class="text-xl font-bold">Event: {event_name}</h2>
          <p class="text-sm text-gray-300 text-center">Allow camera access and point at a QR code.</p>
          <video id="video" playsinline class="w-full max-h-[50vh] rounded-lg bg-black mb-4"></video>
          <canvas id="canvas" class="hidden"></canvas>
          <div id="message" class="text-center text-lg mb-4">Initializing camera…</div>
          <div id="controls" class="flex flex-wrap gap-2 justify-center mb-4">
            <button id="btnStop" class="bg-red-600 hover:bg-red-700 text-white rounded-lg px-4 py-3 w-full sm:w-auto">Stop</button>
            <button id="btnRestart" class="bg-blue-600 hover:bg-blue-700 text-white rounded-lg px-4 py-3 w-full sm:w-auto">Start</button>
            <button id="btnRecent" class="bg-gray-600 hover:bg-gray-700 text-white rounded-lg px-4 py-3 w-full sm:w-auto">Recent</button>
          </div>
          <div id="recent" class="hidden mt-2 text-gray-200 max-h-48 overflow-auto border-t border-gray-700 pt-2 text-sm w-full"></div>
        </div>

        <script src="https://unpkg.com/jsqr/dist/jsQR.js"></script>
        <script>
          const eventName = {json.dumps(event_name)};
          const video = document.getElementById('video');
          const canvas = document.getElementById('canvas');
          const ctx = canvas.getContext('2d');
          const messageEl = document.getElementById('message');
          const flashEl = document.getElementById('flash');
          const recentEl = document.getElementById('recent');
          let stream = null, scanning = false, lastScannedText = null, debounceTimer = null;

          async function startCamera() {{
            if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {{
              messageEl.textContent = "Camera API not supported.";
              return;
            }}
            try {{
              messageEl.textContent = "Requesting camera access...";
              stream = await navigator.mediaDevices.getUserMedia({{ video: {{ facingMode: "environment" }}}});
              video.srcObject = stream;
              await video.play();
              messageEl.textContent = "Scanning for QR — point camera at QR code.";
              scanning = true;
              requestAnimationFrame(tick);
            }} catch (err) {{
              messageEl.textContent = "Camera error: " + err.message;
            }}
          }}

          function stopCamera() {{
            scanning = false;
            if (stream) {{
              stream.getTracks().forEach(t => t.stop());
              stream = null;
            }}
            messageEl.textContent = "Camera stopped.";
          }}

          function showFlash() {{
            flashEl.style.display = 'flex';
            setTimeout(() => flashEl.style.display = 'none', 600);
          }}

          async function sendScan(attendee, description) {{
            try {{
              const resp = await fetch('/api/scan', {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json' }},
                body: JSON.stringify({{ attendee, description, event: eventName }})
              }});
              if (!resp.ok) {{
                const err = await resp.json();
                messageEl.textContent = 'Server error: ' + (err.detail || resp.statusText);
                return;
              }}
              messageEl.textContent = `Saved! Ready for next scan.`;
            }} catch (err) {{
              messageEl.textContent = 'Network error: ' + err.message;
            }}
          }}

          function tick() {{
            if (!scanning) return;
            if (video.readyState === video.HAVE_ENOUGH_DATA) {{
              canvas.width = video.videoWidth;
              canvas.height = video.videoHeight;
              ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
              const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
              const code = jsQR(imgData.data, imgData.width, imgData.height);
              if (code) {{
                const text = code.data;
                if (text && text !== lastScannedText) {{
                  lastScannedText = text;
                  clearTimeout(debounceTimer);
                  debounceTimer = setTimeout(() => lastScannedText = null, 1500);
                  let parsed = null;
                  try {{ parsed = JSON.parse(text); }} catch (e) {{
                    const reAtt = /attendee\\s*[:=]\\s*(.+)/i;
                    const reDesc = /description\\s*[:=]\\s*(.+)/i;
                    parsed = {{
                      attendee: (text.match(reAtt) || [])[1] || null,
                      description: (text.match(reDesc) || [])[1] || ""
                    }};
                  }}
                  if (!parsed || !parsed.attendee) {{
                    messageEl.textContent = 'QR decoded but no attendee: ' + text;
                  }} else {{
                    showFlash();
                    sendScan(parsed.attendee, parsed.description || '');
                  }}
                }}
              }}
            }}
            requestAnimationFrame(tick);
          }}

          document.getElementById('btnStop').addEventListener('click', () => stopCamera());
          document.getElementById('btnRestart').addEventListener('click', async () => {{ stopCamera(); await startCamera(); }});
          document.getElementById('btnRecent').addEventListener('click', async () => {{
            if (recentEl.classList.contains('hidden')) {{
              const r = await fetch('/api/recent?limit=20');
              const data = await r.json();
              recentEl.innerHTML = '<strong>Recent scans:</strong><br/>' + data.map(d => `
                ${{new Date(d.timestamp).toLocaleString()}} — ${{d.attendee}} @ ${{d.event}}
              `).join('<br/>');
              recentEl.classList.remove('hidden');
            }} else {{
              recentEl.classList.add('hidden');
            }}
          }});

          (async () => {{ await startCamera(); }})();
        </script>
      </body>
    </html>
    """
    return HTMLResponse(html)


@app.get("/api/events", tags=["Events"])
async def events_api():
    """Return a list of all distinct events."""
    conn = sqlite3.connect(DB_PATH_ACTIVITIES)
    cur = conn.cursor()
    cur.execute("SELECT DISTINCT event FROM activities ORDER BY event")
    events = [row[0] for row in cur.fetchall()]
    conn.close()
    if not events:
        events = ["No events yet!"]
    return {"events": events}


@app.get("/events", response_class=HTMLResponse, tags=["Navigation"])
async def list_events():
    """Provide a simple page listing all events."""
    html = """
    <!doctype html>
    <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Event Scanner - Events</title>
        <script src="https://cdn.tailwindcss.com"></script>
      </head>
      <body class="bg-gray-100 flex flex-col items-center justify-start min-h-screen p-4">
        <div class="bg-white shadow-xl rounded-2xl p-6 max-w-md w-full mx-auto text-center space-y-4">
          <h1 class="text-2xl font-bold text-gray-800">Events</h1>
          <div id="eventList" class="space-y-2"></div>
        </div>

        <script>
          async function fetchEvents() {
            const resp = await fetch('/api/managed-events');
            const data = await resp.json();
            const eventList = document.getElementById('eventList');
            eventList.innerHTML = '';
            data.events.forEach(event => {
              const div = document.createElement('div');
              div.textContent = event;
              eventList.appendChild(div);
            });
          }

          fetchEvents();
        </script>
      </body>
    </html>
    """
    return HTMLResponse(html)


# --- API QR generator ---
@app.get("/api/qr-gen", tags=["QR"])
async def qr_gen_api(attendee: str, description: Optional[str] = ""):
    payload = {"attendee": attendee, "description": description}
    payload_text = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    img = qrcode.make(payload_text)
    buf = BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return StreamingResponse(buf, media_type="image/png")


# --- QR generator page ---
@app.get("/qr-gen", response_class=HTMLResponse, tags=["QR"])
async def qr_gen_page():
    html = """
    <!doctype html>
    <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>QR Code Generator</title>
        <script src="https://cdn.tailwindcss.com"></script>
      </head>
      <body class="bg-gray-100 flex flex-col items-center justify-start min-h-screen p-4">
        <div class="bg-white shadow-xl rounded-2xl p-6 max-w-md w-full mx-auto text-center space-y-4">
          <h1 class="text-2xl font-bold text-gray-800">QR Code Generator</h1>
          <form id="qrForm" class="space-y-4">
            <input id="attendee" type="text" placeholder="Attendee Name" required
                   class="w-full border rounded-lg px-3 py-3 text-base">
            <input id="description" type="text" placeholder="Description (optional)"
                   class="w-full border rounded-lg px-3 py-3 text-base">
            <button type="submit"
                    class="bg-blue-600 hover:bg-blue-700 text-white font-semibold px-4 py-3 rounded-lg w-full">
              Generate QR & Submit Scan
            </button>
          </form>
          <div id="result" class="hidden space-y-2">
            <p class="text-gray-700 font-semibold">Generated QR Code:</p>
            <img id="qrImage" class="mx-auto border rounded-lg max-w-full" alt="QR Code">
            <p id="status" class="text-green-600 font-semibold"></p>
          </div>
        </div>

        <script src="https://cdn.jsdelivr.net/npm/axios/dist/axios.min.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/qrious/dist/qrious.min.js"></script>
        <script>
          const form = document.getElementById('qrForm');
          const qrImage = document.getElementById('qrImage');
          const resultDiv = document.getElementById('result');
          const statusEl = document.getElementById('status');

          form.addEventListener('submit', async (e) => {
            e.preventDefault();
            const attendee = document.getElementById('attendee').value.trim();
            const description = document.getElementById('description').value.trim();

            if (!attendee) return alert("Attendee name is required.");

            try {
              const resp = await axios.post('/api/scan', {
                attendee,
                description,
                event: "QR Generator"
              });

              if (resp.data.status === "ok") {
                statusEl.textContent = `Scan saved for: ${attendee}`;
                resultDiv.classList.remove('hidden');

                const payload = JSON.stringify({attendee, description});
                const qrCanvas = document.createElement('canvas');
                const qr = new QRious({ element: qrCanvas, value: payload, size: 200 });
                qrImage.src = qrCanvas.toDataURL();
              } else {
                statusEl.textContent = 'Error saving scan.';
              }
            } catch (err) {
              console.error(err);
              statusEl.textContent = 'Network error: ' + err;
              resultDiv.classList.remove('hidden');
            }
          });
        </script>
      </body>
    </html>
    """
    return HTMLResponse(html)
