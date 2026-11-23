"""
FastAPI entrypoint for Secure Messenger.
Mounts API routes and serves static web clients:
- /v1: Naive insecure client
- /v2: Hardened zero-knowledge client
"""

import os
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from . import database, routes

app = FastAPI(
    title="Secure Messenger Lab",
    description="Cybersecurity skill lab comparing naive messaging vs hardened E2EE sensitive messenger",
    version="1.0.0"
)

# Initialize database schema
database.init_db()

# Mount API routes
app.include_router(routes.router)

# Resolve client directories
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_V1_DIR = os.path.join(BASE_DIR, "client_v1")
CLIENT_V2_DIR = os.path.join(BASE_DIR, "client_v2")

# Ensure directories exist
os.makedirs(CLIENT_V1_DIR, exist_ok=True)
os.makedirs(CLIENT_V2_DIR, exist_ok=True)

# Mount static files
app.mount("/v1", StaticFiles(directory=CLIENT_V1_DIR, html=True), name="client_v1")
app.mount("/v2", StaticFiles(directory=CLIENT_V2_DIR, html=True), name="client_v2")

@app.get("/", response_class=HTMLResponse)
def index():
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Secure Messenger - Lab Switchboard</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; padding: 40px; display: flex; justify-content: center; align-items: center; min-height: 80vh; }
            .card { background: #1e293b; border-radius: 12px; padding: 32px; max-width: 650px; width: 100%; box-shadow: 0 10px 25px rgba(0,0,0,0.5); border: 1px solid #334155; }
            h1 { margin-top: 0; color: #38bdf8; font-size: 24px; }
            p { color: #94a3b8; line-height: 1.6; }
            .badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; margin-bottom: 8px; }
            .badge-danger { background: #ef4444; color: white; }
            .badge-success { background: #10b981; color: white; }
            .button-group { display: flex; gap: 16px; margin-top: 24px; }
            .btn { flex: 1; padding: 14px 18px; border-radius: 8px; text-decoration: none; text-align: center; font-weight: 600; font-size: 15px; transition: 0.2s ease; }
            .btn-v1 { background: #334155; color: #f87171; border: 1px solid #ef4444; }
            .btn-v1:hover { background: #475569; }
            .btn-v2 { background: #0284c7; color: white; border: 1px solid #38bdf8; }
            .btn-v2:hover { background: #0369a1; }
            .info-box { background: #0f172a; border-left: 4px solid #38bdf8; padding: 12px 16px; margin-top: 24px; border-radius: 4px; font-size: 14px; }
        </style>
    </head>
    <body>
        <div class="card">
            <h1>🛡️ Secure Messenger Cybersecurity Lab</h1>
            <p>This lab demonstrates practical end-to-end encryption (E2EE), zero-knowledge server architecture, and sensitive-message ephemerality compared to a naive, vulnerable messaging implementation.</p>
            
            <div class="button-group">
                <a href="/v1/" class="btn btn-v1">
                    <span class="badge badge-danger">TARGET</span><br>
                    Client v1 (Insecure)
                    <div style="font-size: 12px; color: #cbd5e1; margin-top: 4px;">Plaintext, no auth, replayable</div>
                </a>
                <a href="/v2/" class="btn btn-v2">
                    <span class="badge badge-success">HARDENED</span><br>
                    Client v2 (Secure)
                    <div style="font-size: 12px; color: #e0f2fe; margin-top: 4px;">X25519, AEAD, KDF, DLP, Expiry</div>
                </a>
            </div>

            <div class="info-box">
                <strong>Lab Verification:</strong> Both clients interact with the exact same FastAPI zero-knowledge backend. Attack scripts in <code>attacks/</code> systematically target both to measure adversarial impact.
            </div>
        </div>
    </body>
    </html>
    """
