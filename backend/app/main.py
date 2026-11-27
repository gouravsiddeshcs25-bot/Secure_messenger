"""
FastAPI entrypoint for Secure Messenger.
Mounts API routes and serves static web clients:
- /   : home page (frontend/landing)
- /v1: Naive insecure client
- /v2: Hardened zero-knowledge client
"""

import os
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
# Repo root: backend/app/main.py -> three levels up
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Load secrets/.env if present (never committed; see secrets/README.md)
try:
    from dotenv import load_dotenv
    _env_path = os.path.join(REPO_ROOT, "secrets", ".env")
    if os.path.exists(_env_path):
        load_dotenv(_env_path)
except ImportError:
    pass

from . import database, routes

app = FastAPI(
    title="Secure Messenger Lab",
    description="Cybersecurity skill lab comparing naive messaging vs hardened E2EE sensitive messenger",
    version="1.0.0"
)

# Initialize database schema
database.init_db()

# Mount API routes
app.include_router(routes.router)      # /api     : secure v2 (login required)
app.include_router(routes.v1_router)   # /api/v1  : insecure v1 (attack-lab target)

# Resolve client directories
CLIENT_V1_DIR = os.path.join(REPO_ROOT, "frontend", "legacy-insecure")
CLIENT_V2_DIR = os.path.join(REPO_ROOT, "frontend", "web")
SHARED_DIR = os.path.join(REPO_ROOT, "frontend", "shared")

# Ensure directories exist
os.makedirs(CLIENT_V1_DIR, exist_ok=True)
os.makedirs(CLIENT_V2_DIR, exist_ok=True)
os.makedirs(SHARED_DIR, exist_ok=True)

# Mount static files
app.mount("/v1", StaticFiles(directory=CLIENT_V1_DIR, html=True), name="client_v1")
app.mount("/v2", StaticFiles(directory=CLIENT_V2_DIR, html=True), name="client_v2")
app.mount("/shared", StaticFiles(directory=SHARED_DIR), name="shared")

LANDING_PAGE = os.path.join(REPO_ROOT, "frontend", "landing", "index.html")

@app.get("/", include_in_schema=False)
def index():
    """Home page: explains the lab and links to both clients (frontend/landing/index.html)."""
    return FileResponse(LANDING_PAGE, media_type="text/html")
