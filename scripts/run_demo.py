#!/usr/bin/env python3
r"""
One command for the demo: starts the server, the cloudflared tunnel and the Telegram bot together.

    python scripts\run_demo.py              # server + tunnel + bot
    python scripts\run_demo.py --no-telegram   # only the server (web demo and attack suite)

What it does:
1. Starts the server on http://127.0.0.1:8000 and waits until it answers.
2. Starts `cloudflared tunnel --protocol http2` (HTTP/2 over TCP, because some networks block QUIC/UDP)
   and reads the https://....trycloudflare.com address from its output.
3. Starts the bot with MINIAPP_URL set to that address + /tg/, so secrets/.env never needs editing when the
   address changes. The bot token still comes from secrets/.env (this script never reads or prints it).
4. Ctrl+C stops all three.
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.request

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TUNNEL_RE = re.compile(r"https://[a-z0-9-]+\.trycloudflare\.com")

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def say(msg: str):
    print(f"[demo] {msg}", flush=True)


def wait_for(url: str, seconds: float) -> bool:
    end = time.time() + seconds
    while time.time() < end:
        try:
            with urllib.request.urlopen(url, timeout=3) as r:
                if r.status < 500:
                    return True
        except Exception:
            pass
        time.sleep(1)
    return False


def find_cloudflared():
    found = shutil.which("cloudflared")
    if found:
        return found
    for path in (r"C:\Program Files (x86)\cloudflared\cloudflared.exe", r"C:\Program Files\cloudflared\cloudflared.exe"):
        if os.path.exists(path):
            return path
    return None


def start_tunnel(exe: str, port: int, timeout: float = 60):
    proc = subprocess.Popen([exe, "tunnel", "--no-autoupdate", "--protocol", "http2", "--url", f"http://localhost:{port}"],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace")
    found = {}

    def reader():
        for line in proc.stdout:
            if "url" not in found:
                m = TUNNEL_RE.search(line)
                if m:
                    found["url"] = m.group(0)
            if " ERR " in line:
                print("[tunnel] " + line.rstrip(), flush=True)

    threading.Thread(target=reader, daemon=True).start()
    end = time.time() + timeout
    while time.time() < end and "url" not in found and proc.poll() is None:
        time.sleep(0.3)
    return proc, found.get("url")


def main():
    ap = argparse.ArgumentParser(description="Start the Secure Messenger demo.")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--no-telegram", action="store_true", help="only start the server")
    args = ap.parse_args()

    procs = []
    try:
        say(f"starting the server on http://127.0.0.1:{args.port} ...")
        server = subprocess.Popen([sys.executable, "-m", "uvicorn", "backend.app.main:app",
                                   "--host", "127.0.0.1", "--port", str(args.port)], cwd=REPO_ROOT)
        procs.append(server)
        if not wait_for(f"http://127.0.0.1:{args.port}/", 30):
            say("the server did not start. Is something else already using port %d? Close it and try again." % args.port)
            return 1
        say(f"server is up:  web app http://127.0.0.1:{args.port}/v2/   insecure v1 http://127.0.0.1:{args.port}/v1/")

        if args.no_telegram:
            say("Telegram parts skipped (--no-telegram). Press Ctrl+C to stop.")
        else:
            exe = find_cloudflared()
            if not exe:
                say("cloudflared is not installed: winget install --id Cloudflare.cloudflared  (then open a new terminal)")
                return 1
            say("starting the tunnel (can take up to a minute) ...")
            tunnel, url = start_tunnel(exe, args.port)
            procs.append(tunnel)
            if not url:
                say("no tunnel address appeared. Check the internet connection or try another network.")
                return 1
            say(f"tunnel address: {url}")
            if not wait_for(url + "/", 45):
                say("the tunnel address does not answer yet; the bot starts anyway, try the Mini App in a few seconds.")

            env = dict(os.environ, MINIAPP_URL=url + "/tg/")
            say("starting the bot (Mini App address " + url + "/tg/) ...")
            bot = subprocess.Popen([sys.executable, os.path.join("backend", "bot", "bot.py")], cwd=REPO_ROOT, env=env)
            procs.append(bot)
            time.sleep(4)
            if bot.poll() is not None:
                say("the bot stopped. Usually TELEGRAM_BOT_TOKEN is missing in secrets\\.env (see README).")
                return 1
            say("all running. In Telegram: open your bot -> Start -> Open CipherBridge. Press Ctrl+C to stop everything.")

        while all(p.poll() is None for p in procs):
            time.sleep(1)
        say("one part stopped unexpectedly; shutting the rest down.")
        return 1
    except KeyboardInterrupt:
        say("stopping ...")
        return 0
    finally:
        for p in reversed(procs):
            if p.poll() is None:
                p.terminate()
        for p in procs:
            try:
                p.wait(timeout=10)
            except Exception:
                p.kill()


if __name__ == "__main__":
    sys.exit(main())
