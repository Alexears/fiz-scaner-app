import json, os, time
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler

BASE = os.path.dirname(os.path.abspath(__file__))
STATE_FILE = os.path.join(BASE, "state.json")

DEFAULT = {
    "last_scan": None,
    "last_scan_at": None,
    "selected_guest_code": "000"
}

def load_state():
    if not os.path.exists(STATE_FILE):
        return DEFAULT.copy()
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        state = DEFAULT.copy()
        state.update(data or {})
        return state
    except Exception:
        return DEFAULT.copy()

def save_state(state):
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)

class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=BASE, **kwargs)

    def end_headers(self):
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Access-Control-Allow-Origin", "*")
        super().end_headers()

    def do_GET(self):
        if self.path.startswith("/api/state"):
            state = load_state()
            raw = json.dumps(state, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return
        return super().do_GET()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8") if length else "{}"
        try:
            data = json.loads(body or "{}")
        except Exception:
            data = {}

        state = load_state()

        if self.path == "/api/scan":
            code = str(data.get("code", "")).strip()
            if len(code) < 3:
                code = code.zfill(3)
            state["last_scan"] = code
            state["last_scan_at"] = int(time.time() * 1000)
            save_state(state)
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(json.dumps({"ok": True}).encode("utf-8"))
            return

        if self.path == "/api/select":
            code = str(data.get("code", "")).strip()
            if len(code) < 3:
                code = code.zfill(3)
            state["selected_guest_code"] = code
            save_state(state)
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(json.dumps({"ok": True}).encode("utf-8"))
            return

        self.send_error(404)

if __name__ == "__main__":
    save_state(load_state())
    port = int(os.environ.get("PORT", 8000))
    print(f"Server running on http://0.0.0.0:{port}")
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
