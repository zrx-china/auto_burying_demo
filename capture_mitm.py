# capture_mitm.py
import json
import time
import threading
from datetime import datetime
from mitmproxy import http, ctx
from config import CONFIG

SESSION_ID = datetime.now().strftime("%Y%m%d_%H%M%S")
OUT_FILE = f"mitm_capture_{SESSION_ID}.jsonl"

LAST_ACTION_TS = time.time()
LOCK = threading.Lock()


def now():
    return datetime.now().isoformat()


def safe_decode(content: bytes):
    try:
        return json.loads(content.decode())
    except Exception:
        try:
            return content.decode(errors="ignore")
        except Exception:
            return None


def write_line(obj: dict):
    """线程安全地写一行 JSON"""
    with LOCK:
        with open(OUT_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(obj, ensure_ascii=False) + "\n")
            f.flush()


def request(flow: http.HTTPFlow):
    global LAST_ACTION_TS

    # 👆 行为标记
    if flow.request.path == "/mark_action":
        LAST_ACTION_TS = time.time()
        ctx.log.info("🧭 点击行为标记")
        return

    url = flow.request.pretty_url

    # 🚫 静态资源过滤
    if any(x in url for x in [".jpg", ".png", ".mp4", ".css", ".woff"]):
        return

    item = {
        "session_id": SESSION_ID,
        "timestamp": now(),
        "host": flow.request.host,
        "method": flow.request.method,
        "url": url,
        "path": flow.request.path,
        "action_gap_ms": int((time.time() - LAST_ACTION_TS) * 1000),
        "body": safe_decode(flow.request.content) if flow.request.content else None
    }

    write_line(item)
    ctx.log.info(f"🌐 {item['host']} {item['method']} {item['path']}")


def done():
    ctx.log.info(f"✅ 实时日志已写入：{OUT_FILE}")