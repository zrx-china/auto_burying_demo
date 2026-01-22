# capture_mitm.py
import json
import time
import threading
from datetime import datetime
from mitmproxy import http, ctx
from config import CONFIG
from request_monitor import RequestClassifier  # 复用你的分类器

# ======================
# 会话信息
# ======================
CURRENT_SESSION_ID = None
OUT_FILE = None

# ======================
# 实时状态（关键）
# ======================
LAST_ACTION_TS = time.time()
LAST_REQUEST_TS = 0          # 最近一次任何请求
LAST_BUSINESS_TS = 0         # 最近一次业务请求
LOCK = threading.Lock()

# ======================
# Session 管理
# ======================
def start_new_session():
    global CURRENT_SESSION_ID, OUT_FILE
    CURRENT_SESSION_ID = datetime.now().strftime("%Y%m%d_%H%M%S")
    OUT_FILE = f"log/mitm_requests_{CURRENT_SESSION_ID}.jsonl"

    info = {
        "session_id": CURRENT_SESSION_ID,
        "log_file": OUT_FILE,
        "start_ts": int(time.time() * 1000)
    }

    with open("log/current_mitm_session.json", "w", encoding="utf-8") as f:
        json.dump(info, f)

    ctx.log.info(f"🆕 新抓包 session: {CURRENT_SESSION_ID}")

# ======================
# 工具函数
# ======================
def now_ms():
    return int(time.time() * 1000)

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

# ======================
# mitmproxy 主入口
# ======================
def request(flow: http.HTTPFlow):
    global LAST_ACTION_TS, LAST_REQUEST_TS, LAST_BUSINESS_TS

    path = flow.request.path
    now = now_ms()

    # ======================
    # 🆕 启动新 session
    # ======================
    if path == "/__start_session__":
        start_new_session()
        flow.response = http.Response.make(200, b"OK")
        return

    # ======================
    # 👆 用户行为标记
    # ======================
    if path == "/mark_action":
        LAST_ACTION_TS = time.time()
        ctx.log.info("🧭 点击行为标记")
        flow.response = http.Response.make(200, b"OK")
        return

    # ======================
    # 📡 实时活动查询接口（关键）
    # ======================
    if path == "/__activity__":
        with LOCK:
            payload = {
                "now": now,
                "last_request_ts": LAST_REQUEST_TS,
                "last_business_ts": LAST_BUSINESS_TS
            }

        flow.response = http.Response.make(
            200,
            json.dumps(payload).encode(),
            {"Content-Type": "application/json"}
        )
        return

    # ======================
    # 以下是真实网络请求
    # ======================
    if not OUT_FILE:
        return  # 尚未 start_session

    url = flow.request.pretty_url
    host = flow.request.host

    # 🚫 静态资源不记录
    if any(x in url for x in [".jpg", ".png", ".mp4", ".css", ".woff"]):
        return

    # ======================
    # 更新实时状态
    # ======================
    with LOCK:
        LAST_REQUEST_TS = now

        req_type = RequestClassifier.classify_request(host, url)
        if req_type == "business":
            LAST_BUSINESS_TS = now

    # ======================
    # 写入日志（供离线分析）
    # ======================
    item = {
        "session_id": CURRENT_SESSION_ID,
        "timestamp": now,
        "host": host,
        "method": flow.request.method,
        "url": url,
        "path": path,
        "classified_type": req_type,
        "action_gap_ms": int((time.time() - LAST_ACTION_TS) * 1000),
        "body": safe_decode(flow.request.content) if flow.request.content else None
    }

    write_line(item)
    ctx.log.info(f"🌐 {req_type.upper():8s} {host} {flow.request.method} {path}")

# ======================
# mitmproxy 退出
# ======================
def done():
    ctx.log.info(f"✅ 抓包完成，日志文件：{OUT_FILE}")