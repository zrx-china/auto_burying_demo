# main.py
from crawler_appium import IntegratedCrawler
from analyze_report import BuryPointAnalyzer
from time import time
import threading
import os
import json
from config import CONFIG
import requests

print("""
=====================================
 埋点自动化检测 Demo
=====================================
""")

print("⚠️ 请确认：")
print("1. mitmdump -s capture_mitm.py 已启动 (如需抓包)")
print("2. 手机代理已指向电脑 IP:8080 (如需抓包)")
print("3. 或者暂时不抓包,只测试遍历功能")
input("\n确认后回车开始...")


requests.get(
    "http://mark.local/__start_session__",
    proxies={
        "http": "http://127.0.0.1:8080",
        "https": "http://127.0.0.1:8080",
    },
    timeout=2
)

session_file = "log/current_mitm_session.json"

if os.path.exists(session_file):
    with open(session_file, "r", encoding="utf-8") as f:
        mitm_session = json.load(f)

    print(f"🧭 发现抓包会话:")
    print(f"   session_id = {mitm_session['session_id']}")
    print(f"   log_file   = {mitm_session['log_file']}")
else:
    mitm_session = None
    print("⚠️ 未发现 mitm 抓包会话，将仅做 UI 遍历")

crawler = IntegratedCrawler(config = CONFIG,
                            mitm_log_file=mitm_session["log_file"] if mitm_session else None)

try:
    start = time()
    crawler.run()
    print(f"⏱ 遍历耗时 {time() - start:.1f}s")
finally:
    print("🧹 后台清理 crawler...")
    threading.Thread(
        target=crawler.stop,
        daemon=True
    ).start()

print("\n✅ 遍历完成！")

print("\n📊 生成埋点评估报告...")
try:
    report_file = BuryPointAnalyzer(mitm_file = f"log/mitm_requests_{mitm_session['session_id']}" , click_log_file = f"log/click_log_{mitm_session['session_id']}").generate_report()
    print(f"✅ 报告保存为: {report_file}")
except Exception as e:
    print(f"⚠️ 报告生成失败: {e}")
