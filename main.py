# main.py
from crawler_appium import AppiumCrawler
from analyze_report import AdvancedAnalyzer
from time import time
import threading

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

crawler = AppiumCrawler()

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

print("\n📊 生成埋点评估报告...")
try:
    AdvancedAnalyzer().generate_report("test_report.html")
except Exception as e:
    print(f"⚠️ 报告生成失败: {e}")
