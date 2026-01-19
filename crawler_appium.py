# crawler_appium.py
import time
from appium import webdriver
from appium.options.android import UiAutomator2Options
from selenium.common.exceptions import WebDriverException
from config import CONFIG
import os
import re
import xml.etree.ElementTree as ET
import requests  # 新增

class AppiumCrawler:
    def __init__(self):
        self.driver = None
        self.visited_activities = set()
        self.clicked_elements = set()

    # ---------- 启动 ----------
    def start_driver(self):
        options = UiAutomator2Options()
        options.platform_name = CONFIG["platform_name"]
        options.device_name = CONFIG["device_name"]
        options.platform_version = CONFIG["platform_version"]
        options.automation_name = CONFIG["automation_name"]
        options.app_package = CONFIG["app_package"]
        options.app_activity = CONFIG["app_activity"]
        options.no_reset = True
        options.new_command_timeout = 300

        # mitmproxy
        options.set_capability("proxy", {
            "proxyType": "manual",
            "httpProxy": f"{CONFIG['proxy_host']}:{CONFIG['proxy_port']}",
            "sslProxy": f"{CONFIG['proxy_host']}:{CONFIG['proxy_port']}"
        })

        self.driver = webdriver.Remote(CONFIG["appium_server"], options=options)
        print("✅ Appium Driver 启动成功")

    # ---------- 等待主页面 ----------
    def wait_for_main_activity(self, timeout=15):
        print("⏳ 等待 App 进入主页面...")
        start = time.time()
        last_act = None
        stable_count = 0

        while time.time() - start < timeout:
            try:
                act = self.driver.current_activity
                print(f"   当前 Activity: {act}")

                if act == last_act:
                    stable_count += 1
                else:
                    stable_count = 0

                if stable_count >= 3 and "logo" not in act.lower():
                    print("✅ UI 已就绪，开始遍历")
                    return True

                last_act = act
                time.sleep(1)
            except Exception:
                time.sleep(1)

        print("⚠️ 主页面等待超时，仍然尝试遍历")
        return False

    # ---------- 安全 dump ----------
    def safe_dump(self):
        try:
            _ = self.driver.page_source
            return True
        except WebDriverException:
            return False

    # ---------- 查找可点元素 ----------
    def find_clickables(self):
        elements = []
        try:
            os.system("adb shell uiautomator dump /sdcard/ui.xml > /dev/null")
            os.system("adb pull /sdcard/ui.xml ./ui.xml > /dev/null")

            tree = ET.parse("ui.xml")
            root = tree.getroot()

            idx = 0
            for node in root.iter("node"):
                if node.attrib.get("clickable") == "true":
                    clazz = node.attrib.get("class", "")
                    text = node.attrib.get("text", "")
                    desc = node.attrib.get("content-desc", "")
                    bounds = node.attrib.get("bounds", "")
                    eid = (clazz, text, desc, bounds)

                    if eid not in self.clicked_elements:
                        elements.append((eid, bounds))

                    idx += 1

            print(f"\n➡️ 共发现 {len(elements)} 个未点击元素")

        except Exception as e:
            print(f"⚠️ 查找元素失败: {e}")

        return elements

    def tap_by_bounds(self, bounds):
        """根据 bounds 点击元素，并标记用户行为"""
        nums = list(map(int, re.findall(r"\d+", bounds)))
        if len(nums) != 4:
            raise ValueError(f"非法 bounds: {bounds}")
        x1, y1, x2, y2 = nums
        x = (x1 + x2) // 2
        y = (y1 + y2) // 2

        print(f"DEBUG: adb tap at ({x}, {y})")
        os.system(f"adb shell input tap {x} {y}")

        # 🔹 点击后标记用户行为（更新 mitmproxy LAST_ACTION_TS）
        try:
            requests.get(
                    "http://mark.local/mark_action",
                    proxies={
                        "http": f"http://{CONFIG['mitm_host']}:{CONFIG['mitm_port']}",
                        "https": f"http://{CONFIG['mitm_host']}:{CONFIG['mitm_port']}",
                    },
                    timeout=1
                )
        except:
            pass

    def adb_back(self):
        """模拟按下返回键"""
        print("DEBUG: adb back")
        os.system("adb shell input keyevent 4")

    def handle_popup(self):
        """扫描当前页面的弹窗按钮并点击"""
        clickables = self.find_clickables()
        for eid, bounds in clickables:
            clazz, text, desc, _ = eid
            if text in ["允许", "拒绝", "确定", "取消", "继续"]:
                print(f"⚡ 发现弹窗按钮，点击: {text}")
                self.tap_by_bounds(bounds)
                time.sleep(1)
                return True
        return False
    
    def wait_for_activity(self, before_act, timeout=10):
        start = time.time()
        while time.time() - start < timeout:
            try:
                act = self.driver.current_activity
            except Exception:
                act = None
            if act != before_act:
                return act
            time.sleep(0.5)
        return act
    
    def wait_for_page_idle(self, check_interval=1, max_attempts=10):
        prev_elements = set()
        for _ in range(max_attempts):
            clickables = set(eid for eid, _ in self.find_clickables())
            while self.handle_popup():
                pass
            if clickables == prev_elements:
                break
            prev_elements = clickables
            time.sleep(check_interval)

    # ---------- DFS ----------
    def dfs(self, depth=0):
        if depth > CONFIG["max_depth"]:
            return

        try:
            current_act = self.driver.current_activity
        except Exception:
            return

        if current_act in self.visited_activities:
            return

        self.visited_activities.add(current_act)
        print(f"\n🔍 深度 {depth} | {current_act}")
        time.sleep(CONFIG["page_wait"])

        while True:
            clickables = self.find_clickables()
            clickables = [(eid, bounds) for eid, bounds in clickables if eid not in self.clicked_elements]
            if not clickables:
                print("⏹ 页面无可点击元素，返回上一层")
                return

            eid, bounds = clickables[0]
            clazz, text, desc, _ = eid
            name = text or desc or clazz
            print(f"   👉 点击 {name[:30]}")

            try:
                while self.handle_popup():
                    pass

                self.tap_by_bounds(bounds)

                new_act = self.wait_for_activity(current_act, timeout=10)
                self.wait_for_page_idle(max_attempts=15)

                if new_act and ("WebView" in new_act or "H5" in new_act):
                    print(f"🌐 WebView，立即返回: {new_act}")
                    self.adb_back()
                    self.wait_for_activity(new_act)
                    self.clicked_elements.add(eid)
                    continue

                self.clicked_elements.add(eid)
                self.dfs(depth + 1)

                self.adb_back()
                self.wait_for_activity(new_act)
                self.wait_for_page_idle(max_attempts=10)

            except Exception as e:
                print(f"      ⚠️ 点击失败: {e}")
                self.clicked_elements.add(eid)

    # ---------- 入口 ----------
    def run(self):
        print("\n" + "=" * 60)
        print("🚀 开始自动遍历 App UI")
        print("=" * 60)

        self.start_driver()
        self.wait_for_main_activity()
        self.dfs()

        print("\n✅ 遍历完成")
        print(f"   页面数: {len(self.visited_activities)}")
        print(f"   点击数: {len(self.clicked_elements)}")

    def stop(self):
        if self.driver:
            self.driver.quit()
            print("🔚 Appium Driver 已关闭")


if __name__ == "__main__":
    crawler = AppiumCrawler()
    try:
        crawler.run()
    finally:
        crawler.stop()