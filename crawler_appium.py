#!/usr/bin/env python3
"""
智能爬虫 - 基于页面变化记录版
核心改进:
1. 基于页面切换检测来记录日志（不是基于代码意图）
2. 同层级遍历：先遍历完当前页面所有元素，再递归子页面
3. 页面指纹识别：通过 Activity + 元素数量判断页面是否真的变化
"""

import time
import os
import re
import json
import xml.etree.ElementTree as ET
from typing import List, Dict, Tuple, Optional, Set
from appium import webdriver
from appium.options.android import UiAutomator2Options
from selenium.common.exceptions import WebDriverException
import requests
from datetime import datetime
import hashlib

from config import CONFIG
from request_monitor import RequestMonitor, RequestClassifier  

from enum import Enum, auto


class BackResult(Enum):
    OK_RETURN = auto()     # 正常返回到父页面
    NO_EFFECT = auto()     # back 无效（页面没变）
    REDIRECT = auto()      # 跳转到非父页面


class PageFingerprint:
    """页面指纹识别 - 增强版"""
    
    @staticmethod
    def get_fingerprint(activity: str, element_count: int, elements: List[Dict]) -> str:
        """
        生成页面指纹 - 增强版
        特征包含：
        1. Activity 名称
        2. 可点击元素数量
        3. 前 10 个元素的文本特征（增加样本）
        4. 所有元素文本的 hash（全局特征）
        5. 元素坐标分布特征
        6. Resource ID 特征
        """
        # 1. 前 10 个元素的标签（从 5 增加到 10）
        element_labels = [elem.get("label", "")[:30] for elem in elements[:10]]
        
        # 2. 所有元素文本的组合 hash
        all_texts = "".join([elem.get("text", "") for elem in elements])
        text_hash = hashlib.md5(all_texts.encode()).hexdigest()[:8]
        
        # 3. 坐标分布特征（防止文本相同但布局不同）
        coords_sum = sum([sum(elem.get("coords", [0, 0])) for elem in elements[:20]])
        
        # 4. Resource ID 特征
        resource_ids = [elem.get("resource_id", "")[-20:] for elem in elements[:5]]
        
        fingerprint_data = {
            "activity": activity,
            "element_count": element_count,
            "labels": element_labels,
            "text_hash": text_hash,
            "coords_sum": coords_sum,
            "resource_ids": resource_ids,
        }
        
        # 生成 hash
        fp_str = json.dumps(fingerprint_data, sort_keys=True)
        return hashlib.md5(fp_str.encode()).hexdigest()[:12]
    
    @staticmethod
    def is_page_changed(fp1: str, fp2: str) -> bool:
        """判断页面是否真的变化"""
        return fp1 != fp2
    
class ClickLogger:
    """点击日志记录器 - 基于页面变化"""
    
    def __init__(self, log_file: str = None):
        if not log_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            log_file = f"log/click_log_{timestamp}.jsonl"
        
        self.log_file = log_file
        self.click_count = 0
        
        with open(self.log_file, "w", encoding="utf-8") as f:
            pass
        
        print(f"📝 点击日志: {self.log_file}")
    
    def log_successful_click(self, 
                        before_activity: str,
                        after_activity: str,
                        element: Dict, 
                        depth: int,
                        page_changed: bool,
                        click_reason: str = "unknown",     # ✅ 新增
                        request_info: Dict = None):        # ✅ 新增
        """
        记录成功的点击
        
        Args:
            before_activity: 点击前的页面
            after_activity: 点击后的页面
            element: 点击的元素
            depth: 深度
            page_changed: 页面是否变化
            click_reason: 点击有效的原因
            request_info: 请求信息
        """
        log_entry = {
            "click_id": self.click_count,
            "timestamp": datetime.now().isoformat(),
            "timestamp_ms": int(time.time() * 1000),
            
            # 页面信息
            "before_activity": before_activity,
            "after_activity": after_activity,
            "page_changed": page_changed,
            "depth": depth,
            
            # 元素信息
            "element": {
                "class": element.get("class", ""),
                "resource_id": element.get("resource_id", ""),
                "text": element.get("text", ""),
                "label": element.get("label", ""),
                "bounds": element.get("bounds", ""),
                "coords": element.get("coords", [])
            },
            
            # ✅ 点击有效性判断依据
            "click_validation": {
                "reason": click_reason,  # "business_request" | "page_change" | "both"
                "page_changed": page_changed,
                "has_business_request": request_info.get("has_business", False) if request_info else False,
                "has_burying_point": request_info.get("has_burying", False) if request_info else False,
            },
            
            # ✅ 请求详情
            "requests": {
                "business_count": request_info.get("business_count", 0) if request_info else 0,
                "burying_count": request_info.get("burying_count", 0) if request_info else 0,
                "business_requests": [
                    {
                        "method": r.get("method"),
                        "host": r.get("host"),
                        "path": r.get("path", ""),
                        "url": r.get("url", "")
                    }
                    for r in request_info.get("business_requests", [])
                ] if request_info else [],
                "burying_requests": [
                    {
                        "method": r.get("method"),
                        "host": r.get("host"),
                        "path": r.get("path", ""),
                        "url": r.get("url", "")
                    }
                    for r in request_info.get("burying_requests", [])
                ] if request_info else [],
            }
        }
        
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")
        
        self.click_count += 1

    def get_summary(self):
        return {
            "total_clicks": self.click_count,
            "log_file": self.log_file
        }

class OptimizedUIParser:
    """UI 解析器"""
    
    def __init__(self, coord_threshold: int = 30):
        self.coord_threshold = coord_threshold
        self.parent_map = {}
    
    def parse_xml_file(self, xml_path: str = "ui.xml") -> List[Dict]:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        return self._parse_tree(root)
    
    def _parse_tree(self, root: ET.Element) -> List[Dict]:
        self.parent_map = {c: p for p in root.iter() for c in p}
        raw_elements = self._extract_clickable_elements(root)
        filtered_elements = self._filter_nested_clickables(raw_elements)
        unique_elements = self._deduplicate_by_coords(filtered_elements)
        enhanced_elements = self._enhance_text(unique_elements)
        return enhanced_elements
    
    def _extract_clickable_elements(self, root: ET.Element) -> List[Dict]:
        elements = []
        
        # 黑名单
        BLACKLIST_IDS = ['com.chinamobile.mcloud:id/root']
        CONTAINER_CLASSES = ['RelativeLayout', 'LinearLayout', 'FrameLayout', 'ViewGroup']
        
        for node in root.iter():
            if node.get('clickable') != 'true':
                continue
            
            bounds = node.get('bounds')
            if not bounds:
                continue
            
            # ✅ 过滤黑名单 ID
            resource_id = node.get('resource-id', '')
            if resource_id in BLACKLIST_IDS:
                continue
            
            # ✅ 过滤全屏布局容器
            class_name = node.get('class', '')
            if bounds.startswith('[0,0][720,') or bounds.startswith('[0,0][719,'):
                # 如果是全屏且是容器类
                is_container = any(c in class_name for c in CONTAINER_CLASSES)
                if is_container:
                    # 检查是否有实际内容（不只是子元素的文本）
                    own_text = node.get('text', '').strip()
                    if not own_text:  # 自己没有文本，说明只是容器
                        continue
            
            coords = self._parse_bounds(bounds)
            if not coords:
                continue
            
            element = {
                "node": node,
                "class": class_name,
                "resource_id": resource_id,
                "text": node.get('text', ''),
                "content_desc": node.get('content-desc', ''),
                "bounds": bounds,
                "coords": coords,
                "depth": self._get_depth(node)
            }
            elements.append(element)
        
        return elements
    
    def _filter_nested_clickables(self, elements: List[Dict]) -> List[Dict]:
        filtered = []
        for elem in elements:
            node = elem["node"]
            has_clickable_ancestor = False
            current = self.parent_map.get(node)
            while current is not None:
                if current.get('clickable') == 'true':
                    has_clickable_ancestor = True
                    break
                current = self.parent_map.get(current)
            if not has_clickable_ancestor:
                filtered.append(elem)
        return filtered
    
    def _deduplicate_by_coords(self, elements: List[Dict]) -> List[Dict]:
        unique = []
        for elem in elements:
            x, y = elem["coords"]
            is_duplicate = False
            for existing in unique:
                ex, ey = existing["coords"]
                distance = ((x - ex) ** 2 + (y - ey) ** 2) ** 0.5
                if distance < self.coord_threshold:
                    is_duplicate = True
                    if self._is_better_element(elem, existing):
                        idx = unique.index(existing)
                        unique[idx] = elem
                    break
            if not is_duplicate:
                unique.append(elem)
        return unique
    
    def _is_better_element(self, elem1: Dict, elem2: Dict) -> bool:
        text1 = elem1.get("text", "").strip()
        text2 = elem2.get("text", "").strip()
        if text1 and not text2:
            return True
        if not text1 and text2:
            return False
        rid1 = elem1.get("resource_id", "")
        rid2 = elem2.get("resource_id", "")
        if rid1 and not rid2:
            return True
        if not rid1 and rid2:
            return False
        return elem1.get("depth", 999) < elem2.get("depth", 999)
    
    def _enhance_text(self, elements: List[Dict]) -> List[Dict]:
        enhanced = []
        for idx, elem in enumerate(elements):
            node = elem["node"]
            text = self._get_best_text(node)
            label = self._generate_label(elem, text)
            result = {
                "index": idx,
                "class": elem["class"],
                "resource_id": elem["resource_id"],
                "text": text,
                "label": label,
                "bounds": elem["bounds"],
                "coords": elem["coords"],
            }
            enhanced.append(result)
        return enhanced
    
    def _get_best_text(self, node: ET.Element) -> str:
        text = node.get('text', '').strip()
        if text:
            return text
        desc = node.get('content-desc', '').strip()
        if desc:
            return desc
        child_texts = []
        seen = set()
        for child in node.iter():
            if child is node:
                continue
            t = child.get('text', '').strip()
            if t and t not in seen:
                child_texts.append(t)
                seen.add(t)
        if child_texts:
            combined = " ".join(child_texts)
            return combined[:100] + "..." if len(combined) > 100 else combined
        rid = node.get('resource-id', '')
        if rid:
            parts = rid.split('/')
            if len(parts) > 1:
                return parts[-1].replace('_', ' ').title()
        return ""
    
    def _generate_label(self, elem: Dict, text: str) -> str:
        if text.strip():
            return text[:50]
        rid = elem.get("resource_id", "")
        if rid:
            parts = rid.split('/')
            if len(parts) > 1:
                return parts[-1]
        class_name = elem.get("class", "").split('.')[-1]
        return f"<{class_name}>"
    
    def _parse_bounds(self, bounds: str) -> Optional[Tuple[int, int]]:
        try:
            match = re.match(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]', bounds)
            if match:
                x1, y1, x2, y2 = map(int, match.groups())
                return ((x1 + x2) // 2, (y1 + y2) // 2)
        except:
            pass
        return None
    
    def _get_depth(self, node: ET.Element) -> int:
        depth = 0
        current = self.parent_map.get(node)
        while current is not None:
            depth += 1
            current = self.parent_map.get(current)
        return depth


class ScreenDisplay:
    """屏幕显示工具"""
    
    @staticmethod
    def show_toast(text: str, duration: int = 2):
        escaped_text = text.replace('"', '\\"').replace("'", "\\'")
        cmd = f'adb shell "am broadcast -a com.android.test.TOAST -e text \'{escaped_text}\'"'
        os.system(cmd + " > /dev/null 2>&1")


class IntegratedCrawler:
    """集成爬虫 - 基于页面变化记录"""
    
    def __init__(self, config: Dict = None, mitm_log_file: str = None):
        self.config = config or CONFIG
        self.log_file = mitm_log_file or "/tmp/mitm_requests.jsonl"
        self.mitm_host = self.config.get("proxy_host", "127.0.0.1")
        self.mitm_port = self.config.get("proxy_port", 8080)
        self.driver = None
        self.parser = OptimizedUIParser(coord_threshold=self.config["coord_threshold"])
        self.screen = ScreenDisplay()
        self.click_logger = ClickLogger()

        
        # 页面指纹识别
        self.page_fp = PageFingerprint()

        # 请求监控器
        self.request_monitor = RequestMonitor(
            log_file=self.log_file
        )
        
        # 遍历状态
        self.visited_pages: Set[str] = set()  # 访问过的页面指纹
        self.current_depth = 0
        
        # 统计
        self.stats = {
            "total_attempts": 0,      # 总尝试点击次数
            "successful_clicks": 0,    # 成功点击次数（页面真的变化）
            "failed_clicks": 0,        # 失败点击次数
            "pages_visited": 0,
            "popups_handled": 0,
        }
    
    def _get_element_signature(self, elem: Dict) -> str:
        """
        生成元素唯一签名（用于去重）
        基于：坐标 + 文本 + resource_id
        """
        coords = elem.get("coords", [0, 0])
        text = elem.get("text", "")
        resource_id = elem.get("resource_id", "")
        
        sig = f"{coords[0]}_{coords[1]}_{text}_{resource_id}"
        return hashlib.md5(sig.encode()).hexdigest()[:12]
    
    def start_driver(self):
        options = UiAutomator2Options()
        options.platform_name = self.config["platform_name"]
        options.device_name = self.config["device_name"]
        options.platform_version = self.config["platform_version"]
        options.automation_name = self.config["automation_name"]
        options.app_package = self.config["app_package"]
        options.app_activity = self.config["app_activity"]
        options.no_reset = True
        options.new_command_timeout = 300
        
        if self.config.get("proxy_host"):
            options.set_capability("proxy", {
                "proxyType": "manual",
                "httpProxy": f"{self.config['proxy_host']}:{self.config['proxy_port']}",
                "sslProxy": f"{self.config['proxy_host']}:{self.config['proxy_port']}"
            })
        
        self.driver = webdriver.Remote(self.config["appium_server"], options=options)
        print("✅ Appium Driver 启动成功")
    
    def wait_for_main_activity(self, timeout: int = 15) -> bool:
        print("⏳ 等待 App 进入主页面...")
        start = time.time()
        last_act = None
        stable_count = 0
        
        while time.time() - start < timeout:
            try:
                act = self.driver.current_activity
                if act == last_act:
                    stable_count += 1
                else:
                    stable_count = 0
                if stable_count >= 3 and "logo" not in act.lower():
                    print(f"✅ 主页面就绪: {act}")
                    return True
                last_act = act
                time.sleep(1)
            except Exception:
                time.sleep(1)
        
        print("⚠️ 主页面等待超时，仍然尝试遍历")
        return False
    
    def dump_ui(self) -> bool:
        try:
            os.system("adb shell uiautomator dump /sdcard/ui.xml > /dev/null 2>&1")
            os.system("adb pull /sdcard/ui.xml ./ui.xml > /dev/null 2>&1")
            return os.path.exists("ui.xml")
        except Exception as e:
            print(f"⚠️ UI dump 失败: {e}")
            return False
    
    def get_current_page_info(self) -> Tuple[str, List[Dict], str]:
        """
        获取当前页面信息
        Returns: (activity, clickable_elements, page_fingerprint)
        """
        try:
            activity = self.driver.current_activity
        except:
            activity = "unknown"
        

        self.dump_ui()
        
        try:
            elements = self.parser.parse_xml_file("ui.xml")
            fingerprint = self.page_fp.get_fingerprint(activity, len(elements), elements)
            return activity, elements, fingerprint
        except Exception as e:
            print(f"⚠️ 获取页面信息失败: {e}")
            return activity, [], ""
    
    # 等待页面加载完成
    def wait_page_stable(self, timeout=8, stable_rounds=2):
        last_fp = None
        stable = 0
        start = time.time()

        while time.time() - start < timeout:
            _, _, fp = self.get_current_page_info()
            if fp == last_fp and fp:
                stable += 1
                if stable >= stable_rounds:
                    return True
            else:
                stable = 0
                last_fp = fp
            time.sleep(0.5)
        return False
 
    def tap_element(self, elem: Dict) -> bool:
        """基于请求的点击有效性判断"""
        x, y = elem["coords"]
        label = elem["label"]
        
        # 获取点击前状态
        before_activity, before_elems, before_fp = self.get_current_page_info()
        
        # 调试模式
        debug_mode = self.config.get("debug_tap", False)
        
        # 记录点击时间（毫秒时间戳）
        click_timestamp = time.time() * 1000
        
        # 执行点击
        display_text = f"点击: {label[:30]}"
        print(f"\n{'  ' * self.current_depth}👆 {display_text} @ ({x}, {y})", end="", flush=True)
        self.screen.show_toast(display_text, duration=1)
        
        os.system(f"adb shell input tap {x} {y}")
        self._mark_user_action()
        self.stats["total_attempts"] += 1
        
        # ✅ 等待 3 秒，让请求发出
        time.sleep(3.0)
        
        # ✅ 1. 检查页面指纹变化
        after_activity, after_elems, after_fp = self.get_current_page_info()
        page_changed = (after_fp != before_fp)
        
        # ✅ 2. 检查请求情况
        request_result = self.request_monitor.check_click_effect(
            click_timestamp, 
            duration=3000,
            debug=debug_mode
        )
        
        # ✅ 3. 判断点击有效性
        # 优先级：业务请求 > 页面变化
        has_business = request_result["has_business"]
        has_burying = request_result["has_burying"]
        
        if has_business and page_changed:
            click_valid = True
            reason = "both"
            message = f"✅ 成功 (页面跳转 + {request_result['business_count']} 个业务请求"
            if has_burying:
                message += f" + {request_result['burying_count']} 个埋点"
            message += ")"
        elif has_business:
            click_valid = True
            reason = "business_request"
            message = f"✅ 成功 (触发 {request_result['business_count']} 个业务请求"
            if has_burying:
                message += f" + {request_result['burying_count']} 个埋点"
            message += ")"
        elif page_changed:
            click_valid = True
            reason = "page_change"
            message = f"✅ 成功 (页面跳转到 {after_activity})"
        else:
            click_valid = False
            reason = "no_effect"
            message = f"❌ 失败 (无页面变化且无业务请求)"
        
        print(f" {message}")
        
        # ✅ 4. 记录日志
        if click_valid:
            self.stats["successful_clicks"] += 1
            self.click_logger.log_successful_click(
                before_activity=before_activity,
                after_activity=after_activity,
                element=elem,
                depth=self.current_depth,
                page_changed=page_changed,
                click_reason=reason,
                request_info=request_result
            )
        else:
            self.stats["failed_clicks"] += 1
        
        return click_valid

    def _mark_user_action(self):
        try:
            requests.get(
                "http://mark.local/mark_action",
                proxies={
                    "http": f"http://{self.config['mitm_host']}:{self.config['mitm_port']}",
                    "https": f"http://{self.config['mitm_host']}:{self.config['mitm_port']}",
                },
                timeout=1
            )
        except:
            pass
    
    # def tab(self):
    #     print(f"{'  ' * self.current_depth}⬅️ 返回")
    #     os.system("adb shell input keyevent 4")
    #     time.sleep(1)
    
    # def safe_back(self, parent_fp: str) -> BackResult:
    #     """改进版：更可靠的返回检测"""
    #     _, _, before_fp = self.get_current_page_info()

    #     print(f"{'   ' * self.current_depth} ⬅️ 执行返回")
    #     os.system("adb shell input keyevent 4")
        
    #     # ✅ 增加初始等待
    #     time.sleep(0.8)

    #     # ✅ 多次检测返回结果
    #     for i in range(10):  # 最多等待 5 秒
    #         _, _, after_fp = self.get_current_page_info()
            
    #         if after_fp != before_fp:
    #             # 页面已变化
    #             if after_fp == parent_fp:
    #                 return BackResult.OK_RETURN
    #             else:
    #                 return BackResult.REDIRECT
            
    #         time.sleep(0.5)
        
    #     # 超时未变化
    #     return BackResult.NO_EFFECT
    def is_network_idle(self, idle_ms=1500):
        r = requests.get(
            f"http://{self.mitm_host}:{self.mitm_port}/__activity__",
            timeout=1
        )
        data = r.json()
        return data["now"] - data["last_request_ts"] > idle_ms

    def safe_back(self, target_fp: str, idle_ms: int = 1500) -> BackResult:
        print(f"{'   ' * self.current_depth} ⬅️ 执行返回")
        os.system("adb shell input keyevent 4")

        start = time.time()

        while time.time() - start < 5:
            _, _, cur_fp = self.get_current_page_info()

            # ✅ 条件 1：UI 语义回到父页面
            if cur_fp == target_fp:
                return BackResult.OK_RETURN

            # ✅ 条件 2：网络已空闲，且刚才是“有效点击”
            if self.is_network_idle(1500):
                return BackResult.OK_RETURN
            
            time.sleep(0.4)

        return BackResult.NO_EFFECT

    def handle_popup(self) -> bool:
        """处理弹窗"""
        _, elements, _ = self.get_current_page_info()
        popup_keywords = ["允许", "拒绝", "确定", "取消", "继续", "跳过", "关闭", "我知道了"]
        
        for elem in elements:
            text = elem.get("text", "")
            if text in popup_keywords:
                print(f"⚡ 发现弹窗按钮: {text}")
                x, y = elem["coords"]
                os.system(f"adb shell input tap {x} {y}")
                self.stats["popups_handled"] += 1
                time.sleep(1)
                return True
        return False
    
    def dfs_traverse(self, depth: int = 0):
        """改进版 DFS：更健壮的页面变化处理"""
        # ✅ 修复1：使用局部变量存储深度，避免污染实例变量
        original_depth = self.current_depth
        self.current_depth = depth
        
        try:
            # ✅ 深度检查
            if depth >= self.config["max_depth"]:
                print(f"{'  ' * depth}🛑 达到最大深度 {self.config['max_depth']}")
                return

            current_activity, _, current_fp = self.get_current_page_info()

            if current_fp in self.visited_pages:
                print(f"{'  ' * depth}🔄 页面已访问: {current_activity}")
                return

            self.visited_pages.add(current_fp)
            self.stats["pages_visited"] += 1

            print(f"\n{'  ' * depth}📱 深度 {depth} | {current_activity}")

            # ✅ 处理弹窗（在 try 内）
            while self.handle_popup():
                time.sleep(0.5)

            clicked_in_this_page = set()

            # ✅ 主遍历循环（在 try 内）
            while True:
                # 每次循环都重新获取当前页面信息
                _, clickable_elements, page_fp = self.get_current_page_info()

                # 如果页面变化，先判断是否在已访问列表
                if page_fp != current_fp:
                    if page_fp in self.visited_pages:
                        print(f"{'  ' * depth}🔄 页面跳转到已访问页面，返回")
                        return
                    else:
                        print(f"{'  ' * depth}⚠️ 页面被劫持到新页面，尝试处理")
                        # 尝试处理这个新页面
                        self.safe_back(current_fp)
                        # 返回后重新检查
                        _, _, new_fp = self.get_current_page_info()
                        if new_fp != current_fp:
                            print(f"{'  ' * depth}❌ 无法返回原页面，终止")
                            return
                        continue

                # 找出未点击的元素
                unclicked = []
                for elem in clickable_elements:
                    sig = self._get_element_signature(elem)
                    if sig not in clicked_in_this_page:
                        unclicked.append(elem)

                if not unclicked:
                    print(f"{'  ' * depth}✓ 当前页面遍历完成")
                    return

                elem = unclicked[0]
                elem_sig = self._get_element_signature(elem)
                clicked_in_this_page.add(elem_sig)

                # 点击前先处理弹窗
                while self.handle_popup():
                    time.sleep(0.5)

                # 点击并等待结果
                page_changed = self.tap_element(elem)

                if not page_changed:
                    # 点击无效，继续下一个元素
                    continue

                # 页面已变化，重新获取信息
                child_activity, _, child_fp = self.get_current_page_info()

                # WebView 特殊处理
                if "WebView" in child_activity or "H5" in child_activity:
                    print(f"{'  ' * (depth+1)}🌐 WebView 页面，直接返回")
                    self.safe_back(current_fp)
                    time.sleep(0.8)
                    continue

                # 递归遍历子页面
                self.dfs_traverse(depth + 1)

                # 返回父页面
                print(f"{'  ' * (depth+1)}⬅️ 尝试返回父页面")
                back_result = self.safe_back(current_fp)

                if back_result == BackResult.OK_RETURN:
                    print(f"{'  ' * (depth+1)}✅ 成功返回")
                    while self.handle_popup():
                        time.sleep(0.5)
                    continue

                elif back_result == BackResult.NO_EFFECT:
                    print(f"{'  ' * (depth+1)}⚠️ 返回无效，尝试多次返回")
                    # 尝试多次返回
                    for retry in range(3):
                        time.sleep(0.5)
                        result = self.safe_back(current_fp)
                        if result == BackResult.OK_RETURN:
                            print(f"{'  ' * (depth+1)}✅ 第 {retry+2} 次返回成功")
                            break
                    else:
                        print(f"{'  ' * (depth+1)}❌ 返回失败，终止本层")
                        return
                    continue

                else:  # REDIRECT
                    print(f"{'  ' * (depth+1)}❌ 返回跳转异常，终止本层")
                    return

        except Exception as e:
            print(f"{'  ' * depth}⚠️ 异常: {e}")
            import traceback
            traceback.print_exc()
            # 尝试返回
            try:
                self.safe_back(current_fp)
            except:
                pass
            return
        
        finally:
            # ✅ 修复1：恢复原始深度
            self.current_depth = original_depth


    def run(self):
        print("\n" + "=" * 80)
        print("🤖 智能 UI 遍历爬虫 - 页面变化检测版")
        print("=" * 80 + "\n")
        
        try:
            self.start_driver()
            self.wait_for_main_activity()
            
            self.dfs_traverse(depth=0)
            
            log_summary = self.click_logger.get_summary()
            
            print("\n" + "=" * 80)
            print("✅ 遍历完成")
            print("=" * 80)
            print(f"📊 统计:")
            print(f"   访问页面: {self.stats['pages_visited']}")
            print(f"   尝试点击: {self.stats['total_attempts']}")
            print(f"   成功点击: {self.stats['successful_clicks']} ({'✅' if self.stats['successful_clicks'] > 0 else '❌'})")
            print(f"   失败点击: {self.stats['failed_clicks']}")
            print(f"   点击成功率: {self.stats['successful_clicks']/max(self.stats['total_attempts'],1)*100:.1f}%")
            print(f"   处理弹窗: {self.stats['popups_handled']}")
            print(f"\n📝 点击日志已保存: {log_summary['log_file']}")
            print(f"   有效记录数: {log_summary['total_clicks']} (只记录成功的点击)")
            print("=" * 80)
            
        except KeyboardInterrupt:
            print("\n⚠️ 用户中断")
        except Exception as e:
            print(f"\n❌ 错误: {e}")
            import traceback
            traceback.print_exc()
        finally:
            self.stop()
    
    def stop(self):
        if self.driver:
            self.driver.quit()
            print("🔚 Appium Driver 已关闭")


if __name__ == "__main__":
    crawler = IntegratedCrawler(CONFIG)
    crawler.run()