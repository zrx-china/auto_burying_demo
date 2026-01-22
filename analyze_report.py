#!/usr/bin/env python3
"""
埋点专业分析器 - 增强版
功能:
1. 只分析埋点域名 dc.cmicapm.com
2. 以有效点击为基准计算覆盖率
3. 深度事件分析和属性分析
4. 生成详细的埋点质量报告
"""

import json
import os
from collections import Counter, defaultdict
from datetime import datetime
from typing import List, Dict, Set, Tuple


class BuryPointAnalyzer:
    """埋点分析器"""
    
    # 埋点域名（可配置）
    BURY_POINT_DOMAIN = "dc.cmicapm.com"
    
    # 时间窗口：点击后多久内的埋点算作匹配（毫秒）
    TIME_WINDOW_MS = 10000  # 扩大到10秒，适应网络延迟
    
    def __init__(self, mitm_file: str = None, click_log_file: str = None):
        """
        Args:
            mitm_file: MITM捕获文件 (mitm_requests_*.jsonl)
            click_log_file: 点击日志文件 (click_log_*.jsonl)
        """
        # 自动查找最新文件
        if not mitm_file:
            mitm_file = self._find_latest_file("mitm_requests_")
        if not click_log_file:
            click_log_file = self._find_latest_file("click_log_")
        
        self.mitm_file = mitm_file
        self.click_log_file = click_log_file
        
        print(f"📁 使用文件:")
        print(f"   MITM: {mitm_file}")
        print(f"   点击日志: {click_log_file}")
        
        # 加载数据
        self.bury_requests = self._load_bury_requests()
        self.click_logs = self._load_click_logs()
        
        print(f"📊 加载埋点请求: {len(self.bury_requests)} 条")
        print(f"🖱️ 加载点击日志: {len(self.click_logs)} 条")
    
    def _find_latest_file(self, prefix: str) -> str:
        """查找最新文件"""
        files = [os.path.join("log", f) for f in os.listdir("log") 
                if f.startswith(prefix) and f.endswith(".jsonl")]
        if not files:
            raise FileNotFoundError(f"❌ 未找到 {prefix}*.jsonl 文件")
        latest = sorted(files)[-1]
        return latest
    
    def _load_bury_requests(self) -> List[Dict]:
        """加载埋点请求（只保留埋点域名的数据）"""
        data = []
        
        with open(self.mitm_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)

                    # 1️⃣ 域名过滤
                    if self.BURY_POINT_DOMAIN not in obj.get("host", ""):
                        continue

                    # 2️⃣ 只保留 POST（过滤 OPTIONS）
                    if obj.get("method") != "POST":
                        continue

                    # 3️⃣ body 必须存在
                    body = obj.get("body")
                    if not body:
                        continue

                    # 解析成功，添加到结果
                    data.append(obj)

                except Exception as e:
                    print(f"⚠️ JSON解析失败: {e}")
        
        return data
    
    def _load_click_logs(self) -> List[Dict]:
        """加载点击日志"""
        if not os.path.exists(self.click_log_file):
            print(f"⚠️ 点击日志文件不存在: {self.click_log_file}")
            return []
        
        data = []
        with open(self.click_log_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data.append(json.loads(line))
                except Exception as e:
                    print(f"⚠️ JSON解析失败: {e}")
        
        return data
    
    def get_valid_clicks(self) -> List[Dict]:
        """获取有效点击（通过click_validation的点击）"""
        valid_clicks = []
        
        for click in self.click_logs:
            validation = click.get("click_validation", {})
            
            # 判断是否为有效点击：
            # 1. 页面发生变化 或
            # 2. 有业务请求 或
            # 3. 有埋点请求
            is_valid = (
                validation.get("page_changed", False) or
                validation.get("has_business_request", False) or
                validation.get("has_burying_request", False)
            )
            
            if is_valid:
                valid_clicks.append(click)
        
        return valid_clicks
    
    def extract_events(self, body, path="", url="") -> List[Dict]:
        """深度提取所有埋点事件"""
        events = []
        
        if isinstance(body, dict):
            # 直接包含event字段
            if "event" in body:
                event_name = body.get("event", "unknown")
                params = {}
                
                # 解析params
                params_raw = body.get("params", {})
                if isinstance(params_raw, str):
                    try:
                        params = json.loads(params_raw)
                    except:
                        params = {"_raw": params_raw}
                elif isinstance(params_raw, dict):
                    params = params_raw
                
                events.append({
                    "event": event_name,
                    "params": params,
                    "path": path,
                    "local_time_ms": body.get("local_time_ms"),
                    "session_id": body.get("session_id")
                })
            
            # 特殊处理：/webid 路径的埋点（设备标识请求）
            elif "/webid" in url and "user_unique_id" in body:
                events.append({
                    "event": "device_id_request",
                    "params": {
                        "app_id": body.get("app_id", ""),
                        "url": body.get("url", "")
                    },
                    "path": path,
                    "local_time_ms": None,
                    "session_id": None
                })
            
            # 递归查找嵌套结构
            for key, value in body.items():
                events.extend(self.extract_events(value, f"{path}.{key}" if path else key, url))
        
        elif isinstance(body, list):
            for idx, item in enumerate(body):
                events.extend(self.extract_events(item, f"{path}[{idx}]", url))
        
        return events
    
    def analyze_coverage(self) -> Dict:
        """
        基于【相邻有效点击边界】的埋点归因模型
        归因区间：[click_i, click_{i+1})
        """
        # 1️⃣ 获取有效点击
        valid_clicks = self.get_valid_clicks()

        print(f"\n🔍 分析覆盖率（相邻点击归因模型）...")
        print(f"   有效点击: {len(valid_clicks)}")
        print(f"   无效点击: {len(self.click_logs) - len(valid_clicks)}")

        if not valid_clicks:
            return {}

        # 2️⃣ 按时间排序
        valid_clicks_sorted = sorted(valid_clicks, key=lambda x: x.get("timestamp_ms", 0))
        bury_requests_sorted = sorted(self.bury_requests, key=lambda x: x.get("timestamp", 0))

        matched = []
        unmatched_clicks = []
        used_bury_indices = set()

        # 统计时间分布
        time_diff_distribution = {
            "0-1s": 0,
            "1-3s": 0,
            "3-5s": 0,
            "5-10s": 0,
            "10s+": 0
        }

        # 3️⃣ 核心归因逻辑：相邻点击切分
        for i, click in enumerate(valid_clicks_sorted):
            click_time = click.get("timestamp_ms", 0)

            # 当前点击的归因区间结束时间
            if i + 1 < len(valid_clicks_sorted):
                next_click_time = valid_clicks_sorted[i + 1].get("timestamp_ms", 0)
            else:
                # 最后一次点击兜底（防止无限吞埋点）
                next_click_time = click_time + self.TIME_WINDOW_MS

            found = False

            for idx, bury in enumerate(bury_requests_sorted):
                if idx in used_bury_indices:
                    continue

                bury_time = bury.get("timestamp", 0)

                # 🎯 核心判断：是否落在当前点击区间
                if click_time <= bury_time < next_click_time:
                    time_diff = bury_time - click_time

                    # 提取事件
                    events = self.extract_events(
                        bury.get("body", {}),
                        "",
                        bury.get("url", "")
                    )

                    # 时间分布统计
                    if time_diff < 1000:
                        time_diff_distribution["0-1s"] += 1
                    elif time_diff < 3000:
                        time_diff_distribution["1-3s"] += 1
                    elif time_diff < 5000:
                        time_diff_distribution["3-5s"] += 1
                    elif time_diff < 10000:
                        time_diff_distribution["5-10s"] += 1
                    else:
                        time_diff_distribution["10s+"] += 1

                    matched.append({
                        "click": click,
                        "bury_request": bury,
                        "events": events,
                        "time_diff_ms": time_diff,
                        "event_count": len(events),
                        "attribution_window": [click_time, next_click_time]
                    })

                    used_bury_indices.add(idx)
                    found = True
                    break

            if not found:
                unmatched_clicks.append(click)

        # 4️⃣ 覆盖率计算
        total_valid_clicks = len(valid_clicks_sorted)
        covered_clicks = len(matched)
        uncovered_clicks = len(unmatched_clicks)
        coverage_rate = (
            covered_clicks / total_valid_clicks * 100
            if total_valid_clicks > 0 else 0
        )

        print(f"   覆盖率: {coverage_rate:.1f}%")

        # 5️⃣ 未覆盖分析
        unmatched_pages = Counter(
            c.get("after_activity", "unknown") for c in unmatched_clicks
        )
        unmatched_elements = Counter(
            c.get("element", {}).get("label", "unknown")
            for c in unmatched_clicks
        )

        # 6️⃣ 无效点击分析
        invalid_clicks = [c for c in self.click_logs if c not in valid_clicks]
        invalid_reasons = Counter(
            c.get("click_validation", {}).get("reason", "unknown")
            for c in invalid_clicks
        )

        return {
            "total_valid_clicks": total_valid_clicks,
            "total_invalid_clicks": len(invalid_clicks),
            "covered_clicks": covered_clicks,
            "uncovered_clicks": uncovered_clicks,
            "coverage_rate": coverage_rate,
            "matched_pairs": matched,
            "unmatched_clicks": unmatched_clicks,
            "unmatched_pages": dict(unmatched_pages.most_common(10)),
            "unmatched_elements": dict(unmatched_elements.most_common(20)),
            "invalid_reasons": dict(invalid_reasons.most_common(10)),
            "time_diff_distribution": time_diff_distribution
        }
    
    def build_trigger_latency_from_coverage(self, coverage: Dict) -> Dict:
        trigger_latency = {
            "即时(<500ms)": 0,
            "快速(500ms-2s)": 0,
            "正常(2s-5s)": 0,
            "延迟(5s-10s)": 0,
            "很慢(>10s)": 0
        }

        for pair in coverage.get("matched_pairs", []):
            gap = pair.get("time_diff_ms", 0)

            if gap < 500:
                trigger_latency["即时(<500ms)"] += 1
            elif gap < 2000:
                trigger_latency["快速(500ms-2s)"] += 1
            elif gap < 5000:
                trigger_latency["正常(2s-5s)"] += 1
            elif gap < 10000:
                trigger_latency["延迟(5s-10s)"] += 1
            else:
                trigger_latency["很慢(>10s)"] += 1

        return trigger_latency

    def analyze_events(self) -> Dict:
        """深度事件分析"""
        print(f"\n🔍 分析事件...")
        
        all_events = []
        
        # 从所有埋点请求中提取事件
        for bury in self.bury_requests:
            events = self.extract_events(bury.get("body", {}), "", bury.get("url", ""))
            for evt in events:
                evt["timestamp"] = bury.get("timestamp")
                evt["action_gap_ms"] = bury.get("action_gap_ms", 0)
                all_events.append(evt)
        
        # 事件统计
        event_counts = Counter(evt["event"] for evt in all_events)
        
        # 事件参数统计
        event_params = defaultdict(lambda: defaultdict(set))
        for evt in all_events:
            for param_key, param_value in evt["params"].items():
                # 截断过长的值
                value_str = str(param_value)[:100]
                event_params[evt["event"]][param_key].add(value_str)
        
        # 响应时间分析
        trigger_latency = self.build_trigger_latency_from_coverage(
            self.analyze_coverage()
        )
        
        print(f"   事件总数: {len(all_events)}")
        print(f"   事件类型: {len(event_counts)}")
        
        return {
            "total_events": len(all_events),
            "unique_event_types": len(event_counts),
            "event_counts": event_counts,
            "event_params": {
                event: {
                    param: list(values)[:10]  # 每个参数显示最多10个不同值
                    for param, values in params.items()
                }
                for event, params in event_params.items()
            },
            "trigger_latency": trigger_latency,
            "all_events": all_events
        }
    
    def analyze_attributes(self, event_analysis: Dict) -> Dict:
        """属性深度分析"""
        print(f"\n🔍 分析属性...")
        
        # 统计每个事件的参数完整度
        event_param_stats = {}
        
        for event, params in event_analysis["event_params"].items():
            param_count = len(params)
            param_value_counts = {
                param: len(values) 
                for param, values in params.items()
            }
            
            event_param_stats[event] = {
                "param_count": param_count,
                "param_names": list(params.keys()),
                "param_diversity": param_value_counts
            }
        
        # 找出参数最丰富和最贫瘠的事件
        events_by_param_count = sorted(
            event_param_stats.items(),
            key=lambda x: x[1]["param_count"],
            reverse=True
        )
        
        # 分析常见参数
        all_param_names = []
        for event_stat in event_param_stats.values():
            all_param_names.extend(event_stat["param_names"])
        
        common_params = Counter(all_param_names).most_common(20)
        
        return {
            "event_param_stats": event_param_stats,
            "richest_events": events_by_param_count[:10],
            "poorest_events": events_by_param_count[-10:],
            "common_params": dict(common_params)
        }
    
    def calculate_quality_score(self, coverage: Dict, event_analysis: Dict, attr_analysis: Dict) -> Dict:
        """计算埋点质量评分"""
        score = {}
        
        # 1. 覆盖率 (40分)
        score["覆盖率"] = int(coverage["coverage_rate"] * 0.4)
        
        # 2. 事件丰富度 (25分)
        event_types = event_analysis["unique_event_types"]
        score["事件丰富度"] = min(25, event_types * 2)
        
        # 3. 响应及时性 (20分)
        latency = event_analysis["trigger_latency"]
        total_events = sum(latency.values())
        if total_events > 0:
            fast_ratio = (latency["即时(<500ms)"] + latency["快速(500ms-2s)"]) / total_events
            score["响应及时性"] = int(fast_ratio * 20)
        else:
            score["响应及时性"] = 0
        
        # 4. 参数完整度 (15分)
        if len(attr_analysis["event_param_stats"]) > 0:
            avg_params = sum(
                stat["param_count"] 
                for stat in attr_analysis["event_param_stats"].values()
            ) / len(attr_analysis["event_param_stats"])
            score["参数完整度"] = min(15, int(avg_params * 1.5))
        else:
            score["参数完整度"] = 0
        
        score["总分"] = sum(score.values())
        
        # 评级
        total = score["总分"]
        if total >= 90:
            score["评级"] = "A+ 优秀"
        elif total >= 80:
            score["评级"] = "A 良好"
        elif total >= 70:
            score["评级"] = "B 中等"
        elif total >= 60:
            score["评级"] = "C 及格"
        else:
            score["评级"] = "D 需改进"
        
        return score
    
    def generate_report(self, output=None):
        """生成详细报告"""
        print("\n" + "="*60)
        print("🚀 开始分析...")
        print("="*60)
        
        # 分析
        coverage = self.analyze_coverage()
        event_analysis = self.analyze_events()
        attr_analysis = self.analyze_attributes(event_analysis)
        quality_score = self.calculate_quality_score(coverage, event_analysis, attr_analysis)
        
        # 自动生成带时间戳的文件名
        if not output:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output = f"埋点分析报告_{timestamp}.html"
        
        # 生成 HTML
        html = self._generate_html(coverage, event_analysis, attr_analysis, quality_score)
        
        with open(output, "w", encoding="utf-8") as f:
            f.write(html)
        
        print("\n" + "="*60)
        print(f"✅ 报告已生成: {output}")
        print(f"📊 有效点击数: {coverage['total_valid_clicks']}")
        print(f"📊 埋点覆盖率: {coverage['coverage_rate']:.1f}%")
        print(f"🏆 质量评分: {quality_score['总分']}/100 ({quality_score['评级']})")
        print("="*60)
        
        return output
    
    def _generate_html(self, coverage: Dict, events: Dict, attrs: Dict, score: Dict) -> str:
        """生成 HTML 报告"""
        
        # 事件表格
        event_html = ""
        for event, count in list(events["event_counts"].most_common(30)):
            params = events["event_params"].get(event, {})
            param_names = list(params.keys())[:8]
            
            event_html += f"""
            <tr>
                <td><strong>{event}</strong></td>
                <td>{count}</td>
                <td>{len(params)}</td>
                <td><code>{', '.join(param_names) if param_names else '-'}</code></td>
            </tr>
            """
        
        # 未覆盖点击
        unmatched_html = ""
        for click in coverage["unmatched_clicks"][:40]:
            element = click.get("element", {})
            unmatched_html += f"""
            <tr>
                <td>{click.get('after_activity', 'unknown')}</td>
                <td>{element.get('label', 'unknown')[:60]}</td>
                <td>{element.get('class', 'unknown')}</td>
                <td>{datetime.fromtimestamp(click.get('timestamp_ms', 0)/1000).strftime('%H:%M:%S')}</td>
            </tr>
            """
        
        if not unmatched_html:
            unmatched_html = "<tr><td colspan='4' style='text-align:center;color:#999;'>暂无数据</td></tr>"
        
        # 匹配对
        matched_html = ""
        for pair in coverage["matched_pairs"][:40]:
            click = pair["click"]
            element = click.get("element", {})
            events_list = pair["events"]
            event_names = [e.get("event", "unknown") for e in events_list]
            
            matched_html += f"""
            <tr>
                <td>{element.get('label', 'unknown')[:40]}</td>
                <td><code>{', '.join(event_names[:3])}</code></td>
                <td>{pair['event_count']}</td>
                <td>{pair['time_diff_ms']} ms</td>
            </tr>
            """
        
        if not matched_html:
            matched_html = "<tr><td colspan='4' style='text-align:center;color:#999;'>暂无数据</td></tr>"
        
        # 未覆盖页面统计
        page_stats_html = ""
        for page, count in coverage["unmatched_pages"].items():
            page_stats_html += f"""
            <tr>
                <td><code>{page}</code></td>
                <td>{count}</td>
                <td>{count / max(coverage['total_valid_clicks'], 1) * 100:.1f}%</td>
            </tr>
            """
        
        if not page_stats_html:
            page_stats_html = "<tr><td colspan='3' style='text-align:center;color:#999;'>暂无数据</td></tr>"
        
        # 参数丰富度分析
        param_rich_html = ""
        for event, stat in list(attrs["richest_events"])[:15]:
            param_rich_html += f"""
            <tr>
                <td><strong>{event}</strong></td>
                <td>{stat['param_count']}</td>
                <td><code>{', '.join(stat['param_names'][:6])}</code></td>
            </tr>
            """
        
        # 常见参数
        common_params_html = ""
        for param, count in list(attrs["common_params"].items())[:20]:
            common_params_html += f"""
            <tr>
                <td><code>{param}</code></td>
                <td>{count}</td>
            </tr>
            """
        
        # 无效点击原因
        invalid_reasons_html = ""
        if coverage["invalid_reasons"]:
            for reason, count in coverage["invalid_reasons"].items():
                invalid_reasons_html += f"""
                <tr>
                    <td>{reason}</td>
                    <td>{count}</td>
                    <td>{count / max(coverage['total_invalid_clicks'], 1) * 100:.1f}%</td>
                </tr>
                """
        else:
            invalid_reasons_html = "<tr><td colspan='3' style='text-align:center;color:#999;'>暂无数据</td></tr>"
        
        return f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>埋点分析报告 - 增强版</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
        }}
        .container {{
            max-width: 1600px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 50px 40px;
            text-align: center;
        }}
        .header h1 {{
            font-size: 2.8em;
            margin-bottom: 15px;
        }}
        .content {{ padding: 40px; }}
        
        .score-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            border-radius: 15px;
            margin: 30px 0;
            box-shadow: 0 5px 20px rgba(102, 126, 234, 0.3);
        }}
        .score-card h3 {{
            font-size: 2em;
            margin-bottom: 20px;
        }}
        .score-bar {{
            background: rgba(255,255,255,0.2);
            height: 45px;
            border-radius: 25px;
            overflow: hidden;
            margin: 20px 0;
        }}
        .score-fill {{
            background: white;
            height: 100%;
            transition: width 1.5s ease;
            display: flex;
            align-items: center;
            justify-content: flex-end;
            padding-right: 20px;
            color: #667eea;
            font-weight: bold;
            font-size: 1.4em;
        }}
        .score-details {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 25px;
        }}
        .score-item {{
            background: rgba(255,255,255,0.1);
            padding: 15px;
            border-radius: 10px;
        }}
        .score-item-label {{
            font-size: 0.9em;
            opacity: 0.9;
        }}
        .score-item-value {{
            font-size: 1.5em;
            font-weight: bold;
            margin-top: 5px;
        }}
        
        .coverage-summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }}
        .coverage-card {{
            background: #f8f9fa;
            padding: 30px;
            border-radius: 12px;
            text-align: center;
            border-left: 5px solid #667eea;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }}
        .coverage-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 8px 20px rgba(0,0,0,0.15);
        }}
        .coverage-value {{
            font-size: 3.2em;
            font-weight: bold;
            background: linear-gradient(135deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin: 10px 0;
        }}
        .coverage-label {{
            color: #718096;
            font-size: 1.1em;
            font-weight: 500;
        }}
        
        .section {{
            margin: 50px 0;
        }}
        .section h2 {{
            color: #2d3748;
            margin-bottom: 25px;
            padding-bottom: 15px;
            border-bottom: 3px solid #667eea;
            font-size: 2em;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
            font-size: 0.95em;
        }}
        th, td {{
            padding: 15px;
            text-align: left;
            border-bottom: 1px solid #e2e8f0;
        }}
        th {{
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.85em;
            letter-spacing: 0.5px;
        }}
        tr:hover {{ 
            background: #f7fafc;
            transition: background 0.2s ease;
        }}
        
        code {{
            background: #edf2f7;
            padding: 4px 8px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            color: #667eea;
        }}
        
        .alert {{
            padding: 20px;
            border-radius: 10px;
            margin: 20px 0;
            font-size: 1.05em;
        }}
        .alert-warning {{
            background: #fff3cd;
            border-left: 5px solid #ffc107;
            color: #856404;
        }}
        .alert-success {{
            background: #d4edda;
            border-left: 5px solid #28a745;
            color: #155724;
        }}
        .alert-info {{
            background: #d1ecf1;
            border-left: 5px solid #17a2b8;
            color: #0c5460;
        }}
        
        .recommendation {{
            background: #f8f9fa;
            padding: 30px;
            border-radius: 12px;
            margin: 25px 0;
            border-left: 5px solid #667eea;
        }}
        .recommendation h3 {{
            color: #667eea;
            margin-bottom: 20px;
            font-size: 1.5em;
        }}
        .recommendation ul {{
            list-style: none;
        }}
        .recommendation li {{
            padding: 12px 0;
            padding-left: 35px;
            position: relative;
            line-height: 1.6;
        }}
        .recommendation li:before {{
            content: "💡";
            position: absolute;
            left: 0;
            font-size: 1.3em;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin: 25px 0;
        }}
        .stat-box {{
            background: #f8f9fa;
            padding: 25px;
            border-radius: 10px;
            border-left: 4px solid #667eea;
        }}
        .stat-box h4 {{
            color: #667eea;
            margin-bottom: 15px;
            font-size: 1.2em;
        }}
        .stat-box .value {{
            font-size: 2.5em;
            font-weight: bold;
            color: #2d3748;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📊 埋点分析报告</h1>
            <p style="font-size: 1.3em; margin-top: 15px;">生成时间: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
            <p style="margin-top: 10px;">埋点域名: <code style="background: rgba(255,255,255,0.2); color: white; padding: 8px 15px; border-radius: 5px; font-size: 1.1em;">{self.BURY_POINT_DOMAIN}</code></p>
            <!---
            <p style="margin-top: 5px; font-size: 0.95em; opacity: 0.9;">时间窗口: {self.TIME_WINDOW_MS}ms</p>
            --->
        </div>
        
        <div class="content">
            <!-- 质量评分 -->
            <div class="score-card">
                <h3>🏆 埋点质量总评: {score['总分']}/100 - {score['评级']}</h3>
                <div class="score-bar">
                    <div class="score-fill" style="width: {score['总分']}%">{score['总分']}</div>
                </div>
                <div class="score-details">
                    <div class="score-item">
                        <div class="score-item-label">覆盖率</div>
                        <div class="score-item-value">{score['覆盖率']}/40</div>
                    </div>
                    <div class="score-item">
                        <div class="score-item-label">事件丰富度</div>
                        <div class="score-item-value">{score['事件丰富度']}/25</div>
                    </div>
                    <div class="score-item">
                        <div class="score-item-label">响应及时性</div>
                        <div class="score-item-value">{score['响应及时性']}/20</div>
                    </div>
                    <div class="score-item">
                        <div class="score-item-label">参数完整度</div>
                        <div class="score-item-value">{score['参数完整度']}/15</div>
                    </div>
                </div>
            </div>
            
            <!-- 覆盖率摘要 -->
            <div class="coverage-summary">
                <div class="coverage-card">
                    <div class="coverage-label">有效点击数</div>
                    <div class="coverage-value">{coverage['total_valid_clicks']}</div>
                </div>
                <div class="coverage-card">
                    <div class="coverage-label">已覆盖点击</div>
                    <div class="coverage-value" style="-webkit-text-fill-color: #28a745;">{coverage['covered_clicks']}</div>
                </div>
                <div class="coverage-card">
                    <div class="coverage-label">未覆盖点击</div>
                    <div class="coverage-value" style="-webkit-text-fill-color: #dc3545;">{coverage['uncovered_clicks']}</div>
                </div>
                <div class="coverage-card">
                    <div class="coverage-label">覆盖率</div>
                    <div class="coverage-value">{coverage['coverage_rate']:.1f}%</div>
                </div>
            </div>
            
            <!-- 数据说明 -->
            <div class="alert alert-info">
                <strong>📌 数据说明</strong><br>
                • 有效点击：通过click_validation验证的点击（页面变化/触发业务请求）<br>
                <!--
                • 无效点击：{coverage['total_invalid_clicks']} 次（未通过验证的点击）<br>
                -->
                • 覆盖率计算：以「有效点击」作为分母。
                            对每一次有效点击，构建其独立的埋点归因时间区间：
                            从该次点击发生时间开始，到下一次有效点击发生时间为止（不超过 {self.TIME_WINDOW_MS} ms 的最大上限）。
                            在该区间内出现的埋点请求将被归因至该次点击，且每一条埋点请求仅允许归因给一次点击。
                            若某次有效点击在其归因区间内未匹配到任何埋点请求，则视为无埋点覆盖。<br>
                • 响应时间定义：从用户有效点击发生，到该点击归因区间内首个埋点请求发出的时间差。<br>
                • 响应时间分布：0-1s ({coverage['time_diff_distribution']['0-1s']}), 1-3s ({coverage['time_diff_distribution']['1-3s']}), 3-5s ({coverage['time_diff_distribution']['3-5s']}), 5-10s ({coverage['time_diff_distribution']['5-10s']})
            </div>
            
            <!-- 警告信息 -->
            {'<div class="alert alert-warning"><strong>⚠️ 覆盖率偏低</strong><br>建议补充缺失的埋点事件，重点关注高频未覆盖页面</div>' if coverage['coverage_rate'] < 60 else '<div class="alert alert-success"><strong>✅ 覆盖率良好</strong><br>埋点设置较为完善，继续保持</div>'}
            
            <!-- 事件统计 -->
            <div class="section">
                <h2>🎯 埋点事件统计 (Top 30)</h2>
                <div class="stats-grid">
                    <div class="stat-box">
                        <h4>总事件数</h4>
                        <div class="value">{events['total_events']}</div>
                    </div>
                    <div class="stat-box">
                        <h4>事件类型数</h4>
                        <div class="value">{events['unique_event_types']}</div>
                    </div>
                </div>
                <table>
                    <thead>
                        <tr>
                            <th>事件名称</th>
                            <th>触发次数</th>
                            <th>参数数量</th>
                            <th>参数列表</th>
                        </tr>
                    </thead>
                    <tbody>
                        {event_html}
                    </tbody>
                </table>
            </div>
            
            <!-- 点击-埋点匹配 -->
            <div class="section">
                <h2>✅ 成功匹配的点击 (前40条)</h2>
                <table>
                    <thead>
                        <tr>
                            <th>点击元素</th>
                            <th>埋点事件</th>
                            <th>事件数量</th>
                            <th>时间差</th>
                        </tr>
                    </thead>
                    <tbody>
                        {matched_html}
                    </tbody>
                </table>
            </div>
            
            <!-- 未覆盖点击 -->
            <div class="section">
                <h2>❌ 未覆盖的点击 (前40条)</h2>
                <table>
                    <thead>
                        <tr>
                            <th>页面</th>
                            <th>点击元素</th>
                            <th>元素类型</th>
                            <th>时间</th>
                        </tr>
                    </thead>
                    <tbody>
                        {unmatched_html}
                    </tbody>
                </table>
            </div>
            
            <!-- 未覆盖页面统计 -->
            <div class="section">
                <h2>📄 缺失埋点的页面统计</h2>
                <table>
                    <thead>
                        <tr>
                            <th>页面名称</th>
                            <th>未覆盖次数</th>
                            <th>占比</th>
                        </tr>
                    </thead>
                    <tbody>
                        {page_stats_html}
                    </tbody>
                </table>
            </div>
            
            <!-- 参数丰富度分析 -->
            <div class="section">
                <h2>📊 参数丰富度分析 (Top 15)</h2>
                <table>
                    <thead>
                        <tr>
                            <th>事件名称</th>
                            <th>参数数量</th>
                            <th>参数列表</th>
                        </tr>
                    </thead>
                    <tbody>
                        {param_rich_html}
                    </tbody>
                </table>
            </div>
            
            <!-- 常见参数 -->
            <div class="section">
                <h2>🔑 常见参数统计 (Top 20)</h2>
                <table>
                    <thead>
                        <tr>
                            <th>参数名称</th>
                            <th>出现次数</th>
                        </tr>
                    </thead>
                    <tbody>
                        {common_params_html}
                    </tbody>
                </table>
            </div>
            
            <!-- 响应时间分析 -->
            <div class="section">
                <h2>⏱️ 埋点触发响应分析</h2>
                <table>
                    <thead>
                        <tr>
                            <th>响应速度</th>
                            <th>次数</th>
                            <th>占比</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(
                            f"<tr><td>{label}</td><td>{count}</td><td>{count/max(sum(events['trigger_latency'].values()),1)*100:.1f}%</td></tr>"
                            for label, count in events['trigger_latency'].items()
                        )}
                    </tbody>
                </table>
            </div>
            
            <!-- 优化建议 -->
            <div class="recommendation">
                <h3>💡 优化建议</h3>
                <ul>
                    {'<li><strong>紧急</strong>：覆盖率低于60%，建议立即补充埋点</li>' if coverage['coverage_rate'] < 60 else ''}
                    {'<li>优先为高频未覆盖页面补充埋点：' + ', '.join(list(coverage['unmatched_pages'].keys())[:3]) + '</li>' if coverage['uncovered_clicks'] > 0 else ''}
                    {'<li>检查时间差较大的匹配对（>5000ms），优化埋点触发时机</li>' if any(p['time_diff_ms'] > 5000 for p in coverage['matched_pairs'][:20]) else ''}
                    {'<li>补充事件参数，提高数据分析维度（当前平均参数数：' + f"{sum(s['param_count'] for s in attrs['event_param_stats'].values()) / max(len(attrs['event_param_stats']), 1):.1f}" + '）</li>' if score['参数完整度'] < 12 else '<li>参数定义完整，继续保持</li>'}
                    {'<li>优化埋点响应速度，减少延迟（当前延迟占比：' + f"{(events['trigger_latency']['延迟(5s-10s)'] + events['trigger_latency']['很慢(>10s)']) / max(sum(events['trigger_latency'].values()), 1) * 100:.1f}%" + '%）</li>' if score['响应及时性'] < 15 else '<li>响应速度良好</li>'}
                    <li>建议定期检查无效点击原因，优化点击验证逻辑</li>
                    <li>关注参数值的多样性，确保数据质量</li>
                    {'<li><strong>注意</strong>：当前时间窗口为' + str(self.TIME_WINDOW_MS) + 'ms，如需调整请修改配置</li>' if self.TIME_WINDOW_MS != 3000 else ''}
                </ul>
            </div>
        </div>
    </div>
</body>
</html>
        """
