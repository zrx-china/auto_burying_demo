# analyze_advanced.py
"""
专业埋点分析器
功能:
- 埋点域名分析
- 事件类型统计
- 属性覆盖度分析
- 事件-属性映射
- 时间序列分析
- 埋点质量评分
"""

import json
import os
from collections import Counter, defaultdict
from urllib.parse import urlparse
from datetime import datetime


class AdvancedAnalyzer:
    def __init__(self, path=None):
        # 自动查找最新的埋点文件
        if not path:
            files = [f for f in os.listdir(".") 
                    if f.startswith("mitm_capture_") and (f.endswith(".jsonl") or f.endswith(".json"))]
            if not files:
                raise FileNotFoundError("❌ 未找到 mitm_capture_* 文件")
            path = sorted(files)[-1]
        
        self.path = path
        self.data = []
        
        # 加载数据 (支持 JSON 和 JSONL 格式)
        with open(path, "r", encoding="utf-8") as f:
            if path.endswith(".jsonl"):
                # JSONL 格式 (每行一个JSON)
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        self.data.append(obj)
                    except Exception as e:
                        print(f"⚠️ JSON 解析失败: {e}")
            else:
                # JSON 格式 (整个文件是一个数组)
                try:
                    self.data = json.load(f)
                except Exception as e:
                    print(f"⚠️ JSON 文件解析失败: {e}")
        
        print(f"📊 加载埋点数据: {len(self.data)} 条")
        
        # 分析结果缓存
        self._analysis_cache = None
    
    def deep_extract_events(self, obj, path=""):
        """
        深度递归提取所有事件信息
        返回: [(event_name, params_dict, path), ...]
        """
        events = []
        
        if isinstance(obj, dict):
            # 检查是否是事件节点
            if "event" in obj:
                event_name = obj.get("event", "unknown")
                params = {}
                
                # 提取 params (可能是字符串或字典)
                params_raw = obj.get("params", {})
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
                    "local_time_ms": obj.get("local_time_ms"),
                    "session_id": obj.get("session_id")
                })
            
            # 继续递归
            for key, value in obj.items():
                events.extend(self.deep_extract_events(value, f"{path}.{key}" if path else key))
        
        elif isinstance(obj, list):
            for idx, item in enumerate(obj):
                events.extend(self.deep_extract_events(item, f"{path}[{idx}]"))
        
        return events
    
    def analyze_domains(self):
        """域名分析"""
        domain_stats = Counter()
        domain_methods = defaultdict(Counter)
        domain_paths = defaultdict(set)
        
        for record in self.data:
            host = record.get("host", "unknown")
            method = record.get("method", "unknown")
            path = record.get("path", "/")
            
            domain_stats[host] += 1
            domain_methods[host][method] += 1
            domain_paths[host].add(path)
        
        return {
            "domain_counts": domain_stats,
            "domain_methods": dict(domain_methods),
            "domain_paths": {k: list(v) for k, v in domain_paths.items()},
            "total_domains": len(domain_stats)
        }
    
    def analyze_events(self):
        """事件分析"""
        all_events = []
        
        for record in self.data:
            body = record.get("body")
            if body:
                extracted = self.deep_extract_events(body)
                for evt in extracted:
                    evt["timestamp"] = record.get("timestamp")
                    evt["host"] = record.get("host")
                    evt["url"] = record.get("url")
                    all_events.append(evt)
        
        # 统计事件类型
        event_counts = Counter(evt["event"] for evt in all_events)
        
        # 事件-域名映射
        event_domains = defaultdict(set)
        for evt in all_events:
            event_domains[evt["event"]].add(evt["host"])
        
        # 事件-参数映射
        event_params = defaultdict(lambda: defaultdict(set))
        for evt in all_events:
            for param_key, param_value in evt["params"].items():
                # 记录参数名和示例值
                event_params[evt["event"]][param_key].add(str(param_value)[:50])
        
        return {
            "total_events": len(all_events),
            "unique_event_types": len(event_counts),
            "event_counts": event_counts,
            "event_domains": {k: list(v) for k, v in event_domains.items()},
            "event_params": {
                event: {
                    param: list(values)[:5]  # 最多显示5个示例值
                    for param, values in params.items()
                }
                for event, params in event_params.items()
            },
            "all_events": all_events
        }
    
    def analyze_properties(self):
        """属性分析 (参数覆盖度)"""
        all_params = defaultdict(Counter)
        param_types = defaultdict(set)
        
        for record in self.data:
            body = record.get("body")
            if body:
                events = self.deep_extract_events(body)
                for evt in events:
                    event_name = evt["event"]
                    for param_key, param_value in evt["params"].items():
                        all_params[event_name][param_key] += 1
                        
                        # 推断参数类型
                        if isinstance(param_value, bool):
                            param_types[param_key].add("boolean")
                        elif isinstance(param_value, int):
                            param_types[param_key].add("integer")
                        elif isinstance(param_value, float):
                            param_types[param_key].add("float")
                        elif isinstance(param_value, str):
                            param_types[param_key].add("string")
                        elif isinstance(param_value, (list, dict)):
                            param_types[param_key].add("object")
        
        return {
            "event_param_coverage": dict(all_params),
            "param_types": {k: list(v) for k, v in param_types.items()},
            "total_unique_params": len(param_types)
        }
    
    def analyze_timeline(self):
        """时间序列分析"""
        timeline = []
        
        for record in self.data:
            timestamp = record.get("timestamp")
            host = record.get("host")
            action_gap = record.get("action_gap_ms", 0)
            
            events = self.deep_extract_events(record.get("body", {}))
            
            timeline.append({
                "timestamp": timestamp,
                "host": host,
                "action_gap_ms": action_gap,
                "event_count": len(events),
                "events": [e["event"] for e in events]
            })
        
        # 分析触发频率
        gap_ranges = {
            "即时(<500ms)": 0,
            "快速(500ms-2s)": 0,
            "正常(2s-5s)": 0,
            "延迟(5s-10s)": 0,
            "很慢(>10s)": 0
        }
        
        for t in timeline:
            gap = t["action_gap_ms"]
            if gap < 500:
                gap_ranges["即时(<500ms)"] += 1
            elif gap < 2000:
                gap_ranges["快速(500ms-2s)"] += 1
            elif gap < 5000:
                gap_ranges["正常(2s-5s)"] += 1
            elif gap < 10000:
                gap_ranges["延迟(5s-10s)"] += 1
            else:
                gap_ranges["很慢(>10s)"] += 1
        
        return {
            "timeline": timeline[:50],  # 只保留前50条
            "trigger_latency": gap_ranges
        }
    
    def calculate_quality_score(self, analysis):
        """计算埋点质量评分"""
        score = {}
        
        # 1. 域名规范性 (满分20)
        domains = analysis["domains"]["total_domains"]
        score["域名规范性"] = min(20, domains * 5)  # 最多4个域名满分
        
        # 2. 事件丰富度 (满分30)
        event_types = analysis["events"]["unique_event_types"]
        score["事件丰富度"] = min(30, event_types * 3)  # 10种事件满分
        
        # 3. 属性完整度 (满分30)
        unique_params = analysis["properties"]["total_unique_params"]
        score["属性完整度"] = min(30, unique_params * 2)  # 15个属性满分
        
        # 4. 响应及时性 (满分20)
        timeline = analysis["timeline"]["trigger_latency"]
        fast_ratio = (timeline["即时(<500ms)"] + timeline["快速(500ms-2s)"]) / max(sum(timeline.values()), 1)
        score["响应及时性"] = int(fast_ratio * 20)
        
        score["总分"] = sum(score.values())
        
        return score
    
    def full_analysis(self):
        """完整分析"""
        if self._analysis_cache:
            return self._analysis_cache
        
        print("\n🔍 开始深度分析...")
        
        analysis = {
            "基础信息": {
                "文件名": self.path,
                "总请求数": len(self.data),
                "分析时间": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            },
            "domains": self.analyze_domains(),
            "events": self.analyze_events(),
            "properties": self.analyze_properties(),
            "timeline": self.analyze_timeline()
        }
        
        analysis["quality_score"] = self.calculate_quality_score(analysis)
        
        self._analysis_cache = analysis
        return analysis
    
    def generate_report(self, output="埋点评估报告_高级版.html"):
        """生成详细报告"""
        analysis = self.full_analysis()
        
        # 生成事件参数表格
        event_param_html = ""
        for event, params in list(analysis["events"]["event_params"].items())[:20]:
            params_list = "<ul>" + "".join(
                f"<li><code>{param}</code>: {', '.join(values[:3])}</li>"
                for param, values in list(params.items())[:10]
            ) + "</ul>"
            
            event_param_html += f"""
            <tr>
                <td><strong>{event}</strong></td>
                <td>{analysis['events']['event_counts'][event]}</td>
                <td>{len(params)}</td>
                <td>{params_list}</td>
            </tr>
            """
        
        # 生成域名表格
        domain_html = ""
        for domain, count in analysis["domains"]["domain_counts"].most_common(10):
            methods = analysis["domains"]["domain_methods"].get(domain, {})
            paths = analysis["domains"]["domain_paths"].get(domain, [])
            
            domain_html += f"""
            <tr>
                <td><code>{domain}</code></td>
                <td>{count}</td>
                <td>{', '.join(f'{k}:{v}' for k,v in methods.items())}</td>
                <td>{len(paths)} 个接口</td>
            </tr>
            """
        
        # 生成质量评分
        score = analysis["quality_score"]
        score_html = f"""
        <div class="score-card">
            <h3>📊 埋点质量总分: {score['总分']}/100</h3>
            <div class="score-bar">
                <div class="score-fill" style="width: {score['总分']}%"></div>
            </div>
            <ul>
                <li>域名规范性: {score['域名规范性']}/20</li>
                <li>事件丰富度: {score['事件丰富度']}/30</li>
                <li>属性完整度: {score['属性完整度']}/30</li>
                <li>响应及时性: {score['响应及时性']}/20</li>
            </ul>
        </div>
        """
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>埋点评估报告 - 高级版</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', -apple-system, sans-serif;
            background: #f5f7fa;
            padding: 20px;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        .content {{ padding: 40px; }}
        
        .score-card {{
            background: #f8f9fa;
            padding: 30px;
            border-radius: 8px;
            margin: 20px 0;
            border-left: 4px solid #667eea;
        }}
        .score-bar {{
            background: #e2e8f0;
            height: 30px;
            border-radius: 15px;
            overflow: hidden;
            margin: 20px 0;
        }}
        .score-fill {{
            background: linear-gradient(90deg, #667eea, #764ba2);
            height: 100%;
            transition: width 1s ease;
        }}
        
        .section {{
            margin: 40px 0;
        }}
        .section h2 {{
            color: #2d3748;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #667eea;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e2e8f0;
        }}
        th {{
            background: #667eea;
            color: white;
            font-weight: 600;
        }}
        tr:hover {{ background: #f7fafc; }}
        
        code {{
            background: #edf2f7;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }}
        
        .metric-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        .metric-card {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }}
        .metric-value {{
            font-size: 2em;
            font-weight: bold;
            color: #667eea;
        }}
        .metric-label {{
            color: #718096;
            margin-top: 5px;
        }}
        
        ul {{ margin-left: 20px; }}
        li {{ margin: 5px 0; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📊 埋点深度评估报告</h1>
            <p>生成时间: {analysis['基础信息']['分析时间']}</p>
            <p>数据文件: {analysis['基础信息']['文件名']}</p>
        </div>
        
        <div class="content">
            <!-- 质量评分 -->
            {score_html}
            
            <!-- 核心指标 -->
            <div class="section">
                <h2>📈 核心指标</h2>
                <div class="metric-grid">
                    <div class="metric-card">
                        <div class="metric-value">{analysis['基础信息']['总请求数']}</div>
                        <div class="metric-label">总请求数</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value">{analysis['domains']['total_domains']}</div>
                        <div class="metric-label">埋点域名数</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value">{analysis['events']['total_events']}</div>
                        <div class="metric-label">总事件数</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value">{analysis['events']['unique_event_types']}</div>
                        <div class="metric-label">事件类型数</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value">{analysis['properties']['total_unique_params']}</div>
                        <div class="metric-label">唯一属性数</div>
                    </div>
                </div>
            </div>
            
            <!-- 域名分析 -->
            <div class="section">
                <h2>🌐 域名分析</h2>
                <table>
                    <thead>
                        <tr>
                            <th>域名</th>
                            <th>请求次数</th>
                            <th>请求方法</th>
                            <th>接口数量</th>
                        </tr>
                    </thead>
                    <tbody>
                        {domain_html}
                    </tbody>
                </table>
            </div>
            
            <!-- 事件分析 -->
            <div class="section">
                <h2>🎯 事件类型分析 (Top 20)</h2>
                <table>
                    <thead>
                        <tr>
                            <th>事件名称</th>
                            <th>触发次数</th>
                            <th>参数数量</th>
                            <th>参数列表 (示例值)</th>
                        </tr>
                    </thead>
                    <tbody>
                        {event_param_html}
                    </tbody>
                </table>
            </div>
            
            <!-- 响应时间分析 -->
            <div class="section">
                <h2>⏱️ 触发响应分析</h2>
                <table>
                    <thead>
                        <tr>
                            <th>响应速度</th>
                            <th>次数</th>
                            <th>占比</th>
                        </tr>
                    </thead>
                    <tbody>
                        {
                            ''.join(
                                f"<tr><td>{label}</td><td>{count}</td><td>{count/max(sum(analysis['timeline']['trigger_latency'].values()),1)*100:.1f}%</td></tr>"
                                for label, count in analysis['timeline']['trigger_latency'].items()
                            )
                        }
                    </tbody>
                </table>
            </div>
            
            <!-- 建议 -->
            <div class="section">
                <h2>💡 优化建议</h2>
                <ul>
                    {'<li>✅ 域名规范良好</li>' if score['域名规范性'] >= 15 else '<li>⚠️ 建议整合埋点域名,减少DNS查询</li>'}
                    {'<li>✅ 事件覆盖充分</li>' if score['事件丰富度'] >= 20 else '<li>⚠️ 建议补充关键业务事件</li>'}
                    {'<li>✅ 属性定义完整</li>' if score['属性完整度'] >= 20 else '<li>⚠️ 建议补充事件属性,提高分析维度</li>'}
                    {'<li>✅ 响应速度快</li>' if score['响应及时性'] >= 15 else '<li>⚠️ 建议优化埋点触发时机,减少延迟</li>'}
                </ul>
            </div>
        </div>
    </div>
</body>
</html>
        """
        
        with open(output, "w", encoding="utf-8") as f:
            f.write(html)
        
        print(f"\n✅ 详细报告已生成: {output}")
        print(f"📊 质量评分: {score['总分']}/100")
        
        return output
    
    def export_to_excel(self, output="埋点分析数据.xlsx"):
        """导出到Excel (可选,需要 openpyxl)"""
        try:
            import pandas as pd
            
            analysis = self.full_analysis()
            
            with pd.ExcelWriter(output, engine='openpyxl') as writer:
                # 事件统计
                pd.DataFrame([
                    {"事件名": k, "次数": v}
                    for k, v in analysis["events"]["event_counts"].most_common()
                ]).to_excel(writer, sheet_name="事件统计", index=False)
                
                # 域名统计
                pd.DataFrame([
                    {"域名": k, "次数": v}
                    for k, v in analysis["domains"]["domain_counts"].items()
                ]).to_excel(writer, sheet_name="域名统计", index=False)
                
                # 时间线
                pd.DataFrame(analysis["timeline"]["timeline"]).to_excel(
                    writer, sheet_name="时间线", index=False
                )
            
            print(f"✅ Excel 数据已导出: {output}")
        except ImportError:
            print("⚠️ 需要安装 pandas 和 openpyxl: pip install pandas openpyxl")


if __name__ == "__main__":
    analyzer = AdvancedAnalyzer()
    analyzer.generate_report()
    # analyzer.export_to_excel()  # 可选:导出Excel