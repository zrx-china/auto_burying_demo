#!/usr/bin/env python3
"""
请求监控模块
用于分析 mitmproxy 捕获的请求，判断点击有效性
"""

import json
import fnmatch
from typing import Dict, List, Literal


class RequestClassifier:
    """请求分类器"""
    
    # ✅ 业务域名（根据你的 App 实际情况配置）
    BUSINESS_DOMAINS = [
        "*.chinamobile.com",
        "*.cmcc.com",
        "*.mcloud.com",
        "*mcloud*",  # 包含 mcloud 的域名
        "ad.mcloud.139.com",
        "data.cmicapm.com",
        "ai.yun.139.com",
        "group.yun.139.com",
        "middle.yun.139.com",
        "mrp.139.com",
        "online-njs.yun.139.com",
        "ose.caiyun.feixin.10086.cn",
        "personal-kd-njs.yun.139.com",
        "vsbo.caiyun.feixin.10086.cn",
        "ypqy.mcloud.139.com",
        "ael.yun.139.com"
    ]
    
    # ✅ 埋点域名
    BURYING_DOMAINS = [
        "dc.cmicapm.com"
    ]
    
    # ✅ 噪音域名（需要过滤的）
    NOISE_DOMAINS = [
        # CDN
        "*.cdnjs.cloudflare.com",
        "*.cloudflare.com",
        "*.akamai.net",
        "*.cdn.*.com",
        "*cdn*",
        
        # Google
        "*.googleapis.com",
        "*.gstatic.com",
        "*.google.com",
        "*.googlesyndication.com",
        
        # 统计分析
        "analytics.*",
        "*.analytics.com",
        "beacon.*",
        "track.*",
        "metric.*",
        "*.umeng.com",
        "*.cnzz.com",
        
        # 广告
        "ad.*",
        "ads.*",
        "*.doubleclick.net",
        
        # 社交媒体
        "*.qq.com",
        "*.weixin.qq.com",
        "*.baidu.com",
        "*.sina.com",
        "*.weibo.com",
        
        # 其他常见噪音
        "*.alipay.com",
        "*.taobao.com",
        "*.alicdn.com",
    ]
    
    @classmethod
    def classify_request(cls, host: str, url: str) -> Literal["business", "burying", "noise"]:
        """
        分类请求
        
        Args:
            host: 请求的主机名
            url: 完整的 URL
        
        Returns:
            "business": 业务请求
            "burying": 埋点请求
            "noise": 噪音请求
        """
        # 1. 先检查埋点域名（最高优先级）
        for pattern in cls.BURYING_DOMAINS:
            if fnmatch.fnmatch(host, pattern) or pattern.replace("*", "") in host:
                return "burying"
        
        # 2. 检查噪音域名
        for pattern in cls.NOISE_DOMAINS:
            if fnmatch.fnmatch(host, pattern):
                return "noise"
        
        # 3. 检查业务域名
        for pattern in cls.BUSINESS_DOMAINS:
            if fnmatch.fnmatch(host, pattern) or pattern.replace("*", "") in host:
                return "business"
        
        # 4. 默认当作噪音（保守策略）
        return "noise"


class RequestMonitor:
    """请求监控器 - 从 mitmproxy 日志读取并分析"""
    
    def __init__(self, log_file: str = "/tmp/mitm_requests.jsonl"):
        """
        初始化请求监控器
        
        Args:
            log_file: mitmproxy 日志文件路径
        """
        self.log_file = log_file
        self.classifier = RequestClassifier()
    
    def get_requests_in_window(self, start_ts: float, end_ts: float) -> Dict:
        """
        获取时间窗口内的请求并分类
        
        Args:
            start_ts: 开始时间戳（毫秒）
            end_ts: 结束时间戳（毫秒）
        
        Returns:
            {
                "business": [...],  # 业务请求
                "burying": [...],   # 埋点请求
                "noise": [...],     # 噪音请求
            }
        """
        business_reqs = []
        burying_reqs = []
        noise_reqs = []
        
        try:
            with open(self.log_file, "r", encoding="utf-8") as f:
                for line in f:
                    if not line.strip():
                        continue
                    
                    try:
                        req = json.loads(line)
                        ts = req.get("timestamp", 0)
                        
                        # 在时间窗口内
                        if start_ts <= ts <= end_ts:
                            host = req.get("host", "")
                            url = req.get("url", "")
                            
                            # 分类
                            req_type = self.classifier.classify_request(host, url)
                            req["classified_type"] = req_type
                            
                            if req_type == "business":
                                business_reqs.append(req)
                            elif req_type == "burying":
                                burying_reqs.append(req)
                            else:
                                noise_reqs.append(req)
                    
                    except json.JSONDecodeError:
                        continue
        
        except FileNotFoundError:
            # 文件不存在，返回空结果
            pass
        
        return {
            "business": business_reqs,
            "burying": burying_reqs,
            "noise": noise_reqs,
        }
    
    def check_click_effect(self, start_ts: float, duration: float = 3000, 
                          debug: bool = False) -> Dict:
        """
        检查点击效果
        
        Args:
            start_ts: 点击时间戳（毫秒）
            duration: 检测时长（毫秒），默认3秒
            debug: 是否输出调试信息
        
        Returns:
            {
                "has_business": bool,
                "has_burying": bool,
                "business_count": int,
                "burying_count": int,
                "business_requests": [...],
                "burying_requests": [...],
            }
        """
        end_ts = start_ts + duration
        requests = self.get_requests_in_window(start_ts, end_ts)
        
        result = {
            "has_business": len(requests["business"]) > 0,
            "has_burying": len(requests["burying"]) > 0,
            "business_count": len(requests["business"]),
            "burying_count": len(requests["burying"]),
            "business_requests": requests["business"],
            "burying_requests": requests["burying"],
        }
        
        if debug:
            print(f"  📊 请求分析:")
            print(f"     业务请求: {result['business_count']} 个")
            print(f"     埋点请求: {result['burying_count']} 个")
            print(f"     噪音请求: {len(requests['noise'])} 个 (已过滤)")
            
            if result['business_count'] > 0:
                print(f"     业务请求列表:")
                for req in requests["business"][:3]:  # 只显示前3个
                    print(f"       - {req.get('method')} {req.get('host')}{req.get('path', '')}")
            
            if result['burying_count'] > 0:
                print(f"     埋点请求列表:")
                for req in requests["burying"]:
                    print(f"       - {req.get('method')} {req.get('host')}{req.get('path', '')}")
        
        return result