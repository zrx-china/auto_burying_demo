# config.py
# ================== 全局配置 ==================

CONFIG = {
    # ========== App 信息 ==========
    "app_package": "com.chinamobile.mcloud",
    "app_activity": "com.chinamobile.mcloud.client.logo.LogoActivity",

    # ========== 设备配置 ==========
    "device_name": "3GBBB22726206326",
    "platform_name": "Android",
    "platform_version": "10",
    "automation_name": "UiAutomator2",

    # ========== Appium Server ==========
    "appium_server": "http://127.0.0.1:4723",

    # ========== 代理配置 (抓包用) ==========
    # ⚠️ 测试遍历时可以注释掉这两行
    "proxy_host": "127.0.0.1",
    "proxy_port": 8080,

    # ========== 埋点域名 ==========
    "tracking_domains": [
        "ad.mcloud.139.com",
        "dc.cmicapm.com",
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
    ],

    # ========== 遍历参数 ==========
    "max_depth": 1,              # 最大遍历深度 (推荐 1-3)
    "page_wait": 2,               # 每页等待时间(秒)
    "coord_threshold": 30,         # 坐标去重阈值（像素）
    # "max_clicks_per_page": 3      # 每页最多点击多少个元素

    # ... 其他配置 ...
    "debug_tap": False  # 开启点击调试
}