# Android 埋点自动化检测 Demo

> 基于 Appium + mitmproxy 的埋点自动遍历与评估 Demo  
> 适用于：埋点 QA / 数据治理 / 自动化验收 /流程验证

---

## 一、项目目标

本项目用于验证「埋点是否随着用户行为自动触发」，实现以下能力：

- 🤖 **自动遍历 Android App 页面**
- 📡 **自动抓取埋点网络请求**
- 📊 **自动分析埋点覆盖情况**
- 📝 **自动生成评估报告（HTML）**

目标 App（示例）：**中国移动云盘（Android）**

---

## 二、项目目录结构

```text
auto_burying_demo/
│
├── config.py              # 全局配置（包名、代理、遍历参数）
├── crawler_appium.py      # UI 自动遍历模块（Appium）
├── capture_mitm.py        # 埋点抓包模块（mitmproxy 脚本）
├── analyze_report.py      # 埋点分析与报告生成
│
├── main.py                # 主流程入口（调度各模块）
├── requirements.txt       # Python 依赖
└── README.md              # 使用说明
```

## 三、环境准备

1️⃣ Python 环境（推荐 venv）

python3 -m venv autoburying
source autoburying/bin/activate
pip install -r requirements.txt

依赖说明：
	•	appium-python-client：UI 自动化
	•	mitmproxy：HTTP/HTTPS 抓包
	•	pandas：数据分析
	•	openpyxl：Excel 支持（可选）

⸻

2️⃣ Appium 环境

需要 Node.js（>=16）

npm install -g appium
appium driver install uiautomator2

启动 Appium 服务：

appium

默认监听：http://127.0.0.1:4723

⸻

3️⃣ Android 手机准备

必须条件
	•	Android 实机（推荐，模拟器也可）
	•	已安装目标 App（如：中国移动云盘）
	•	打开 开发者模式
	•	打开 USB 调试

连接确认：

adb devices

看到设备 ID 即成功。

⸻

## 四、抓包环境配置（非常关键）

1️⃣ 启动 mitmproxy 抓包

新开一个终端：

mitmdump -s capture_mitm.py -p 8080

说明：
	•	所有经过代理的请求都会被捕获
	•	命中埋点域名的请求会写入 bury_points.json

⸻

2️⃣ 手机 WiFi 代理设置

手机 → 当前 WiFi → 高级 / 修改网络：
代理类型： 手动
代理 IP： 电脑局域网 IP
代理端口： 8080

⚠️ 不是 127.0.0.1，而是你 Mac 的局域网 IP

⸻

3️⃣ 安装 mitm 证书（HTTPS 必须）

手机浏览器访问：

http://mitm.it

	•	下载 Android 证书
	•	安装为 用户 CA 证书
	•	Android 10+ 需允许用户证书抓包

⸻

## 五、运行 Demo（标准流程）

Step 1：启动appium 【终端1】

Step 2：确认 mitmproxy 已运行 【终端2】

终端中能看到请求日志

Step 3：运行主程序 【终端3】

python main.py

程序将自动：
	1.	启动 App
	2.	自动遍历页面并点击元素
	3.	同时抓取埋点请求
	4.	生成分析报告

⸻

## 六、输出结果说明

mitm_capture_yyyymmdd_时间戳.jsonl：原始埋点请求数据
test_report.html： 自动生成的埋点评估报告

打开 test_report.html 即可查看结果。
