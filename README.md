
# Simple WAF Middleware

一个轻量级 Web 应用防火墙中间件，基于 Flask 开发，用于学习和演示 WAF 核心功能。

## 功能特性

- ✅ SQL 注入检测与拦截
- ✅ XSS 攻击检测与拦截  
- ✅ 路径遍历防护
- ✅ 恶意 User-Agent 过滤
- ✅ IP 频率限制（60 次/分钟）
- ✅ 自动黑名单（封禁 5 分钟）
- ✅ URL 白名单
- ✅ JSON 结构化告警日志

## 技术栈

- Python 3
- Flask
- 正则表达式
- 内存存储（IP 请求计数 + 黑名单）

## 快速开始

### 1. 克隆项目
bash
git clone https://github.com/你的用户名/simple-waf.git
cd simple-waf

2. 创建虚拟环境
bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

3. 安装依赖
bash
pip install flask requests

4. 启动服务
bash
python app.py

5. 测试（新开一个终端）
bash
python test_client.py
项目结构
text
simple-waf/
├── app.py              # Flask 主程序
├── waf_middleware.py   # WAF 核心逻辑
├── rules.json          # 规则配置文件
├── test_client.py      # 自动化测试脚本
└── waf_alerts.log      # 拦截日志（运行后生成）
核心代码说明
1. 攻击检测
通过正则匹配请求中的恶意特征，支持 SQL 注入、XSS、路径遍历等。

2. 频率限制
基于滑动窗口实现 IP 级别的请求频率限制，超过阈值自动加入黑名单。

3. 日志记录
所有拦截行为以 JSON 格式记录到日志文件，便于后续分析。

测试结果
测试项	预期结果	实际结果
正常请求	200	✅ 通过
SQL 注入	403	✅ 通过
XSS 攻击	403	✅ 通过
路径遍历	403	✅ 通过
恶意 User-Agent	403	✅ 通过
频率限制	429	✅ 通过
拦截效果演示
访问包含 SQL 注入 payload 的 URL：

text
http://127.0.0.1:5000/search?q=1 UNION SELECT 1,2,3
返回结果：

json
{
  "error": "Malicious request blocked: SQL Injection",
  "ip": "127.0.0.1",
  "timestamp": "2026-05-13 20:30:42"
}
后续优化方向
支持 Redis 分布式存储（替代内存）

增加机器学习检测未知攻击

开发可视化仪表盘

支持 HTTPS 流量解密

适用场景
学习 WAF 工作原理

Web 安全入门实践

简历项目展示

作者
刘贤达
