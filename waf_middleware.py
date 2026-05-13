import re
import json
import time
from collections import defaultdict
from flask import request, jsonify

# 加载配置
with open('rules.json', 'r') as f:
    config = json.load(f)

RULES = config['rules']
RATE_LIMIT = config['rate_limit']['requests_per_minute']
BLOCK_DURATION = config['rate_limit']['block_duration_seconds']
WHITELIST_URLS = config['whitelist_urls']

# 存储数据结构
ip_requests = defaultdict(list)
blacklist = {}

def log_alert(ip, message):
    """记录告警日志"""
    log_entry = {
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'ip': ip,
        'message': message,
        'path': request.path
    }
    with open('waf_alerts.log', 'a') as f:
        f.write(json.dumps(log_entry) + '\n')
    print(f"[ALERT] {log_entry}")

def decode_payload(text):
    """简单的URL解码"""
    result = text
    for _ in range(3):
        decoded = re.sub(r'%([0-9A-Fa-f]{2})', lambda m: chr(int(m.group(1), 16)), result)
        if decoded == result:
            break
        result = decoded
    return result

def detect_attack(req):
    """检测请求是否包含攻击特征"""
    if req.path in WHITELIST_URLS:
        return None
    
    path = decode_payload(req.path)
    args = {k: decode_payload(v) for k, v in req.args.items()}
    body = decode_payload(req.get_data(as_text=True)) if req.method in ['POST', 'PUT'] else ''
    ua = decode_payload(req.headers.get('User-Agent', ''))
    
    all_text = f"{path} {args} {body} {ua}"
    
    for rule in RULES:
        if re.search(rule['pattern'], all_text):
            return rule['name']
    return None

def is_rate_limited(ip):
    """检查频率限制"""
    now = time.time()
    # 清理1分钟前的记录
    ip_requests[ip] = [t for t in ip_requests[ip] if now - t < 60]
    
    print(f"[DEBUG] IP {ip} 最近请求次数: {len(ip_requests[ip])}")
    
    if len(ip_requests[ip]) >= RATE_LIMIT:
        blacklist[ip] = now + BLOCK_DURATION
        log_alert(ip, f"Rate limit exceeded, blacklisted for {BLOCK_DURATION}s")
        return True
    
    ip_requests[ip].append(now)
    return False

def waf_protect():
    """WAF主入口"""
    ip = request.remote_addr
    
    # 黑名单检查
    if ip in blacklist:
        if time.time() < blacklist[ip]:
            return jsonify({"error": "Your IP is temporarily banned"}), 403
        else:
            del blacklist[ip]
    
    # 频率限制
    if is_rate_limited(ip):
        return jsonify({"error": "Too many requests"}), 429
    
    # 攻击检测
    attack = detect_attack(request)
    if attack:
        log_alert(ip, f"Attack detected: {attack}")
        return jsonify({"error": f"Malicious request blocked: {attack}"}), 403
    
    return None