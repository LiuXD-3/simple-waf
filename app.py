from flask import Flask, request, jsonify
from waf_middleware import waf_protect

app = Flask(__name__)

# 注册WAF中间件（每个请求都会先经过WAF）
app.before_request(waf_protect)

# 测试路由
@app.route('/')
def home():
    return {
        'message': 'Welcome to protected website',
        'status': 'WAF is active',
        'your_ip': request.remote_addr
    }

@app.route('/search')
def search():
    q = request.args.get('q', '')
    return {
        'query': q,
        'results': f'Searching for: {q}',
        'message': 'This is a protected search endpoint'
    }

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')
    return {
        'message': f'Login attempt for user: {username}',
        'status': 'success' if username == 'admin' else 'failed'
    }

@app.route('/health')
def health():
    return {'status': 'ok'}, 200

@app.route('/waf/stats', methods=['GET'])
def waf_stats():
    """查看WAF统计信息"""
    from waf_middleware import ip_requests, blacklist
    return {
        'active_ips': len(ip_requests),
        'blacklisted_ips': len(blacklist),
        'blacklist_details': {ip: time for ip, time in list(blacklist.items())[:10]}
    }

if __name__ == '__main__':
    print("=" * 50)
    print("WAF 已启动")
    print("监听地址: http://127.0.0.1:5000")
    print("规则数量: 4")
    print("频率限制: 60 次/分钟")
    print("=" * 50)
    app.run(debug=True, host='0.0.0.0', port=5000)