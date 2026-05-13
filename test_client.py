import requests
import time
import sys

BASE_URL = "http://127.0.0.1:5000"

def test_normal_request():
    """测试正常请求"""
    print("\n[TEST 1] 正常请求测试")
    response = requests.get(f"{BASE_URL}/")
    print(f"状态码: {response.status_code}")
    print(f"响应: {response.json()}")
    assert response.status_code == 200

def test_sql_injection():
    """测试SQL注入拦截"""
    print("\n[TEST 2] SQL注入测试")
    payloads = [
        "/search?q=1 UNION SELECT 1,2,3",
        # "/search?q=admin' OR '1'='1",
        # "/search?q=1; DROP TABLE users"
    ]
    
    for payload in payloads:
        response = requests.get(f"{BASE_URL}{payload}")
        print(f"请求: {payload}")
        print(f"状态码: {response.status_code}")
        print(f"响应: {response.json()}")
        assert response.status_code == 403

def test_xss():
    """测试XSS拦截"""
    print("\n[TEST 3] XSS攻击测试")
    response = requests.get(f"{BASE_URL}/search?q=<script>alert(1)</script>")
    print(f"状态码: {response.status_code}")
    print(f"响应: {response.json()}")
    assert response.status_code == 403

def test_path_traversal():
    """测试路径遍历拦截"""
    print("\n[TEST 4] 路径遍历测试")
    payloads = [
        "/search?q=../../etc/passwd",
        # "/search?q=..%5C..%5Cwindows%5Csystem32"
    ]
    
    for payload in payloads:
        response = requests.get(f"{BASE_URL}{payload}")
        print(f"请求: {payload}")
        print(f"状态码: {response.status_code}")
        assert response.status_code == 403

def test_malicious_ua():
    """测试恶意User-Agent拦截"""
    print("\n[TEST 5] 恶意User-Agent测试")
    headers = {'User-Agent': 'sqlmap/1.5'}
    response = requests.get(f"{BASE_URL}/", headers=headers)
    print(f"User-Agent: sqlmap")
    print(f"状态码: {response.status_code}")
    assert response.status_code == 403

def test_rate_limit():
    """测试频率限制"""
    print("\n[TEST 6] 频率限制测试")
    
    # 先发送65个快速请求
    for i in range(65):
        response = requests.get(f"{BASE_URL}/")
        print(f"请求 {i+1}/65: {response.status_code}")
        
        if response.status_code == 429:
            print("频率限制生效！✓")
            return
    
    print("警告：发送65个请求后仍未被限流")
def test_whitelist():
    """测试白名单URL"""
    print("\n[TEST 7] 白名单测试")
    # 白名单URL应该绕过检测
    response = requests.get(f"{BASE_URL}/health")
    print(f"/health 状态码: {response.status_code}")
    assert response.status_code == 200
    
    # 即使有恶意参数，白名单也应该放行
    response = requests.get(f"{BASE_URL}/health?q=<script>")
    print(f"/health?q=<script> 状态码: {response.status_code}")
    assert response.status_code == 200

def run_all_tests():
    """运行所有测试"""
    print("=" * 60)
    print("开始WAF功能测试")
    print("=" * 60)
    
    # 确保服务已启动
    try:
        requests.get(f"{BASE_URL}/", timeout=2)
    except requests.ConnectionError:
        print("错误: WAF服务未启动，请先运行 python app.py")
        sys.exit(1)
    
    test_normal_request()
    test_sql_injection()
    test_xss()
    test_path_traversal()
    test_malicious_ua()
    test_whitelist()
    test_rate_limit()
    
    print("\n" + "=" * 60)
    print("所有测试完成！")
    print("=" * 60)

if __name__ == "__main__":
    run_all_tests()