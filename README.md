## 📝 项目简介

密码算法实现平台是一个基于Flask的Web应用，为密码学教学、研究和实践提供全面支持。本平台集成了多种主流密码学算法，通过直观的Web界面和RESTful API接口，使用户能够便捷地学习和应用各类密码学技术。

### 🌟 核心特点

- **丰富的算法库**：涵盖对称加密、非对称加密、哈希函数、数字签名等多种密码学算法
- **双重接口设计**：同时提供Web可视化界面和完整的RESTful API
- **实用密码学场景**：包含数字证书、安全通信等实际应用示例
- **良好的代码组织**：模块化设计，便于扩展和维护

## 🔐 支持的算法

### 对称加密
- **AES**：支持ECB、CBC、CFB、OFB、CTR多种工作模式
- **SM4**：中国国家密码算法
- **RC6**：Rivest设计的高性能分组密码

### 哈希与认证
- **哈希函数**：SHA1、SHA256、SHA3-256、SHA3-512、RIPEMD160
- **消息认证码**：HMAC-SHA1、HMAC-SHA256
- **密钥派生**：PBKDF2

### 编码转换
- **Base64**：标准Base64和URL安全Base64
- **字符编码**：UTF-8编解码
- **十六进制**：二进制与十六进制转换

### 公钥密码学
- **RSA**：加密/解密、签名/验证
- **ECC**：椭圆曲线密码学
- **ECDSA**：椭圆曲线数字签名算法

## 🛠️ 技术栈

- **后端**：Python 3.7+、Flask 2.0+、PyCryptodome
- **前端**：HTML5、CSS3、Bootstrap 5、jQuery
- **API设计**：RESTful风格
- **安全性**：请求限流、输入验证、错误处理

## 📥 安装指南

### 环境要求
- Python 3.7+
- pip包管理器

### 安装步骤

1. **克隆代码库**
   ```bash
   git clone https://github.com/yourusername/CAPI2.git
   cd CAPI2
   ```

2. **创建虚拟环境**
   ```bash
   python -m venv venv
   
   # Windows激活
   venv\Scripts\activate
   
   # Linux/Mac激活
   source venv/bin/activate
   ```

3. **安装依赖包**
   ```bash
   pip install -r requirements.txt
   
   # 安装可能缺失的依赖
   pip install gmssl ecdsa
   ```

4. **启动应用**
   ```bash
   python run.py
   ```

5. **访问应用**
   ```
   http://localhost:5000
   ```

## 📚 使用指南

### Web界面使用
1. 访问主页 `http://localhost:5000`
2. 从侧边栏选择算法类别
3. 在操作面板中填写参数
4. 点击执行按钮
5. 查看结果区域获取输出

### API调用示例

#### SHA256哈希计算
```python
import requests
import json

url = "http://localhost:5000/api/hash/sha256"
data = {"message": "需要计算哈希的内容"}
headers = {"Content-Type": "application/json"}

response = requests.post(url, data=json.dumps(data), headers=headers)
result = response.json()

print(result)
# 输出: {"success": true, "data": {"hash": "..."}, "message": "SHA256哈希计算成功"}
```

#### AES加密示例
```python
import requests
import json
import base64

url = "http://localhost:5000/api/symmetric/aes/encrypt"
data = {
    "plaintext": "需要加密的数据",
    "key": "经过Base64编码的密钥",
    "mode": "CBC"
}
headers = {"Content-Type": "application/json"}

response = requests.post(url, data=json.dumps(data), headers=headers)
result = response.json()

print(result)
```

## 🗂️ 项目结构

```
CAPI2/
├── app/                     # 应用主目录
│   ├── __init__.py          # 应用初始化
│   ├── config.py            # 配置文件
│   ├── crypto/              # 密码学算法实现
│   │   ├── symmetric.py     # 对称加密算法
│   │   ├── hash.py          # 哈希算法
│   │   ├── encoding.py      # 编码算法
│   │   └── asymmetric.py    # 非对称加密算法
│   ├── routes/              # 路由定义
│   │   ├── web_routes.py    # Web界面路由
│   │   └── api_routes.py    # API路由
│   └── templates/           # 前端模板
├── logs/                    # 日志目录
├── run.py                   # 应用入口
├── requirements.txt         # 依赖列表
└── README.md                # 项目说明
```

## 📡 API文档

所有API遵循统一的JSON响应格式：

```json
{
  "success": true/false,      // 操作是否成功
  "data": { ... },           // 成功时返回的数据
  "message": "..."           // 状态消息或错误信息
}
```

### 主要API端点类别

- `/api/status` - API状态检查
- `/api/symmetric/...` - 对称加密算法
- `/api/hash/...` - 哈希和认证算法
- `/api/encoding/...` - 编码转换
- `/api/asymmetric/...` - 非对称加密算法

详细API文档可通过项目源码中的`api_routes.py`文件查看每个端点的具体用法。

## 📄 许可证

本项目采用MIT许可证开源。

---

💻 密码算法实现平台 - 让密码学变得触手可及
