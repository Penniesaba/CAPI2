# 密码算法实现平台 (CodeInsightX)

<div align="center">
  <img src="https://img.shields.io/badge/Python-3.7+-blue.svg" alt="Python 3.7+">
  <img src="https://img.shields.io/badge/Flask-2.0.1+-green.svg" alt="Flask 2.0.1+">
  <img src="https://img.shields.io/badge/Bootstrap-5.1.3-purple.svg" alt="Bootstrap 5.1.3">
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT">
</div>

## 项目简介

密码算法实现平台是一个基于Flask的Web应用，旨在展示和实现各种密码学算法，为网络信息安全教学和研究提供支持。该平台提供了直观的Web界面和完善的API接口，使用户能够交互式地体验和学习各类密码算法的原理和应用。

### 项目特点

- 📚 **全面的算法实现**：覆盖对称加密、哈希、编码和非对称加密等多种密码学算法
- 🖥️ **美观的用户界面**：基于Bootstrap 5构建的现代化界面，支持响应式设计
- 🔌 **完整的API支持**：所有功能都提供REST API接口，便于集成到其他系统
- 📝 **详细的原理讲解**：每种算法都配有理论知识讲解，帮助用户理解算法原理
- 🔒 **实用的密码学应用**：包含数字证书、安全通信等密码学应用场景

## 实现的算法

### 对称加密算法
- AES (高级加密标准)，支持ECB、CBC、CFB、OFB、CTR模式
- SM4 (国密对称加密)
- RC6 (Rivest加密)

### 哈希算法
- 基础哈希：SHA1、SHA256、SHA3-256、SHA3-512、RIPEMD160
- HMAC (消息认证码)：HMAC-SHA1、HMAC-SHA256
- PBKDF2 (密钥派生)

### 编码算法
- Base64编码/解码
- URL安全的Base64编码/解码
- UTF-8编码/解码
- 十六进制编码/解码

### 非对称加密算法
- RSA加密/解密
- ECC (椭圆曲线加密)
- 数字签名：RSA签名、ECDSA签名

### 密码学应用
- 数字证书
- 安全通信
- 密码安全

## 技术栈

- **后端**：Python 3.7+, Flask 2.0+, PyCryptodome
- **前端**：HTML5, CSS3, JavaScript, Bootstrap 5, jQuery
- **API**：RESTful API架构
- **依赖管理**：pip, requirements.txt

## 安装指南

### 前提条件

- Python 3.7或更高版本
- pip包管理器

### 步骤

1. 克隆仓库：
   ```bash
   git clone https://github.com/yourusername/CodeInsightX.git
   cd CodeInsightX
   ```

2. 创建并激活虚拟环境（推荐）：
   ```bash
   python -m venv venv
   # Windows
   venv\Scripts\activate
   # Linux/Mac
   source venv/bin/activate
   ```

3. 安装依赖：
   ```bash
   pip install -r requirements.txt
   ```

4. 启动应用：
   ```bash
   python run.py
   ```

5. 在浏览器中访问：
   ```
   http://localhost:5000
   ```

## 使用指南

### Web界面

1. 打开浏览器，访问 `http://localhost:5000`
2. 从左侧导航栏选择需要使用的算法类型
3. 根据页面表单输入相应参数
4. 点击对应的按钮执行算法操作
5. 查看结果显示区域获取计算结果

### API调用示例

#### SHA256哈希计算

```python
import requests
import json

url = "http://localhost:5000/api/hash/sha256"
data = {"message": "Hello, World!"}
headers = {"Content-Type": "application/json"}

response = requests.post(url, data=json.dumps(data), headers=headers)
result = response.json()

print(result)
# 输出: {"success": true, "data": {"hash": "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"}}
```

#### AES加密

```python
import requests
import json
import base64

url = "http://localhost:5000/api/symmetric/aes-encrypt"
data = {
    "plaintext": "需要加密的数据",
    "key": base64.b64encode(b"sixteen byte key").decode('utf-8'),
    "mode": "CBC",
    "iv": base64.b64encode(b"sixteen byte iv.").decode('utf-8')
}
headers = {"Content-Type": "application/json"}

response = requests.post(url, data=json.dumps(data), headers=headers)
result = response.json()

print(result)
```

## 项目结构

```
CodeInsightX/
├── app/                     # 应用主目录
│   ├── __init__.py          # 应用初始化
│   ├── config.py            # 配置文件
│   ├── crypto/              # 密码学算法实现
│   │   ├── symmetric.py     # 对称加密算法
│   │   ├── hash.py          # 哈希算法
│   │   ├── encoding.py      # 编码算法
│   │   └── asymmetric.py    # 非对称加密算法
│   ├── routes/              # 路由定义
│   │   ├── web.py           # Web界面路由
│   │   └── api.py           # API路由
│   └── templates/           # 前端模板
│       ├── base.html        # 基础布局模板
│       ├── crypto_forms/    # 算法操作表单
│       └── theory/          # 算法原理介绍
├── run.py                   # 应用入口
├── requirements.txt         # 依赖列表
└── README.md                # 项目说明（本文件）
```

## API文档

完整的API文档可在应用运行后通过访问 `http://localhost:5000/docs` 获取。

API遵循统一的返回格式：
```json
{
  "success": true/false,
  "data": { ... },   // 成功时返回的数据
  "message": "..."   // 失败时的错误信息
}
```

## 贡献指南

欢迎对本项目进行贡献！您可以通过以下方式参与：

1. 提交bug和功能需求
2. 提交代码改进和新功能实现
3. 完善文档和使用示例
4. 优化用户界面和交互体验

请确保您的代码遵循项目的编码规范，并通过测试。

## 许可证

本项目采用MIT许可证。详见 [LICENSE](LICENSE) 文件。

## 联系方式

如有问题或建议，请通过以下方式联系：

- 项目地址：[GitHub仓库](https://github.com/yourusername/CodeInsightX)
- 电子邮件：your.email@example.com

---

🔐 密码算法实现平台 - 让密码学变得简单易懂 