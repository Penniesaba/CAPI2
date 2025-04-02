#!/usr/bin/env python
# -*- coding: utf-8 -*-

from flask import Blueprint, request, jsonify, current_app
import logging
import json
import traceback
from app.crypto.symmetric import AES, SM4, RC6
from app.crypto.hash import HashFunctions, HMACFunctions, KeyDerivation, HashAlgorithms
from app.crypto.encoding import Encoding
from app.crypto.asymmetric import RSAEncryption, ECCEncryption

# 创建蓝图
api_bp = Blueprint('api', __name__)

# 获取日志记录器
logger = logging.getLogger(__name__)

# 辅助函数：统一API响应格式
def api_response(success, data=None, message="", status_code=200):
    """
    统一API响应格式
    
    参数:
        success: 是否成功
        data: 响应数据
        message: 响应消息
        status_code: HTTP状态码
    
    返回:
        JSON响应
    """
    response = {
        "success": success,
        "data": data,
        "message": message
    }
    return jsonify(response), status_code

# 错误处理装饰器
def handle_errors(func):
    """
    API错误处理装饰器
    
    捕获并处理异常，返回统一格式的错误响应
    """
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            error_message = str(e)
            logger.error(f"API错误: {error_message}")
            logger.error(traceback.format_exc())
            return api_response(False, None, error_message, 500)
    wrapper.__name__ = func.__name__
    return wrapper

# API状态检查端点
@api_bp.route('/status', methods=['GET'])
@handle_errors
def status():
    """API状态检查端点"""
    logger.info("API状态检查")
    return api_response(True, {"status": "running"}, "API服务正常运行")

# —————————————— 对称加密算法 API ——————————————

# AES密钥生成
@api_bp.route('/symmetric/aes/generate-key', methods=['POST'])
@handle_errors
def aes_generate_key():
    """生成AES密钥"""
    data = request.get_json()
    key_size = data.get('key_size', 256)
    
    # 验证密钥大小
    if key_size not in [128, 192, 256]:
        return api_response(False, None, "密钥大小必须是128、192或256位", 400)
    
    key = AES.generate_key(key_size)
    logger.info(f"生成AES-{key_size}密钥")
    
    return api_response(True, {"key": key}, "AES密钥生成成功")

# AES加密
@api_bp.route('/symmetric/aes/encrypt', methods=['POST'])
@handle_errors
def aes_encrypt():
    """AES加密"""
    data = request.get_json()
    plaintext = data.get('plaintext', '')
    key = data.get('key', '')
    mode = data.get('mode', 'CBC')
    iv = data.get('iv', None)
    
    # 验证输入
    if not plaintext or not key:
        return api_response(False, None, "明文和密钥不能为空", 400)
    
    # 验证模式
    if mode not in ['ECB', 'CBC', 'CFB', 'OFB', 'CTR']:
        return api_response(False, None, "不支持的加密模式", 400)
    
    # 执行加密
    ciphertext = AES.encrypt(plaintext, key, mode, iv)
    logger.info(f"执行AES-{mode}加密")
    
    return api_response(True, {"ciphertext": ciphertext}, "AES加密成功")

# AES解密
@api_bp.route('/symmetric/aes/decrypt', methods=['POST'])
@handle_errors
def aes_decrypt():
    """AES解密"""
    data = request.get_json()
    ciphertext = data.get('ciphertext', '')
    key = data.get('key', '')
    mode = data.get('mode', 'CBC')
    iv = data.get('iv', None)
    
    # 验证输入
    if not ciphertext or not key:
        return api_response(False, None, "密文和密钥不能为空", 400)
    
    # 验证模式
    if mode not in ['ECB', 'CBC', 'CFB', 'OFB', 'CTR']:
        return api_response(False, None, "不支持的加密模式", 400)
    
    # 执行解密
    plaintext = AES.decrypt(ciphertext, key, mode, iv)
    logger.info(f"执行AES-{mode}解密")
    
    return api_response(True, {"plaintext": plaintext}, "AES解密成功")

# SM4密钥生成
@api_bp.route('/symmetric/sm4/generate-key', methods=['POST'])
@handle_errors
def sm4_generate_key():
    """生成SM4密钥"""
    key = SM4.generate_key()
    logger.info("生成SM4密钥")
    
    return api_response(True, {"key": key}, "SM4密钥生成成功")

# SM4加密
@api_bp.route('/symmetric/sm4/encrypt', methods=['POST'])
@handle_errors
def sm4_encrypt():
    """SM4加密"""
    data = request.get_json()
    plaintext = data.get('plaintext', '')
    key = data.get('key', '')
    mode = data.get('mode', 'ECB')
    iv = data.get('iv', None)
    
    # 验证输入
    if not plaintext or not key:
        return api_response(False, None, "明文和密钥不能为空", 400)
    
    # 验证模式
    if mode not in ['ECB', 'CBC']:
        return api_response(False, None, "不支持的加密模式", 400)
    
    # 执行加密
    ciphertext = SM4.encrypt(plaintext, key, mode, iv)
    logger.info(f"执行SM4-{mode}加密")
    
    return api_response(True, {"ciphertext": ciphertext}, "SM4加密成功")

# SM4解密
@api_bp.route('/symmetric/sm4/decrypt', methods=['POST'])
@handle_errors
def sm4_decrypt():
    """SM4解密"""
    data = request.get_json()
    ciphertext = data.get('ciphertext', '')
    key = data.get('key', '')
    mode = data.get('mode', 'ECB')
    iv = data.get('iv', None)
    
    # 验证输入
    if not ciphertext or not key:
        return api_response(False, None, "密文和密钥不能为空", 400)
    
    # 验证模式
    if mode not in ['ECB', 'CBC']:
        return api_response(False, None, "不支持的加密模式", 400)
    
    # 执行解密
    plaintext = SM4.decrypt(ciphertext, key, mode, iv)
    logger.info(f"执行SM4-{mode}解密")
    
    return api_response(True, {"plaintext": plaintext}, "SM4解密成功")

# RC6密钥生成
@api_bp.route('/symmetric/rc6/generate-key', methods=['POST'])
@handle_errors
def rc6_generate_key():
    """生成RC6密钥"""
    key = RC6.generate_key()
    logger.info("生成RC6密钥")
    
    return api_response(True, {"key": key}, "RC6密钥生成成功")

# RC6加密
@api_bp.route('/symmetric/rc6/encrypt', methods=['POST'])
@handle_errors
def rc6_encrypt():
    """RC6加密"""
    data = request.get_json()
    plaintext = data.get('plaintext', '')
    key = data.get('key', '')
    
    # 验证输入
    if not plaintext or not key:
        return api_response(False, None, "明文和密钥不能为空", 400)
    
    # 执行加密
    ciphertext = RC6.encrypt(plaintext, key)
    logger.info("执行RC6加密")
    
    return api_response(True, {"ciphertext": ciphertext}, "RC6加密成功")

# RC6解密
@api_bp.route('/symmetric/rc6/decrypt', methods=['POST'])
@handle_errors
def rc6_decrypt():
    """RC6解密"""
    data = request.get_json()
    ciphertext = data.get('ciphertext', '')
    key = data.get('key', '')
    
    # 验证输入
    if not ciphertext or not key:
        return api_response(False, None, "密文和密钥不能为空", 400)
    
    # 执行解密
    plaintext = RC6.decrypt(ciphertext, key)
    logger.info("执行RC6解密")
    
    return api_response(True, {"plaintext": plaintext}, "RC6解密成功")

# —————————————— 哈希算法 API ——————————————

# SHA1哈希
@api_bp.route('/hash/sha1', methods=['POST'])
@handle_errors
def hash_sha1():
    """SHA1哈希"""
    data = request.get_json()
    message = data.get('message', '')
    
    # 验证输入
    if not message:
        return api_response(False, None, "消息不能为空", 400)
    
    # 执行哈希
    hash_value = HashAlgorithms.sha1(message)
    logger.info("执行SHA1哈希")
    
    return api_response(True, {"hash": hash_value}, "SHA1哈希计算成功")

# SHA256哈希
@api_bp.route('/hash/sha256', methods=['POST'])
@handle_errors
def hash_sha256():
    """SHA256哈希"""
    data = request.get_json()
    message = data.get('message', '')
    
    # 验证输入
    if not message:
        return api_response(False, None, "消息不能为空", 400)
    
    # 执行哈希
    hash_value = HashAlgorithms.sha256(message)
    logger.info("执行SHA256哈希")
    
    return api_response(True, {"hash": hash_value}, "SHA256哈希计算成功")

# SHA3-256哈希
@api_bp.route('/hash/sha3-256', methods=['POST'])
@handle_errors
def hash_sha3_256():
    """SHA3-256哈希"""
    data = request.get_json()
    message = data.get('message', '')
    
    # 验证输入
    if not message:
        return api_response(False, None, "消息不能为空", 400)
    
    # 执行哈希
    hash_value = HashAlgorithms.sha3_256(message)
    logger.info("执行SHA3-256哈希")
    
    return api_response(True, {"hash": hash_value}, "SHA3-256哈希计算成功")

# SHA3-512哈希
@api_bp.route('/hash/sha3-512', methods=['POST'])
@handle_errors
def hash_sha3_512():
    """SHA3-512哈希"""
    data = request.get_json()
    message = data.get('message', '')
    
    # 验证输入
    if not message:
        return api_response(False, None, "消息不能为空", 400)
    
    # 执行哈希
    hash_value = HashAlgorithms.sha3_512(message)
    logger.info("执行SHA3-512哈希")
    
    return api_response(True, {"hash": hash_value}, "SHA3-512哈希计算成功")

# RIPEMD160哈希
@api_bp.route('/hash/ripemd160', methods=['POST'])
@handle_errors
def hash_ripemd160():
    """RIPEMD160哈希"""
    data = request.get_json()
    message = data.get('message', '')
    
    # 验证输入
    if not message:
        return api_response(False, None, "消息不能为空", 400)
    
    # 执行哈希
    hash_value = HashAlgorithms.ripemd160(message)
    logger.info("执行RIPEMD160哈希")
    
    return api_response(True, {"hash": hash_value}, "RIPEMD160哈希计算成功")

# HMAC-SHA1
@api_bp.route('/hash/hmac-sha1', methods=['POST'])
@handle_errors
def hmac_sha1():
    """HMAC-SHA1"""
    data = request.get_json()
    message = data.get('message', '')
    key = data.get('key', '')
    
    # 验证输入
    if not message or not key:
        return api_response(False, None, "消息和密钥不能为空", 400)
    
    # 执行HMAC
    hmac_value = HashAlgorithms.hmac_sha1(key, message)
    logger.info("执行HMAC-SHA1")
    
    return api_response(True, {"hmac": hmac_value}, "HMAC-SHA1计算成功")

# HMAC-SHA256
@api_bp.route('/hash/hmac-sha256', methods=['POST'])
@handle_errors
def hmac_sha256():
    """HMAC-SHA256"""
    data = request.get_json()
    message = data.get('message', '')
    key = data.get('key', '')
    
    # 验证输入
    if not message or not key:
        return api_response(False, None, "消息和密钥不能为空", 400)
    
    # 执行HMAC
    hmac_value = HashAlgorithms.hmac_sha256(key, message)
    logger.info("执行HMAC-SHA256")
    
    return api_response(True, {"hmac": hmac_value}, "HMAC-SHA256计算成功")

# 生成盐值
@api_bp.route('/hash/generate-salt', methods=['POST'])
@handle_errors
def generate_salt():
    """生成盐值"""
    data = request.get_json()
    length = data.get('length', 16)
    
    # 验证长度
    if length < 8 or length > 32:
        return api_response(False, None, "盐值长度应在8到32字节之间", 400)
    
    # 生成盐值
    salt = KeyDerivation.generate_salt(length)
    logger.info(f"生成{length}字节盐值")
    
    return api_response(True, {"salt": salt}, "盐值生成成功")

# PBKDF2
@api_bp.route('/hash/pbkdf2', methods=['POST'])
@handle_errors
def pbkdf2():
    """PBKDF2密钥派生"""
    data = request.get_json()
    password = data.get('password', '')
    salt = data.get('salt', '')
    iterations = data.get('iterations', 1000)
    dklen = data.get('dklen', 32)
    
    # 验证输入
    if not password or not salt:
        return api_response(False, None, "密码和盐值不能为空", 400)
    
    # 验证迭代次数和密钥长度
    if iterations < 1000:
        return api_response(False, None, "迭代次数应至少为1000", 400)
    
    if dklen < 16 or dklen > 64:
        return api_response(False, None, "派生密钥长度应在16到64字节之间", 400)
    
    # 执行PBKDF2
    derived_key = KeyDerivation.pbkdf2(password, salt, iterations, dklen)
    logger.info(f"执行PBKDF2（迭代{iterations}次，密钥长度{dklen}字节）")
    
    return api_response(True, {"derived_key": derived_key}, "PBKDF2密钥派生成功")

# PBKDF2验证
@api_bp.route('/hash/pbkdf2-verify', methods=['POST'])
@handle_errors
def pbkdf2_verify():
    """PBKDF2密钥验证"""
    data = request.get_json()
    password = data.get('password', '')
    derived_key = data.get('derived_key', '')
    salt = data.get('salt', '')
    iterations = data.get('iterations', 1000)
    dklen = data.get('dklen', 32)
    
    # 验证输入
    if not password or not derived_key or not salt:
        return api_response(False, None, "密码、派生密钥和盐值不能为空", 400)
    
    # 执行PBKDF2验证
    result = KeyDerivation.pbkdf2_verify(password, derived_key, salt, iterations, dklen)
    logger.info(f"执行PBKDF2验证（迭代{iterations}次，密钥长度{dklen}字节）")
    
    return api_response(True, {"verified": result}, "PBKDF2密钥验证完成")

# —————————————— 编码算法 API ——————————————

# Base64编码
@api_bp.route('/encoding/base64-encode', methods=['POST'])
@handle_errors
def base64_encode():
    """Base64编码"""
    data = request.get_json()
    text = data.get('text', '')
    
    # 验证输入
    if not text:
        return api_response(False, None, "文本不能为空", 400)
    
    # 执行编码
    encoded = Encoding.base64_encode(text)
    logger.info("执行Base64编码")
    
    return api_response(True, {"encoded": encoded}, "Base64编码成功")

# Base64解码
@api_bp.route('/encoding/base64-decode', methods=['POST'])
@handle_errors
def base64_decode():
    """Base64解码"""
    data = request.get_json()
    encoded = data.get('encoded', '')
    
    # 验证输入
    if not encoded:
        return api_response(False, None, "编码后的文本不能为空", 400)
    
    # 执行解码
    text = Encoding.base64_decode(encoded)
    logger.info("执行Base64解码")
    
    return api_response(True, {"text": text}, "Base64解码成功")

# URL安全的Base64编码
@api_bp.route('/encoding/url-safe-base64-encode', methods=['POST'])
@handle_errors
def url_safe_base64_encode():
    """URL安全的Base64编码"""
    data = request.get_json()
    text = data.get('text', '')
    
    # 验证输入
    if not text:
        return api_response(False, None, "文本不能为空", 400)
    
    # 执行编码
    encoded = Encoding.url_safe_base64_encode(text)
    logger.info("执行URL安全的Base64编码")
    
    return api_response(True, {"encoded": encoded}, "URL安全的Base64编码成功")

# URL安全的Base64解码
@api_bp.route('/encoding/url-safe-base64-decode', methods=['POST'])
@handle_errors
def url_safe_base64_decode():
    """URL安全的Base64解码"""
    data = request.get_json()
    encoded = data.get('encoded', '')
    
    # 验证输入
    if not encoded:
        return api_response(False, None, "编码后的文本不能为空", 400)
    
    # 执行解码
    text = Encoding.url_safe_base64_decode(encoded)
    logger.info("执行URL安全的Base64解码")
    
    return api_response(True, {"text": text}, "URL安全的Base64解码成功")

# UTF-8编码
@api_bp.route('/encoding/utf8-encode', methods=['POST'])
@handle_errors
def utf8_encode():
    """UTF-8编码"""
    data = request.get_json()
    text = data.get('text', '')
    
    # 验证输入
    if not text:
        return api_response(False, None, "文本不能为空", 400)
    
    # 执行编码
    encoded = Encoding.utf8_encode(text)
    logger.info("执行UTF-8编码")
    
    return api_response(True, {"encoded": encoded}, "UTF-8编码成功")

# UTF-8解码
@api_bp.route('/encoding/utf8-decode', methods=['POST'])
@handle_errors
def utf8_decode():
    """UTF-8解码"""
    data = request.get_json()
    encoded = data.get('encoded', '')
    
    # 验证输入
    if not encoded:
        return api_response(False, None, "编码后的文本不能为空", 400)
    
    # 执行解码
    text = Encoding.utf8_decode(encoded)
    logger.info("执行UTF-8解码")
    
    return api_response(True, {"text": text}, "UTF-8解码成功")

# 十六进制编码
@api_bp.route('/encoding/hex-encode', methods=['POST'])
@handle_errors
def hex_encode():
    """十六进制编码"""
    data = request.get_json()
    text = data.get('text', '')
    
    # 验证输入
    if not text:
        return api_response(False, None, "文本不能为空", 400)
    
    # 执行编码
    encoded = Encoding.hex_encode(text)
    logger.info("执行十六进制编码")
    
    return api_response(True, {"encoded": encoded}, "十六进制编码成功")

# 十六进制解码
@api_bp.route('/encoding/hex-decode', methods=['POST'])
@handle_errors
def hex_decode():
    """十六进制解码"""
    data = request.get_json()
    encoded = data.get('encoded', '')
    
    # 验证输入
    if not encoded:
        return api_response(False, None, "编码后的文本不能为空", 400)
    
    # 执行解码
    text = Encoding.hex_decode(encoded)
    logger.info("执行十六进制解码")
    
    return api_response(True, {"text": text}, "十六进制解码成功")

# —————————————— 非对称加密算法 API ——————————————

# 生成RSA密钥对
@api_bp.route('/asymmetric/rsa/generate-key-pair', methods=['POST'])
@handle_errors
def rsa_generate_key_pair():
    """生成RSA密钥对"""
    data = request.get_json()
    key_size = data.get('key_size', 1024)
    
    # 验证密钥大小
    if key_size not in [1024, 2048, 3072, 4096]:
        return api_response(False, None, "密钥大小必须是1024、2048、3072或4096位", 400)
    
    # 生成密钥对
    key_pair = RSAEncryption.generate_key_pair(key_size)
    logger.info(f"生成RSA-{key_size}密钥对")
    
    return api_response(True, key_pair, "RSA密钥对生成成功")

# RSA加密
@api_bp.route('/asymmetric/rsa/encrypt', methods=['POST'])
@handle_errors
def rsa_encrypt():
    """RSA加密"""
    data = request.get_json()
    plaintext = data.get('plaintext', '')
    public_key = data.get('public_key', '')
    
    # 验证输入
    if not plaintext or not public_key:
        return api_response(False, None, "明文和公钥不能为空", 400)
    
    # 执行加密
    ciphertext = RSAEncryption.encrypt(plaintext, public_key)
    logger.info("执行RSA加密")
    
    return api_response(True, {"ciphertext": ciphertext}, "RSA加密成功")

# RSA解密
@api_bp.route('/asymmetric/rsa/decrypt', methods=['POST'])
@handle_errors
def rsa_decrypt():
    """RSA解密"""
    data = request.get_json()
    ciphertext = data.get('ciphertext', '')
    private_key = data.get('private_key', '')
    
    # 验证输入
    if not ciphertext or not private_key:
        return api_response(False, None, "密文和私钥不能为空", 400)
    
    # 执行解密
    plaintext = RSAEncryption.decrypt(ciphertext, private_key)
    logger.info("执行RSA解密")
    
    return api_response(True, {"plaintext": plaintext}, "RSA解密成功")

# RSA签名
@api_bp.route('/asymmetric/rsa/sign', methods=['POST'])
@handle_errors
def rsa_sign():
    """RSA签名"""
    data = request.get_json()
    message = data.get('message', '')
    private_key = data.get('private_key', '')
    hash_algorithm = data.get('hash_algorithm', 'SHA1')
    
    # 验证输入
    if not message or not private_key:
        return api_response(False, None, "消息和私钥不能为空", 400)
    
    # 验证哈希算法
    if hash_algorithm not in ['SHA1', 'SHA256']:
        return api_response(False, None, "不支持的哈希算法", 400)
    
    # 执行签名
    signature = RSAEncryption.sign(message, private_key, hash_algorithm)
    logger.info(f"执行RSA-{hash_algorithm}签名")
    
    return api_response(True, {"signature": signature}, "RSA签名成功")

# RSA签名验证
@api_bp.route('/asymmetric/rsa/verify', methods=['POST'])
@handle_errors
def rsa_verify():
    """RSA签名验证"""
    data = request.get_json()
    message = data.get('message', '')
    signature = data.get('signature', '')
    public_key = data.get('public_key', '')
    hash_algorithm = data.get('hash_algorithm', 'SHA1')
    
    # 验证输入
    if not message or not signature or not public_key:
        return api_response(False, None, "消息、签名和公钥不能为空", 400)
    
    # 验证哈希算法
    if hash_algorithm not in ['SHA1', 'SHA256']:
        return api_response(False, None, "不支持的哈希算法", 400)
    
    # 执行验证
    result = RSAEncryption.verify(message, signature, public_key, hash_algorithm)
    logger.info(f"执行RSA-{hash_algorithm}签名验证")
    
    return api_response(True, {"verified": result}, "RSA签名验证完成")

# 生成ECC密钥对
@api_bp.route('/asymmetric/ecc/generate-key-pair', methods=['POST'])
@handle_errors
def ecc_generate_key_pair():
    """生成ECC密钥对"""
    data = request.get_json()
    curve = data.get('curve', 'P-256')
    
    # 验证曲线
    if curve not in ['P-256', 'P-384', 'P-521']:
        return api_response(False, None, "不支持的椭圆曲线", 400)
    
    # 生成密钥对
    key_pair = ECCEncryption.generate_key_pair(curve)
    logger.info(f"生成ECC密钥对（曲线：{curve}）")
    
    return api_response(True, key_pair, "ECC密钥对生成成功")

# 生成ECDSA密钥对
@api_bp.route('/asymmetric/ecdsa/generate-key-pair', methods=['POST'])
@handle_errors
def ecdsa_generate_key_pair():
    """生成ECDSA密钥对"""
    # 生成密钥对
    key_pair = ECCEncryption.generate_ecdsa_key_pair()
    logger.info("生成ECDSA密钥对")
    
    return api_response(True, key_pair, "ECDSA密钥对生成成功")

# ECDSA签名
@api_bp.route('/asymmetric/ecdsa/sign', methods=['POST'])
@handle_errors
def ecdsa_sign():
    """ECDSA签名"""
    data = request.get_json()
    message = data.get('message', '')
    private_key = data.get('private_key', '')
    deterministic = data.get('deterministic', False)
    
    # 验证输入
    if not message or not private_key:
        return api_response(False, None, "消息和私钥不能为空", 400)
    
    # 执行签名
    if deterministic:
        signature = ECCEncryption.ecdsa_sign_with_deterministic(message, private_key)
        logger.info("执行确定性ECDSA签名")
    else:
        signature = ECCEncryption.ecdsa_sign(message, private_key)
        logger.info("执行ECDSA签名")
    
    return api_response(True, {"signature": signature}, "ECDSA签名成功")

# ECDSA签名验证
@api_bp.route('/asymmetric/ecdsa/verify', methods=['POST'])
@handle_errors
def ecdsa_verify():
    """ECDSA签名验证"""
    data = request.get_json()
    message = data.get('message', '')
    signature = data.get('signature', '')
    public_key = data.get('public_key', '')
    deterministic = data.get('deterministic', False)
    
    # 验证输入
    if not message or not signature or not public_key:
        return api_response(False, None, "消息、签名和公钥不能为空", 400)
    
    # 执行验证
    if deterministic:
        result = ECCEncryption.ecdsa_verify_with_deterministic(message, signature, public_key)
        logger.info("执行确定性ECDSA签名验证")
    else:
        result = ECCEncryption.ecdsa_verify(message, signature, public_key)
        logger.info("执行ECDSA签名验证")
    
    return api_response(True, {"verified": result}, "ECDSA签名验证完成") 