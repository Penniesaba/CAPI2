#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import base64
import binascii
from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15, DSS
from Crypto.Hash import SHA1, SHA256
import ecdsa
from ecdsa import SigningKey, VerifyingKey, NIST256p, SECP256k1
import hashlib

# 获取模块级别的日志记录器
logger = logging.getLogger(__name__)

class RSAEncryption:
    """
    RSA公钥加密算法实现
    
    包括加密、解密、签名和验证
    """
    
    @staticmethod
    def generate_key_pair(key_size=1024):
        """
        生成RSA密钥对
        
        参数:
            key_size: 密钥大小（比特）
        
        返回:
            包含公钥和私钥PEM格式的字典
        """
        try:
            # 生成RSA密钥对
            key = RSA.generate(key_size)
            
            # 导出公钥和私钥
            private_key = key.export_key().decode('utf-8')
            public_key = key.publickey().export_key().decode('utf-8')
            
            logger.info(f"已生成RSA-{key_size}密钥对")
            return {
                'private_key': private_key,
                'public_key': public_key
            }
        except Exception as e:
            logger.error(f"RSA密钥对生成失败: {str(e)}")
            raise
    
    @staticmethod
    def encrypt(plaintext, public_key):
        """
        RSA加密
        
        参数:
            plaintext: 明文字符串
            public_key: PEM格式的公钥
        
        返回:
            Base64编码的密文
        """
        try:
            # 导入公钥
            key = RSA.import_key(public_key)
            
            # 创建加密器
            cipher = PKCS1_OAEP.new(key)
            
            # 加密数据
            plaintext_bytes = plaintext.encode('utf-8')
            ciphertext = cipher.encrypt(plaintext_bytes)
            
            # Base64编码
            encoded = base64.b64encode(ciphertext).decode('utf-8')
            
            logger.info("RSA加密成功")
            return encoded
        except Exception as e:
            logger.error(f"RSA加密失败: {str(e)}")
            raise
    
    @staticmethod
    def decrypt(ciphertext, private_key):
        """
        RSA解密
        
        参数:
            ciphertext: Base64编码的密文
            private_key: PEM格式的私钥
        
        返回:
            解密后的明文字符串
        """
        try:
            # 导入私钥
            key = RSA.import_key(private_key)
            
            # 创建解密器
            cipher = PKCS1_OAEP.new(key)
            
            # Base64解码密文
            ciphertext_bytes = base64.b64decode(ciphertext)
            
            # 解密数据
            plaintext_bytes = cipher.decrypt(ciphertext_bytes)
            plaintext = plaintext_bytes.decode('utf-8')
            
            logger.info("RSA解密成功")
            return plaintext
        except Exception as e:
            logger.error(f"RSA解密失败: {str(e)}")
            raise
    
    @staticmethod
    def sign(message, private_key, hash_algorithm='SHA1'):
        """
        RSA签名
        
        参数:
            message: 要签名的消息（字符串）
            private_key: PEM格式的私钥
            hash_algorithm: 哈希算法（SHA1或SHA256）
        
        返回:
            Base64编码的签名
        """
        try:
            # 导入私钥
            key = RSA.import_key(private_key)
            
            # 计算消息哈希
            message_bytes = message.encode('utf-8')
            if hash_algorithm == 'SHA1':
                h = SHA1.new(message_bytes)
            elif hash_algorithm == 'SHA256':
                h = SHA256.new(message_bytes)
            else:
                raise ValueError(f"不支持的哈希算法: {hash_algorithm}")
            
            # 签名
            signature = pkcs1_15.new(key).sign(h)
            
            # Base64编码
            encoded = base64.b64encode(signature).decode('utf-8')
            
            logger.info(f"RSA-{hash_algorithm}签名成功")
            return encoded
        except Exception as e:
            logger.error(f"RSA签名失败: {str(e)}")
            raise
    
    @staticmethod
    def verify(message, signature, public_key, hash_algorithm='SHA1'):
        """
        RSA签名验证
        
        参数:
            message: 原始消息（字符串）
            signature: Base64编码的签名
            public_key: PEM格式的公钥
            hash_algorithm: 哈希算法（SHA1或SHA256）
        
        返回:
            验证结果（布尔值）
        """
        try:
            # 导入公钥
            key = RSA.import_key(public_key)
            
            # 计算消息哈希
            message_bytes = message.encode('utf-8')
            if hash_algorithm == 'SHA1':
                h = SHA1.new(message_bytes)
            elif hash_algorithm == 'SHA256':
                h = SHA256.new(message_bytes)
            else:
                raise ValueError(f"不支持的哈希算法: {hash_algorithm}")
            
            # Base64解码签名
            signature_bytes = base64.b64decode(signature)
            
            # 验证签名
            try:
                pkcs1_15.new(key).verify(h, signature_bytes)
                logger.info(f"RSA-{hash_algorithm}签名验证成功")
                return True
            except (ValueError, TypeError):
                logger.info(f"RSA-{hash_algorithm}签名验证失败")
                return False
        except Exception as e:
            logger.error(f"RSA签名验证失败: {str(e)}")
            raise


class ECCEncryption:
    """
    ECC椭圆曲线加密算法实现
    
    包括密钥生成、ECDSA签名和验证
    """
    
    @staticmethod
    def generate_key_pair(curve='P-256'):
        """
        生成ECC密钥对
        
        参数:
            curve: 椭圆曲线名称
        
        返回:
            包含公钥和私钥PEM格式的字典
        """
        try:
            # 生成ECC密钥对
            key = ECC.generate(curve=curve)
            
            # 导出公钥和私钥
            private_key = key.export_key(format='PEM')
            public_key = key.public_key().export_key(format='PEM')
            
            logger.info(f"已生成ECC密钥对（曲线：{curve}）")
            return {
                'private_key': private_key,
                'public_key': public_key
            }
        except Exception as e:
            logger.error(f"ECC密钥对生成失败: {str(e)}")
            raise
    
    @staticmethod
    def generate_ecdsa_key_pair(curve=NIST256p):
        """
        生成ECDSA密钥对
        
        参数:
            curve: 椭圆曲线
        
        返回:
            包含编码的公钥和私钥的字典
        """
        try:
            # 生成私钥
            sk = SigningKey.generate(curve=curve)
            
            # 获取公钥
            vk = sk.get_verifying_key()
            
            # 导出密钥（PEM格式）
            private_key = sk.to_pem().decode('utf-8')
            public_key = vk.to_pem().decode('utf-8')
            
            logger.info("已生成ECDSA密钥对")
            return {
                'private_key': private_key,
                'public_key': public_key
            }
        except Exception as e:
            logger.error(f"ECDSA密钥对生成失败: {str(e)}")
            raise
    
    @staticmethod
    def ecdsa_sign(message, private_key):
        """
        ECDSA签名
        
        参数:
            message: 要签名的消息（字符串）
            private_key: PEM格式的私钥
        
        返回:
            十六进制编码的签名
        """
        try:
            # 导入私钥
            sk = SigningKey.from_pem(private_key)
            
            # 计算消息哈希
            message_hash = hashlib.sha256(message.encode('utf-8')).digest()
            
            # 签名
            signature = sk.sign_digest(message_hash)
            
            # 十六进制编码
            signature_hex = binascii.hexlify(signature).decode('utf-8')
            
            logger.info("ECDSA签名成功")
            return signature_hex
        except Exception as e:
            logger.error(f"ECDSA签名失败: {str(e)}")
            raise
    
    @staticmethod
    def ecdsa_verify(message, signature, public_key):
        """
        ECDSA签名验证
        
        参数:
            message: 原始消息（字符串）
            signature: 十六进制编码的签名
            public_key: PEM格式的公钥
        
        返回:
            验证结果（布尔值）
        """
        try:
            # 导入公钥
            vk = VerifyingKey.from_pem(public_key)
            
            # 计算消息哈希
            message_hash = hashlib.sha256(message.encode('utf-8')).digest()
            
            # 十六进制解码签名
            signature_bytes = binascii.unhexlify(signature)
            
            # 验证签名
            try:
                result = vk.verify_digest(signature_bytes, message_hash)
                logger.info("ECDSA签名验证成功")
                return True
            except ecdsa.BadSignatureError:
                logger.info("ECDSA签名验证失败")
                return False
        except Exception as e:
            logger.error(f"ECDSA签名验证失败: {str(e)}")
            raise
    
    @staticmethod
    def ecdsa_sign_with_deterministic(message, private_key):
        """
        确定性ECDSA签名（使用RFC 6979）
        
        参数:
            message: 要签名的消息（字符串）
            private_key: PEM格式的私钥
        
        返回:
            十六进制编码的签名
        """
        try:
            # 导入私钥
            sk = SigningKey.from_pem(private_key)
            
            # 签名（使用RFC 6979确定性k值）
            message_bytes = message.encode('utf-8')
            signature = sk.sign(message_bytes, hashfunc=hashlib.sha256, sigencode=ecdsa.util.sigencode_der)
            
            # 十六进制编码
            signature_hex = binascii.hexlify(signature).decode('utf-8')
            
            logger.info("确定性ECDSA签名成功")
            return signature_hex
        except Exception as e:
            logger.error(f"确定性ECDSA签名失败: {str(e)}")
            raise
    
    @staticmethod
    def ecdsa_verify_with_deterministic(message, signature, public_key):
        """
        确定性ECDSA签名验证
        
        参数:
            message: 原始消息（字符串）
            signature: 十六进制编码的签名
            public_key: PEM格式的公钥
        
        返回:
            验证结果（布尔值）
        """
        try:
            # 导入公钥
            vk = VerifyingKey.from_pem(public_key)
            
            # 十六进制解码签名
            signature_bytes = binascii.unhexlify(signature)
            
            # 验证签名
            try:
                result = vk.verify(signature_bytes, message.encode('utf-8'), hashfunc=hashlib.sha256, sigdecode=ecdsa.util.sigdecode_der)
                logger.info("确定性ECDSA签名验证成功")
                return True
            except ecdsa.BadSignatureError:
                logger.info("确定性ECDSA签名验证失败")
                return False
        except Exception as e:
            logger.error(f"确定性ECDSA签名验证失败: {str(e)}")
            raise 