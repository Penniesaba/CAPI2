#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import binascii
import os
import hashlib
import hmac
from Crypto.Hash import SHA1, SHA256, SHA3_256, SHA3_512, RIPEMD160
from Crypto.Protocol.KDF import PBKDF2

# 获取模块级别的日志记录器
logger = logging.getLogger(__name__)

class HashFunctions:
    """
    哈希算法实现类
    
    包括SHA1、SHA256、SHA3、RIPEMD160
    """
    
    @staticmethod
    def sha1(data):
        """
        SHA1哈希函数
        
        参数:
            data: 要哈希的数据（字符串）
        
        返回:
            十六进制字符串表示的哈希值
        """
        try:
            # 使用hashlib标准库实现
            sha1_hash = hashlib.sha1(data.encode('utf-8')).hexdigest()
            logger.info("SHA1哈希计算成功")
            return sha1_hash
        except Exception as e:
            logger.error(f"SHA1哈希计算失败: {str(e)}")
            raise
    
    @staticmethod
    def sha256(data):
        """
        SHA256哈希函数
        
        参数:
            data: 要哈希的数据（字符串）
        
        返回:
            十六进制字符串表示的哈希值
        """
        try:
            # 使用hashlib标准库实现
            sha256_hash = hashlib.sha256(data.encode('utf-8')).hexdigest()
            logger.info("SHA256哈希计算成功")
            return sha256_hash
        except Exception as e:
            logger.error(f"SHA256哈希计算失败: {str(e)}")
            raise
    
    @staticmethod
    def sha3_256(data):
        """
        SHA3-256哈希函数
        
        参数:
            data: 要哈希的数据（字符串）
        
        返回:
            十六进制字符串表示的哈希值
        """
        try:
            # 使用hashlib标准库实现
            sha3_hash = hashlib.sha3_256(data.encode('utf-8')).hexdigest()
            logger.info("SHA3-256哈希计算成功")
            return sha3_hash
        except Exception as e:
            logger.error(f"SHA3-256哈希计算失败: {str(e)}")
            raise
    
    @staticmethod
    def sha3_512(data):
        """
        SHA3-512哈希函数
        
        参数:
            data: 要哈希的数据（字符串）
        
        返回:
            十六进制字符串表示的哈希值
        """
        try:
            # 使用hashlib标准库实现
            sha3_hash = hashlib.sha3_512(data.encode('utf-8')).hexdigest()
            logger.info("SHA3-512哈希计算成功")
            return sha3_hash
        except Exception as e:
            logger.error(f"SHA3-512哈希计算失败: {str(e)}")
            raise
    
    @staticmethod
    def ripemd160(data):
        """
        RIPEMD160哈希函数
        
        参数:
            data: 要哈希的数据（字符串）
        
        返回:
            十六进制字符串表示的哈希值
        """
        try:
            # 使用pycryptodome实现
            h = RIPEMD160.new()
            h.update(data.encode('utf-8'))
            ripemd160_hash = h.hexdigest()
            logger.info("RIPEMD160哈希计算成功")
            return ripemd160_hash
        except Exception as e:
            logger.error(f"RIPEMD160哈希计算失败: {str(e)}")
            raise


class HMACFunctions:
    """
    HMAC算法实现类
    
    包括HMacSHA1、HmacSHA256
    """
    
    @staticmethod
    def hmac_sha1(key, data):
        """
        HMAC-SHA1消息认证码
        
        参数:
            key: 密钥（字符串）
            data: 要认证的数据（字符串）
        
        返回:
            十六进制字符串表示的HMAC值
        """
        try:
            # 转换为字节
            key_bytes = key.encode('utf-8')
            data_bytes = data.encode('utf-8')
            
            # 计算HMAC
            h = hmac.new(key_bytes, data_bytes, hashlib.sha1)
            hmac_value = h.hexdigest()
            logger.info("HMAC-SHA1计算成功")
            return hmac_value
        except Exception as e:
            logger.error(f"HMAC-SHA1计算失败: {str(e)}")
            raise
    
    @staticmethod
    def hmac_sha256(key, data):
        """
        HMAC-SHA256消息认证码
        
        参数:
            key: 密钥（字符串）
            data: 要认证的数据（字符串）
        
        返回:
            十六进制字符串表示的HMAC值
        """
        try:
            # 转换为字节
            key_bytes = key.encode('utf-8')
            data_bytes = data.encode('utf-8')
            
            # 计算HMAC
            h = hmac.new(key_bytes, data_bytes, hashlib.sha256)
            hmac_value = h.hexdigest()
            logger.info("HMAC-SHA256计算成功")
            return hmac_value
        except Exception as e:
            logger.error(f"HMAC-SHA256计算失败: {str(e)}")
            raise


class KeyDerivation:
    """
    密钥派生函数类
    
    包括PBKDF2算法
    """
    
    @staticmethod
    def generate_salt(length=16):
        """
        生成随机盐值
        
        参数:
            length: 盐值长度（字节）
        
        返回:
            十六进制字符串表示的盐值
        """
        try:
            salt = os.urandom(length)
            salt_hex = binascii.hexlify(salt).decode('utf-8')
            logger.info(f"已生成{length}字节盐值")
            return salt_hex
        except Exception as e:
            logger.error(f"盐值生成失败: {str(e)}")
            raise
    
    @staticmethod
    def pbkdf2(password, salt, iterations=1000, dklen=32, hash_module=SHA256):
        """
        PBKDF2密钥派生
        
        参数:
            password: 密码（字符串）
            salt: 盐值（十六进制字符串）
            iterations: 迭代次数
            dklen: 派生密钥长度（字节）
            hash_module: 哈希模块（默认SHA256）
        
        返回:
            十六进制字符串表示的派生密钥
        """
        try:
            # 转换为字节
            password_bytes = password.encode('utf-8')
            salt_bytes = bytes.fromhex(salt)
            
            # 派生密钥
            key = PBKDF2(password_bytes, salt_bytes, dklen=dklen, count=iterations, hmac_hash_module=hash_module)
            key_hex = binascii.hexlify(key).decode('utf-8')
            
            logger.info(f"PBKDF2密钥派生成功（迭代{iterations}次，密钥长度{dklen}字节）")
            return key_hex
        except Exception as e:
            logger.error(f"PBKDF2密钥派生失败: {str(e)}")
            raise
    
    @staticmethod
    def pbkdf2_verify(password, derived_key, salt, iterations=1000, dklen=32, hash_module=SHA256):
        """
        验证PBKDF2派生密钥
        
        参数:
            password: 密码（字符串）
            derived_key: 已派生的密钥（十六进制字符串）
            salt: 盐值（十六进制字符串）
            iterations: 迭代次数
            dklen: 派生密钥长度（字节）
            hash_module: 哈希模块（默认SHA256）
        
        返回:
            验证结果（布尔值）
        """
        try:
            # 转换为字节
            password_bytes = password.encode('utf-8')
            salt_bytes = bytes.fromhex(salt)
            derived_key_bytes = bytes.fromhex(derived_key)
            
            # 派生密钥
            key = PBKDF2(password_bytes, salt_bytes, dklen=dklen, count=iterations, hmac_hash_module=hash_module)
            
            # 比较派生密钥
            result = key == derived_key_bytes
            
            if result:
                logger.info("PBKDF2密钥验证成功")
            else:
                logger.info("PBKDF2密钥验证失败")
            
            return result
        except Exception as e:
            logger.error(f"PBKDF2密钥验证失败: {str(e)}")
            raise 