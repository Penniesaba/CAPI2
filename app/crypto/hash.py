#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import binascii
import os
import hashlib
import hmac
from Crypto.Hash import SHA1, SHA256, SHA3_256, SHA3_512, RIPEMD160, HMAC
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import base64

# 获取模块级别的日志记录器
logger = logging.getLogger(__name__)

class HashAlgorithms:
    """
    哈希算法实现类
    包含SHA1, SHA256, SHA3-256, SHA3-512, RIPEMD160, HMAC和PBKDF2算法
    """
    
    @staticmethod
    def sha1(message):
        """
        计算SHA1哈希值
        
        Args:
            message (str): 需要计算哈希的消息
            
        Returns:
            str: 十六进制格式的哈希值
        """
        hash_obj = SHA1.new()
        hash_obj.update(message.encode('utf-8'))
        return hash_obj.hexdigest()
    
    @staticmethod
    def sha256(message):
        """
        计算SHA256哈希值
        
        Args:
            message (str): 需要计算哈希的消息
            
        Returns:
            str: 十六进制格式的哈希值
        """
        hash_obj = SHA256.new()
        hash_obj.update(message.encode('utf-8'))
        return hash_obj.hexdigest()
    
    @staticmethod
    def sha3_256(message):
        """
        计算SHA3-256哈希值
        
        Args:
            message (str): 需要计算哈希的消息
            
        Returns:
            str: 十六进制格式的哈希值
        """
        hash_obj = SHA3_256.new()
        hash_obj.update(message.encode('utf-8'))
        return hash_obj.hexdigest()
    
    @staticmethod
    def sha3_512(message):
        """
        计算SHA3-512哈希值
        
        Args:
            message (str): 需要计算哈希的消息
            
        Returns:
            str: 十六进制格式的哈希值
        """
        hash_obj = SHA3_512.new()
        hash_obj.update(message.encode('utf-8'))
        return hash_obj.hexdigest()
    
    @staticmethod
    def ripemd160(message):
        """
        计算RIPEMD160哈希值
        
        Args:
            message (str): 需要计算哈希的消息
            
        Returns:
            str: 十六进制格式的哈希值
        """
        hash_obj = RIPEMD160.new()
        hash_obj.update(message.encode('utf-8'))
        return hash_obj.hexdigest()
    
    @staticmethod
    def hmac_sha1(message, key):
        """
        计算HMAC-SHA1值
        
        Args:
            message (str): 需要计算HMAC的消息
            key (str): 密钥
            
        Returns:
            str: 十六进制格式的HMAC值
        """
        hmac_obj = HMAC.new(key.encode('utf-8'), digestmod=SHA1)
        hmac_obj.update(message.encode('utf-8'))
        return hmac_obj.hexdigest()
    
    @staticmethod
    def hmac_sha256(message, key):
        """
        计算HMAC-SHA256值
        
        Args:
            message (str): 需要计算HMAC的消息
            key (str): 密钥
            
        Returns:
            str: 十六进制格式的HMAC值
        """
        hmac_obj = HMAC.new(key.encode('utf-8'), digestmod=SHA256)
        hmac_obj.update(message.encode('utf-8'))
        return hmac_obj.hexdigest()
    
    @staticmethod
    def pbkdf2(password, salt=None, iterations=10000, key_length=32, hash_function='sha256'):
        """
        使用PBKDF2算法派生密钥
        
        Args:
            password (str): 原始密码
            salt (bytes, optional): 盐值，如果不提供则随机生成
            iterations (int, optional): 迭代次数，默认10000
            key_length (int, optional): 生成的密钥长度（字节），默认32
            hash_function (str, optional): 使用的哈希函数，可选值: "sha1", "sha256"，默认"sha256"
            
        Returns:
            dict: 包含以下键的字典：
                - derived_key: Base64编码的派生密钥
                - salt: Base64编码的盐值
                - iterations: 迭代次数
                - key_length: 密钥长度
                - hash_function: 使用的哈希函数
        """
        if salt is None:
            salt = get_random_bytes(16)
        elif isinstance(salt, str):
            # 如果盐值是Base64编码的字符串，则解码
            try:
                salt = base64.b64decode(salt)
            except:
                # 如果解码失败，则将字符串直接编码为字节
                salt = salt.encode('utf-8')
        
        # 选择哈希函数
        if hash_function.lower() == 'sha1':
            hash_module = SHA1
        else:  # 默认使用SHA256
            hash_module = SHA256
            hash_function = 'sha256'
        
        # 派生密钥
        derived_key = PBKDF2(
            password=password.encode('utf-8'),
            salt=salt,
            dkLen=key_length,
            count=iterations,
            hmac_hash_module=hash_module
        )
        
        # 返回结果
        return {
            'derived_key': base64.b64encode(derived_key).decode('utf-8'),
            'salt': base64.b64encode(salt).decode('utf-8'),
            'iterations': iterations,
            'key_length': key_length,
            'hash_function': hash_function
        }
    
    @staticmethod
    def pbkdf2_verify(password, derived_key, salt, iterations=10000, key_length=32, hash_function='sha256'):
        """
        验证密码是否匹配PBKDF2派生的密钥
        
        Args:
            password (str): 要验证的密码
            derived_key (str): Base64编码的已派生密钥
            salt (str): Base64编码的盐值
            iterations (int, optional): 迭代次数，默认10000
            key_length (int, optional): 密钥长度（字节），默认32
            hash_function (str, optional): 使用的哈希函数，可选值: "sha1", "sha256"，默认"sha256"
            
        Returns:
            bool: 密码是否匹配
        """
        # 解码盐值和已派生密钥
        try:
            salt_bytes = base64.b64decode(salt)
            expected_key = base64.b64decode(derived_key)
        except:
            return False
        
        # 使用相同参数派生新密钥
        result = HashAlgorithms.pbkdf2(
            password=password,
            salt=salt_bytes,
            iterations=iterations,
            key_length=key_length,
            hash_function=hash_function
        )
        
        # 比较新派生的密钥与预期密钥
        new_key = base64.b64decode(result['derived_key'])
        return new_key == expected_key


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