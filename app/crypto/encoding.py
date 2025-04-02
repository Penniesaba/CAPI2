#!/usr/bin/env python
# -*- coding: utf-8 -*-

import base64
import logging
import binascii

# 获取模块级别的日志记录器
logger = logging.getLogger(__name__)

class Encoding:
    """
    编码算法实现类
    
    包括Base64和UTF-8编码
    """
    
    @staticmethod
    def base64_encode(data):
        """
        Base64编码
        
        参数:
            data: 要编码的数据（字符串）
        
        返回:
            Base64编码的字符串
        """
        try:
            # 转换为字节并编码
            data_bytes = data.encode('utf-8')
            encoded = base64.b64encode(data_bytes).decode('utf-8')
            logger.info("Base64编码成功")
            return encoded
        except Exception as e:
            logger.error(f"Base64编码失败: {str(e)}")
            raise
    
    @staticmethod
    def base64_decode(data):
        """
        Base64解码
        
        参数:
            data: Base64编码的字符串
        
        返回:
            解码后的字符串
        """
        try:
            # 解码
            decoded_bytes = base64.b64decode(data)
            decoded = decoded_bytes.decode('utf-8')
            logger.info("Base64解码成功")
            return decoded
        except Exception as e:
            logger.error(f"Base64解码失败: {str(e)}")
            raise
    
    @staticmethod
    def url_safe_base64_encode(data):
        """
        URL安全的Base64编码
        
        参数:
            data: 要编码的数据（字符串）
        
        返回:
            URL安全的Base64编码字符串
        """
        try:
            # 转换为字节并编码
            data_bytes = data.encode('utf-8')
            encoded = base64.urlsafe_b64encode(data_bytes).decode('utf-8')
            logger.info("URL安全Base64编码成功")
            return encoded
        except Exception as e:
            logger.error(f"URL安全Base64编码失败: {str(e)}")
            raise
    
    @staticmethod
    def url_safe_base64_decode(data):
        """
        URL安全的Base64解码
        
        参数:
            data: URL安全的Base64编码字符串
        
        返回:
            解码后的字符串
        """
        try:
            # 解码
            decoded_bytes = base64.urlsafe_b64decode(data)
            decoded = decoded_bytes.decode('utf-8')
            logger.info("URL安全Base64解码成功")
            return decoded
        except Exception as e:
            logger.error(f"URL安全Base64解码失败: {str(e)}")
            raise
    
    @staticmethod
    def utf8_encode(data):
        """
        UTF-8编码
        
        参数:
            data: 要编码的数据（字符串）
        
        返回:
            UTF-8编码的十六进制字符串
        """
        try:
            # 编码为UTF-8
            encoded_bytes = data.encode('utf-8')
            hex_encoded = binascii.hexlify(encoded_bytes).decode('utf-8')
            logger.info("UTF-8编码成功")
            return hex_encoded
        except Exception as e:
            logger.error(f"UTF-8编码失败: {str(e)}")
            raise
    
    @staticmethod
    def utf8_decode(hex_data):
        """
        UTF-8解码
        
        参数:
            hex_data: UTF-8编码的十六进制字符串
        
        返回:
            解码后的字符串
        """
        try:
            # 解码UTF-8
            encoded_bytes = binascii.unhexlify(hex_data)
            decoded = encoded_bytes.decode('utf-8')
            logger.info("UTF-8解码成功")
            return decoded
        except Exception as e:
            logger.error(f"UTF-8解码失败: {str(e)}")
            raise
    
    @staticmethod
    def hex_encode(data):
        """
        十六进制编码
        
        参数:
            data: 要编码的数据（字符串）
        
        返回:
            十六进制编码的字符串
        """
        try:
            # 编码为十六进制
            encoded_bytes = data.encode('utf-8')
            hex_encoded = binascii.hexlify(encoded_bytes).decode('utf-8')
            logger.info("十六进制编码成功")
            return hex_encoded
        except Exception as e:
            logger.error(f"十六进制编码失败: {str(e)}")
            raise
    
    @staticmethod
    def hex_decode(hex_data):
        """
        十六进制解码
        
        参数:
            hex_data: 十六进制编码的字符串
        
        返回:
            解码后的字符串
        """
        try:
            # 解码十六进制
            encoded_bytes = binascii.unhexlify(hex_data)
            decoded = encoded_bytes.decode('utf-8')
            logger.info("十六进制解码成功")
            return decoded
        except Exception as e:
            logger.error(f"十六进制解码失败: {str(e)}")
            raise 