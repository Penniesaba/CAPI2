#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import logging
import binascii
from Crypto.Cipher import AES as PyCryptoAES
from Crypto.Util.Padding import pad, unpad
from gmssl import sm4 as gm_sm4
import base64

# 获取模块级别的日志记录器
logger = logging.getLogger(__name__)

class AES:
    """
    AES对称加密算法实现
    
    支持ECB、CBC、CFB、OFB、CTR模式
    """
    
    @staticmethod
    def generate_key(key_size=256):
        """
        生成随机密钥
        
        参数:
            key_size: 密钥大小（比特），支持128、192、256
        
        返回:
            base64编码的密钥字符串
        """
        try:
            # 将比特转为字节
            key_bytes = key_size // 8
            key = os.urandom(key_bytes)
            logger.info(f"已生成AES-{key_size}密钥")
            return base64.b64encode(key).decode('utf-8')
        except Exception as e:
            logger.error(f"AES密钥生成失败: {str(e)}")
            raise

    @staticmethod
    def encrypt(plaintext, key, mode='CBC', iv=None):
        """
        AES加密
        
        参数:
            plaintext: 明文字符串
            key: Base64编码的密钥
            mode: 加密模式，支持ECB、CBC、CFB、OFB、CTR
            iv: 初始向量，CBC/CFB/OFB模式需要
        
        返回:
            base64编码的密文
        """
        try:
            # 解码密钥
            key_bytes = base64.b64decode(key)
            
            # 字符串转字节
            plaintext_bytes = plaintext.encode('utf-8')
            
            # 处理模式
            if mode == 'ECB':
                cipher = PyCryptoAES.new(key_bytes, PyCryptoAES.MODE_ECB)
                padded_data = pad(plaintext_bytes, PyCryptoAES.block_size)
                ciphertext = cipher.encrypt(padded_data)
            elif mode == 'CBC':
                if iv is None:
                    iv = os.urandom(PyCryptoAES.block_size)
                else:
                    iv = base64.b64decode(iv)
                cipher = PyCryptoAES.new(key_bytes, PyCryptoAES.MODE_CBC, iv)
                padded_data = pad(plaintext_bytes, PyCryptoAES.block_size)
                ciphertext = iv + cipher.encrypt(padded_data)
            elif mode == 'CFB':
                if iv is None:
                    iv = os.urandom(PyCryptoAES.block_size)
                else:
                    iv = base64.b64decode(iv)
                cipher = PyCryptoAES.new(key_bytes, PyCryptoAES.MODE_CFB, iv)
                ciphertext = iv + cipher.encrypt(plaintext_bytes)
            elif mode == 'OFB':
                if iv is None:
                    iv = os.urandom(PyCryptoAES.block_size)
                else:
                    iv = base64.b64decode(iv)
                cipher = PyCryptoAES.new(key_bytes, PyCryptoAES.MODE_OFB, iv)
                ciphertext = iv + cipher.encrypt(plaintext_bytes)
            elif mode == 'CTR':
                if iv is None:
                    # CTR模式中的nonce作为初始计数器
                    nonce = os.urandom(PyCryptoAES.block_size // 2)
                else:
                    nonce = base64.b64decode(iv)[:PyCryptoAES.block_size // 2]
                cipher = PyCryptoAES.new(key_bytes, PyCryptoAES.MODE_CTR, nonce=nonce)
                ciphertext = nonce + cipher.encrypt(plaintext_bytes)
            else:
                raise ValueError(f"不支持的加密模式: {mode}")
            
            # Base64编码
            encoded = base64.b64encode(ciphertext).decode('utf-8')
            logger.info(f"AES-{mode}加密成功")
            return encoded
        except Exception as e:
            logger.error(f"AES加密失败: {str(e)}")
            raise

    @staticmethod
    def decrypt(ciphertext, key, mode='CBC', iv=None):
        """
        AES解密
        
        参数:
            ciphertext: Base64编码的密文
            key: Base64编码的密钥
            mode: 加密模式，支持ECB、CBC、CFB、OFB、CTR
            iv: 初始向量，对于ECB模式不需要
        
        返回:
            解密后的明文字符串
        """
        try:
            # 解码密钥和密文
            key_bytes = base64.b64decode(key)
            ciphertext_bytes = base64.b64decode(ciphertext)
            
            # 处理模式
            if mode == 'ECB':
                cipher = PyCryptoAES.new(key_bytes, PyCryptoAES.MODE_ECB)
                padded_plaintext = cipher.decrypt(ciphertext_bytes)
                plaintext_bytes = unpad(padded_plaintext, PyCryptoAES.block_size)
            elif mode == 'CBC':
                iv = ciphertext_bytes[:PyCryptoAES.block_size]
                cipher = PyCryptoAES.new(key_bytes, PyCryptoAES.MODE_CBC, iv)
                padded_plaintext = cipher.decrypt(ciphertext_bytes[PyCryptoAES.block_size:])
                plaintext_bytes = unpad(padded_plaintext, PyCryptoAES.block_size)
            elif mode == 'CFB':
                iv = ciphertext_bytes[:PyCryptoAES.block_size]
                cipher = PyCryptoAES.new(key_bytes, PyCryptoAES.MODE_CFB, iv)
                plaintext_bytes = cipher.decrypt(ciphertext_bytes[PyCryptoAES.block_size:])
            elif mode == 'OFB':
                iv = ciphertext_bytes[:PyCryptoAES.block_size]
                cipher = PyCryptoAES.new(key_bytes, PyCryptoAES.MODE_OFB, iv)
                plaintext_bytes = cipher.decrypt(ciphertext_bytes[PyCryptoAES.block_size:])
            elif mode == 'CTR':
                nonce = ciphertext_bytes[:PyCryptoAES.block_size // 2]
                cipher = PyCryptoAES.new(key_bytes, PyCryptoAES.MODE_CTR, nonce=nonce)
                plaintext_bytes = cipher.decrypt(ciphertext_bytes[PyCryptoAES.block_size // 2:])
            else:
                raise ValueError(f"不支持的加密模式: {mode}")
            
            plaintext = plaintext_bytes.decode('utf-8')
            logger.info(f"AES-{mode}解密成功")
            return plaintext
        except Exception as e:
            logger.error(f"AES解密失败: {str(e)}")
            raise


class SM4:
    """
    国密SM4对称加密算法实现
    
    支持ECB和CBC模式
    """
    
    @staticmethod
    def generate_key():
        """
        生成随机SM4密钥
        
        返回:
            十六进制字符串表示的密钥
        """
        try:
            # SM4密钥固定为128位（16字节）
            key = os.urandom(16)
            hex_key = binascii.hexlify(key).decode('utf-8')
            logger.info("已生成SM4密钥")
            return hex_key
        except Exception as e:
            logger.error(f"SM4密钥生成失败: {str(e)}")
            raise

    @staticmethod
    def encrypt(plaintext, key, mode='ECB', iv=None):
        """
        SM4加密
        
        参数:
            plaintext: 明文字符串
            key: 十六进制字符串表示的密钥
            mode: 加密模式，支持ECB和CBC
            iv: 初始向量，CBC模式需要（16字节十六进制字符串）
        
        返回:
            十六进制字符串表示的密文
        """
        try:
            # 将十六进制密钥转为字节
            key_bytes = bytes.fromhex(key)
            
            # 创建SM4实例
            sm4_crypt = gm_sm4.CryptSM4()
            
            if mode.upper() == 'ECB':
                # 设置密钥
                sm4_crypt.set_key(key_bytes, gm_sm4.SM4_ENCRYPT)
                # 加密
                ciphertext = sm4_crypt.crypt_ecb(plaintext.encode('utf-8'))
            elif mode.upper() == 'CBC':
                if iv is None:
                    iv = os.urandom(16)
                    iv_hex = binascii.hexlify(iv).decode('utf-8')
                else:
                    iv = bytes.fromhex(iv)
                    iv_hex = iv
                
                # 设置密钥
                sm4_crypt.set_key(key_bytes, gm_sm4.SM4_ENCRYPT)
                # 加密
                ciphertext = sm4_crypt.crypt_cbc(iv, plaintext.encode('utf-8'))
                # 附加IV
                return iv_hex + binascii.hexlify(ciphertext).decode('utf-8')
            else:
                raise ValueError(f"不支持的SM4加密模式: {mode}")
            
            # 返回十六进制字符串
            hex_ciphertext = binascii.hexlify(ciphertext).decode('utf-8')
            logger.info(f"SM4-{mode}加密成功")
            return hex_ciphertext
        except Exception as e:
            logger.error(f"SM4加密失败: {str(e)}")
            raise

    @staticmethod
    def decrypt(ciphertext, key, mode='ECB', iv=None):
        """
        SM4解密
        
        参数:
            ciphertext: 十六进制字符串表示的密文
            key: 十六进制字符串表示的密钥
            mode: 加密模式，支持ECB和CBC
            iv: 初始向量，CBC模式需要（如果为None，则从密文提取）
        
        返回:
            解密后的明文字符串
        """
        try:
            # 将十六进制密钥转为字节
            key_bytes = bytes.fromhex(key)
            
            # 创建SM4实例
            sm4_crypt = gm_sm4.CryptSM4()
            
            if mode.upper() == 'ECB':
                # 将十六进制密文转为字节
                ciphertext_bytes = bytes.fromhex(ciphertext)
                
                # 设置密钥
                sm4_crypt.set_key(key_bytes, gm_sm4.SM4_DECRYPT)
                # 解密
                plaintext_bytes = sm4_crypt.crypt_ecb(ciphertext_bytes)
            elif mode.upper() == 'CBC':
                if iv is None:
                    # 从密文中提取IV（前32个字符，即16字节的十六进制表示）
                    iv = bytes.fromhex(ciphertext[:32])
                    ciphertext = ciphertext[32:]
                else:
                    iv = bytes.fromhex(iv)
                
                # 将十六进制密文转为字节
                ciphertext_bytes = bytes.fromhex(ciphertext)
                
                # 设置密钥
                sm4_crypt.set_key(key_bytes, gm_sm4.SM4_DECRYPT)
                # 解密
                plaintext_bytes = sm4_crypt.crypt_cbc(iv, ciphertext_bytes)
            else:
                raise ValueError(f"不支持的SM4加密模式: {mode}")
            
            # 返回明文字符串
            plaintext = plaintext_bytes.decode('utf-8')
            logger.info(f"SM4-{mode}解密成功")
            return plaintext
        except Exception as e:
            logger.error(f"SM4解密失败: {str(e)}")
            raise


class RC6:
    """
    RC6对称加密算法实现
    
    RC6是一种分组密码算法，w=32, r=20的RC6实现
    """
    
    # RC6参数
    w = 32  # 字长（比特）
    r = 20  # 轮数
    
    @staticmethod
    def _rotl(val, r_bits, max_bits):
        """32位左循环移位"""
        return ((val << r_bits) & (2**max_bits - 1)) | (val >> (max_bits - r_bits))
    
    @staticmethod
    def _rotr(val, r_bits, max_bits):
        """32位右循环移位"""
        return ((val & (2**max_bits - 1)) >> r_bits) | (val << (max_bits - r_bits) & (2**max_bits - 1))
    
    @staticmethod
    def _key_schedule(key):
        """RC6密钥调度"""
        w = RC6.w
        r = RC6.r
        
        # 常量P和Q
        P = 0xB7E15163
        Q = 0x9E3779B9
        
        # 将密钥转换为字数组
        key_bytes = key
        if isinstance(key, str):
            # 如果是十六进制字符串，转换为字节
            key_bytes = bytes.fromhex(key)
        
        # 确保key_bytes至少有16字节
        if len(key_bytes) < 16:
            key_bytes = key_bytes.ljust(16, b'\0')
        
        # 计算c（密钥字长）
        c = len(key_bytes) // 4
        
        # 创建L数组
        L = [0] * c
        for i in range(c):
            L[i] = int.from_bytes(key_bytes[i*4:i*4+4], byteorder='little')
        
        # 创建S数组（轮密钥）
        S = [0] * (2*r + 4)
        S[0] = P
        
        for i in range(1, 2*r+4):
            S[i] = (S[i-1] + Q) & 0xFFFFFFFF
        
        # 混合L和S
        i = j = 0
        A = B = 0
        
        for k in range(3 * max(c, 2*r+4)):
            A = S[i] = RC6._rotl((S[i] + A + B) & 0xFFFFFFFF, 3, 32)
            B = L[j] = RC6._rotl((L[j] + A + B) & 0xFFFFFFFF, (A + B) % 32, 32)
            i = (i + 1) % (2*r + 4)
            j = (j + 1) % c
        
        return S
    
    @staticmethod
    def generate_key():
        """
        生成随机RC6密钥
        
        返回:
            十六进制字符串表示的密钥
        """
        try:
            # RC6通常使用16字节（128位）密钥
            key = os.urandom(16)
            hex_key = binascii.hexlify(key).decode('utf-8')
            logger.info("已生成RC6密钥")
            return hex_key
        except Exception as e:
            logger.error(f"RC6密钥生成失败: {str(e)}")
            raise
    
    @staticmethod
    def encrypt(plaintext, key):
        """
        RC6加密
        
        参数:
            plaintext: 明文字符串
            key: 十六进制字符串表示的密钥
        
        返回:
            十六进制字符串表示的密文
        """
        try:
            # 将十六进制密钥转为字节
            key_bytes = bytes.fromhex(key)
            
            # 生成轮密钥
            S = RC6._key_schedule(key_bytes)
            
            # 转换明文为字节并填充
            plaintext_bytes = plaintext.encode('utf-8')
            padding_len = 16 - (len(plaintext_bytes) % 16)
            plaintext_bytes += bytes([padding_len]) * padding_len
            
            # 分割明文为16字节块并加密
            ciphertext = b''
            for i in range(0, len(plaintext_bytes), 16):
                block = plaintext_bytes[i:i+16]
                # 将16字节块转换为4个32位整数
                A = int.from_bytes(block[0:4], byteorder='little')
                B = int.from_bytes(block[4:8], byteorder='little')
                C = int.from_bytes(block[8:12], byteorder='little')
                D = int.from_bytes(block[12:16], byteorder='little')
                
                # 预处理
                B = (B + S[0]) & 0xFFFFFFFF
                D = (D + S[1]) & 0xFFFFFFFF
                
                # 执行r轮加密
                for j in range(1, RC6.r + 1):
                    t = RC6._rotl((B * (2*B + 1)) & 0xFFFFFFFF, 5, 32)
                    u = RC6._rotl((D * (2*D + 1)) & 0xFFFFFFFF, 5, 32)
                    A = (RC6._rotl(A ^ t, u % 32, 32) + S[2*j]) & 0xFFFFFFFF
                    C = (RC6._rotl(C ^ u, t % 32, 32) + S[2*j+1]) & 0xFFFFFFFF
                    A, B, C, D = B, C, D, A
                
                # 后处理
                A = (A + S[2*RC6.r + 2]) & 0xFFFFFFFF
                C = (C + S[2*RC6.r + 3]) & 0xFFFFFFFF
                
                # 将4个32位整数转回16字节
                ciphertext += A.to_bytes(4, byteorder='little')
                ciphertext += B.to_bytes(4, byteorder='little')
                ciphertext += C.to_bytes(4, byteorder='little')
                ciphertext += D.to_bytes(4, byteorder='little')
            
            # 返回十六进制字符串表示的密文
            hex_ciphertext = binascii.hexlify(ciphertext).decode('utf-8')
            logger.info("RC6加密成功")
            return hex_ciphertext
        except Exception as e:
            logger.error(f"RC6加密失败: {str(e)}")
            raise
    
    @staticmethod
    def decrypt(ciphertext, key):
        """
        RC6解密
        
        参数:
            ciphertext: 十六进制字符串表示的密文
            key: 十六进制字符串表示的密钥
        
        返回:
            解密后的明文字符串
        """
        try:
            # 将十六进制密钥和密文转为字节
            key_bytes = bytes.fromhex(key)
            ciphertext_bytes = bytes.fromhex(ciphertext)
            
            # 生成轮密钥
            S = RC6._key_schedule(key_bytes)
            
            # 分割密文为16字节块并解密
            plaintext = b''
            for i in range(0, len(ciphertext_bytes), 16):
                block = ciphertext_bytes[i:i+16]
                # 将16字节块转换为4个32位整数
                A = int.from_bytes(block[0:4], byteorder='little')
                B = int.from_bytes(block[4:8], byteorder='little')
                C = int.from_bytes(block[8:12], byteorder='little')
                D = int.from_bytes(block[12:16], byteorder='little')
                
                # 预处理（逆向）
                C = (C - S[2*RC6.r + 3]) & 0xFFFFFFFF
                A = (A - S[2*RC6.r + 2]) & 0xFFFFFFFF
                
                # 执行r轮解密（逆向）
                for j in range(RC6.r, 0, -1):
                    A, B, C, D = D, A, B, C
                    u = RC6._rotl((D * (2*D + 1)) & 0xFFFFFFFF, 5, 32)
                    t = RC6._rotl((B * (2*B + 1)) & 0xFFFFFFFF, 5, 32)
                    C = RC6._rotr((C - S[2*j+1]) & 0xFFFFFFFF, t % 32, 32) ^ u
                    A = RC6._rotr((A - S[2*j]) & 0xFFFFFFFF, u % 32, 32) ^ t
                
                # 后处理（逆向）
                D = (D - S[1]) & 0xFFFFFFFF
                B = (B - S[0]) & 0xFFFFFFFF
                
                # 将4个32位整数转回16字节
                plaintext += A.to_bytes(4, byteorder='little')
                plaintext += B.to_bytes(4, byteorder='little')
                plaintext += C.to_bytes(4, byteorder='little')
                plaintext += D.to_bytes(4, byteorder='little')
            
            # 去除填充
            padding_len = plaintext[-1]
            plaintext = plaintext[:-padding_len]
            
            # 返回明文字符串
            result = plaintext.decode('utf-8')
            logger.info("RC6解密成功")
            return result
        except Exception as e:
            logger.error(f"RC6解密失败: {str(e)}")
            raise 