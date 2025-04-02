#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
from datetime import timedelta

class Config:
    """应用配置类"""
    # 基本配置
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'hard-to-guess-string-for-development'
    DEBUG = os.environ.get('FLASK_DEBUG') or True
    
    # 安全配置
    SESSION_COOKIE_SECURE = False  # 生产环境设为True
    PERMANENT_SESSION_LIFETIME = timedelta(days=1)
    
    # API相关配置
    API_RATE_LIMIT = "200 per day, 50 per hour"
    
    # 加密算法相关配置
    RSA_KEY_SIZE = 1024
    ECC_KEY_SIZE = 160
    AES_KEY_SIZES = [128, 192, 256]
    AES_MODES = ['ECB', 'CBC', 'CFB', 'OFB', 'CTR']
    
    # PBKDF2配置
    PBKDF2_DEFAULT_ITERATIONS = 1000
    PBKDF2_DEFAULT_DKLEN = 32
    
    # 日志配置
    LOG_LEVEL = os.environ.get('LOG_LEVEL') or 'INFO' 