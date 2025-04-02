#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
from logging.handlers import RotatingFileHandler
import os
from flask import Flask

def create_app(test_config=None):
    """
    创建并配置Flask应用
    """
    # 创建Flask应用实例
    app = Flask(__name__)
    
    # 加载配置
    if test_config is None:
        # 从config.py加载配置
        app.config.from_pyfile('config.py', silent=True)
    else:
        # 加载测试配置
        app.config.from_mapping(test_config)
    
    # 确保实例文件夹存在
    try:
        os.makedirs(app.instance_path, exist_ok=True)
    except OSError:
        pass
    
    # 配置日志
    if not app.debug:
        # 创建日志处理器
        if not os.path.exists('logs'):
            os.mkdir('logs')
        file_handler = RotatingFileHandler('logs/crypto_app.log', maxBytes=10240, backupCount=10)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        file_handler.setLevel(logging.INFO)
        
        # 添加处理器到应用日志记录器
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)
    
    # 记录应用启动
    app.logger.info('密码算法应用启动')
    
    # 注册路由
    from app.routes import api_routes
    app.register_blueprint(api_routes.api_bp, url_prefix='/api')
    
    # 恢复Web路由
    from app.routes.web_routes import web_bp
    app.register_blueprint(web_bp)
    
    return app 