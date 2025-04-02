#!/usr/bin/env python
# -*- coding: utf-8 -*-

from flask import Blueprint, render_template, redirect, url_for

# 创建Web蓝图
web_bp = Blueprint('web', __name__)

@web_bp.route('/')
def index():
    """
    首页路由
    """
    return render_template('index.html')

@web_bp.route('/symmetric')
def symmetric():
    """
    对称加密算法页面
    """
    return render_template('crypto_forms/symmetric.html')

@web_bp.route('/symmetric_theory')
def symmetric_theory():
    """
    对称加密算法原理页面
    """
    return render_template('theory/symmetric_theory.html')

@web_bp.route('/hash_functions')
def hash_functions():
    """
    哈希算法页面
    """
    return render_template('crypto_forms/hash.html')

@web_bp.route('/hash_theory')
def hash_theory():
    """
    哈希算法原理页面
    """
    return render_template('theory/hash_theory.html')

@web_bp.route('/encoding')
def encoding():
    """
    编码算法页面
    """
    return render_template('crypto_forms/encoding.html')

@web_bp.route('/encoding_theory')
def encoding_theory():
    """
    编码算法原理页面
    """
    return render_template('theory/encoding_theory.html')

@web_bp.route('/asymmetric')
def asymmetric():
    """
    非对称加密算法页面
    """
    return render_template('crypto_forms/asymmetric.html')

@web_bp.route('/asymmetric_theory')
def asymmetric_theory():
    """
    非对称加密算法原理页面
    """
    return render_template('theory/asymmetric_theory.html')

@web_bp.route('/digital_certificate')
def digital_certificate():
    """
    数字证书页面
    """
    return render_template('applications/digital_certificate.html')

@web_bp.route('/secure_communication')
def secure_communication():
    """
    安全通信页面
    """
    return render_template('applications/secure_communication.html')

@web_bp.route('/password_security')
def password_security():
    """
    密码安全页面
    """
    return render_template('applications/password_security.html')

@web_bp.route('/docs')
def docs():
    """
    API文档页面
    """
    return render_template('docs.html')

@web_bp.route('/about')
def about():
    """
    关于页面
    """
    return render_template('about.html') 