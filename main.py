# coding=utf-8
#! /usr/bin/env python# -*- coding: utf-8 -*-
import base64
import requests, json, re, os
from bs4 import BeautifulSoup


session = requests.session()
# 配置用户名（一般是邮箱）
username = os.environ.get('USERNAME')

# 配置用户名对应的密码 和上面的email对应上
password = os.environ.get('PASSWORD')

# AnPlus
AnPlus = os.environ.get('AnPlus')

def x(a, b):
    b = b + "PTNo2n3Ev5"
    output = []
    for i in range(len(a)):
        char_code = ord(a[i]) ^ ord(b[i % len(b)])
        output.append(chr(char_code))
    return ''.join(output)

def getGuardRet(guard):
    b = guard[:8]
    a_int = int(guard[12:])
    a = str(((a_int * 0x2) + 0x12 - 0x2))
    encrypted = x(a, b)
    encoded = base64.b64encode(encrypted.encode()).decode()
    return encoded

def set_ret(input_str):
    encrypted = getGuardRet(input_str)
    return encrypted

def push(content):
    if AnPlus != '1' :
        payload = {
            "title": u"xhuzim签到:"+content,
            "content": content,
            "channel": "97024"
        }

        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }

        response = requests.post("https://api.anpush.com/push/"+AnPlus, headers=headers, data=payload)
        print('AnPlus消息推送推送成功' if response.status_code == 200 else 'AnPlus消息推送推送失败')
    else:
        print('未使用消息推送推送！')

def getCsrf(html_content):
    # print(html_content)
    soup = BeautifulSoup(html_content, 'html.parser')
    pattern = re.compile(r'\?page=logout&csrf=([a-zA-Z0-9]+)')
    match = pattern.search(html_content)
    csrf_token = match.group(1)
    return csrf_token
# 会不定时更新域名，记得Sync fork
# 定义请求的 URL
url="https://xhfrp.xhuzim.top/"
mainUrl="https://xhfrp.xhuzim.top/?page=login"
loginUrl = "https://xhfrp.xhuzim.top/?action=login&page=login"
userInfoUrl = "https://xhfrp.xhuzim.top/?page=panel"
checkPageUrl = "https://xhfrp.xhuzim.top/?page=panel&module=sign"
checkUrl = 'https://xhfrp.xhuzim.top/?page=panel&module=sign&sign&csrf='

headers = {
        'cache-control': 'max-age=0',
        'sec-ch-ua': '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'upgrade-insecure-requests': '1',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'sec-fetch-site': 'same-origin',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-dest': 'document',
        'referer':'https://xhfrp.xhuzim.top/',
        'accept-encoding': 'gzip, deflate, br, zstd',
        'accept-language': 'zh-CN,zh;q=0.9',
        'priority': 'u=0, i'
    }

# 定义请求的 body
data = {
    "g-recaptcha-response": "",
    "username": username,
    "password": password
}

res = requests.get(url)
guard =  res.cookies.get_dict().get("guard") 

# 如果没有 guard，直接停止后续操作
if not guard:
    print("No 'guard' cookie found, stopping execution.")
    res = requests.get(url)
    match = re.search(r'document.cookie = "(.*?);', res.text)
    if not not match:
        validator = match.group(1)
        headers['cookie'] = validator
        res = requests.get(url,headers=headers)
        PHPSESSID =  res.cookies.get_dict().get("PHPSESSID") 
        headers['cookie'] = f'PHPSESSID={PHPSESSID};{validator}'
else:
    # 如果有 guard，则继续执行后续操作
    guardret = set_ret(f'{guard}')
    headers['cookie'] = f'guard={guard};guardret={guardret}'

    # 发起第二个请求
    ok_response = requests.get(url, headers=headers)

    # 获取第二个请求的 cookies
    ok_set_cookie = ok_response.cookies.get_dict()
    guard = ok_set_cookie.get("guard")

    # 更新 headers 中的 cookie
    headers['cookie'] = f'PHPSESSID={ok_set_cookie.get("PHPSESSID")};guardok={ok_set_cookie.get("guardok")}'

if True:

    # 发送 POST 请求
    response = session.post(loginUrl, headers=headers, data=data)
    print(response.text)
    info = session.get(userInfoUrl, headers=headers)
    # print(info.text)
    token = getCsrf(info.text)
    checkPag = session.get(checkPageUrl, headers=headers)
    print(checkPag)
    check = session.get(checkUrl + token, headers=headers)
    print(check.text)
    push(check.text)
