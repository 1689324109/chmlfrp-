# coding=utf-8
#! /usr/bin/env python# -*- coding: utf-8 -*-
import requests, json, re, os
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs

session = requests.session()
# 配置用户名（一般是邮箱）
username = os.environ.get('USERNAME')
# username = "1689324109"
# 配置用户名对应的密码 和上面的email对应上
password = os.environ.get('PASSWORD')
# password = "zcj.080818"
# AnPlus
AnPlus = os.environ.get('AnPlus')
# AnPlus = 'J9C9I7V7RI4YEPHHRDHB2WL137ZDAY'
def push(content):
    if AnPlus != '1' :
        payload = {
            "title": u"ikuuu签到:"+content,
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
    soup = BeautifulSoup(html_content, 'html.parser')

    pattern = re.compile(r'\?page=logout&csrf=([a-zA-Z0-9]+)')
    match = pattern.search(html_content)
    csrf_token = match.group(1)
    return csrf_token
# 会不定时更新域名，记得Sync fork
# 定义请求的 URL
loginUrl = "https://xhfrp.xhuzim.top/?action=login&page=login"
userInfoUrl = "https://xhfrp.xhuzim.top/?page=panel"
checkPageUrl = "https://xhfrp.xhuzim.top/?page=panel&module=sign"
checkUrl = 'https://xhfrp.xhuzim.top/?page=panel&module=sign&sign&csrf='

# 定义请求的头部
headers = {
    "content-type": "application/x-www-form-urlencoded",
    "sec-ch-ua": '"Not)A;Brand";v="99", "Google Chrome";v="127", "Chromium";v="127"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "upgrade-insecure-requests": "1",
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36',
    'origin': 'https://xhfrp.xhuzim.top'
}

# 定义请求的 body
data = {
    "g-recaptcha-response": "",
    "username": username,
    "password": password
}

# 发送 POST 请求
response = session.post(loginUrl, headers=headers, data=data)
print(response)
info = session.get(userInfoUrl, headers=headers)
token = getCsrf(info.text)
checkPag = session.get(checkPageUrl, headers=headers)
print(checkPag)
check = session.get(checkUrl + token, headers=headers)
print(check.text)
push(check.text)
#     print(response['msg'])
#     # 获取账号名称
#     info_html = session.get(url=info_url,headers=header).text
# #     info = "".join(re.findall('<span class="user-name text-bold-600">(.*?)</span>', info_html, re.S))
# #     print(info)
#     # 进行签到
#     result = json.loads(session.post(url=check_url,headers=header).text)
#     print(result['msg'])
#     content = result['msg']
#     # 进行推送
#     push(content)

