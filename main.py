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
        'cookie': 'guard=c367b661Ce4n7;guardret=UAM=',
        'priority': 'u=0, i'
    }

# 定义请求的 body
data = {
    "g-recaptcha-response": "",
    "username": "1689324109",
    "password": "zcj.080818"
}

res = requests.get(url)
guard =  res.cookies.get_dict().get("guard")
guardret = set_ret(f'{guard}')
headers['cookie'] = f'guard={guard};guardret={guardret}'
# print(headers)
ok_response = requests.get(url, headers=headers)

ok_set_cookie = ok_response.cookies.get_dict()
guard = ok_set_cookie.get("guard")

headers['cookie'] = f'PHPSESSID={ok_set_cookie.get("PHPSESSID")};guardok={ok_set_cookie.get("guardok")}'


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
