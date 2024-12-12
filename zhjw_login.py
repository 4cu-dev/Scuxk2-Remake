import re
import ddddocr
import hashlib
import requests
from main import load_setting, load_user_data, user_data

failed_OCR_limit = 3  # 当自动识别验证码出错超过该值，切换为手动输入
basic_header = {
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/116.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
    'Origin': 'http://zhjw.scu.edu.cn',
    'Referer': 'http://zhjw.scu.edu.cn/login',
    'Upgrade-Insecure-Requests': '1',
    'Priority': 'u=0, i',
}

root_url = "http://zhjw.scu.edu.cn/"
login_url = "http://zhjw.scu.edu.cn/login"
login_post_url = "http://zhjw.scu.edu.cn/j_spring_security_check"
captcha_url = "http://zhjw.scu.edu.cn/img/captcha.jpg"
captcha_solver = ddddocr.DdddOcr(beta=True, show_ad=False)
session = requests.Session()
session.headers.update(basic_header)  # set header
# session.cookies.update({'student.urpSoft.cn': 'aaaRD3DbGHzbY45qY6Toz'})


def md5_32(input_str: str) -> str:
    # 创建 MD5 对象
    md5 = hashlib.md5()
    # 更新要加密的字符串
    md5.update(input_str.encode('utf-8'))
    # 获取 MD5 哈希值并转换为小写
    return md5.hexdigest().lower()


def zhjw_login(username, password):
    login_page = session.get(login_url)
    print(session.headers)
    print(session.cookies)
    # login_page = session.get(login_url)
    # print(session.cookies)
    token_value_pattern = r'name="tokenValue" value="(.*?)">'
    token_value_match = re.search(token_value_pattern, login_page.text)
    if token_value_match:
        token_value = token_value_match.group(1)
        if token_value.strip() != "":
            print("tokenValue:", token_value)
        else:
            print("tokenValue 未找到")
            return -1
    else:
        print("tokenValue 未找到")
        return -2
    # dddocr识别
    captcha_text = "0000"  # initialize
    for _ in range(failed_OCR_limit):
        captcha_img = session.get(captcha_url)
        image_data = captcha_img.content
        captcha_text = captcha_solver.classification(image_data)
        print("自动识别到验证码：", captcha_text)
        if len(captcha_text) == 4:
            print("识别验证码:", captcha_text)
            break
        print("验证码识别错误，即将重新获取验证码...")

    post_data = {
        'tokenValue': token_value,
        'j_username': username,
        'j_password': '*'.join([
            md5_32(password + "{Urp602019}"),
            md5_32(password)
        ]),
        'j_captcha': str(captcha_text),
        '_spring_security_remember_me': 'on',
    }
    print(post_data)
    login_resp = session.post(login_post_url, data=post_data)
    login_resp_text = login_resp.text
    if '用户密码错误' in login_resp_text:
        print('用户名或密码错误')
        return -1
    if '欢迎您' in login_resp_text:
        print('登录成功')
        return 0

    # unkown error
    print(login_resp_text)
    return -2


if __name__ == '__main__':
    setting = load_setting()
    user_data = load_user_data()
    zhjw_login(user_data["std_id"], user_data["password"])
