import json
import os
import re
from ast import literal_eval
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue
from random import choice
from threading import RLock, Thread
from time import sleep, time
from urllib.parse import parse_qsl, unquote_plus, urlencode, urljoin, urlsplit

import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from requests.structures import CaseInsensitiveDict
from selenium.webdriver.support.expected_conditions import any_of, title_is
from selenium.webdriver.support.ui import WebDriverWait
from undetected_chromedriver import Chrome, ChromeOptions
from urllib3 import Retry

from utils import get_id

re_checked_in = re.compile(r'(?:已经?|重复)签到')
re_var_sub_token = re.compile(r'var sub_token = "(.+?)"')
re_email_code = re.compile(r'(?:码|碼|証|code).*?(?<![\da-z])([\da-z]{6})(?![\da-z])', re.I | re.S)
re_snapmail_domains = re.compile(r'emailDomainList.*?(\[.*?\])')
re_mailcx_js_path = re.compile(r'/_next/static/chunks/\d+-[\da-f]{16}.js')
re_mailcx_domains = re.compile(r'mailHosts:(\[.*?\])')
re_guerrillamail_domains = re.compile(r'<option.*option>')
re_guerrillamail_domain = re.compile(r'>([^<]+)')


class Response:
    def __init__(self, content: bytes, headers: CaseInsensitiveDict[str], status_code: int, reason: str):
        self.content = content
        self.headers = headers
        self.status_code = status_code
        self.reason = reason

    @property
    def text(self):
        if not hasattr(self, '_Response__text'):
            self.__text = self.content.decode()
        return self.__text

    def json(self):
        if not hasattr(self, '_Response__json'):
            self.__json = json.loads(self.text)
        return self.__json

    def bs(self):
        if not hasattr(self, '_Response__bs'):
            self.__bs = BeautifulSoup(self.text, 'html.parser')
        return self.__bs

    def __str__(self):
        return f'{self.status_code} {self.reason} {self.text}'


class Session(requests.Session):
    def __init__(self, host=None, user_agent=None):
        super().__init__()
        self.mount('https://', HTTPAdapter(max_retries=Retry(total=5, backoff_factor=0.1)))
        self.mount('http://', HTTPAdapter(max_retries=Retry(total=5, backoff_factor=0.1)))
        self.headers['User-Agent'] = user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36'
        self.set_host(host)

    def set_host(self, host):
        if host:
            self.base = 'https://' + host
            self.host = host
        else:
            self.base = None
            self.host = None

    def close(self):
        super().close()
        if hasattr(self, 'chrome'):
            self.chrome.quit()

    def reset(self):
        self.cookies.clear()
        self.headers.pop('authorization', None)
        self.headers.pop('token', None)
        if hasattr(self, 'chrome'):
            self.chrome.delete_all_cookies()
            for cookie in self.chrome_default_cookies:
                self.chrome.add_cookie(cookie)

    def head(self, url='', **kwargs) -> Response:
        return super().head(url, **kwargs)

    def get(self, url='', **kwargs) -> Response:
        return super().get(url, **kwargs)

    def post(self, url='', data=None, **kwargs) -> Response:
        return super().post(url, data, **kwargs)

    def put(self, url='', data=None, **kwargs) -> Response:
        return super().put(url, data, **kwargs)

    def request(self, method, url: str = '', data=None, timeout=5, **kwargs):
        url = urljoin(self.base, url)
        if not hasattr(self, 'chrome'):
            res = super().request(method, url, data=data, timeout=timeout, **kwargs)
            res = Response(res.content, res.headers, res.status_code, res.reason)
            if res.status_code != 403 and (
                'Content-Type' not in res.headers
                or not res.headers['Content-Type'].startswith('text/html')
                or not res.content
                or res.content[0] != 60
                or not res.bs().title
                or res.bs().title.text not in ('Just a moment...', '')
            ):
                return res
        cur_host = urlsplit(url).hostname
        if urlsplit(self.get_chrome().current_url).hostname != cur_host:
            self.chrome.get('https://' + cur_host)
            WebDriverWait(self.chrome, 15).until_not(any_of(title_is('Just a moment...'), title_is('')))
            self.chrome_default_cookies = self.chrome.get_cookies()
        headers = CaseInsensitiveDict()
        if 'authorization' in self.headers:
            headers['authorization'] = self.headers['authorization']
        if data:
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
            body = repr(data if isinstance(data, str) else urlencode(data))
        else:
            body = 'null'
        content, header_list, status_code, reason = self.chrome.execute_script(f'''
            const res = await fetch({repr(url)}, {{ method: {repr(method)}, headers: {repr(headers)}, body: {body} }})
            return [new Uint8Array(await res.arrayBuffer()), [...res.headers], res.status, res.statusText]
        ''')
        return Response(bytes(content), CaseInsensitiveDict(header_list), int(status_code), reason)

    def get_chrome(self):
        if not hasattr(self, 'chrome'):
            print(f'{self.host} using Chrome')
            options = ChromeOptions()
            options.add_argument('--disable-web-security')
            options.add_argument('--ignore-certificate-errors')
            options.add_argument('--allow-running-insecure-content')
            options.page_load_strategy = 'eager'
            self.chrome = Chrome(
                options=options,
                driver_executable_path=os.path.join(os.getenv('CHROMEWEBDRIVER'), 'chromedriver')
            )
            self.chrome.set_page_load_timeout(15)
        return self.chrome

    def get_ip_info(self):
        """return (ip, 位置, 运营商)"""
        addr = self.get(f'https://ip125.com/api/{self.get("https://ident.me").text}?lang=zh-CN').json()
        return (
            addr['query'],
            addr['country'] + (',' + addr['city'] if addr['city'] and addr['city'] != addr['country'] else ''),
            addr['isp'] + (',' + addr['org'] if addr['org'] and addr['org'] != addr['isp'] else '')
        )


class V2BoardSession(Session):
    def __set_auth(self, email: str, reg_info: dict):
        self.login_info = reg_info['data']
        self.email = email
        if 'v2board_session' not in self.cookies:
            self.headers['authorization'] = self.login_info['auth_data']

    def reset(self):
        super().reset()
        if hasattr(self, 'login_info'):
            del self.login_info
        if hasattr(self, 'email'):
            del self.email

    @staticmethod
    def raise_for_fail(res):
        if 'data' not in res:
            raise Exception(res)

    def register(self, email: str, password=None, email_code=None, invite_code=None) -> str | None:
        self.reset()
        res = self.post('api/v1/passport/auth/register', {
            'email': email,
            'password': password or email.split('@')[0],
            **({'email_code': email_code} if email_code else {}),
            **({'invite_code': invite_code} if invite_code else {})
        }).json()
        if 'data' in res:
            self.__set_auth(email, res)
            return None
        if 'message' in res:
            return res['message']
        raise Exception(res)

    def login(self, email: str = None, password=None):
        if hasattr(self, 'login_info') and (not email or email == getattr(self, 'email', None)):
            return
        self.reset()
        res = self.post('api/v1/passport/auth/login', {
            'email': email,
            'password': password or email.split('@')[0]
        }).json()
        self.raise_for_fail(res)
        self.__set_auth(email, res)

    def send_email_code(self, email):
        res = self.post('api/v1/passport/comm/sendEmailVerify', {
            'email': email
        }, timeout=60).json()
        self.raise_for_fail(res)

    def buy(self, data):
        res = self.post(
            'api/v1/user/order/save',
            data,
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        ).json()
        self.raise_for_fail(res)
        res = self.post('api/v1/user/order/checkout', {
            'trade_no': res['data']
        }).json()
        self.raise_for_fail(res)

    def get_sub_url(self, **params) -> str:
        res = self.get('api/v1/user/getSubscribe').json()
        self.raise_for_fail(res)
        self.sub_url = res['data']['subscribe_url']
        return self.sub_url

    def get_sub_info(self):
        res = self.get('api/v1/user/getSubscribe').json()
        self.raise_for_fail(res)
        d = res['data']
        return {
            'upload': d['u'],
            'download': d['d'],
            'total': d['transfer_enable'],
            'expire': d['expired_at']
        }


class SSPanelSession(Session):
    def __init__(self, host=None, user_agent=None, auth_path=None):
        super().__init__(host, user_agent)
        self.auth_path = auth_path or 'auth'

    def reset(self):
        super().reset()
        if hasattr(self, 'email'):
            del self.email

    @staticmethod
    def raise_for_fail(res):
        if not res.get('ret'):
            raise Exception(res)

    def register(self, email: str, password=None, email_code=None, invite_code=None, name_eq_email=None, reg_fmt=None, im_type=False, aff=None) -> str | None:
        self.reset()
        email_code_k, invite_code_k = ('email_code', 'invite_code') if reg_fmt == 'B' else ('emailcode', 'code')
        password = password or email.split('@')[0]
        res = self.post(f'{self.auth_path}/register', {
            'name': email if name_eq_email == 'T' else password,
            'email': email,
            'passwd': password,
            'repasswd': password,
            **({email_code_k: email_code} if email_code else {}),
            **({invite_code_k: invite_code} if invite_code else {}),
            **({'imtype': 1, 'wechat': password} if im_type else {}),
            **({'aff': aff} if aff is not None else {}),
        }).json()
        if res.get('ret'):
            self.email = email
            return None
        if 'msg' in res:
            return res['msg']
        raise Exception(res)

    def login(self, email: str = None, password=None):
        if not email:
            email = self.email
        if 'email' in self.cookies and email == unquote_plus(self.cookies['email']):
            return
        self.reset()
        res = self.post(f'{self.auth_path}/login', {
            'email': email,
            'passwd': password or email.split('@')[0]
        }).json()
        self.raise_for_fail(res)
        self.email = email

    def send_email_code(self, email):
        res = self.post(f'{self.auth_path}/send', {
            'email': email
        }, timeout=60).json()
        self.raise_for_fail(res)

    def buy(self, data):
        res = self.post(
            'user/buy',
            data,
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        ).json()
        self.raise_for_fail(res)

    def checkin(self):
        res = self.post('user/checkin').json()
        if not res.get('ret') and ('msg' not in res or not re_checked_in.search(res['msg'])):
            raise Exception(res)

    def get_sub_url(self, **params) -> str:
        r = self.get('user')
        tag = r.bs().find(attrs={'data-clipboard-text': True})
        if tag:
            sub_url = tag['data-clipboard-text']
            for k, v in parse_qsl(urlsplit(sub_url).query):
                if k == 'url':
                    sub_url = v
                    break
            params = {k: params[k] for k in params.keys() & ('sub', 'clash')}
            if not params:
                params = 'sub=3'
            else:
                params = urlencode(params)
            self.sub_url = f'{sub_url.split("?")[0]}?{params}'
        else:
            self.sub_url = re_var_sub_token.search(r.text)[1]
        return self.sub_url


class HkspeedupSession(Session):
    def reset(self):
        super().reset()
        if hasattr(self, 'email'):
            del self.email

    @staticmethod
    def raise_for_fail(res):
        if res.get('code') != 200:
            raise Exception(res)

    def register(self, email: str, password=None, email_code=None, invite_code=None) -> str | None:
        self.reset()
        password = password or email.split('@')[0]
        res = self.post('user/register', json={
            'email': email,
            'password': password,
            'ensurePassword': password,
            **({'code': email_code} if email_code else {}),
            **({'inviteCode': invite_code} if invite_code else {})
        }).json()
        if res.get('code') == 200:
            self.email = email
            return None
        if 'message' in res:
            return res['message']
        raise Exception(res)

    def login(self, email: str = None, password=None):
        if not email:
            email = self.email
        if 'token' in self.headers and email == self.email:
            return
        self.reset()
        res = self.post('user/login', json={
            'email': email,
            'password': password or email.split('@')[0]
        }).json()
        self.raise_for_fail(res)
        self.headers['token'] = res['data']['token']
        self.email = email

    def send_email_code(self, email):
        res = self.post('user/sendAuthCode', json={
            'email': email
        }, timeout=60).json()
        self.raise_for_fail(res)

    def checkin(self):
        res = self.post('user/checkIn').json()
        if not res.get('ret') and ('message' not in res or not re_checked_in.search(res['message'])):
            raise Exception(res)

    def get_sub_url(self, **params) -> str:
        res = self.get('user/info').json()
        self.raise_for_fail(res)
        self.sub_url = f"{self.base}/subscribe/{res['data']['subscribePassword']}"
        return self.sub_url


class TempEmailSession(Session):
    def get_domains(self) -> list[str]: ...

    def set_email_address(self, address: str): ...

    def get_messages(self) -> list[str]: ...


class MailGW(TempEmailSession):
    def __init__(self):
        super().__init__('api.mail.gw')

    def get_domains(self) -> list[str]:
        r = self.get('domains')
        if r.status_code != 200:
            raise Exception(f'获取 mail.gw 邮箱域名失败: {r}')
        return [item['domain'] for item in r.json()['hydra:member']]

    def set_email_address(self, address: str):
        account = {'address': address, 'password': address.split('@')[0]}
        r = self.post('accounts', json=account)
        if r.status_code != 201:
            raise Exception(f'创建 mail.gw 账户失败: {r}')
        r = self.post('token', json=account)
        if r.status_code != 200:
            raise Exception(f'获取 mail.gw token 失败: {r}')
        self.headers['Authorization'] = f'Bearer {r.json()["token"]}'

    def get_messages(self) -> list[str]:
        messages = []
        r = self.get('messages')
        if r.status_code == 200:
            items = r.json()['hydra:member']
            if items:
                with ThreadPoolExecutor(len(items)) as executor:
                    for r in executor.map(lambda item: self.get(f'messages/{item["id"]}'), items):
                        if r.status_code == 200:
                            messages.append(r.json()['text'])
        return messages


class Snapmail(TempEmailSession):
    def __init__(self):
        super().__init__('snapmail.cc')

    def get_domains(self) -> list[str]:
        r = self.get('scripts/controllers/addEmailBox.js')
        if r.status_code != 200:
            raise Exception(f'获取 snapmail.cc addEmailBox.js 失败: {r}')
        return literal_eval(re_snapmail_domains.search(r.text)[1])

    def set_email_address(self, address: str):
        self.address = address

    def get_messages(self) -> list[str]:
        r = self.get(f'emailList/{self.address}')
        if r.status_code == 200 and isinstance(r.json(), list):
            return [BeautifulSoup(item['html'], 'html.parser').get_text('\n', strip=True) for item in r.json()]
        return []


class MailCX(TempEmailSession):
    def __init__(self):
        super().__init__('api.mail.cx/api/v1/')

    def get_domains(self) -> list[str]:
        r = self.get('https://mail.cx')
        if r.status_code != 200:
            raise Exception(f'获取 mail.cx 页面失败: {r}')
        js_paths = []
        for js in BeautifulSoup(r.text, 'html.parser').find_all('script'):
            if js.has_attr('src') and re_mailcx_js_path.fullmatch(js['src']):
                js_paths.append(js['src'])
        if js_paths:
            executor = ThreadPoolExecutor(len(js_paths))
            try:
                for future in as_completed(executor.submit(self.get, urljoin('https://mail.cx', js_path)) for js_path in js_paths):
                    r = future.result()
                    if r.status_code == 200:
                        m = re_mailcx_domains.search(r.text)
                        if m:
                            return literal_eval(m[1])
            finally:
                executor.shutdown(wait=False, cancel_futures=True)
        return []

    def set_email_address(self, address: str):
        r = self.post('auth/authorize_token')
        if r.status_code != 200:
            raise Exception(f'获取 mail.cx token 失败: {r}')
        self.headers['Authorization'] = f'Bearer {r.json()}'
        self.address = address

    def get_messages(self) -> list[str]:
        messages = []
        r = self.get(f'mailbox/{self.address}')
        if r.status_code == 200:
            items = r.json()
            if items:
                with ThreadPoolExecutor(len(items)) as executor:
                    for r in executor.map(lambda item: self.get(f'mailbox/{self.address}/{item["id"]}'), items):
                        if r.status_code == 200:
                            messages.append(r.json()['body']['text'])
        return messages


class GuerrillaMail(TempEmailSession):
    def __init__(self):
        super().__init__('api.guerrillamail.com/ajax.php')

    def get_domains(self) -> list[str]:
        r = self.get('https://www.spam4.me')
        if r.status_code != 200:
            raise Exception(f'获取 spam4.me 页面失败: {r}')
        return re_guerrillamail_domain.findall(re_guerrillamail_domains.search(r.text)[0])

    def set_email_address(self, address: str):
        r = self.get(f'?f=set_email_user&email_user={address.split("@")[0]}')
        if r.status_code != 200 or not r.text or not r.json().get('email_addr'):
            raise Exception(f'设置 guerrillamail.com 账户失败: {r}')

    def get_messages(self) -> list[str]:
        messages = []
        r = self.get('?f=get_email_list&offset=0')
        if r.status_code == 200 and r.text and int(r.json()['count']) > 0:
            items = r.json()['list']
            if items:
                with ThreadPoolExecutor(len(items)) as executor:
                    for r in executor.map(lambda item: self.get(f'?f=fetch_email&email_id={item["mail_id"]}'), items):
                        if r.status_code == 200 and r.text and r.text != 'false':
                            t = BeautifulSoup(r.json()['mail_body'], 'html.parser').get_text('\n', strip=True)
                            messages.append(t)
        return messages


class TempEmail:
    def __init__(self):
        self.__lock_account = RLock()
        self.__lock = RLock()
        self.__queues: list[tuple[str, Queue, float]] = []

    def get_email(self) -> str:
        with self.__lock_account:
            if not hasattr(self, '_TempEmail__address'):
                sessions = MailGW(), Snapmail(), MailCX(), GuerrillaMail()
                id = get_id()
                domain_len_limit = 31 - len(id)
                with ThreadPoolExecutor(len(sessions)) as executor:
                    def fn(session: TempEmailSession):
                        try:
                            domains = session.get_domains()
                        except Exception as e:
                            domains = []
                            print(e)
                        return session, domains
                    session, domain = choice([(s, d) for s, ds in executor.map(fn, sessions)
                                             for d in ds if len(d) <= domain_len_limit])
                address = f'{id}@{domain}'
                session.set_email_address(address)
                self.__session = session
                self.__address = address
        return self.__address

    def get_email_code(self, keyword) -> str | None:
        queue = Queue(1)
        with self.__lock:
            self.__queues.append((keyword, queue, time() + 60))
            if not hasattr(self, '_TempEmail__th'):
                self.__th = Thread(target=self.__run)
                self.__th.start()
        return queue.get()

    def __run(self):
        while True:
            sleep(1)
            try:
                messages = self.__session.get_messages()
            except Exception as e:
                messages = []
                print(f'TempEmail.__run: {e}')
            with self.__lock:
                new_len = 0
                for item in self.__queues:
                    keyword, queue, end_time = item
                    for message in messages:
                        if keyword in message:
                            m = re_email_code.search(message)
                            queue.put(m[1] if m else m)
                            break
                    else:
                        if time() > end_time:
                            queue.put(None)
                        else:
                            self.__queues[new_len] = item
                            new_len += 1
                del self.__queues[new_len:]
                if new_len == 0:
                    delattr(self, '_TempEmail__th')
                    break
