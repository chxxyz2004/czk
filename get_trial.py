import os
from base64 import b64decode, b64encode
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from itertools import chain
from random import choice
from time import time

from apis import (HkspeedupSession, Session, SSPanelSession, TempEmail,
                  V2BoardSession)
from subconverter import gen_clash_config, get
from utils import (clear_files, get_id, list_file_paths, list_folder_paths,
                   re_non_empty_base64, read, read_cfg, remove, size2str,
                   str2timestamp, timestamp2str, to_zero, write, write_cfg)

PanelSession = V2BoardSession | SSPanelSession | HkspeedupSession

panel_class_map = {
    'v2board': V2BoardSession,
    'sspanel': SSPanelSession,
    'hkspeedup': HkspeedupSession,
}

temp_email = TempEmail()


# 注册/登录/解析/下载


def get_sub(session: PanelSession, opt: dict, cache: dict[str, list[str]]):
    url = cache['sub_url'][0]
    suffix = ' - ' + opt['name']
    if 'speed_limit' in opt:
        suffix += ' ⚠️限速 ' + opt['speed_limit']
    info, *rest = get(url, opt.get('exclude'), suffix)
    if not info and hasattr(session, 'get_sub_info'):
        session.login(cache['email'][0])
        info = session.get_sub_info()
    return info, *rest


def should_turn(session: PanelSession, opt: dict, cache: dict[str, list[str]]):
    if 'sub_url' not in cache:
        return True,

    now = time()
    info, *rest = get_sub(session, opt, cache)

    return (
        not info
        or opt.get('turn') == 'always'
        or float(info['total']) - (float(info['upload']) + float(info['download'])) < (1 << 27)
        or (opt.get('expire') != 'never' and info.get('expire') and str2timestamp(info.get('expire')) - now < ((now - str2timestamp(cache['time'][0])) / 7 if 'reg_limit' in opt else 1600))
    ), info, *rest


def _register(session: PanelSession, email, *args, **kwargs):
    try:
        return session.register(email, *args, **kwargs)
    except Exception as e:
        raise Exception(f'注册失败({email}): {e}')


def register(session: PanelSession, opt: dict):
    kwargs = {k: opt[k] for k in opt.keys() & ('name_eq_email', 'reg_fmt', 'aff')}
    invite_codes = opt.get('invite_code')
    if isinstance(invite_codes, str):
        kwargs['invite_code'] = choice(invite_codes.split())
    email = kwargs['email'] = f'{get_id()}@gmail.com'
    while True:
        if not (msg := _register(session, **kwargs)):
            return
        if '后缀' in msg:
            if email.split('@')[1] != 'gmail.com':
                break
            email = kwargs['email'] = f'{get_id()}@qq.com'
        elif '验证码' in msg:
            try:
                email = kwargs['email'] = temp_email.get_email()
                session.send_email_code(email)
            except Exception as e:
                raise Exception(f'发送邮箱验证码失败({email}): {e}')
            email_code = temp_email.get_email_code(opt['name'])
            if not email_code:
                raise Exception(f'获取邮箱验证码超时({email})')
            kwargs['email_code'] = email_code
        elif '联' in msg:
            kwargs['im_type'] = True
        else:
            break
    raise Exception(f'注册失败({email}): {msg}{" " + kwargs.get("invite_code") if "邀" in msg else ""}')


def is_checkin(session, opt: dict):
    return hasattr(session, 'checkin') and opt.get('checkin') != 'F'


def try_checkin(session: PanelSession, opt: dict, cache: dict[str, list[str]], log: list):
    if is_checkin(session, opt) and cache.get('email'):
        if len(cache['last_checkin']) < len(cache['email']):
            cache['last_checkin'] += ['0'] * (len(cache['email']) - len(cache['last_checkin']))
        last_checkin = to_zero(str2timestamp(cache['last_checkin'][0]))
        now = time()
        if now - last_checkin > 24.5 * 3600:
            try:
                session.login(cache['email'][0])
                session.checkin()
                cache['last_checkin'][0] = timestamp2str(now)
                cache.pop('尝试签到失败', None)
            except Exception as e:
                cache['尝试签到失败'] = [e]
                log.append(f'尝试签到失败({session.host}): {e}')
    else:
        cache.pop('last_checkin', None)


def do_turn(session: PanelSession, opt: dict, cache: dict[str, list[str]], log: list) -> bool:
    is_new_reg = False
    reg_limit = opt.get('reg_limit')
    if not reg_limit:
        register(session, opt)
        is_new_reg = True
        cache['email'] = [session.email]
        if is_checkin(session, opt):
            cache['last_checkin'] = ['0']
    else:
        if len(cache['email']) < int(reg_limit):
            register(session, opt)
            is_new_reg = True
            cache['email'].append(session.email)
            if is_checkin(session, opt):
                cache['last_checkin'] += ['0'] * (len(cache['email']) - len(cache['last_checkin']))
        elif len(cache['email']) > int(reg_limit):
            del cache['email'][:-int(reg_limit)]
            if is_checkin(session, opt):
                del cache['last_checkin'][:-int(reg_limit)]

        cache['email'] = cache['email'][-1:] + cache['email'][:-1]
        if is_checkin(session, opt):
            cache['last_checkin'] = cache['last_checkin'][-1:] + cache['last_checkin'][:-1]

    try:
        session.login(cache['email'][0])
    except Exception as e:
        raise Exception(f'登录失败: {e}')

    if 'buy' in opt:
        try:
            session.buy(opt['buy'])
        except Exception as e:
            log.append(f'购买失败({session.host}): {e}')

    try_checkin(session, opt, cache, log)
    cache['sub_url'] = [session.get_sub_url(**opt)]
    cache['time'] = [timestamp2str(time())]
    log.append(f'{"更新订阅链接(新注册)" if is_new_reg else "续费续签"}({session.host}) {cache["sub_url"][0]}')


def try_turn(session: PanelSession, opt: dict, cache: dict[str, list[str]], log: list):
    cache.pop('更新旧订阅失败', None)
    cache.pop('更新订阅链接/续费续签失败', None)
    cache.pop('获取订阅失败', None)

    try:
        turn, *sub = should_turn(session, opt, cache)
    except Exception as e:
        cache['更新旧订阅失败'] = [e]
        log.append(f'更新旧订阅失败({session.host})({cache["sub_url"][0]}): {e}')
        return None

    if turn:
        try:
            do_turn(session, opt, cache, log)
        except Exception as e:
            cache['更新订阅链接/续费续签失败'] = [e]
            log.append(f'更新订阅链接/续费续签失败({session.host}): {e}')
            return sub
        try:
            sub = get_sub(session, opt, cache)
        except Exception as e:
            cache['获取订阅失败'] = [e]
            log.append(f'获取订阅失败({session.host})({cache["sub_url"][0]}): {e}')

    return sub


def cache_sub_info(info, opt: dict, cache: dict[str, list[str]]):
    if not info:
        raise Exception('no sub info')
    used = float(info["upload"]) + float(info["download"])
    total = float(info["total"])
    rest = '(剩余 ' + size2str(total - used)
    if opt.get('expire') == 'never' or not info.get('expire'):
        expire = '永不过期'
    else:
        ts = info['expire']
        if isinstance(ts, str):
            ts = str2timestamp(ts)
        expire = timestamp2str(ts)
        rest += ' ' + str(timedelta(seconds=ts - time()))
    rest += ')'
    cache['sub_info'] = [size2str(used), size2str(total), expire, rest]


def save_sub_base64(base64, host):
    if not re_non_empty_base64.fullmatch(base64):
        raise Exception('no base64' if base64 else 'no content')
    write(f'trials/{host}', base64)


def save_sub_clash(clash, host):
    gen_clash_config(f'trials/{host}.yaml', f'trials_providers/{host}', clash)


def save_sub(info, base64, clash, base64_url, clash_url, host, opt: dict, cache: dict[str, list[str]], log: list):
    cache.pop('保存订阅信息失败', None)
    cache.pop('保存base64订阅失败', None)
    cache.pop('保存clash订阅失败', None)

    try:
        cache_sub_info(info, opt, cache)
    except Exception as e:
        cache['保存订阅信息失败'] = [e]
        log.append(f'保存订阅信息失败({host})({clash_url}): {e}')
    try:
        save_sub_base64(base64, host)
    except Exception as e:
        cache['保存base64订阅失败'] = [e]
        log.append(f'保存base64订阅失败({host})({base64_url}): {e}')
    try:
        save_sub_clash(clash, host)
    except Exception as e:
        cache['保存clash订阅失败'] = [e]
        log.append(f'保存clash订阅失败({host})({clash_url}): {e}')


def get_and_save(session: PanelSession, opt: dict, cache: dict[str, list[str]], log: list):
    try_checkin(session, opt, cache, log)
    sub = try_turn(session, opt, cache, log)
    if sub:
        save_sub(*sub, session.host, opt, cache, log)


def get_trial(Class, host, opt: dict, cache: dict[str, list[str]]):
    log = []
    session = Class(host, **{k: opt[k] for k in opt.keys() & ('auth_path',)})
    get_and_save(session, opt, cache, log)
    return log


def get_ip_info():
    try:
        return ['  '.join(Session().get_ip_info())]
    except Exception as e:
        return [f'获取 ip 信息失败 {e}']


def build_options(cfg):
    opt = {
        host: dict(zip(opt[::2], opt[1::2]))
        for host, *opt in chain(*(cfg[k] for k in panel_class_map))
    }
    for host, _opt in opt.items():
        _opt.setdefault('name', host)
    return opt


if __name__ == '__main__':
    pre_repo = read('.github/repo_get_trial')
    cur_repo = os.getenv('GITHUB_REPOSITORY')
    if pre_repo != cur_repo:
        remove('trial.cache')
        write('.github/repo_get_trial', cur_repo)

    cfg = read_cfg('trial.cfg')

    opt = build_options(cfg)

    cache = read_cfg('trial.cache', dict_items=True)

    for host in [*cache]:
        if host not in opt:
            del cache[host]

    for path in list_file_paths('trials'):
        host, ext = os.path.splitext(os.path.basename(path))
        if ext != '.yaml':
            host += ext
        else:
            host = host.split('_')[0]
        if host not in opt:
            remove(path)

    for path in list_folder_paths('trials_providers'):
        host = os.path.basename(path)
        if '.' in host and host not in opt:
            clear_files(path)
            remove(path)

    with ThreadPoolExecutor(32) as executor:
        f_ip_info = executor.submit(get_ip_info)

        args = [(v, h, opt[h], cache[h]) for k, v in panel_class_map.items() for h, *_ in cfg[k]]

        logs = executor.map(get_trial, *zip(*args))

        for log in chain((f.result() for f in [f_ip_info]), logs):
            for line in log:
                print(line)

    nodes, total_node_n = b'', 0

    for host in opt:
        cur_nodes = b64decode(read(f'trials/{host}', True))
        node_n = cur_nodes.count(b'\n')
        if (d := node_n - (int(cache[host]['node_n'][0]) if 'node_n' in cache[host] else 0)) != 0:
            print(f'{host} 节点数 {"+" if d > 0 else ""}{d} ({node_n})')
        cache[host]['node_n'] = node_n
        nodes += cur_nodes
        total_node_n += node_n

    print('总节点数', total_node_n)

    write_cfg('trial.cache', cache)

    write('trial', b64encode(nodes))

    gen_clash_config(
        'trial.yaml',
        'trials_providers',
        providers_dirs=(path for path in list_folder_paths('trials_providers') if '.' in os.path.basename(path))
    )
