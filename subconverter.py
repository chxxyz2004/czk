import os
from collections import defaultdict
from copy import deepcopy
from random import randint
from threading import RLock
from time import time
from urllib.parse import quote, urljoin

from ruamel.yaml import YAML, CommentedMap

from apis import Session
from get_trial_update_url import get_short_url
from utils import (DOMAIN_SUFFIX_Tree, IP_CIDR_SegmentTree, clear_files,
                   list_file_paths, read, read_cfg, write)

github_raw_url_prefix = f"https://ghproxy.com/https://raw.githubusercontent.com/{os.getenv('GITHUB_REPOSITORY')}/{os.getenv('GITHUB_REF_NAME')}"

subconverters = [row[0] for row in read_cfg('subconverters.cfg')['default']]
exclude_en = quote(
    'Data Left|Traffic|Expir[ey]|剩[余餘]流量|[到过過效]期|[时時][间間]|重置|官.?网|官方|产品|平台|勿连|修复|更新|地址|网站|网址|售后|客服|联系|使用|购买|公告|版本|出现|没网|情况|开通|数量|分割线'
)


def _yaml():
    yaml = YAML()
    yaml.version = (1, 1)
    yaml.width = float('inf')
    return yaml


base_yaml: CommentedMap = read('base.yaml', reader=_yaml().load)
group_to_provider_map = {g['name']: g['use'][0] for g in base_yaml['proxy-groups'] if 'use' in g}


def _get_by_any(session: Session, url):
    if session.host:
        try:
            res = session.get(url)
            if res.status_code == 200:
                return res
        except Exception:
            pass
    idx_map = {}
    for i in range(len(subconverters) - 1, -1, -1):
        j = randint(0, i)
        session.set_host(subconverters[idx_map.get(j, j)])
        idx_map[j] = idx_map.get(i, i)
        try:
            res = session.get(url)
            if res.status_code == 200:
                return res
        except Exception:
            pass
    raise Exception(f'_get_by_any: 全部后端获取失败({url})')


_lock_rules = RLock()
_rules = None


def _get_rules():
    global _rules
    with _lock_rules:
        if not _rules:
            session = Session(user_agent='ClashforWindows')
            url = f"sub?target=clash&config={quote(f'https://goo.gs/config#{time()}')}&url=ss://YWVzLTEyOC1nY206YWJj@c.c:1%231"
            try:
                res = _get_by_any(session, url)
                cfg = _yaml().load(res.content)
                _rules = _remove_redundant_rules(cfg['rules'])
            except Exception as e:
                raise Exception(f'get_rules: 获取规则失败: {e}')
    return _rules


def _remove_redundant_rules(rules):
    keywords = []
    domain_tree = DOMAIN_SUFFIX_Tree()
    ip_trees = defaultdict(IP_CIDR_SegmentTree)
    sets = defaultdict(set)
    i = 0
    for rule in rules:
        t, v, *_ = rule.split(',')
        if t.startswith('DOMAIN'):
            if any(w in v for w in keywords):
                continue
            if t == 'DOMAIN-KEYWORD':
                keywords.append(v)
            elif not domain_tree.add(v, t == 'DOMAIN-SUFFIX'):
                continue
        elif 'IP-CIDR' in t:
            if not ip_trees[t].add(v):
                continue
        else:
            if v in sets[t]:
                continue
            sets[t].add(v)
        rules[i] = rule
        i += 1
    del rules[i:]
    return rules


def get(url, exclude=None, suffix=None):
    session = Session(user_agent='ClashforWindows')
    if exclude:
        exclude = exclude_en + quote(f'|{exclude}')
    else:
        exclude = exclude_en
    params = f"exclude={exclude}&config={quote(f'https://goo.gs/config#{time()}')}&url={quote(f'{url}#{time()}')}"
    if suffix:
        params += '&rename=' + quote(f'$@{suffix}')
    clash_url = f'sub?target=clash&udp=true&scv=true&expand=false&classic=true&{params}'
    base64_url = f'sub?target=mixed&{params}'

    res = _get_by_any(session, clash_url)
    info = res.headers.get('subscription-userinfo')
    if info:
        info = dict(kv.split('=') for kv in info.split('; '))
    clash = res.content
    clash_url = urljoin(session.base, clash_url)

    res = _get_by_any(session, base64_url)
    base64 = res.content
    base64_url = urljoin(session.base, base64_url)

    return info, base64, clash, base64_url, clash_url


def _parse_node_groups(y: YAML, clash):
    cfg = y.load(clash)
    name_to_node_map = {p['name']: p for p in cfg['proxies']}
    provider_map = {}
    for g in cfg['proxy-groups']:
        name, proxies = g['name'], g['proxies']
        if (
            name in group_to_provider_map
            and group_to_provider_map[name] not in provider_map
            and proxies[0] != 'DIRECT'
        ):
            provider_map[group_to_provider_map[name]] = proxies
    return name_to_node_map, provider_map, cfg['proxies']


def _read_and_merge_providers(y: YAML, providers_dirs):
    name_to_node_map = {}
    provider_map = defaultdict(list)
    for providers_dir in providers_dirs:
        for path in list_file_paths(providers_dir):
            name = os.path.splitext(os.path.basename(path))[0]
            if not name.startswith('p_'):
                proxies = read(path, reader=y.load)['proxies']
                name_to_node_map |= ((node['name'], node) for node in proxies)
                provider_map[name] += (node['name'] for node in proxies)
    return name_to_node_map, provider_map, [*name_to_node_map.values()]


def _split_providers(provider_map: dict[str, list[str]]):
    node_to_providers = defaultdict(list)
    for k, v in provider_map.items():
        for node in v:
            node_to_providers[node].append(k)

    providers_to_nodes = defaultdict(list)
    for k, v in node_to_providers.items():
        providers_to_nodes[tuple(v)].append(k)

    provider_to_providers = defaultdict(list)
    for k in providers_to_nodes:
        for provider in k:
            provider_to_providers[provider].append(k)

    to_real_providers_kvs = []
    providers_to_name = {}
    providers_set = set()
    for k, v in provider_to_providers.items():
        v_t = tuple(v)
        if v_t not in providers_set:
            providers_set.add(v_t)
            if len(v) == 1:
                providers_to_name[v[0]] = k
            to_real_providers_kvs.append((k, v))

    real_provider_kvs = []
    for k, v in providers_to_nodes.items():
        if k not in providers_to_name:
            providers_to_name[k] = f"p_{'_'.join(k)}"
        real_provider_kvs.append((providers_to_name[k], v))

    to_order = defaultdict(lambda: 99, ((k, i) for i, k in enumerate(base_yaml['proxy-providers'])))

    for k, v in to_real_providers_kvs:
        for i, providers in enumerate(v):
            v[i] = providers_to_name[providers]
        v.sort(key=lambda k: to_order[k])

    to_real_providers_kvs.sort(key=lambda kv: to_order[kv[0]])
    to_real_providers = dict(to_real_providers_kvs)
    real_provider_kvs.sort(key=lambda kv: to_order[kv[0]])
    real_provider_map = dict(real_provider_kvs)

    return to_real_providers, real_provider_map


def _split_and_write_providers(y: YAML, providers_dir, clash=None, providers_dirs=None):
    if clash:
        name_to_node_map, provider_map, all_proxies = _parse_node_groups(y, clash)
    else:
        name_to_node_map, provider_map, all_proxies = _read_and_merge_providers(y, providers_dirs)
    to_real_providers, real_provider_map = _split_providers(provider_map)
    clear_files(providers_dir)
    for k, v in (provider_map | real_provider_map).items():
        write(
            f'{providers_dir}/{k}.yaml',
            lambda f: y.dump({'proxies': [name_to_node_map[name] for name in v]}, f)
        )
    provider_map = {k: provider_map[k] for k in to_real_providers}
    real_providers = [*real_provider_map]
    return provider_map, to_real_providers, real_providers, all_proxies


def _add_proxy_providers(cfg, real_providers, providers_dir, use_short_url):
    providers = {}
    base_provider = base_yaml['proxy-providers']['All']
    for k in real_providers:
        provider = deepcopy(base_provider)
        if use_short_url:
            provider['url'] = get_short_url(k)
        else:
            provider['url'] = f'{github_raw_url_prefix}/{providers_dir}/{k}.yaml'
        provider['path'] = f'{providers_dir}/{k}.yaml'
        providers[k] = provider
    cfg['proxy-providers'] = providers


def _remove_redundant_groups(cfg, provider_map):
    groups = cfg['proxy-groups']
    removed_groups = set()
    i = 0
    for g in groups:
        if 'use' in g and g['use'][0] not in provider_map:
            removed_groups.add(g['name'])
        else:
            groups[i] = g
            i += 1
    del groups[i:]
    for g in groups:
        proxies = g.get('proxies')
        if proxies:
            i = 0
            for name in proxies:
                if name not in removed_groups:
                    proxies[i] = name
                    i += 1
            del proxies[i:]


def _to_real_providers(cfg, to_real_providers):
    for g in cfg['proxy-groups']:
        if 'use' in g:
            g['use'] = to_real_providers[g['use'][0]]


def _to_proxies(cfg, provider_map):
    health_check = base_yaml['proxy-providers']['All']['health-check']
    for g in cfg['proxy-groups']:
        if 'use' in g:
            if g['type'] != 'select':
                g['url'] = health_check['url']
                g['interval'] = health_check['interval']
            g['proxies'] = provider_map[g['use'][0]]
            del g['use']


def gen_clash_config(config_path, providers_dir, clash=None, providers_dirs=None):
    y = _yaml()
    split_result = _split_and_write_providers(y, providers_dir, clash, providers_dirs)
    provider_map, to_real_providers, real_providers, all_proxies = split_result

    cfg = deepcopy(base_yaml)
    del cfg['proxy-providers']
    _remove_redundant_groups(cfg, provider_map)
    hardcode_cfg = deepcopy(cfg)

    _to_real_providers(cfg, to_real_providers)
    _add_proxy_providers(cfg, real_providers, providers_dir, config_path == 'trial.yaml')
    cfg['rules'] = _get_rules()

    _to_proxies(hardcode_cfg, provider_map)
    hardcode_cfg['proxies'] = all_proxies
    hardcode_cfg['rules'] = _get_rules()

    write(config_path, lambda f: y.dump(hardcode_cfg, f))
    prefix, ext = os.path.splitext(config_path)
    write(f'{prefix}_pp{ext}', lambda f: y.dump(cfg, f))
