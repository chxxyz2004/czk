import os
from concurrent.futures import ThreadPoolExecutor
from subprocess import getoutput

from apis import Session
from utils import list_file_paths

GITHUB_REPOSITORY = os.getenv('GITHUB_REPOSITORY')


def get_short_url(name: str = None):
    return f"https://goo.gs/{get_alias(name)}"


def get_alias(name: str = None):
    if GITHUB_REPOSITORY == 'zsokami/sub':
        if name == 'yaml':
            return 'ty'
        elif name:
            return f"t_{name}"
        else:
            return 'trial'
    else:
        repo = GITHUB_REPOSITORY.replace('/', '__')
        if name:
            return f"gh__{repo}__t_{name}"
        else:
            return f"gh__{repo}__trial"


if __name__ == '__main__':
    gh_raw_url_prefix = f"https://cdn.jsdelivr.net/gh/{GITHUB_REPOSITORY}@{getoutput('git rev-parse HEAD')}"

    if GITHUB_REPOSITORY == 'zsokami/sub':
        API_KEY = os.getenv('API_KEY')
    else:
        API_KEY = 'wMZJfKSns5lLIZ7if32owHe9w06EVAV6ZjbnCoeFs65PNN95lrwDxnKSGAMV'

    def upsert(name, url):
        session = Session('goo.gs/api/v1/links/')
        session.headers['Authorization'] = f"Bearer {API_KEY}"
        alias = get_alias(name)
        try:
            items = session.get(params={'search': alias, 'by': 'alias'}).json()['data']
            item = next((item for item in items if item['alias'] == alias), None)
            if item:
                r = session.put(str(item['id']), data={'url': url})
            else:
                r = session.post(data={'url': url, 'alias': alias})
            if 200 <= r.status_code < 300:
                return r.json()['data']['short_url']
            else:
                return r
        except Exception as e:
            return f"{alias}: {e}"

    names_and_urls = [
        ('base64', f"{gh_raw_url_prefix}/trial"),
        ('', f"{gh_raw_url_prefix}/trial.yaml"),
        ('yaml', f"{gh_raw_url_prefix}/trial_pp.yaml")
    ]

    descriptions = [
        'base64 版',
        'clash 硬编码版',
        'clash 提供器版'
    ]

    for path in list_file_paths('trials_providers'):
        name = os.path.splitext(os.path.basename(path))[0]
        names_and_urls.append((name, f"{gh_raw_url_prefix}/{path}"))
        descriptions.append(name)

    with ThreadPoolExecutor(len(names_and_urls)) as executor:
        for r, description in zip(executor.map(upsert, *zip(*names_and_urls)), descriptions):
            print(f'{description}: {r}')
