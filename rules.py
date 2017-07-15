import json
import os
import re

from utils import eprint


block = []
allow = []

rules_dir = os.environ.get('ANTICRAP_RULES_DIR', 'rules')

block_rules_file_path = os.path.join(rules_dir, 'block.json')
allow_rules_file_path = os.path.join(rules_dir, 'allow.json')


def load_rules():
    global block
    global allow

    if os.path.exists(block_rules_file_path):
        with open(block_rules_file_path) as file_object:
            block = json.load(file_object)
            eprint('{} block rules loaded.'.format(len(block)))

    if os.path.exists(allow_rules_file_path):
        with open(allow_rules_file_path) as file_object:
            allow = json.load(file_object)
            eprint('{} allow rules loaded.'.format(len(allow)))


def persist_rules():
    global block
    global allow
    global block_rules_file_path
    global allow_rules_file_path

    with open(block_rules_file_path, 'w') as file_object:
        json.dump(block, file_object)

    with open(allow_rules_file_path, 'w') as file_object:
        json.dump(allow, file_object)


def is_affirmative(text):
    print(text + ' ')
    return input().lower() in ('y', 's', 'yes', 'sim', 'si', 'sí', '1')


def modify(proxy, req, req_body):
    return


def should_block(proxy, req, req_body):
    global block

    values = {
        'referer': proxy.headers.get('Referer', None),
        'host': proxy.headers.get('Host', None),
        'path': req.path,
        'filename': os.path.basename(req.path),
    }

    for rule in block:
        for key, regexp in rule.items():
            value = values.get(key)
            if not re.match(regexp, value):
                break
        else:
            eprint('BLOCKING:', values)
            eprint('RULE:', rule)
            return True

    eprint('NOT BLOCKING:', values)

    return False


def should_allow(proxy, req, req_body):
    global allow

    values = {
        'referer': proxy.headers.get('Referer', None),
        'host': proxy.headers.get('Host', None),
        'path': req.path,
        'filename': os.path.basename(req.path),
    }

    for rule in allow:
        for key, regexp in rule.items():
            value = values.get(key)
            if not re.match(regexp, value):
                break
        else:
            eprint('ALLOWING:', values)
            eprint('RULE:', rule)
            return True

    eprint('NOT ALLOWING:', values)

    return False


def add_to_should_block(*args, **kwargs):
    global block
    """
    {
        'referer': 'http://www.ahnegao.com.br/',
        'path': 'http://www.mtvnlatservices.com/inhouse/finosf/ads.gpt.dfp.js',
        'filename': 'ads.gpt.dfp.js',
        'host': 'www.mtvnlatservices.com'
    }
    """
    based_on = {
        'referer': is_affirmative('Block based on REFERER ({})?'.format(kwargs['referer'])),
        'host': is_affirmative('Block based on HOST ({})?'.format(kwargs['host'])),
        'filename': is_affirmative('Block based on FILE NAME ({})?'.format(kwargs['filename'])),
        'path': is_affirmative('Block based on PATH ({})?'.format(kwargs['path'])),
    }

    regexps = {}

    for key, use_it in based_on.items():
        if not use_it:
            continue

        suggested_regexp = "^{}$".format(kwargs[key])
        regexp = input(' Regular expression for `{}` [{}]: '.format(key, suggested_regexp))
        if regexp == '':
            regexp = suggested_regexp

        regexps[key] = regexp

    block.append(regexps)
    persist_rules()


def add_to_should_allow(*args, **kwargs):
    global allow
    """
    {
        'referer': 'http://www.ahnegao.com.br/',
        'path': 'http://www.mtvnlatservices.com/inhouse/finosf/ads.gpt.dfp.js',
        'filename': 'ads.gpt.dfp.js',
        'host': 'www.mtvnlatservices.com'
    }
    """
    based_on = {
        'referer': is_affirmative('Allow based on REFERER ({})?'.format(kwargs['referer'])),
        'host': is_affirmative('Allow based on HOST ({})?'.format(kwargs['host'])),
        'filename': is_affirmative('Allow based on FILE NAME ({})?'.format(kwargs['filename'])),
        'path': is_affirmative('Allow based on PATH ({})?'.format(kwargs['path'])),
    }

    regexps = {}

    for key, use_it in based_on.items():
        if not use_it:
            continue

        suggested_regexp = "^{}$".format(kwargs[key])
        regexp = input(' Regular expression for `{}` [{}]: '.format(key, suggested_regexp))
        if regexp == '':
            regexp = suggested_regexp

        regexps[key] = regexp

    allow.append(regexps)
    persist_rules()


def block_the_domain(*args, **kwargs):
    host = kwargs['host']

    parts = host.split('.')
    relevant_part = '.'.join(parts[-2:])
    regexp = '.+{}'.format(relevant_part)

    block.append({'host': regexp})
    persist_rules()
