import os
from hashlib import md5

from clint.textui import puts, colored

from fnmatch import compile_pattern


class HardCache:
    def __init__(self):
        self.base_dir = '/tmp/hard-cache/'
        self.must_cache_list = self.load_must_cache_list_from_file()

        if not os.path.isdir(self.base_dir):
            os.makedirs(self.base_dir)

    def load_must_cache_list_from_file(self):
        must_cache_list = []

        rules_file_path = os.path.join(
            os.environ['ANTICRAP_RULES_DIR'],
            'must-cache.txt'
        )

        with open(rules_file_path) as file_obj:
            for unstripped_line in file_obj:
                line = unstripped_line.split('#')[0].strip()
                if not line:
                    continue

                # *.facebook.com/blebs.js
                pattern = compile_pattern(os.path.normcase(line))
                must_cache_list.append((line, pattern))

        return must_cache_list

    def get_cache_key(self, path):
        filename = os.path.basename(path)
        only_filename, extension = os.path.splitext(filename)
        _hash = md5(bytes(path, 'utf-8')).hexdigest()

        cache_key = '{}-{}.{}'.format(only_filename, _hash, extension)
        return cache_key

    def get_file_path(self, path):
        key = self.get_cache_key(path)
        return os.path.join(self.base_dir, key)

    def key_exists(self, path):
        return os.path.isfile(self.get_file_path(path))

    def analyse(self, proxy, req, req_body):
        path = req.path

        for entry, pattern in self.must_cache_list:
            if pattern(path) is not None:
                if self.key_exists(path):
                    puts(colored.white('CACHED: `{}` (rule: `{}`)'.format(path, entry)))
                    with open(self.get_file_path(path), 'rb') as fobj:
                        return fobj.read()
                else:
                    puts(colored.yellow('NOT CACHED: `{}` (rule: `{}`)'.format(path, entry)))

                return None

    def analyse_response(self, proxy, req, req_body, res, res_body):
        path = req.path

        for entry, pattern in self.must_cache_list:
            if pattern(path) is not None:
                if not self.key_exists(path):
                    with open(self.get_file_path(path), 'wb') as fobj:
                        puts(colored.white('SAVING IN CACHE: `{}` (rule: `{}`)'.format(path, entry)))
                        fobj.write(res_body)

                return None
