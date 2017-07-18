import os

from clint.textui import puts, colored

from fnmatch import compile_pattern


class Blocker:
    def __init__(self):
        self.block_list = self.load_block_list_from_file()
        self.white_list = set()

    def load_block_list_from_file(self):
        block_list = []

        block_rules_file_path = os.path.join(
            os.environ['ANTICRAP_RULES_DIR'],
            'block.txt'
        )

        with open(block_rules_file_path) as file_obj:
            for unstripped_line in file_obj:
                line = unstripped_line.split('#')[0].strip()
                if not line:
                    continue

                # *.facebook.com referred
                path, *options = line.split(' ')  # NOQA
                if 'literal' in options:
                    paths = (path,)
                else:
                    paths = (
                        '*://{}*'.format(path),  # The domain
                        '*://*.{}*'.format(path),  # The subdomains
                    )

                for path in paths:
                    pattern = compile_pattern(os.path.normcase(path))
                    block_list.append((path, pattern, options))

        return block_list

    def analyse(self, proxy, req, req_body):
        referer = proxy.headers.get('Referer', None)
        path = req.path
        host = proxy.headers.get('Host', None)

        for entry, pattern, options in self.block_list:
            if pattern(path) is not None:
                if not referer or 'referred' in options and host in referer:
                    return

                puts(colored.yellow('BLOCKING `{}` (rule: `{}` {})'.format(path, entry, options)))
                if referer and 'referred' in options:
                    puts(colored.yellow(' Referer: {}'.format(referer)))
                return False

        if referer is not None and host not in referer:
            puts(colored.cyan('ALLOWING `{}` (referrer: {})'.format(path, referer)))
