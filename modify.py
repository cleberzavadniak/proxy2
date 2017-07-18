import os

import bs4

from fnmatch import compile_pattern


class Modifier:
    def __init__(self):
        self.modify_list = self.load_modify_list_from_file()

    def load_modify_list_from_file(self):
        modify_list = {}

        modify_rules_file_path = os.path.join(
            os.environ['ANTICRAP_RULES_DIR'],
            'modify.txt'
        )

        url = None
        entry = None
        with open(modify_rules_file_path) as file_obj:
            for unstripped_line in file_obj:
                line = unstripped_line.strip()

                if not line:
                    continue

                elif line.startswith('## '):
                    parts = line[3:].split(' ')

                    entry = {
                        'element': ' '.join(parts[0:-1]),
                        'operation': parts[-1],
                        'content': [],
                    }
                    modify_list[url].append(entry)

                elif line.startswith('# '):
                    url = compile_pattern(os.path.normcase(line[2:]))
                    modify_list[url] = []

                else:
                    entry['content'].append(line)

        return modify_list

    def analyse(self, proxy, req, req_body, res, res_body):
        for pattern, modifiers in self.modify_list.items():
            if pattern(req.path):
                soup = bs4.BeautifulSoup(res_body, 'html.parser')

                for modifier in modifiers:
                    temp_soup = bs4.BeautifulSoup('\n'.join(modifier['content']), 'html.parser')
                    contents = temp_soup.contents

                    for element in soup.find_all(modifier['element']):
                        method = getattr(element, modifier['operation'])
                        for item in contents:
                            method(item)

                return bytes(soup.prettify(), 'utf-8')
