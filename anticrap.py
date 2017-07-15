import os.path
import time
import queue

import rules
from utils import eprint


questions_queue = queue.Queue()


class Question:
    def __init__(self, text, options, handler_arguments):
        self.text = text
        self.options = options
        self.handler_arguments_args, self.handler_arguments_kwargs = handler_arguments
        self.is_answered = False
        self.handler = None
        self.handled = False
        self.must_skip = False

    def enqueue_and_wait(self):
        global questions_queue

        questions_queue.put(self)

        while not self.is_answered:
            time.sleep(1)

    def run(self):

        options_map = {}
        counter = 0
        options_texts = []
        for option_text, option_handler, is_assinc in self.options:
            key = str(counter)
            options_map[key] = (option_handler, is_assinc)
            options_texts.append(' {}: {}'.format(key, option_text))
            counter += 1

        while True:
            print('\nAC> {}'.format(self.text))
            print('\n'.join(options_texts))
            print('> ',)
            answer = input()
            handler_tuple = options_map.get(answer, None)
            if handler_tuple is None:
                continue

            handler, is_assinc = handler_tuple

            self.handler = handler
            if not is_assinc:
                self.handle('HANDLING ON ANTICRAP THREAD')
            self.is_answered = True

            break

    def handle(self, msg):
        if not self.handled:
            eprint(msg)
            self.handler(self, *self.handler_arguments_args, **self.handler_arguments_kwargs)
            self.handled = True


def skip(question, *args, **kwargs):
    eprint('SKIPPING:', args, kwargs)
    question.must_skip = True


def ask_for_block_or_allow(proxy, req, req_body, question_class=Question):
    referer = proxy.headers.get('Referer', None)
    host = proxy.headers.get('Host', None)
    path = req.path
    filename = os.path.basename(path)

    question = question_class("`{}` is trying to download `{}` from `{}`!".format(
        referer, path, host
    ), (
        ('Block this entire domain NOW!', rules.block_the_domain, False),
        ('Block', rules.add_to_should_block, False),
        ('Allow', rules.add_to_should_allow, False),
        ('Skip', skip, True),
    ), ((), {
        'referer': referer,
        'path': path,
        'filename': filename,
        'host': host
    }))

    question.enqueue_and_wait()
    question.handle('HANDLING OUTSIDE ANTICRAP THREAD')
    return question


def apply_request_rules(proxy, req, req_body):
    referer = proxy.headers.get('Referer', None)
    host = proxy.headers.get('Host', None)

    if referer is not None and host not in referer:
        while True:
            if rules.should_allow(proxy, req, req_body):
                return rules.modify(proxy, req, req_body)

            elif rules.should_block(proxy, req, req_body):
                return False

            if questions_queue.empty():
                question = ask_for_block_or_allow(proxy, req, req_body)
                if question.must_skip:
                    return rules.modify(proxy, req, req_body)

                continue

            time.sleep(2)


def run():
    global questions_queue

    eprint('STARTING ANTICRAP')

    while True:
        next_question = questions_queue.get()
        next_question.run()
