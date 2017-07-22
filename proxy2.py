import sys
import os
import socket
import ssl
import select
import threading
import gzip
import zlib
import time
import json
import re
from subprocess import Popen, PIPE

from urllib import parse as url_parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from http.client import HTTPConnection, HTTPSConnection
from socketserver import ThreadingMixIn
from io import BytesIO
from html.parser import HTMLParser

from clint.textui import colored

from utils import puts

import block
import hardcache
import modify


class ForbiddenError(Exception):
    pass


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    address_family = socket.AF_INET6
    daemon_threads = True

    def handle_error(self, request, client_address):
        # surpress socket/ssl related errors
        cls, e = sys.exc_info()[:2]
        if cls is socket.error or cls is ssl.SSLError:
            pass
        else:
            return HTTPServer.handle_error(self, request, client_address)


class ProxyRequestHandler(BaseHTTPRequestHandler):
    cakey = 'certs/ca.key'
    cacert = 'certs/ca.crt'
    certkey = 'certs/cert.key'
    certdir = 'certs/certs/'
    timeout = 5
    lock = threading.Lock()
    version_table = {10: 'HTTP/1.0', 11: 'HTTP/1.1'}

    def __init__(self, *args, **kwargs):
        self.tls = threading.local()
        self.tls.conns = {}
        self.has_certs_for = []
        self.has_ca = False

        try:
            BaseHTTPRequestHandler.__init__(self, *args, **kwargs)
        except ConnectionResetError as ex:  # NOQA
            puts(colored.red('{}: {} | {}'.format(ex, args, kwargs)))

    def log_message(self, format, *args):
        pass

    def log_error(self, format, *args):
        if isinstance(args[0], socket.timeout):
            return

        self.log_message(format, *args)

    def send_error(self, error_number, reason=None):
        try:
            return super().send_error(error_number, reason)
        except BrokenPipeError as ex:  # NOQA
            puts(colored.red('{} on send_error({}, {})'.format(ex, error_number, reason)))

    def do_CONNECT(self):
        if self.has_ca:
            return self.connect_intercept()

        if os.path.isfile(self.cakey) and os.path.isfile(self.cacert) and os.path.isfile(self.certkey) and os.path.isdir(self.certdir):
            self.has_ca = True
            return self.connect_intercept()

        return self.connect_relay()

    def connect_intercept(self):
        hostname = self.path.split(':')[0]
        certpath = "{}/{}.crt".format(self.certdir.rstrip('/'), hostname)
        if certpath not in self.has_certs_for:
            with self.lock:
                if not os.path.isfile(certpath):
                    epoch = str(int(time.time() * 1000))
                    p1 = Popen(["openssl", "req", "-new", "-key", self.certkey, "-subj", "/CN={}".format(hostname)], stdout=PIPE)
                    p2 = Popen(["openssl", "x509", "-req", "-days", "3650", "-CA", self.cacert, "-CAkey", self.cakey, "-set_serial", epoch, "-out", certpath], stdin=p1.stdout, stderr=PIPE)
                    p2.communicate()
                    puts(colored.white('CREATING CERTS FOR {}'.format(hostname)))
                    self.has_certs_for.append(certpath)

        self.output("{} {} {}\r\n".format(self.protocol_version, 200, 'Connection Established'))
        self.output(b'\r\n', None)

        self.connection = ssl.wrap_socket(self.connection, keyfile=self.certkey, certfile=certpath, server_side=True)
        self.rfile = self.connection.makefile("rb", self.rbufsize)
        self.wfile = self.connection.makefile("wb", self.wbufsize)

        conntype = self.headers.get('Proxy-Connection', '')
        if self.protocol_version == "HTTP/1.1" and conntype.lower() != 'close':
            self.close_connection = 0
        else:
            self.close_connection = 1

    def connect_relay(self):
        address = self.path.split(':', 1)
        address[1] = int(address[1]) or 443
        try:
            s = socket.create_connection(address, timeout=self.timeout)
        except Exception:
            self.send_error(502)
            return
        self.send_response(200, 'Connection Established')
        self.end_headers()

        conns = [self.connection, s]
        self.close_connection = 0
        while not self.close_connection:
            rlist, wlist, xlist = select.select(conns, [], conns, self.timeout)
            if xlist or not rlist:
                break
            for r in rlist:
                other = conns[1] if r is conns[0] else conns[0]
                data = r.recv(8192)
                if not data:
                    self.close_connection = 1
                    break
                other.sendall(data)

    def pre_response_handler_used(self, req, req_body):
        data = self.pre_response_handler(req, req_body)
        if data is not None:
            self.output("{} {} {}\r\n".format(self.protocol_version, 200, 'OK'))
            self.send_header('Content-Length', len(data))
            self.send_header('Connection', 'close')
            self.end_headers()
            self.output(data, None)
            return True

    def do_GET(self):
        req = self
        content_length = int(req.headers.get('Content-Length', 0))
        req_body = self.rfile.read(content_length) if content_length else None
        self.make_req_path_complete(req)

        if req.path == 'http://anticrap/certificates/':
            self.send_cacert()
            return

        if self.pre_response_handler_used(req, req_body):
            return

        req_body_modified = self.request_handler(req, req_body)
        if req_body_modified is False:
            self.send_error(403)
            return
        elif req_body_modified is not None:
            req_body = req_body_modified

        if req_body:
            req.headers['Content-Length'] = str(len(req_body))

        try:
            return self.do_remote_GET(req, req_body)
        except ForbiddenError:
            self.send_error(403)
            return

    def make_req_path_complete(self, req):
        if req.path[0] == '/':
            if isinstance(self.connection, ssl.SSLSocket):
                req.path = "https://{}{}".format(req.headers['Host'], req.path)
            else:
                req.path = "http://{}{}".format(req.headers['Host'], req.path)

    def get_url_info(self, path):
        u = url_parse.urlsplit(path)
        scheme, netloc, path = u.scheme, u.netloc, (u.path + '?' + u.query if u.query else u.path)
        assert scheme in ('http', 'https')
        return scheme, netloc, path

    def connect_to(self, scheme, netloc):
        origin = (scheme, netloc)
        if origin not in self.tls.conns:
            if scheme == 'https':
                self.tls.conns[origin] = HTTPSConnection(netloc, timeout=self.timeout)
            else:
                self.tls.conns[origin] = HTTPConnection(netloc, timeout=self.timeout)
        return self.tls.conns[origin]

    def is_success(self, status):
        return status // 100 == 2

    def is_stream_response(self, res):
        return 'Content-Length' not in res.headers and 'no-store' in res.headers.get('Cache-Control', '')

    def do_stream(self, req, req_body, res):
        setattr(res, 'headers', self.filter_headers(res.headers))
        self.relay_streaming(req, res)

        with self.lock:
            self.save_handler(req, req_body, res, '')

    def call_response_handler(self, req, req_body, res, res_body_plain):
        # TEST: modifying response body doen't seem to work on https...
        return res_body_plain

        res_body_modified = self.response_handler(req, req_body, res, res_body_plain)

        if res_body_modified is not None:
            print('MODIFIED!')
            res.headers['Content-Length'] = str(len(res_body_modified))
            return res_body_modified

        return res_body_plain

    def output(self, data, encoding='utf-8', flush=False, help_text=None):
        if encoding:
            bdata = bytes(data, encoding)
        else:
            bdata = data

        try:
            self.wfile.write(bdata)
            if flush:
                self.wfile.flush()
        except (BrokenPipeError, ssl.SSLEOFError) as ex:  # NOQA
            puts(colored.red('OUTPUT ERROR: {}: {} ({}) ({} bytes)'.format(
                type(ex), ex, help_text, len(bdata)
            )))

    def remove_tls_connection(self, origin):
        if origin in self.tls.conns:
            del self.tls.conns[origin]

    def do_remote_GET(self, req, req_body):
        scheme, netloc, path = self.get_url_info(req.path)

        if netloc:
            req.headers['Host'] = netloc
        setattr(req, 'headers', self.filter_headers(req.headers))

        conn = self.connect_to(scheme, netloc)
        try:
            conn.request(self.command, path, req_body, dict(req.headers))
        except ConnectionRefusedError as ex:  # NOQA
            puts(colored.red('CONNECTION ERROR: {}: {}'.format(ex, req.path)))
            return

        try:
            res = conn.getresponse()
            setattr(res, 'headers', res.msg)
            setattr(res, 'response_version', self.version_table[res.version])

            if self.is_stream_response(res):
                return self.do_stream(req, req_body, res)

            for i in range(0, 10):
                res_body = res.read()

                if res.status // 100 != 2 or len(res_body) > 0:
                    break
        except Exception as ex:
            origin = (scheme, netloc)
            self.remove_tls_connection(origin)
            self.send_error(502)
            return

        content_encoding = res.headers.get('Content-Encoding', 'identity')
        res_body_plain = self.decode_content_body(res_body, content_encoding)

        # TEST
        # res_body_plain = self.call_response_handler(req, req_body, res, res_body_plain)
        # res_body = self.encode_content_body(res_body_plain, content_encoding)

        setattr(res, 'headers', self.filter_headers(res.headers))
        self.output("{} {} {}\r\n".format(self.protocol_version, res.status, res.reason), help_text='Response header for {}'.format(req.path))
        for k, v in list(res.headers.items()):
            self.send_header(k, v)
        self.end_headers()

        if len(res_body) == 0 and res.status == 304:  # Not Modified...
            self.wfile.flush()
        else:
            if len(res_body) != int(res.headers.get('Content-Length', 0)):
                print('WRONG SIZE FOR {}: {} versus {}'.format(req.path, len(res_body), res.headers.get('Content-Length')))
            self.output(res_body, None, flush=True, help_text='Response body for {}'.format(req.path))

        with self.lock:
            self.save_handler(req, req_body, res, res_body_plain)

    def relay_streaming(self, req, res):
        puts(colored.magenta('STREAM: {} {}'.format(req.path, res.status)))
        self.output("{} {} {}\r\n".format(self.protocol_version, res.status, res.reason), help_text='Stream response header for {}'.format(req.path))
        self.output('{}'.format(res.headers), help_text='Stream response headers for {}'.format(req.path))

        if res.status == 204:  # No Content
            return

        sys.stdout.flush()
        try:
            while True:
                chunk = res.read(8192)
                if not chunk:
                    break
                self.wfile.write(chunk)
            self.wfile.flush()
        except socket.error as ex:
            # connection closed by client
            puts(colored.red('OUTPUT STREAM ERROR: {}: {} ({})'.format(type(ex), ex, req.path)))

    do_HEAD = do_GET
    do_POST = do_GET
    do_PUT = do_GET
    do_DELETE = do_GET
    do_OPTIONS = do_GET

    def filter_headers(self, headers):
        # http://tools.ietf.org/html/rfc2616#section-13.5.1
        hop_by_hop = ('connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailers', 'transfer-encoding', 'upgrade')
        for k in hop_by_hop:
            del headers[k]

        # accept only supported encodings
        if 'Accept-Encoding' in headers:
            ae = headers['Accept-Encoding']
            filtered_encodings = [x for x in re.split(r',\s*', ae) if x in ('identity', 'gzip', 'x-gzip', 'deflate')]
            headers['Accept-Encoding'] = ', '.join(filtered_encodings)

        return headers

    def encode_content_body(self, text, encoding):
        if encoding == 'identity':
            return text

        if encoding in ('gzip', 'x-gzip'):
            io = BytesIO()
            with gzip.GzipFile(fileobj=io, mode='wb') as f:
                f.write(text)
            return io.getvalue()

        if encoding == 'deflate':
            return zlib.compress(text)

        puts(colored.red('encode_content_body: using identity for {}'.format(encoding)))
        return text

    def decode_content_body(self, data, encoding):
        if encoding == 'identity':
            return data

        if encoding in ('gzip', 'x-gzip'):
            io = BytesIO(data)
            with gzip.GzipFile(fileobj=io, mode='rb') as f:
                return f.read()

        if encoding == 'deflate':
            try:
                return zlib.decompress(data)
            except zlib.error:
                return zlib.decompress(data, -zlib.MAX_WBITS)

        puts(colored.red('decode_content_body: using identity for {}'.format(encoding)))
        return data

    def send_cacert(self):
        with open(self.cacert, 'rb') as f:
            data = f.read()

        self.output("{} {} {}\r\n".format(self.protocol_version, 200, 'OK'))
        self.send_header('Content-Type', 'application/x-x509-ca-cert')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.output(data, None)

    def end_headers(self, *args, **kwargs):
        try:
            super().end_headers(*args, **kwargs)
        except (AttributeError, BrokenPipeError, ssl.SSLEOFError) as ex:  # NOQA
            puts(colored.red('{} on end_headers'.format(ex)))

    def parse_qsl(self, s):
        return '\n'.join("{:<20} {}".format(k, v) for k, v in url_parse.parse_qsl(s, keep_blank_values=True))

    def print_cookies_info(self, req):
        cookie = req.headers.get('Cookie', '')
        if cookie:
            cookie = self.parse_qsl(re.sub(r';\s*', '&', cookie))
            puts(colored.green("==== COOKIE ====\n{}\n".format(cookie)))

    def print_query_parameters_info(self, req):
        u = url_parse.urlsplit(req.path)
        if u.query:
            query_text = self.parse_qsl(u.query)
            puts(colored.green("==== QUERY PARAMETERS ====\n{}\n".format(query_text)))

    def print_authorization_info(self, req):
        auth = req.headers.get('Authorization', '')
        if auth.lower().startswith('basic'):
            token = auth.split()[1].decode('base64')
            puts(colored.red("==== BASIC AUTH ====\n{}\n".format(token)))

    def print_req_body_text(self, req, req_body):
        if req_body is not None:
            req_body_text = None
            content_type = req.headers.get('Content-Type', '')

            if content_type.startswith('application/x-www-form-urlencoded'):
                req_body_text = self.parse_qsl(req_body)
            elif content_type.startswith('application/json'):
                try:
                    json_obj = json.loads(req_body)
                    json_str = json.dumps(json_obj, indent=2)
                    if json_str.count('\n') < 50:
                        req_body_text = json_str
                    else:
                        lines = json_str.splitlines()
                        req_body_text = "{}\n({} lines)".format('\n'.join(lines[:50]), len(lines))
                except ValueError:
                    req_body_text = req_body
            elif len(req_body) < 1024:
                req_body_text = req_body

            if req_body_text:
                puts(colored.green("==== REQUEST BODY ====\n{}\n".format(req_body_text)))

    def print_set_cookie_info(self, res):
        if hasattr(res.headers, 'getheaders'):
            cookies = res.headers.getheaders('Set-Cookie')
        else:
            cookies = res.headers.get_all('Set-Cookie')
        if cookies:
            cookies = '\n'.join(cookies)
            puts(colored.red("==== SET-COOKIE ====\n{}\n".format(cookies)))

    def print_res_body_info(self, res, res_body):
        if res_body is not None:
            res_body_text = None
            content_type = res.headers.get('Content-Type', '')

            if content_type.startswith('application/json'):
                try:
                    json_obj = json.loads(res_body)
                    json_str = json.dumps(json_obj, indent=2)
                    if json_str.count('\n') < 50:
                        res_body_text = json_str
                    else:
                        lines = json_str.splitlines()
                        res_body_text = "{}\n({} lines)".format('\n'.join(lines[:50]), len(lines))
                except ValueError:
                    res_body_text = res_body
            elif content_type.startswith('text/html'):
                m = re.search(r'<title[^>]*>\s*([^<]+?)\s*</title>', str(res_body), re.I)
                if m:
                    h = HTMLParser()
                    puts(colored.green("==== HTML TITLE ====\n{}\n".format(h.unescape(m.group(1)))))
            elif content_type.startswith('text/') and len(res_body) < 1024:
                res_body_text = res_body

            if res_body_text:
                puts(colored.green("==== RESPONSE BODY ====\n{}\n".format(res_body_text)))

    def print_info(self, req, req_body, res, res_body):
        req_header_text = "{} {} {}\n{}".format(req.command, req.path, req.request_version, req.headers)
        res_header_text = "{} {} {}\n{}".format(res.response_version, res.status, res.reason, res.headers)

        puts(colored.magenta(req_header_text))

        self.print_query_parameters_info(req)
        self.print_cookies_info(req)
        self.print_authorization_info(req)
        self.print_req_body_text(req, req_body)

        puts(colored.cyan(res_header_text))

        self.print_set_cookie_info(res)
        self.print_res_body_info(res, res_body)


class MyAntiCrapProxy(ProxyRequestHandler):
    def request_handler(self, req, req_body):
        return self.blocker.analyse(self, req, req_body)

    def pre_response_handler(self, req, req_body):
        return self.cache.analyse(self, req, req_body)

    def response_handler(self, req, req_body, res, res_body):
        self.cache.analyse_response(self, req, req_body, res, res_body)
        return self.modifier.analyse(self, req, req_body, res, res_body)

    def save_handler(self, req, req_body, res, res_body):
        if res.status // 100 in (4, 5):
            try:
                self.print_info(req, req_body, res, res_body)
            except:
                pass
            else:
                puts(colored.yellow('^' * 50))


def test(HandlerClass=MyAntiCrapProxy, ServerClass=ThreadingHTTPServer, protocol="HTTP/1.1"):
    if sys.argv[1:]:
        port = int(sys.argv[1])
    else:
        port = 3128
    server_address = ('', port)

    HandlerClass.protocol_version = protocol
    HandlerClass.blocker = block.Blocker()
    HandlerClass.modifier = modify.Modifier()
    HandlerClass.cache = hardcache.HardCache()
    httpd = ServerClass(server_address, HandlerClass)

    sa = httpd.socket.getsockname()
    print(("Serving HTTP Proxy on {} port {} ...".format(sa[0], sa[1])))
    httpd.serve_forever()


if __name__ == '__main__':
    test()
