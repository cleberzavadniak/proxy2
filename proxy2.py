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

from clint.textui import puts, colored

import block
import hardcache
import modify


def print_color(c, s):
    print(("\x1b[{}m{}\x1b[0m".format(c, s)))


def join_with_script_dir(path):
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), path)


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
    cakey = join_with_script_dir('ca.key')
    cacert = join_with_script_dir('ca.crt')
    certkey = join_with_script_dir('cert.key')
    certdir = join_with_script_dir('certs/')
    timeout = 5
    lock = threading.Lock()

    def __init__(self, *args, **kwargs):
        self.tls = threading.local()
        self.tls.conns = {}
        self.has_certs = False
        self.has_ca = False

        BaseHTTPRequestHandler.__init__(self, *args, **kwargs)

    def log_message(self, format, *args):
        pass

    def log_error(self, format, *args):
        if isinstance(args[0], socket.timeout):
            return

        self.log_message(format, *args)

    def send_error(self, error_number, reason=None):
        try:
            super().send_error(error_number, reason)
        except BrokenPipeError:  # NOQA
            pass

    def do_CONNECT(self):
        if self.has_ca:
            self.connect_intercept()
        elif os.path.isfile(self.cakey) and os.path.isfile(self.cacert) and os.path.isfile(self.certkey) and os.path.isdir(self.certdir):
            self.has_ca = True
            self.connect_intercept()
        else:
            self.connect_relay()

    def connect_intercept(self):
        hostname = self.path.split(':')[0]
        certpath = "{}/{}.crt".format(self.certdir.rstrip('/'), hostname)
        if not self.has_certs:
            with self.lock:
                if not os.path.isfile(certpath):
                    epoch = str(int(time.time() * 1000))
                    p1 = Popen(["openssl", "req", "-new", "-key", self.certkey, "-subj", "/CN={}".format(hostname)], stdout=PIPE)
                    p2 = Popen(["openssl", "x509", "-req", "-days", "3650", "-CA", self.cacert, "-CAkey", self.cakey, "-set_serial", epoch, "-out", certpath], stdin=p1.stdout, stderr=PIPE)
                    p2.communicate()
                    self.has_certs = True

        self.wfile.write("{} {} {}\r\n".format(self.protocol_version, 200, 'Connection Established').encode('utf-8'))
        self.wfile.write(b'\r\n')

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
            self.wfile.write("{} {} {}\r\n".format(self.protocol_version, 200, 'OK').encode('utf-8'))
            # self.send_header('Content-Type', 'application/x-x509-ca-cert')
            self.send_header('Content-Length', len(data))
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(data)
            return True

    def do_GET(self):
        if self.path == 'http://anticrap/certificates/':
            self.send_cacert()
            return

        req = self
        content_length = int(req.headers.get('Content-Length', 0))
        req_body = self.rfile.read(content_length) if content_length else None

        if req.path[0] == '/':
            if isinstance(self.connection, ssl.SSLSocket):
                req.path = "https://{}{}".format(req.headers['Host'], req.path)
            else:
                req.path = "http://{}{}".format(req.headers['Host'], req.path)

        if self.pre_response_handler_used(req, req_body):
            return

        req_body_modified = self.request_handler(req, req_body)
        if req_body_modified is False:
            self.send_error(403)
            return
        elif req_body_modified is not None:
            req_body = req_body_modified
            req.headers['Content-length'] = str(len(req_body))

        u = url_parse.urlsplit(req.path)
        scheme, netloc, path = u.scheme, u.netloc, (u.path + '?' + u.query if u.query else u.path)
        assert scheme in ('http', 'https')
        if netloc:
            req.headers['Host'] = netloc
        setattr(req, 'headers', self.filter_headers(req.headers))

        try:
            origin = (scheme, netloc)
            if origin not in self.tls.conns:
                if scheme == 'https':
                    self.tls.conns[origin] = HTTPSConnection(netloc, timeout=self.timeout)
                else:
                    self.tls.conns[origin] = HTTPConnection(netloc, timeout=self.timeout)
            conn = self.tls.conns[origin]
            conn.request(self.command, path, req_body, dict(req.headers))
            res = conn.getresponse()
            version_table = {10: 'HTTP/1.0', 11: 'HTTP/1.1'}
            setattr(res, 'headers', res.msg)
            setattr(res, 'response_version', version_table[res.version])

            # streaming:
            if 'Content-Length' not in res.headers and 'no-store' in res.headers.get('Cache-Control', ''):
                # self.response_handler(req, req_body, res, '')
                setattr(res, 'headers', self.filter_headers(res.headers))
                self.relay_streaming(req, res)

                with self.lock:
                    self.save_handler(req, req_body, res, '')
                return

            res_body = res.read()
        except Exception:
            if origin in self.tls.conns:
                del self.tls.conns[origin]
            self.send_error(502)
            return

        content_encoding = res.headers.get('Content-Encoding', 'identity')
        try:
            res_body_plain = self.decode_content_body(res_body, content_encoding)
        except Exception as ex:
            if 'Unknown Content-Encoding' in ex.args[0]:
                res_body_plain = self.decode_content_body(res_body, 'identity')

        res_body_modified = self.response_handler(req, req_body, res, res_body_plain)
        if res_body_modified is False:
            self.send_error(403)
            return
        elif res_body_modified is not None:
            res_body_plain = res_body_modified
            res_body = self.encode_content_body(res_body_plain, content_encoding)
            res.headers['Content-Length'] = str(len(res_body))

        setattr(res, 'headers', self.filter_headers(res.headers))

        self.wfile.write(bytes("{} {} {}\r\n".format(self.protocol_version, res.status, res.reason), 'utf-8'))
        for k, v in list(res.headers.items()):
            self.send_header(k, v)

        try:
            self.end_headers()
        except (AttributeError, BrokenPipeError, ssl.SSLEOFError):
            pass

        try:
            self.wfile.write(res_body)
            self.wfile.flush()
        except (BrokenPipeError, ssl.SSLEOFError):  # NOQA
            pass

        with self.lock:
            self.save_handler(req, req_body, res, res_body_plain)

    def relay_streaming(self, req, res):
        puts(colored.magenta('STREAM: {} {}'.format(req.path, res.status)))
        self.wfile.write(bytes("{} {} {}\r\n".format(self.protocol_version, res.status, res.reason), 'utf-8'))

        self.wfile.write(bytes('{}'.format(res.headers), 'utf-8'))

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
        except socket.error:
            # connection closed by client
            pass

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
            data = text
        elif encoding in ('gzip', 'x-gzip'):
            io = BytesIO()
            with gzip.GzipFile(fileobj=io, mode='wb') as f:
                f.write(text)
            data = io.getvalue()
        elif encoding == 'deflate':
            data = zlib.compress(text)
        else:
            raise Exception("Unknown Content-Encoding: {}".format(encoding))
        return data

    def decode_content_body(self, data, encoding):
        if encoding == 'identity':
            text = data
        elif encoding in ('gzip', 'x-gzip'):
            io = BytesIO(data)
            with gzip.GzipFile(fileobj=io, mode='rb') as f:
                text = f.read()
        elif encoding == 'deflate':
            try:
                text = zlib.decompress(data)
            except zlib.error:
                text = zlib.decompress(data, -zlib.MAX_WBITS)
        else:
            raise Exception("Unknown Content-Encoding: {}".format(encoding))
        return text

    def send_cacert(self):
        with open(self.cacert, 'rb') as f:
            data = f.read()

        self.wfile.write("{} {} {}\r\n".format(self.protocol_version, 200, 'OK').encode('utf-8'))
        self.send_header('Content-Type', 'application/x-x509-ca-cert')
        self.send_header('Content-Length', len(data))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(data)

    def print_info(self, req, req_body, res, res_body):
        def parse_qsl(s):
            return '\n'.join("{:<20} {}".format(k, v) for k, v in url_parse.parse_qsl(s, keep_blank_values=True))

        req_header_text = "{} {} {}\n{}".format(req.command, req.path, req.request_version, req.headers)
        res_header_text = "{} {} {}\n{}".format(res.response_version, res.status, res.reason, res.headers)

        print_color(33, req_header_text)

        u = url_parse.urlsplit(req.path)
        if u.query:
            query_text = parse_qsl(u.query)
            print_color(32, "==== QUERY PARAMETERS ====\n{}\n".format(query_text))

        cookie = req.headers.get('Cookie', '')
        if cookie:
            cookie = parse_qsl(re.sub(r';\s*', '&', cookie))
            print_color(32, "==== COOKIE ====\n{}\n".format(cookie))

        auth = req.headers.get('Authorization', '')
        if auth.lower().startswith('basic'):
            token = auth.split()[1].decode('base64')
            print_color(31, "==== BASIC AUTH ====\n{}\n".format(token))

        if req_body is not None:
            req_body_text = None
            content_type = req.headers.get('Content-Type', '')

            if content_type.startswith('application/x-www-form-urlencoded'):
                req_body_text = parse_qsl(req_body)
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
                print_color(32, "==== REQUEST BODY ====\n{}\n".format(req_body_text))

        print_color(36, res_header_text)

        if hasattr(res.headers, 'getheaders'):
            cookies = res.headers.getheaders('Set-Cookie')
        else:
            cookies = res.headers.get_all('Set-Cookie')
        if cookies:
            cookies = '\n'.join(cookies)
            print_color(31, "==== SET-COOKIE ====\n{}\n".format(cookies))

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
                    print_color(32, "==== HTML TITLE ====\n{}\n".format(h.unescape(m.group(1))))
            elif content_type.startswith('text/') and len(res_body) < 1024:
                res_body_text = res_body

            if res_body_text:
                print_color(32, "==== RESPONSE BODY ====\n{}\n".format(res_body_text))

    def request_handler(self, req, req_body):
        pass

    def response_handler(self, req, req_body, res, res_body):
        pass

    def save_handler(self, req, req_body, res, res_body):
        self.print_info(req, req_body, res, res_body)


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
            # puts(colored.yellow('> {}: {} {}'.format(req.path, res.status, res.reason)))
            # puts(colored.yellow(str(res_body, 'utf-8')))
            self.print_info(req, req_body, res, res_body)
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
