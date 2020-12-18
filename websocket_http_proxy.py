#!/usr/bin/env python3


import struct
import pathlib
import sys
import threading
import socket
import errno
import ssl
import time
import select
import json
import re
import gzip
import brotli
import http.client
import html
import queue
from urllib.parse import urlparse, urlsplit, parse_qsl
from base64 import b64encode
from hashlib import sha1
from io import StringIO, BytesIO
from http.server import BaseHTTPRequestHandler
from http.server import HTTPServer
from socketserver import ThreadingMixIn
from subprocess import Popen, PIPE

# This is the websocket client we use to connect to the remote
import websocket

##########
# Config #
##########
# Our local port we want to listen on
proxy_port = 9999
# Do we have SSL certs?
secure = True

# Nr of characters after which messages are truncated (0 to turn off message printing)
trunc = 125
#trunc = 0

##################
# Implementation #
##################

off='\033[0m'
red='\033[0;91m'
grn='\033[0;32m'
yel='\033[0;33m'
cya='\033[0;36m'

class WebSocketError(Exception):
    pass

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    # Handle requests in a separate thread
    daemon_threads = True

class HttpProxy(BaseHTTPRequestHandler):
    cakey = None
    cacert = None
    certkey = None
    certdir = None

    timeout = 100
    lock = threading.Lock()
    protocol_version = "HTTP/1.1"

    def __init__(self, *args, **kwargs):
        if secure:
            self.cakey = pathlib.Path(__file__).parent.joinpath("certs/ca.key")
            self.cacert = pathlib.Path(__file__).parent.joinpath("certs/ca.crt")
            self.certkey = pathlib.Path(__file__).parent.joinpath("certs/cert.key")
            self.certdir = pathlib.Path(__file__).parent.joinpath("certs/specific_certs/")
        self.tls = threading.local()
        self.tls.conns = {}

        BaseHTTPRequestHandler.__init__(self, *args, **kwargs)

    def do_CONNECT(self):
        if secure:
            self.connect_intercept()
        else:
            self.connect_relay()

    def connect_intercept(self):
        hostname = self.path.split(':')[0]
        specific_cert = self.certdir.joinpath(f"{hostname}.crt")

        with self.lock:
            if not specific_cert.is_file():
                epoch = "%d" % (time.time() * 1000)
                p1 = Popen(["openssl", "req", "-new", "-key", self.certkey, "-subj", "/CN=%s" % hostname], stdout=PIPE)
                p2 = Popen(["openssl", "x509", "-req", "-days", "3650", "-CA", self.cacert, "-CAkey", self.cakey, "-set_serial", epoch, "-out", specific_cert], stdin=p1.stdout, stderr=PIPE)
                p2.communicate()

        self.wfile.write(("%s %d %s\r\n" % (self.protocol_version, 200, 'Connection Established')).encode())
        if not hasattr(self, '_headers_buffer'):
            self._headers_buffer = []
        self.end_headers()

        self.connection = ssl.wrap_socket(self.connection, keyfile=self.certkey, certfile=specific_cert, server_side=True)
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
        except Exception as e:
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

    def do_GET(self):
        if self.path == 'http://ca.crt/':
            self.send_cacert()
            return

        req = self
        content_length = int(req.headers.get('Content-Length', 0))
        req_body = self.rfile.read(content_length) if content_length else None

        if req.path[0] == '/':
            if isinstance(self.connection, ssl.SSLSocket):
                req.path = f"https://{req.headers['Host']}{req.path}"
            else:
                req.path = f"http://{req.headers['Host']}{req.path}"

        #print(f"REQ for {req.path}")
        req_body_modified = self.request_handler(req, req_body)
        if req_body_modified is False:
            self.send_error(403)
            return
        elif req_body_modified is not None:
            req_body = req_body_modified
            req.headers['Content-length'] = str(len(req_body))

        u = urlsplit(req.path)
        scheme, netloc, path = u.scheme, u.netloc, (u.path + '?' + u.query if u.query else u.path)
        assert scheme in ('http', 'https')
        if netloc:
            req.headers['Host'] = netloc
        setattr(req, 'headers', self.filter_headers(req.headers))

        try:
            origin = (scheme, netloc)
            if not origin in self.tls.conns:
                if scheme == 'https':
                    self.tls.conns[origin] = http.client.HTTPSConnection(netloc, timeout=self.timeout)
                else:
                    self.tls.conns[origin] = http.client.HTTPConnection(netloc, timeout=self.timeout)
            conn = self.tls.conns[origin]
            conn.request(self.command, path, req_body, dict(req.headers))
            res = conn.getresponse()

            version_table = {10: 'HTTP/1.0', 11: 'HTTP/1.1'}
            setattr(res, 'headers', res.msg)
            setattr(res, 'response_version', version_table[res.version])

            # support streaming
            if not 'Content-Length' in res.headers and 'no-store' in res.headers.get('Cache-Control', ''):
                self.response_handler(req, req_body, res, '')
                setattr(res, 'headers', self.filter_headers(res.headers))
                self.relay_streaming(res)
                with self.lock:
                    self.save_handler(req, req_body, res, '')
                return

            res_body = res.read()
        except Exception as e:
            print(e)
            if origin in self.tls.conns:
                del self.tls.conns[origin]
            self.send_error(502)
            return

        content_encoding = res.headers.get('Content-Encoding', 'identity')
        res_body_plain = self.decode_content_body(res_body, content_encoding)

        res_body_modified = self.response_handler(req, req_body, res, res_body_plain)
        if res_body_modified is False:
            self.send_error(403)
            return
        elif res_body_modified is not None:
            res_body_plain = res_body_modified
            res_body = self.encode_content_body(res_body_plain, content_encoding)
            res.headers['Content-Length'] = str(len(res_body))

        setattr(res, 'headers', self.filter_headers(res.headers))

        self.wfile.write(("%s %d %s\r\n" % (self.protocol_version, res.status, res.reason)).encode())
        self.wfile.write(str(res.headers).encode())
        if len(res_body) != 0:
            self.wfile.write(res_body)
        self.wfile.flush()

        with self.lock:
            self.save_handler(req, req_body, res, res_body_plain)

    do_HEAD = do_GET
    do_POST = do_GET
    do_PUT = do_GET
    do_DELETE = do_GET
    do_OPTIONS = do_GET

    def relay_streaming(self, res):
        self.wfile.write(("%s %d %s\r\n" % (self.protocol_version, res.status, res.reason)).encode())
        self.wfile.write(str(res.headers).encode())
        self.end_headers()
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

    def filter_headers(self, headers):
        # http://tools.ietf.org/html/rfc2616#section-13.5.1
        hop_by_hop = ('connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailers', 'transfer-encoding', 'upgrade')
        #hop_by_hop = ('keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailers', 'transfer-encoding')
        for k in hop_by_hop:
            del headers[k]

        # accept only supported encodings
        if 'Accept-Encoding' in headers:
            ae = headers['Accept-Encoding']
            filtered_encodings = [x for x in re.split(r',\s*', ae) if x in ('identity', 'gzip', 'x-gzip', 'deflate', 'br')]
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
        elif encoding == 'br':
            data = brotli.compress(text)
        else:
            raise Exception("Unknown Content-Encoding: %s" % encoding)
        return data

    def decode_content_body(self, data, encoding):
        if encoding == 'identity':
            text = data
        elif encoding in ('gzip', 'x-gzip'):
            io = BytesIO(data)
            with gzip.GzipFile(fileobj=io) as f:
                text = f.read()
        elif encoding == 'deflate':
            try:
                text = zlib.decompress(data)
            except zlib.error:
                text = zlib.decompress(data, -zlib.MAX_WBITS)
        elif encoding == 'br':
            text = brotli.compress(data)
        else:
            raise Exception("Unknown Content-Encoding: %s" % encoding)
        return text

    def send_cacert(self):
        with open(self.cacert, 'rb') as f:
            data = f.read()

        self.wfile.write(("%s %d %s\r\n" % (self.protocol_version, 200, 'OK')).encode())
        self.send_header('Content-Type', 'application/x-x509-ca-cert')
        self.send_header('Content-Length', len(data))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(data)

    def log_error(self, *args, **kwargs):
        # Hacky way to suppress timeout errors
        #if 'Request timed out' in args[0]:
        #    return
        BaseHTTPRequestHandler.log_error(self, *args, **kwargs)


    def print_info(self, req, req_body, res, res_body):
        def _parse_qsl(s):
            return '\n'.join("%-20s %s" % (k, v) for k, v in parse_qsl(s, keep_blank_values=True))

        req_header_text = "%s %s %s\n%s" % (req.command, req.path, req.request_version, req.headers)
        res_header_text = "%s %d %s\n%s" % (res.response_version, res.status, res.reason, res.headers)

        print(f"{yel}{req_header_text}{off}")

        u = urlsplit(req.path)
        if u.query:
            query_text = _parse_qsl(u.query)
            print(f"{grn}==== QUERY PARAMETERS ====\n{query_text}\n{off}")

        cookie = req.headers.get('Cookie', '')
        if cookie:
            cookie = _parse_qsl(re.sub(r';\s*', '&', cookie))
            print(f"{grn}==== COOKIE ====\n{cookie}\n{off}")

        auth = req.headers.get('Authorization', '')
        if auth.lower().startswith('basic'):
            token = auth.split()[1].decode('base64')
            print(f"{red}==== BASIC AUTH ====\n{token}\n{off}")

        if req_body is not None:
            req_body_text = None
            content_type = req.headers.get('Content-Type', '')

            if content_type.startswith('application/x-www-form-urlencoded'):
                req_body_text = _parse_qsl(req_body)
            elif content_type.startswith('application/json'):
                try:
                    json_obj = json.loads(req_body)
                    json_str = json.dumps(json_obj, indent=2)
                    if json_str.count('\n') < 50:
                        req_body_text = json_str
                    else:
                        lines = json_str.splitlines()
                        req_body_text = "%s\n(%d lines)" % ('\n'.join(lines[:50]), len(lines))
                except ValueError:
                    req_body_text = req_body
            elif len(req_body) < 1024:
                req_body_text = req_body

            if req_body_text:
                print(f"{grn}==== REQUEST BODY ====\n{req_body_text}\n{off}")

        print(f"{cya}{res_header_text}{off}")

        cookies = res.headers.get_all('Set-Cookie')
        if cookies:
            cookies = '\n'.join(cookies)
            print(f"{red}==== SET-COOKIE ====\n{cookies}\n{off}")

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
                        res_body_text = "%s\n(%d lines)" % ('\n'.join(lines[:50]), len(lines))
                except ValueError:
                    res_body_text = res_body
            elif content_type.startswith('text/html'):
                m = re.search(r'<title[^>]*>\s*([^<]+?)\s*</title>', res_body.decode(), re.I)
                if m:
                    print(f"{grn}==== HTML TITLE ====\n{html.unescape(m.group(1))}\n{off}")
            elif content_type.startswith('text/') and len(res_body) < 1024:
                res_body_text = res_body

            if res_body_text:
                print(f"{grn}==== RESPONSE BODY ====\n{res_body_text}\n{off}")

    def request_handler(self, req, req_body):
        """Override this handler to process incoming HTTP requests. (Return the modified body)"""
        pass

    def response_handler(self, req, req_body, res, res_body):
        """Override this handler to process outgoing HTTP responses. (Return the modified body)"""
        pass

    def save_handler(self, req, req_body, res, res_body):
        """Override this handler to log full HTTP REQ/RES pairs. Default action: print to console."""
        self.print_info(req, req_body, res, res_body)
        pass



class WsHttpProxy(HttpProxy):
    _ws_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
    _opcode_continu = 0x0
    _opcode_text = 0x1
    _opcode_binary = 0x2
    _opcode_close = 0x8
    _opcode_ping = 0x9
    _opcode_pong = 0xa

    mutex = threading.Lock()


    def do_GET(self):
        if self.headers.get("Upgrade", None) == "websocket":
            print("Initiating websocket handshake")
            self._handshake()
            #This handler is in websocket mode now.
            #do_GET only returns after client close or socket error.
            self._read_messages()
        else:
            HttpProxy.do_GET(self)

    def send_message(self, message):
        self._send_message(self._opcode_text, message)

    def _read_messages(self):
        while self.connected == True:
            try:
                self._read_next_message()
            except (socket.error, WebSocketError) as e:
                #websocket content error, time-out or disconnect.
                self.log_message("RCV: Close connection: Socket Error %s" % str(e.args))
                self._ws_close()
            except Exception as err:
                #unexpected error in websocket connection.
                self.log_error("RCV: Exception: in _read_messages: %s" % str(err.args))
                self._ws_close()

    def _read_next_message(self):
        try:
            self.opcode = ord(self.rfile.read(1)) & 0x0F
            length = ord(self.rfile.read(1)) & 0x7F
            if length == 126:
                length = struct.unpack(">H", self.rfile.read(2))[0]
            elif length == 127:
                length = struct.unpack(">Q", self.rfile.read(8))[0]
            masks = [byte for byte in self.rfile.read(4)]
            decoded = ""
            for char in self.rfile.read(length):
                decoded += chr(char ^ masks[len(decoded) % 4])
            self._on_message(decoded)
        except (struct.error, TypeError) as e:
            #catch exceptions from ord() and struct.unpack()
            print(f"debug, {e}")
            if self.connected:
                raise WebSocketError("Websocket read aborted while listening")
            else:
                #the socket was closed while waiting for input
                self.log_error("RCV: _read_next_message aborted after closed connection")
                pass

    def _send_message(self, opcode, message):
        try:
            self.connection.send(bytes([0x80 + opcode]))
            length = len(message.encode())
            if length <= 125:
                self.connection.send(chr(length).encode())
            elif length >= 126 and length <= 65535:
                self.connection.send(chr(126).encode())
                self.connection.send(struct.pack(">H", length))
            else:
                self.connection.send(chr(127).encode())
                self.connection.send(struct.pack(">Q", length))
            if length > 0:
                self.connection.send(message.encode())
        except socket.error as e:
            #websocket content error, time-out or disconnect.
            self.log_message("SND: Close connection: Socket Error %s" % str(e.args))
            self._ws_close()
        except Exception as err:
            #unexpected error in websocket connection.
            self.log_error("SND: Exception: in _send_message: %s" % str(err.args))
            self._ws_close()

    def _handshake(self):
        headers=self.headers
        if headers.get("Upgrade", None) != "websocket":
            return
        key = headers['Sec-WebSocket-Key']
        protocol = headers.get('Sec-WebSocket-Protocol')
        digest = b64encode(sha1((key + self._ws_GUID).encode('utf-8')).digest()).strip().decode()

        self.send_response(101, 'Switching Protocols')
        self.send_header('Connection', 'Upgrade')
        self.send_header('Upgrade', 'websocket')
        self.send_header('Sec-WebSocket-Accept', digest)
        if protocol:
            self.send_header('Sec-WebSocket-Protocol', protocol)
        self.end_headers()
        self.connected = True
        #self.close_connection = 0 # INTERESTING, DO WE NEED TO UNCOMMENT THIS?
        self.on_ws_connected()

    def _ws_close(self):
        #avoid closing a single socket two time for send and receive.
        self.mutex.acquire()
        try:
            if self.connected:
                self.connected = False
                #Terminate BaseHTTPRequestHandler.handle() loop:
                self.close_connection = 1
                #send close and ignore exceptions. An error may already have occurred.
                try:
                    self._send_close()
                except:
                    pass
                self.on_ws_closed()
            else:
                self.log_message("_ws_close websocket in closed state. Ignore.")
                pass
        finally:
            self.mutex.release()

    def _on_message(self, message):
        #self.log_message("_on_message: opcode: %02X msg: %s" % (self.opcode, message))
        # close
        if self.opcode == self._opcode_close:
            self.connected = False
            #Terminate BaseHTTPRequestHandler.handle() loop:
            self.close_connection = 1
            try:
                self._send_close()
            except:
                pass
            self.on_ws_closed()
        # ping
        elif self.opcode == self._opcode_ping:
            _send_message(self._opcode_pong, message)
        # pong
        elif self.opcode == self._opcode_pong:
            pass
        # data
        elif (self.opcode == self._opcode_continu or self.opcode == self._opcode_text or self.opcode == self._opcode_binary):
            self.on_ws_message(message)

    def _send_close(self):
        #Dedicated _send_close allows for catch all exception handling
        msg = bytearray()
        msg.append(0x80 + self._opcode_close)
        msg.append(0x00)
        self.connection.send(msg)

    def request_handler(self, req, req_body):
        """Override this handler to process incoming HTTP requests. (Return the modified body)"""
        pass

    def response_handler(self, req, req_body, res, res_body):
        """Override this handler to process outgoing HTTP responses. (Return the modified body)"""
        pass

    def save_handler(self, req, req_body, res, res_body):
        """Override this handler to log full HTTP REQ/RES pairs. Default action: print to console."""
        #self.print_info(req, req_body, res, res_body)
        pass

    def on_ws_message(self, message):
        """Override this handler to process incoming websocket messages."""
        pass

    def on_ws_connected(self):
        """Override this handler."""
        pass

    def on_ws_closed(self):
        """Override this handler."""
        pass


class WSProxy(WsHttpProxy):
    _closed = False

    # These 2 variables allow us to clone the recv functionality
    clone_recv = False
    recv_queue = queue.Queue()

    def on_ws_message(self, message):
        if message is None:
            message = ''
        if trunc != 0:
            print(f"{red}CLIENT: '{message[:trunc] + (message[trunc:] and '..')}'{off}")
        # Send client message to remote
        self._remote_websocket.send(str(message))

    def on_ws_connected(self):
        global first_ws_connection
        self.log_message('%s','websocket connected')

        if first_ws_connection is None:
            first_ws_connection = self

        # Called whenever a new connection is made to the server
        if secure:
            remote_url = "wss://" + self.headers['Host'] + self.path
        else:
            remote_url = "ws://" + self.headers['Host'] + self.path
        self.log_message('%s',f"Connecting to remote websocket {remote_url}")
        self._remote_websocket = websocket.WebSocket(sslopt={"cert_reqs": ssl.CERT_NONE})
        self._remote_websocket.connect(remote_url)
        def forward_to_client(proxy_obj):
            # Send responses to client
            self.log_message('%s',"Starting thread to forward server messages to the client")
            while not proxy_obj._closed:
                message = str(proxy_obj._remote_websocket.recv())
                if trunc != 0:
                    print(f"{grn}SERVER: '{message[:trunc] + (message[trunc:] and '..')}'{off}")
                proxy_obj.send_message(message)
                if self.clone_recv:
                    self.recv_queue.put(message)
            proxy_obj._remote_websocket.close()
            proxy_obj.log_message('%s',"Server websocket closed")
        threading.Thread(target=forward_to_client, args=(self,)).start()

    def on_ws_closed(self):
        self._closed = True
        self.log_message('%s','Client websocket closed')


# Class to mimic websocket-client api
class WsClientApiWrapper:
    proxy = None
    def __init__(self, proxy):
          self.proxy = proxy
          self.proxy.clone_recv = True

    def send(self, msg):
        self.proxy.on_ws_message(msg)

    def recv(self, block=True):
        return self.proxy.recv_queue.get(block)


first_ws_connection = None
def start_and_grab_first_websocket():
    threading.Thread(target=main).start()
    while first_ws_connection is None:
        print("Waiting for websocket connection")
        time.sleep(1)
    print("Websocket connection established")
    print("Wrapping connection to mimic 'websocket-client' api")
    return WsClientApiWrapper(first_ws_connection)



def main():
    try:
        handler = WSProxy
        server = ThreadedHTTPServer(('127.0.0.1', proxy_port), handler)
        sockname = server.socket.getsockname()
        if secure:
            print(f"started https intercept proxy server at {sockname[0]} (port {proxy_port})")
        else:
            print(f"started https relay proxy server at {sockname[0]} (port {proxy_port})")
        server.serve_forever()
    except KeyboardInterrupt:
        print('^C received, shutting down server')
        server.socket.close()

if __name__ == '__main__':
    main()
