import io
import json
import logging
import socket
import struct
import traceback
import weakref
import paramiko
import tornado.web
import os
import pty
import fcntl
import termios
import uuid
import threading

from concurrent.futures import ThreadPoolExecutor
from tornado.ioloop import IOLoop
from tornado.options import options
from tornado.process import cpu_count
from webssh.utils import (
    is_valid_ip_address, is_valid_port, is_valid_hostname, to_bytes, to_str,
    to_int, to_ip_address, UnicodeType, is_ip_hostname, is_same_primary_domain,
    is_valid_encoding
)
from webssh.worker import recycle_worker, clients

try:
    from json.decoder import JSONDecodeError
except ImportError:
    JSONDecodeError = ValueError

try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse


DEFAULT_PORT = 22

swallow_http_errors = True
redirecting = None


class InvalidValueError(Exception):
    pass


# =====================================================================
# 核心调试版：本地伪终端 Mock 核心类
# =====================================================================
class LocalChan(object):
    def __init__(self, fd):
        self.fd = fd

    def resize_pty(self, cols, rows, xpix=0, ypix=0):
        try:
            winsize = struct.pack("HHHH", rows, cols, xpix, ypix)
            fcntl.ioctl(self.fd, termios.TIOCSWINSZ, winsize)
            logging.info(f"[DEBUG-TTY] Resized window to cols={cols}, rows={rows}")
        except Exception as e:
            logging.error(f"[DEBUG-TTY] Failed to resize terminal: {e}")


class LocalWorker(object):
    def __init__(self, loop, fd, pid):
        self.loop = loop
        self.fd = fd
        self.pid = pid
        self.id = uuid.uuid4().hex
        self.chan = LocalChan(fd)
        self.closed = False
        self.encoding = 'utf-8'
        self.handler = None
        self.src_addr = None

        logging.info(f"[DEBUG-TTY] LocalWorker initialized. PID={self.pid}, FD={self.fd}. Starting read thread...")
        self.read_thread = threading.Thread(target=self._loop_read, daemon=True)
        self.read_thread.start()

    def set_handler(self, handler):
        self.handler = handler
        logging.info(f"[DEBUG-TTY] Handler bound to Worker {self.id}")

    def _loop_read(self):
        logging.info("[DEBUG-TTY] Read thread is now running and polling PTY...")
        while not self.closed:
            try:
                data = os.read(self.fd, 65536)
                if not data:
                    logging.info("[DEBUG-TTY] Read EOF (no data) from PTY.")
                    self.loop.add_callback(self.close, 'EOF')
                    break
                
                logging.info(f"[DEBUG-TTY] Read {len(data)} bytes from TTY: {data[:100]}")
                
                if self.handler:
                    self.loop.add_callback(self._send_to_client, data)
                else:
                    logging.warning("[DEBUG-TTY] Read data from PTY, but no frontend handler is connected yet.")
            except (OSError, IOError) as e:
                logging.error(f"[DEBUG-TTY] OSError in read thread: {e}")
                self.loop.add_callback(self.close, f"Read Error: {e}")
                break

    def _send_to_client(self, data):
        if self.closed or not self.handler:
            return
        try:
            self.handler.write_message(data.decode(self.encoding, errors='ignore'))
        except Exception as e:
            logging.debug(f"[DEBUG-TTY] Text send failed, trying binary... Error: {e}")
            try:
                self.handler.write_message(data, binary=True)
            except Exception as e2:
                logging.error(f"[DEBUG-TTY] Binary send also failed: {e2}")

    def write_to_fd(self, data):
        if self.closed:
            return
        try:
            logging.info(f"[DEBUG-TTY] Writing to PTY: {repr(data)}")
            os.write(self.fd, data.encode(self.encoding, errors='ignore'))
        except (OSError, IOError) as e:
            logging.error(f"[DEBUG-TTY] Write error: {e}")
            self.close(reason=f"Write error: {e}")

    def close(self, reason=None):
        if self.closed:
            return
        self.closed = True
        logging.info(f"[DEBUG-TTY] Closing session {self.id}. Reason: {reason}")
        if self.handler:
            try:
                self.handler.close(reason=reason)
            except Exception:
                pass
        try:
            os.close(self.fd)
        except Exception:
            pass
        try:
            os.kill(self.pid, 9)
        except Exception:
            pass
# =====================================================================


class SSHClient(paramiko.SSHClient):
    pass


class PrivateKey(object):
    def __init__(self, privatekey, password=None, filename=''):
        self.privatekey = privatekey


class MixinHandler(object):

    custom_headers = {
        'Server': 'TornadoServer'
    }

    html = ('<html><head><title>{code} {reason}</title></head><body>{code} '
            '{reason}</body></html>')

    def initialize(self, loop=None):
        self.check_request()
        self.loop = loop
        self.origin_policy = self.settings.get('origin_policy')

    def check_request(self):
        context = self.request.connection.context
        result = self.is_forbidden(context, self.request.host_name)
        self._transforms = []
        if result:
            self.set_status(403)
            self.finish(
                self.html.format(code=self._status_code, reason=self._reason)
            )
        elif result is False:
            to_url = self.get_redirect_url(
                self.request.host_name, options.sslport, self.request.uri
            )
            self.redirect(to_url, permanent=True)
        else:
            self.context = context

    def check_origin(self, origin):
        if self.origin_policy == '*':
            return True

        parsed_origin = urlparse(origin)
        netloc = parsed_origin.netloc.lower()
        logging.debug('netloc: {}'.format(netloc))

        host = self.request.headers.get('Host')
        logging.debug('host: {}'.format(host))

        if netloc == host:
            return True

        if self.origin_policy == 'same':
            return False
        elif self.origin_policy == 'primary':
            return is_same_primary_domain(netloc.rsplit(':', 1)[0],
                                          host.rsplit(':', 1)[0])
        else:
            return origin in self.origin_policy

    def is_forbidden(self, context, hostname):
        ip = context.address[0]
        lst = context.trusted_downstream
        ip_address = None

        if lst and ip not in lst:
            logging.warning(
                'IP {!r} not found in trusted downstream {!r}'.format(ip, lst)
            )
            return True

        if context._orig_protocol == 'http':
            if redirecting and not is_ip_hostname(hostname):
                ip_address = to_ip_address(ip)
                if not ip_address.is_private:
                    return False

            if options.fbidhttp:
                if ip_address is None:
                    ip_address = to_ip_address(ip)
                if not ip_address.is_private:
                    logging.warning('Public plain http request is forbidden.')
                    return True

    def get_redirect_url(self, hostname, port, uri):
        port = '' if port == 443 else ':%s' % port
        return 'https://{}{}{}'.format(hostname, port, uri)

    def set_default_headers(self):
        for header in self.custom_headers.items():
            self.set_header(*header)

    def get_value(self, name):
        value = self.get_argument(name)
        if not value:
            raise InvalidValueError('Missing value {}'.format(name))
        return value

    def get_context_addr(self):
        return self.context.address[:2]

    def get_client_addr(self):
        if options.xheaders:
            return self.get_real_client_addr() or self.get_context_addr()
        else:
            return self.get_context_addr()

    def get_real_client_addr(self):
        ip = self.request.remote_ip

        if ip == self.request.headers.get('X-Real-Ip'):
            port = self.request.headers.get('X-Real-Port')
        elif ip in self.request.headers.get('X-Forwarded-For', ''):
            port = self.request.headers.get('X-Forwarded-Port')
        else:
            return

        port = to_int(port)
        if port is None or not is_valid_port(port):
            port = 65535

        return (ip, port)


class NotFoundHandler(MixinHandler, tornado.web.ErrorHandler):

    def initialize(self):
        super(NotFoundHandler, self).initialize()

    def prepare(self):
        raise tornado.web.HTTPError(404)


class IndexHandler(MixinHandler, tornado.web.RequestHandler):

    executor = ThreadPoolExecutor(max_workers=cpu_count()*5)

    def initialize(self, loop, policy, host_keys_settings):
        super(IndexHandler, self).initialize(loop)
        self.policy = policy
        self.host_keys_settings = host_keys_settings
        self.ssh_client = None
        self.debug = self.settings.get('debug', False)
        self.font = self.settings.get('font', '')
        self.result = dict(id=None, status=None, encoding=None)

    def write_error(self, status_code, **kwargs):
        if swallow_http_errors and self.request.method == 'POST':
            exc_info = kwargs.get('exc_info')
            if exc_info:
                reason = getattr(exc_info[1], 'log_message', None)
                if reason:
                    self._reason = reason
            self.result.update(status=self._reason)
            self.set_status(200)
            self.finish(self.result)
        else:
            super(IndexHandler, self).write_error(status_code, **kwargs)

    def get_hostname(self):
        return "localhost"

    def get_port(self):
        return DEFAULT_PORT

    def get_args(self):
        return ("localhost", DEFAULT_PORT, "localuser", "", None)

    # =====================================================================
    # 核心修改：以交互式启动本地 Shell 并支持 TERM 环境（加强调试版）
    # =====================================================================
    def ssh_connect(self, args):
        logging.info("[DEBUG-POST] Received connect request. Attempting PTY fork...")
        try:
            pid, fd = pty.fork()
            if pid == 0:
                # 子进程
                os.environ["TERM"] = "xterm-256color"
                
                # 寻找可用 shell
                shell_path = "/bin/bash"
                if not os.path.exists(shell_path):
                    shell_path = "/bin/sh"
                    if not os.path.exists(shell_path):
                        shell_path = "sh"
                
                try:
                    # 启动交互式 shell
                    os.execvp(shell_path, [shell_path, "-i"])
                except Exception as err:
                    # 如果 execvp 失败，将错误直接写入 stderr
                    os.write(2, f"\n[FATAL-SHELL] Exec failed: {err}\n".encode())
                    os._exit(1)
            else:
                # 父进程
                logging.info(f"[DEBUG-POST] Fork success. Child PID={pid}, FD={fd}")
                worker = LocalWorker(self.loop, fd, pid)
                worker.encoding = 'utf-8'
                return worker
        except Exception as e:
            logging.error(f"[DEBUG-POST] Fork failed: {e}")
            raise ValueError(f"Spawn local shell failed: {e}")

    def check_origin(self):
        event_origin = self.get_argument('_origin', u'')
        header_origin = self.request.headers.get('Origin')
        origin = event_origin or header_origin

        if origin:
            if not super(IndexHandler, self).check_origin(origin):
                raise tornado.web.HTTPError(
                    403, 'Cross origin operation is not allowed.'
                )

            if not event_origin and self.origin_policy != 'same':
                self.set_header('Access-Control-Allow-Origin', origin)

    def head(self):
        pass

    def get(self):
        self.render('index.html', debug=self.debug, font=self.font)

    @tornado.gen.coroutine
    def post(self):
        if self.debug and self.get_argument('error', u''):
            raise ValueError('Uncaught exception')

        ip, port = self.get_client_addr()
        workers = clients.get(ip, {})
        if workers and len(workers) >= options.maxconn:
            raise tornado.web.HTTPError(403, 'Too many live connections.')

        self.check_origin()

        try:
            args = self.get_args()
        except InvalidValueError as exc:
            raise tornado.web.HTTPError(400, str(exc))

        future = self.executor.submit(self.ssh_connect, args)

        try:
            worker = yield future
        except (ValueError, paramiko.SSHException) as exc:
            logging.error(traceback.format_exc())
            self.result.update(status=str(exc))
        else:
            if not workers:
                clients[ip] = workers
            worker.src_addr = (ip, port)
            workers[worker.id] = worker
            self.loop.call_later(options.delay, recycle_worker, worker)
            self.result.update(id=worker.id, encoding=worker.encoding)
            logging.info(f"[DEBUG-POST] Returned Worker ID={worker.id} to frontend.")

        self.write(self.result)


class WsockHandler(MixinHandler, tornado.websocket.WebSocketHandler):

    def initialize(self, loop):
        super(WsockHandler, self).initialize(loop)
        self.worker_ref = None

    def open(self):
        self.src_addr = self.get_client_addr()
        logging.info('[DEBUG-WS] Connected from {}:{}'.format(*self.src_addr))

        workers = clients.get(self.src_addr[0])
        if not workers:
            logging.error("[DEBUG-WS] Websocket authentication failed: No workers found for this IP.")
            self.close(reason='Websocket authentication failed.')
            return

        try:
            worker_id = self.get_value('id')
            logging.info(f"[DEBUG-WS] Handshaking with worker_id={worker_id}")
        except (tornado.web.MissingArgumentError, InvalidValueError) as exc:
            logging.error(f"[DEBUG-WS] Missing worker_id: {exc}")
            self.close(reason=str(exc))
        else:
            worker = workers.get(worker_id)
            if worker:
                workers[worker_id] = None
                self.set_nodelay(True)
                worker.set_handler(self)
                self.worker_ref = weakref.ref(worker)
                logging.info("[DEBUG-WS] Handshake established. WebSocket is now bridged to PTY.")
                
                # 尝试往 TTY 里面发一个换行，强行触发一次 Shell 的渲染更新
                worker.write_to_fd("\n")
            else:
                logging.error("[DEBUG-WS] Websocket authentication failed: Worker ID not match.")
                self.close(reason='Websocket authentication failed.')

    def on_message(self, message):
        worker = self.worker_ref()
        if not worker:
            self.close(reason='No worker found')
            return

        if worker.closed:
            self.close(reason='Worker closed')
            return

        try:
            msg = json.loads(message)
        except JSONDecodeError:
            return

        if not isinstance(msg, dict):
            return

        resize = msg.get('resize')
        if resize and len(resize) == 2:
            try:
                worker.chan.resize_pty(*resize)
            except (TypeError, struct.error, paramiko.SSHException):
                pass

        data = msg.get('data')
        if data and isinstance(data, UnicodeType):
            worker.write_to_fd(data)

    def on_close(self):
        logging.info('[DEBUG-WS] Disconnected from {}:{}'.format(*self.src_addr))
        if not self.close_reason:
            self.close_reason = 'client disconnected'

        worker = self.worker_ref() if self.worker_ref else None
        if worker:
            worker.close(reason=self.close_reason)
