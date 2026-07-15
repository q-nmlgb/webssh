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
import threading # 新增：用于多线程并发读取

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
# 核心修复：基于多线程的伪终端 Mock 核心类
# =====================================================================
class LocalChan(object):
    """模拟 Paramiko Channel，提供窗口大小自适应能力"""
    def __init__(self, fd):
        self.fd = fd

    def resize_pty(self, cols, rows, xpix=0, ypix=0):
        try:
            winsize = struct.pack("HHHH", rows, cols, xpix, ypix)
            fcntl.ioctl(self.fd, termios.TIOCSWINSZ, winsize)
        except Exception as e:
            logging.error(f"Failed to resize terminal: {e}")


class LocalWorker(object):
    """通过后台守护线程直接对 PTY 进行阻塞读写，完全避免 Tornado Event Loop 的文件描述符兼容性问题"""
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

        # 启动后台阻塞读取线程
        self.read_thread = threading.Thread(target=self._loop_read, daemon=True)
        self.read_thread.start()

    def set_handler(self, handler):
        self.handler = handler

    def _loop_read(self):
        """后台线程：同步阻塞读取 PTY 数据"""
        while not self.closed:
            try:
                # 阻塞式读取，对 TTY 极其稳定
                data = os.read(self.fd, 65536)
                if not data:
                    self.loop.add_callback(self.close, 'EOF')
                    break
                
                # 只有在前端 WebSocket 连接准备好后才投递数据
                if self.handler:
                    self.loop.add_callback(self._send_to_client, data)
            except (OSError, IOError) as e:
                self.loop.add_callback(self.close, f"Read Error: {e}")
                break

    def _send_to_client(self, data):
        """在 Tornado 主线程中发送 WebSocket 消息"""
        if self.closed or not self.handler:
            return
        try:
            # 优先使用 text 传输，不兼容时降级为二进制传输
            self.handler.write_message(data.decode(self.encoding, errors='ignore'))
        except Exception:
            try:
                self.handler.write_message(data, binary=True)
            except Exception:
                pass

    def write_to_fd(self, data):
        """写入用户输入到 PTY"""
        if self.closed:
            return
        try:
            os.write(self.fd, data.encode(self.encoding, errors='ignore'))
        except (OSError, IOError) as e:
            self.close(reason=f"Write error: {e}")

    def close(self, reason=None):
        if self.closed:
            return
        self.closed = True
        logging.info(f"Local session {self.id} closed. Reason: {reason}")
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
    # 核心修改：以交互式启动本地 Shell 并支持 TERM 环境
    # =====================================================================
    def ssh_connect(self, args):
        logging.info("Bypassing SSH. Spawning local interactive shell in container...")
        try:
            pid, fd = pty.fork()
            if pid == 0:
                # 1. 声明终端环境变量以完美支持 xterm.js 的控制序列渲染
                os.environ["TERM"] = "xterm-256color"
                
                # 2. 启动交互式 shell (加上 -i 确保它输出 Prompt，比如 user@host:~$)
                try:
                    os.execvp("bash", ["bash", "-i"])
                except Exception:
                    try:
                        os.execvp("sh", ["sh", "-i"])
                    except Exception as err:
                        logging.error(f"Failed to execute shells: {err}")
                        os._exit(1)
            else:
                # 在父进程中不设置 O_NONBLOCK，使得同步后台读取线程能够安全工作
                worker = LocalWorker(self.loop, fd, pid)
                worker.encoding = 'utf-8'
                return worker
        except Exception as e:
            logging.error(f"Failed to spawn local shell: {e}")
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

        self.write(self.result)


class WsockHandler(MixinHandler, tornado.websocket.WebSocketHandler):

    def initialize(self, loop):
        super(WsockHandler, self).initialize(loop)
        self.worker_ref = None

    def open(self):
        self.src_addr = self.get_client_addr()
        logging.info('Connected from {}:{}'.format(*self.src_addr))

        workers = clients.get(self.src_addr[0])
        if not workers:
            self.close(reason='Websocket authentication failed.')
            return

        try:
            worker_id = self.get_value('id')
        except (tornado.web.MissingArgumentError, InvalidValueError) as exc:
            self.close(reason=str(exc))
        else:
            worker = workers.get(worker_id)
            if worker:
                workers[worker_id] = None
                self.set_nodelay(True)
                worker.set_handler(self)
                self.worker_ref = weakref.ref(worker)
                # 核心改变：不再使用 loop.add_handler(worker.fd...) 托管给 Tornado，读取由 LocalWorker 自己的后台守护线程完成
            else:
                self.close(reason='Websocket authentication failed.')

    def on_message(self, message):
        logging.debug('{!r} from {}:{}'.format(message, *self.src_addr))
        worker = self.worker_ref()
        if not worker:
            logging.debug(
                "received message to closed worker from {}:{}".format(
                    *self.src_addr
                )
            )
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
            # 核心改变：直接向 PTY 写入
            worker.write_to_fd(data)

    def on_close(self):
        logging.info('Disconnected from {}:{}'.format(*self.src_addr))
        if not self.close_reason:
            self.close_reason = 'client disconnected'

        worker = self.worker_ref() if self.worker_ref else None
        if worker:
            worker.close(reason=self.close_reason)
