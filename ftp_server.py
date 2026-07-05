import os
import json
import sys
import threading
import ctypes
import ctypes.wintypes
import ipaddress
import socket
import subprocess
import logging
from datetime import datetime
from pyftpdlib.authorizers import DummyAuthorizer, AuthenticationFailed
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

log = logging.getLogger("ftp_server")

class DailyFileHandler(logging.Handler):
    def __init__(self, log_dir):
        super().__init__()
        self.log_dir = log_dir
        self.current_date = None
        self._handler = None

    def _ensure(self):
        date_str = datetime.now().strftime("%Y-%m-%d")
        if date_str != self.current_date:
            if self._handler:
                self._handler.close()
            path = os.path.join(self.log_dir, f"{date_str}.log")
            self._handler = logging.FileHandler(path, encoding="utf-8")
            self.current_date = date_str
        return self._handler

    def emit(self, record):
        h = self._ensure()
        if self.formatter:
            h.setFormatter(self.formatter)
        h.emit(record)

    def close(self):
        if self._handler:
            self._handler.close()
        super().close()

def setup_logging():
    base = os.path.dirname(sys.executable) if getattr(sys, "frozen", False) else os.path.dirname(os.path.abspath(__file__))
    log_dir = os.path.join(base, "log")
    os.makedirs(log_dir, exist_ok=True)

    log.setLevel(logging.INFO)

    fh = DailyFileHandler(log_dir)
    fh.setLevel(logging.INFO)
    fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
    log.addHandler(fh)

    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
    log.addHandler(ch)

    for logger_name in ["pyftpdlib", "pyftpdlib.log", "pyftpdlib.ioloop"]:
        l = logging.getLogger(logger_name)
        l.setLevel(logging.INFO)
        l.handlers.clear()
        l.addHandler(fh)
        l.addHandler(ch)

class SmartFTPHandler(FTPHandler):
    # 内网网络范围（写死）
    PRIVATE_NETWORKS = [
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('192.168.0.0/16'),
        ipaddress.ip_network('127.0.0.0/8'),
        ipaddress.ip_network('fc00::/7'),      # IPv6 private
        ipaddress.ip_network('fe80::/10'),     # IPv6 link-local
    ]
    
    # 路由器IP（动态配置）
    router_ip = None
    local_ip = None
    
    @classmethod
    def is_private_ip(cls, ip_string):
        """检查 IP 是否为私有网络"""
        try:
            ip = ipaddress.ip_address(ip_string)
            return any(ip in net for net in cls.PRIVATE_NETWORKS)
        except ValueError:
            return False
    
    def on_connect(self):
        """
        根据客户端连接来源判断是否使用 masquerade_address
        - 客户端是路由器IP → 返回masquerade（内网通过外网域名访问）
        - 客户端是本地网络内的其他IP → 返回本地IP
        - 客户端是外网IP → 返回masquerade
        """
        if not type(self).masquerade_address:
            return
        
        # 如果客户端IP是路由器IP，说明是内网客户端通过外网域名访问
        if type(self).router_ip and self.remote_ip == type(self).router_ip:
            log.info(f"[Connect] 内网客户端通过外网访问 (来自路由器 {self.remote_ip}) -> 使用 masquerade: {type(self).masquerade_address}")
            return
        
        # 检查客户端是否来自本地私网
        client_is_private = self.is_private_ip(self.remote_ip)
        
        if client_is_private:
            # 直接从内网连接 → 使用本地IP
            self.masquerade_address = None
            log.info(f"[Connect] 内网客户端 {self.remote_ip} -> 使用本地 IP")
        else:
            # 外网客户端 → 使用masquerade
            log.info(f"[Connect] 外网客户端 {self.remote_ip} -> 使用 masquerade: {type(self).masquerade_address}")

advapi32 = ctypes.windll.advapi32
kernel32 = ctypes.windll.kernel32
LOGON32_LOGON_NETWORK = 3
LOGON32_PROVIDER_DEFAULT = 0

def authenticate_windows_user(username, password):
    handle = ctypes.wintypes.HANDLE()
    result = advapi32.LogonUserW(
        username, None, password,
        LOGON32_LOGON_NETWORK,
        LOGON32_PROVIDER_DEFAULT,
        ctypes.byref(handle)
    )
    if result:
        kernel32.CloseHandle(handle)
        return True
    return False

def get_external_ip_upnp():
    try:
        import miniupnpc
        u = miniupnpc.UPnP()
        u.discoverdelay = 200
        u.discover()
        u.selectigd()
        ip = u.externalipaddress()
        return ip if ip else None
    except Exception:
        return None

def get_router_ip_upnp():
    try:
        import miniupnpc
        from urllib.parse import urlparse
        u = miniupnpc.UPnP()
        u.discoverdelay = 200
        u.discover()
        u.selectigd()
        if u.controlurl:
            host = urlparse(u.controlurl).hostname
            if host and host.count('.') == 3:
                try:
                    ipaddress.ip_address(host)
                    log.info(f"Router IP (UPnP): {host}")
                    return host
                except ValueError:
                    pass
    except Exception:
        pass
    return None

def get_router_ip_windows():
    """通过 route print 获取默认网关"""
    try:
        result = subprocess.run(
            ["route", "print", "0.0.0.0"],
            capture_output=True, text=True
        )
        for line in result.stdout.splitlines():
            if "0.0.0.0" in line:
                parts = line.split()
                if len(parts) >= 3 and parts[2].count('.') == 3:
                    gateway = parts[2]
                    try:
                        ipaddress.ip_address(gateway)
                        log.info(f"Router IP: {gateway}")
                        return gateway
                    except ValueError:
                        continue
    except Exception as e:
        log.error(f"Router IP detection failed: {e}")
    return None

def get_router_ip(cfg):
    """
    优先级：
    1. 配置文件中指定
    2. UPnP 自动获取
    3. Windows ipconfig 获取
    """
    # 检查配置文件
    if cfg.get("router_ip"):
        log.info(f"使用配置文件中的路由器IP: {cfg['router_ip']}")
        return cfg["router_ip"]
    
    router_ip = get_router_ip_upnp()
    if router_ip:
        return router_ip

    router_ip = get_router_ip_windows()
    if router_ip:
        return router_ip
    
    log.warning("无法获取路由器IP")
    return None

def get_local_ip():
    """获取本机IP"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return None

def setup_upnp_ports(cfg):
    try:
        import miniupnpc
    except ImportError:
        log.warning("UPnP: miniupnpc not available")
        return None

    try:
        u = miniupnpc.UPnP()
        u.discoverdelay = 200
        nd = u.discover()
        if nd == 0:
            log.warning("UPnP: no gateway found")
            return None
        log.info(f"UPnP: {nd} gateway(s) found")
        u.selectigd()
        log.info(f"UPnP: local IP: {u.lanaddr}")
    except Exception as e:
        log.error(f"UPnP discovery failed: {e}")
        return None

    ip = u.externalipaddress()
    if ip:
        SmartFTPHandler.masquerade_address = ip
        log.info(f"External IP (UPnP): {ip}")
    else:
        log.warning("UPnP: could not get external IP")

    local_ip = u.lanaddr
    if not local_ip or local_ip == "0.0.0.0":
        local_ip = get_local_ip()
        if local_ip:
            log.info(f"UPnP: using local IP from socket: {local_ip}")

    ok = True

    control_port = cfg.get("port", 21)
    try:
        u.addportmapping(control_port, 'TCP', local_ip, control_port, 'FTP Control', '')
        log.info(f"UPnP mapped: port {control_port} TCP")
    except Exception as e:
        log.error(f"UPnP failed to map port {control_port}: {e}")
        ok = False

    passive_ports = cfg.get("passive_ports", [50000, 50010])
    mapped = 0
    for port in range(passive_ports[0], passive_ports[1] + 1):
        try:
            u.addportmapping(port, 'TCP', local_ip, port, 'FTP Passive', '')
            mapped += 1
        except Exception as e:
            log.error(f"UPnP failed to map port {port}: {e}")
    if mapped > 0:
        log.info(f"UPnP mapped: {mapped}/{passive_ports[1] - passive_ports[0] + 1} passive ports")
        ok = True

    return u

def remove_upnp_mappings(u, cfg):
    if u is None:
        return
    try:
        control_port = cfg.get("port", 21)
        passive_ports = cfg.get("passive_ports", [50000, 50010])
        try:
            u.deleteportmapping(control_port, 'TCP')
        except Exception:
            pass
        for port in range(passive_ports[0], passive_ports[1] + 1):
            try:
                u.deleteportmapping(port, 'TCP')
            except Exception:
                pass
        log.info("UPnP: port mappings removed")
    except Exception as e:
        log.warning(f"UPnP cleanup failed: {e}")

class WindowsAuthorizer(DummyAuthorizer):
    def __init__(self, cfg):
        super().__init__()
        self.cfg = cfg

    def validate_authentication(self, username, password, handler):
        if username == "anonymous":
            if not self.cfg["anonymous"].get("allow_wan", True) and not SmartFTPHandler.is_private_ip(handler.remote_ip):
                raise AuthenticationFailed("Anonymous access from WAN is not allowed")
            return
        if not self.cfg["windows_auth"]["enabled"]:
            raise AuthenticationFailed("Windows authentication is disabled")
        if username.lower() != "administrator":
            deny = self.cfg["windows_auth"].get("deny_users", [])
            if username.lower() in [u.lower() for u in deny]:
                raise AuthenticationFailed("This user account is not allowed")
        if not authenticate_windows_user(username, password):
            raise AuthenticationFailed("Invalid username or password")

    def get_home_dir(self, username):
        if username == "anonymous":
            return self.user_table["anonymous"]["home"]
        home = self.cfg["windows_auth"].get("home_dir")
        if home:
            return os.path.abspath(home)
        home = os.path.expanduser(f"~{username}")
        if home.startswith("~") or not os.path.isdir(home):
            home = f"C:\\Users\\{username}"
        return home

    def has_user(self, username):
        if username == "anonymous":
            return "anonymous" in self.user_table
        return True

    def get_perms(self, username):
        if username == "anonymous":
            return self.user_table["anonymous"]["perm"]
        return self.cfg["windows_auth"]["perms"]

    def has_perm(self, username, perm, path=None):
        if username == "anonymous":
            return super().has_perm(username, perm, path)
        return True

    def get_msg_login(self, username):
        try:
            return self.user_table[username]["msg_login"]
        except KeyError:
            return "Login successful."

    def get_msg_quit(self, username):
        try:
            return self.user_table[username]["msg_quit"]
        except KeyError:
            return "Goodbye."

    def impersonate_user(self, username, password):
        pass

    def terminate_impersonation(self, username):
        pass

def load_config():
    base = sys._MEIPASS if getattr(sys, "frozen", False) else os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(base, "config.json")
    if not os.path.exists(path):
        path = os.path.join(os.path.dirname(sys.executable), "config.json")
    if not os.path.exists(path):
        log.error(f"Config file not found: {path}")
        log.error("Copy config.example.json to config.json and edit it.")
        sys.exit(1)
    with open(path, encoding="utf-8-sig") as f:
        return json.load(f)

def external_ip_updater(cfg, stop_event):
    interval = cfg.get("external_ip", {}).get("check_interval", 60)
    while not stop_event.wait(interval):
        ip = get_external_ip_upnp()
        if ip and ip != SmartFTPHandler.masquerade_address:
            SmartFTPHandler.masquerade_address = ip
            log.info(f"External IP updated: {ip}")

def create_server():
    cfg = load_config()

    authorizer = WindowsAuthorizer(cfg)

    anon = cfg.get("anonymous", {})
    if anon.get("enabled", True):
        home = os.path.abspath(anon.get("home_dir", "."))
        authorizer.add_anonymous(home, perm=anon.get("perms", "elr"))

    SmartFTPHandler.authorizer = authorizer

    # 获取本机 IP
    SmartFTPHandler.local_ip = get_local_ip()
    log.info(f"Local IP: {SmartFTPHandler.local_ip}")
    
    # 获取路由器 IP
    SmartFTPHandler.router_ip = get_router_ip(cfg)

    ext_ip_cfg = cfg.get("external_ip", {})
    if not ext_ip_cfg.get("upnp", False):
        SmartFTPHandler.masquerade_address = cfg.get("masquerade_address")

    ports = cfg.get("passive_ports", [50000, 50010])
    SmartFTPHandler.passive_ports = range(ports[0], ports[1] + 1)

    host = cfg.get("host", "0.0.0.0")
    port = cfg.get("port", 21)
    return cfg, FTPServer((host, port), SmartFTPHandler)

def main():
    setup_logging()
    cfg, server = create_server()
    upnp_obj = None
    ext_ip_cfg = cfg.get("external_ip", {})

    if ext_ip_cfg.get("upnp", False):
        upnp_obj = setup_upnp_ports(cfg)
        if not upnp_obj and not SmartFTPHandler.masquerade_address:
            SmartFTPHandler.masquerade_address = cfg.get("masquerade_address")

    log.info(f"FTP Server started on {cfg['host']}:{cfg['port']}")
    ports = cfg.get("passive_ports", [50000, 50010])
    log.info(f"Passive ports: {ports[0]}-{ports[1]}")
    log.info(f"External IP: {SmartFTPHandler.masquerade_address or '(not set)'}")
    log.info(f"Router IP: {SmartFTPHandler.router_ip or '(not detected)'}")
    if ext_ip_cfg.get("upnp", False):
        log.info(f"UPnP external IP check enabled (interval: {ext_ip_cfg.get('check_interval', 60)}s)")
        log.info("UPnP port mapping active")
    if cfg.get("anonymous", {}).get("enabled", True):
        log.info(f"Anonymous: read-only access (home: {cfg['anonymous'].get('home_dir', '.')})")
    if cfg.get("windows_auth", {}).get("enabled", True):
        log.info("Windows users: full access")
    log.info("Press Ctrl+C to stop")

    stop_event = threading.Event()
    if ext_ip_cfg.get("upnp", False):
        t = threading.Thread(target=external_ip_updater, args=(cfg, stop_event), daemon=True)
        t.start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        stop_event.set()
        log.info("\nServer stopped.")
    finally:
        remove_upnp_mappings(upnp_obj, cfg)

if __name__ == "__main__":
    main()
