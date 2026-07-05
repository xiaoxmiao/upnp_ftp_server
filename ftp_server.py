import os
import json
import sys
import threading
import ctypes
import ctypes.wintypes
import ipaddress
import socket
import subprocess
from pyftpdlib.authorizers import DummyAuthorizer, AuthenticationFailed
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

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
            print(f"[Connect] 内网客户端通过外网访问 (来自路由器 {self.remote_ip}) -> 使用 masquerade: {type(self).masquerade_address}")
            return
        
        # 检查客户端是否来自本地私网
        client_is_private = self.is_private_ip(self.remote_ip)
        
        if client_is_private:
            # 直接从内网连接 → 使用本地IP
            self.masquerade_address = None
            print(f"[Connect] 内网客户端 {self.remote_ip} -> 使用本地 IP")
        else:
            # 外网客户端 → 使用masquerade
            print(f"[Connect] 外网客户端 {self.remote_ip} -> 使用 masquerade: {type(self).masquerade_address}")

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
    """通过 UPnP 获取路由器IP"""
    try:
        import miniupnpc
        u = miniupnpc.UPnP()
        u.discoverdelay = 200
        u.discover()
        u.selectigd()
        # 获取路由器的本地IP
        router_ip = u.lanaddr
        if router_ip and router_ip != "0.0.0.0":
            print(f"UPnP: 获取路由器IP: {router_ip}")
            return router_ip
    except Exception as e:
        print(f"UPnP: 获取路由器IP失败: {e}")
    return None

def get_router_ip_windows():
    """通过 Windows 命令获取路由器IP（默认网关）"""
    try:
        # 使用 GBK 编码（Windows 中文系统默认编码）
        result = subprocess.run(
            ["ipconfig"],
            capture_output=True,
            text=False
        )
        
        # 尝试 GBK 解码，失败则尝试 UTF-8
        try:
            output = result.stdout.decode('gbk')
        except UnicodeDecodeError:
            try:
                output = result.stdout.decode('utf-8')
            except UnicodeDecodeError:
                output = result.stdout.decode('utf-8', errors='ignore')
        
        lines = output.split('\n')
        for i, line in enumerate(lines):
            # 寻找 IPv4 网关行
            if "默认网关" in line or "Default Gateway" in line:
                # 跳过 IPv6 网关
                if i > 0 and "IPv6" in lines[i-1]:
                    continue
                
                parts = line.split(':')
                if len(parts) >= 2:
                    gateway = parts[-1].strip()
                    # 验证是否为有效的 IPv4 地址
                    if gateway and '.' in gateway:  # IPv4 包含点号
                        try:
                            ipaddress.ip_address(gateway)
                            print(f"Windows: 获取路由器IP: {gateway}")
                            return gateway
                        except ValueError:
                            continue
    except Exception as e:
        print(f"Windows: 获取路由器IP失败: {e}")
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
        print(f"使用配置文件中的路由器IP: {cfg['router_ip']}")
        return cfg["router_ip"]
    
    # 尝试 UPnP
    router_ip = get_router_ip_upnp()
    if router_ip:
        return router_ip
    
    # 尝试 Windows ipconfig
    router_ip = get_router_ip_windows()
    if router_ip:
        return router_ip
    
    print("警告: 无法获取路由器IP")
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
        print("UPnP: miniupnpc not available")
        return None

    try:
        u = miniupnpc.UPnP()
        u.discoverdelay = 200
        nd = u.discover()
        if nd == 0:
            print("UPnP: no gateway found")
            return None
        print(f"UPnP: {nd} gateway(s) found")
        u.selectigd()
        print(f"UPnP: local IP: {u.lanaddr}")
    except Exception as e:
        print(f"UPnP discovery failed: {e}")
        return None

    ip = u.externalipaddress()
    if ip:
        SmartFTPHandler.masquerade_address = ip
        print(f"External IP (UPnP): {ip}")
    else:
        print("UPnP: could not get external IP")

    local_ip = u.lanaddr
    if not local_ip or local_ip == "0.0.0.0":
        local_ip = get_local_ip()
        if local_ip:
            print(f"UPnP: using local IP from socket: {local_ip}")

    ok = True

    control_port = cfg.get("port", 21)
    try:
        u.addportmapping(control_port, 'TCP', local_ip, control_port, 'FTP Control', '')
        print(f"UPnP mapped: port {control_port} TCP")
    except Exception as e:
        print(f"UPnP failed to map port {control_port}: {e}")
        ok = False

    passive_ports = cfg.get("passive_ports", [50000, 50010])
    mapped = 0
    for port in range(passive_ports[0], passive_ports[1] + 1):
        try:
            u.addportmapping(port, 'TCP', local_ip, port, 'FTP Passive', '')
            mapped += 1
        except Exception as e:
            print(f"UPnP failed to map port {port}: {e}")
    if mapped > 0:
        print(f"UPnP mapped: {mapped}/{passive_ports[1] - passive_ports[0] + 1} passive ports")
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
        print("UPnP: port mappings removed")
    except Exception as e:
        print(f"UPnP cleanup failed: {e}")

class WindowsAuthorizer(DummyAuthorizer):
    def __init__(self, cfg):
        super().__init__()
        self.cfg = cfg

    def validate_authentication(self, username, password, handler):
        if username == "anonymous":
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
        print(f"Config file not found: {path}")
        print("Copy config.example.json to config.json and edit it.")
        sys.exit(1)
    with open(path, encoding="utf-8-sig") as f:
        return json.load(f)

def external_ip_updater(cfg, stop_event):
    interval = cfg.get("external_ip", {}).get("check_interval", 60)
    while not stop_event.wait(interval):
        ip = get_external_ip_upnp()
        if ip and ip != SmartFTPHandler.masquerade_address:
            SmartFTPHandler.masquerade_address = ip
            print(f"External IP updated: {ip}")

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
    print(f"Local IP: {SmartFTPHandler.local_ip}")
    
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
    cfg, server = create_server()
    upnp_obj = None
    ext_ip_cfg = cfg.get("external_ip", {})

    if ext_ip_cfg.get("upnp", False):
        upnp_obj = setup_upnp_ports(cfg)
        if not upnp_obj and not SmartFTPHandler.masquerade_address:
            SmartFTPHandler.masquerade_address = cfg.get("masquerade_address")

    print(f"FTP Server started on {cfg['host']}:{cfg['port']}")
    ports = cfg.get("passive_ports", [50000, 50010])
    print(f"Passive ports: {ports[0]}-{ports[1]}")
    print(f"External IP: {SmartFTPHandler.masquerade_address or '(not set)'}")
    print(f"Router IP: {SmartFTPHandler.router_ip or '(not detected)'}")
    if ext_ip_cfg.get("upnp", False):
        print(f"UPnP external IP check enabled (interval: {ext_ip_cfg.get('check_interval', 60)}s)")
        print("UPnP port mapping active")
    if cfg.get("anonymous", {}).get("enabled", True):
        print(f"Anonymous: read-only access (home: {cfg['anonymous'].get('home_dir', '.')})")
    if cfg.get("windows_auth", {}).get("enabled", True):
        print("Windows users: full access")
    print("Press Ctrl+C to stop")

    stop_event = threading.Event()
    if ext_ip_cfg.get("upnp", False):
        t = threading.Thread(target=external_ip_updater, args=(cfg, stop_event), daemon=True)
        t.start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        stop_event.set()
        print("\nServer stopped.")
    finally:
        remove_upnp_mappings(upnp_obj, cfg)

if __name__ == "__main__":
    main()
