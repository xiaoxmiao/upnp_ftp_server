import os
import json
import sys
import threading
import ctypes
import ctypes.wintypes
from pyftpdlib.authorizers import DummyAuthorizer, AuthenticationFailed
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

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

def setup_upnp_ports(cfg):
    try:
        import miniupnpc
        import socket
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
        FTPHandler.masquerade_address = ip
        print(f"External IP (UPnP): {ip}")
    else:
        print("UPnP: could not get external IP")

    local_ip = u.lanaddr
    if not local_ip or local_ip == "0.0.0.0":
        local_ip = socket.gethostbyname(socket.gethostname())
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
        if ip and ip != FTPHandler.masquerade_address:
            FTPHandler.masquerade_address = ip
            print(f"External IP updated: {ip}")

def create_server():
    cfg = load_config()

    authorizer = WindowsAuthorizer(cfg)

    anon = cfg.get("anonymous", {})
    if anon.get("enabled", True):
        home = os.path.abspath(anon.get("home_dir", "."))
        authorizer.add_anonymous(home, perm=anon.get("perms", "elr"))

    FTPHandler.authorizer = authorizer

    ext_ip_cfg = cfg.get("external_ip", {})
    if not ext_ip_cfg.get("upnp", False):
        FTPHandler.masquerade_address = cfg.get("masquerade_address")

    ports = cfg.get("passive_ports", [50000, 50010])
    FTPHandler.passive_ports = range(ports[0], ports[1] + 1)

    host = cfg.get("host", "0.0.0.0")
    port = cfg.get("port", 21)
    return cfg, FTPServer((host, port), FTPHandler)

def main():
    cfg, server = create_server()
    upnp_obj = None
    ext_ip_cfg = cfg.get("external_ip", {})

    if ext_ip_cfg.get("upnp", False):
        upnp_obj = setup_upnp_ports(cfg)
        if not upnp_obj and not FTPHandler.masquerade_address:
            FTPHandler.masquerade_address = cfg.get("masquerade_address")

    print(f"FTP Server started on {cfg['host']}:{cfg['port']}")
    ports = cfg.get("passive_ports", [50000, 50010])
    print(f"Passive ports: {ports[0]}-{ports[1]}")
    print(f"External IP: {FTPHandler.masquerade_address or '(not set)'}")
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
