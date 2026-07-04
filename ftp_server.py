import os
import json
import sys
import ctypes
import ctypes.wintypes
import win32serviceutil
import win32service
import servicemanager
from pyftpdlib.authorizers import DummyAuthorizer, AuthenticationFailed
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

advapi32 = ctypes.windll.advapi32
LOGON32_LOGON_NETWORK = 3
LOGON32_PROVIDER_DEFAULT = 0

SERVICE_NAME = "FtpServer"
SERVICE_DISPLAY_NAME = "FTP Server"

def authenticate_windows_user(username, password):
    handle = ctypes.wintypes.HANDLE()
    result = advapi32.LogonUserW(
        username, None, password,
        LOGON32_LOGON_NETWORK,
        LOGON32_PROVIDER_DEFAULT,
        ctypes.byref(handle)
    )
    if result:
        advapi32.CloseHandle(handle)
        return True
    return False

class WindowsAuthorizer(DummyAuthorizer):
    def __init__(self, cfg):
        super().__init__()
        self.cfg = cfg

    def validate_authentication(self, username, password, handler):
        if username == "anonymous":
            if password:
                raise AuthenticationFailed("Invalid password")
            return
        if not self.cfg["windows_auth"]["enabled"]:
            raise AuthenticationFailed("Windows authentication is disabled")
        if not authenticate_windows_user(username, password):
            raise AuthenticationFailed("Invalid username or password")

    def get_home_dir(self, username):
        if username == "anonymous":
            return self.user_table["anonymous"]["home"]
        return os.path.expanduser(f"~{username}")

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
    with open(path, encoding="utf-8") as f:
        return json.load(f)

def create_server():
    cfg = load_config()

    authorizer = WindowsAuthorizer(cfg)

    anon = cfg.get("anonymous", {})
    if anon.get("enabled", True):
        home = os.path.abspath(anon.get("home_dir", "."))
        authorizer.add_anonymous(home, perm=anon.get("perms", "elr"))

    FTPHandler.authorizer = authorizer
    FTPHandler.masquerade_address = cfg.get("masquerade_address")
    ports = cfg.get("passive_ports", [50000, 50010])
    FTPHandler.passive_ports = range(ports[0], ports[1] + 1)

    host = cfg.get("host", "0.0.0.0")
    port = cfg.get("port", 21)
    return cfg, FTPServer((host, port), FTPHandler)

class FTPService(win32serviceutil.ServiceFramework):
    _svc_name_ = SERVICE_NAME
    _svc_display_name_ = SERVICE_DISPLAY_NAME
    _svc_description_ = "Custom FTP Server with Windows authentication"

    def __init__(self, args):
        super().__init__(args)
        self.server = None

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        if self.server:
            self.server.close_all()
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STOPPED,
            (self._svc_name_, ""),
        )

    def SvcDoRun(self):
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, ""),
        )
        self.ReportServiceStatus(win32service.SERVICE_RUNNING)
        try:
            self.cfg, self.server = create_server()
            self.server.serve_forever()
        except Exception as e:
            servicemanager.LogErrorMsg(f"FTP Server error: {e}")

def run_console():
    cfg, server = create_server()

    print(f"FTP Server started on {cfg['host']}:{cfg['port']}")
    ports = cfg.get("passive_ports", [50000, 50010])
    print(f"Passive ports: {ports[0]}-{ports[1]}")
    if cfg.get("masquerade_address"):
        print(f"External IP: {cfg['masquerade_address']}")
    if cfg.get("anonymous", {}).get("enabled", True):
        print(f"Anonymous: read-only access (home: {cfg['anonymous'].get('home_dir', '.')})")
    if cfg.get("windows_auth", {}).get("enabled", True):
        print("Windows users: full access")
    print("Press Ctrl+C to stop")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")

def main():
    if len(sys.argv) > 1 and sys.argv[1] in ("install", "remove", "start", "stop", "restart", "debug"):
        win32serviceutil.HandleCommandLine(FTPService)
    else:
        run_console()

if __name__ == "__main__":
    main()
