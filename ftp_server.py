import os
import ctypes
import ctypes.wintypes
from pyftpdlib.authorizers import DummyAuthorizer, AuthenticationFailed
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

advapi32 = ctypes.windll.advapi32
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
        advapi32.CloseHandle(handle)
        return True
    return False

class WindowsAuthorizer(DummyAuthorizer):
    def validate_authentication(self, username, password, handler):
        if username == "anonymous":
            if password:
                raise AuthenticationFailed("Invalid password")
            return
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
            return "elr"
        return "elradfmw"

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

def main():
    authorizer = WindowsAuthorizer()
    authorizer.add_anonymous(os.getcwd(), perm="elr")

    FTPHandler.authorizer = authorizer
    FTPHandler.masquerade_address = "sohai.space"
    FTPHandler.passive_ports = range(50000, 50011)

    server = FTPServer(("0.0.0.0", 21), FTPHandler)

    print("FTP Server started on port 21")
    print("Passive ports: 50000-50010")
    print("External IP: sohai.space")
    print("Anonymous: read-only access (empty password)")
    print("Windows users: full access (use your Windows credentials)")
    print("Press Ctrl+C to stop")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")

if __name__ == "__main__":
    main()
