import subprocess
import ctypes
import sys
import os
import platform
import psutil
import socket
import threading
from datetime import datetime

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = socket.gethostbyname(socket.gethostname())

def windows_isadmin():
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

def upgrade_win():
    if not windows_isadmin():
        script = os.path.abspath(sys.argv[0])
        params = subprocess.list2cmdline(sys.argv)

        print('Requesting administrative privileges...')
        ret = ctypes.windll.shell32.ShellExecuteW(None, 'runas', sys.executable, params, os.getcwd(), 1)

        if ret <= 32:
            print('Failed to obtain administrative privileges on Windows.')
            sys.exit(1)

def grant_permission():
    sys = platform.system()
    if sys == 'Windows':
        upgrade_win()
    elif sys in ('Linux', 'Darwin'):
        if os.geteuid() != 0:
            os.execvp('sudo', ['sudo', sys.executable] + sys.argv)
    else:
        print(f'Unsupported operating system: {sys}')
        print('Supported OS: Windows, Linux, macOS')

def getpidbyport(port):
    results = list()
    for proc in psutil.net_connections(kind='inet'):
        if proc.laddr and proc.laddr.port == port and proc.pid:
            try:
                p = psutil.Process(proc.pid).name()
                results.append((proc.pid, p))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    return results

def create_dict():
    pdict = {}
    for conn in psutil.net_connections(kind='inet'):
        if conn.laddr and conn.pid and conn.status in (psutil.CONN_LISTEN, 'NONE'):
            pdict.setdefault(conn.laddr.port, set()).add(conn.pid)
    return pdict


def scan(port):
    try:
        out = s.connect_ex((host, port))
        if out == 0:
            print(f'Port {port} is open')
            return True
    except socket.error as error:
        print(f'Error at port {port} connection: {error}')
        return False
    except Exception as e:
        print(f'Unexpected error at port {port} connection: {e}')
        return False

if __name__ == '__main__':

    grant_permission()

    if len(sys.argv) != 3:
        print('Error: Invalid number of arguments.')
        print(f'Usage: python3 portscan.py <start_port> <end_port>')
        sys.exit(1)

    start_port = int(sys.argv[1])
    end_port = int(sys.argv[2])

    print(f'Starting port scan from {start_port} to {end_port} on host {host}...')
    map = create_dict()

    try:
        threads = []

        for port in range(start_port, end_port + 1):
            pids = map.get(port, set())
            if pids:
                for pid in pids:
                    try:
                        process_name = psutil.Process(pid).name()
                        print(f'Port {port} is open and used by PID {pid} ({process_name})')
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        print(f'Port {port} is open and used by unknown process (PID: {pid})')
            thread = threading.Thread(target=scan, args=(port,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        input('Press Enter to exit...')

    except socket.error as error:
        print(f'Socket error: {error}')
        sys.exit(1)
    
    except KeyboardInterrupt:
        print('Scan interrupted by user.')
        sys.exit(0)

    print(f'Port scan completed from {start_port} to {end_port}.')
    print(f'Finished: {datetime.now()}')
