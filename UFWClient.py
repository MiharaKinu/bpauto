import subprocess

class UFWClient:
    def __init__(self, db_client):
        self.db_client = db_client

    def ban_ip(self, ip):
        if not isinstance(ip, str):
            return (False, 'Invalid IP type')
        try:
            subprocess.run(['ufw', 'deny', 'from', ip], check=True)
            return (True, None)
        except subprocess.CalledProcessError as e:
            return (False, f'Failed to ban IP {ip}: {e}')

    def unban_ip(self, ip):
        if not isinstance(ip, str):
            return (False, 'Invalid IP type')
        try:
            subprocess.run(['ufw', 'delete', 'deny', 'from', ip], check=True)
            return (True, None)
        except subprocess.CalledProcessError as e:
            return (False, f'Failed to unban IP {ip}: {e}')

    def get_banned_ips(self):
        try:
            result = subprocess.run(['ufw', 'status'], capture_output=True, text=True, check=True)
            banned_ips = []
            for line in result.stdout.splitlines():
                if 'DENY' in line:
                    parts = line.split()
                    if len(parts) >= 3 and parts[0] == 'Anywhere':
                        banned_ips.append((parts[2], 'Anywhere'))
                    elif len(parts) >= 2 and parts[1] == 'DENY':
                        banned_ips.append((parts[0], 'Anywhere'))
            return (True, banned_ips)
        except subprocess.CalledProcessError as e:
            return (False, f'Failed to get banned IPs: {e}')
