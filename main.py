import yaml
import re
import os
import subprocess
import time
import sys
from collections import defaultdict
from UFWClient import UFWClient
from fnmatch import fnmatch
from DatabaseClient import DatabaseClient

def load_config(config_path='config.yaml'):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_file = os.path.join(script_dir, config_path)
    with open(config_file, 'r') as f:
        return yaml.safe_load(f)

def tail_logs(log_paths, lines=1000):
    log_data = []
    for log_path in log_paths:
        if os.path.isfile(log_path):
            output = subprocess.run(['tail', '-n', str(lines), log_path], capture_output=True, text=True)
            log_data.extend(output.stdout.strip().split("\n"))
    return log_data

def extract_ip_and_path(log_data):
    pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+).+?"(GET|POST|HEAD|PUT|DELETE)\s([^\s]+)')
    extracted = [(m.group(1), m.group(3)) for m in pattern.finditer('\n'.join(log_data))]
    return extracted

def match_paths(entries, patterns):
    matched = set()
    for ip, path in entries:
        for pattern in patterns:
            # 处理正则表达式规则
            if pattern.startswith('/^/'): 
                try:
                    # 移除前缀 /^/ 并编译正则表达式
                    regex_pattern = pattern[3:]
                    if re.match(regex_pattern, path):
                        matched.add((ip, path, pattern))
                except re.error:
                    continue
            # 处理普通的通配符规则
            elif fnmatch(path, pattern):
                matched.add((ip, path, pattern))
    return matched

def print_ban_info(ip: str, path: str, pattern: str) -> None:
    """
    以表格形式打印封禁信息
    """
    print("\033[32m+" + "="*50 + "+\033[0m")
    print(f"\033[32m| IP地址: {ip:<42} |\033[0m")
    print(f"\033[36m| 访问路径: {path:<40} |\033[0m")
    print(f"\033[33m| 匹配规则: {pattern:<40} |\033[0m")
    print("\033[32m+" + "="*50 + "+\033[0m")

def process_bans():
    """
    核心封禁处理流程
    """
    config = load_config()
    db_client = DatabaseClient()
    ufw = UFWClient(db_client)
    
    log_paths: List[str] = config.get('log', [])
    patterns: List[str] = config.get('patterns', [])
    whitelist: List[str] = config.get('whitelist', [])
    log_lines: int = config.get('log_lines', 5000)

    print("\033[36m[*] Reading logs...\033[0m")
    log_data = tail_logs(log_paths, log_lines)
    ip_path_entries = extract_ip_and_path(log_data)

    print("\033[36m[*] Checking existing bans...\033[0m")
    existing_bans = {ip for ip, _ in db_client.get_existing_bans()}
    # 获取UFW现有黑名单
    success, ufw_result = ufw.get_banned_ips()
    if not success:
        print(f"\033[31m[!] Failed to get UFW bans: {ufw_result}\033[0m")
        return
    ufw_bans = {ip for ip, _ in ufw_result}

    new_ips = {ip for ip, _ in ip_path_entries if ip not in existing_bans}
    
    new_entries = [(ip, path) for ip, path in ip_path_entries if ip in new_ips]
    matched_entries = match_paths(new_entries, patterns)

    if not matched_entries:
        print("\033[33m[!] No new IPs to ban\033[0m")
        return

    print("\033[36m[*] Processing bans...\033[0m")
    banned_count = 0
    skipped_count = 0
    whitelist_count = 0  # 新增：统计白名单跳过数量
    processed_ips = set()
    whitelisted_ips = set()
    
    for ip, path, pattern in matched_entries:
        if ip in processed_ips:
            continue
            
        if ip in whitelist:
            if ip not in whitelisted_ips:
                print(f"\033[33m[!] Skipping ban for whitelisted IP: {ip}\033[0m")
                whitelisted_ips.add(ip)
                whitelist_count += 1  # 新增：增加白名单计数
            continue
            
        if ip in ufw_bans:
            print(f"\033[33m[!] Skipping UFW ban for existing IP: {ip}\033[0m")
            if db_client.save_ban(ip, path, pattern):
                skipped_count += 1
                processed_ips.add(ip)
            else:
                print(f"\033[31m[!] Failed to save ban to database for IP: {ip}\033[0m")
            continue
            
        print_ban_info(ip, path, pattern)
        success, error = ufw.ban_ip(ip)
        if success:
            if db_client.save_ban(ip, path, pattern):
                banned_count += 1
                processed_ips.add(ip)
            else:
                print(f"\033[31m[!] Failed to save ban to database for IP: {ip}\033[0m")
        else:
            print(f"\033[31m[!] Failed to ban IP {ip}: {error}\033[0m")

    print("\033[36m" + "="*50 + "\033[0m")
    print(f"\033[1m本次封禁：\033[32m{banned_count}\033[0m 个IP")
    print(f"\033[1m本次跳过：\033[33m{skipped_count}\033[0m 个IP")
    print(f"\033[1m白名单跳过：\033[33m{whitelist_count}\033[0m 个IP")  # 新增：显示白名单跳过数量
    print("\033[36m" + "="*50 + "\033[0m")

if __name__ == '__main__':
    from CLIHandler import CLIHandler
    handler = CLIHandler()
    sys.exit(handler.handle_arguments(sys.argv))
