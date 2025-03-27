import yaml
import re
import os
import subprocess
import time
import sys
import signal
from collections import defaultdict
from UFWClient import UFWClient
from fnmatch import fnmatch
from DatabaseClient import DatabaseClient

# 修改导入部分
from utils import extract_ip_and_path, match_paths, print_ban_info, load_config, tail_logs

def signal_handler(signum, frame):
    print("\n\033[33m[!] 程序被用户中断，正在退出...\033[0m")
    sys.exit(0)

def process_bans():
    """
    核心封禁处理流程
    """
    # 注册信号处理器
    signal.signal(signal.SIGINT, signal_handler)
    
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
