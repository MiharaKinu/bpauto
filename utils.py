import yaml
import re
import os
import sys
from fnmatch import fnmatch
import subprocess

def load_config():
    try:
        application_path = get_application_path()
        config_path = os.path.join(application_path, 'config.yaml')
        
        if not os.path.exists(config_path):
            print(f"\033[31m[!] 配置文件不存在: {config_path}\033[0m")
            return None
            
        with open(config_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
            
        if not config:
            print("\033[31m[!] 配置文件为空或格式错误\033[0m")
            return None
            
        return config
    except Exception as e:
        print(f"\033[31m[!] 加载配置文件时出错: {str(e)}\033[0m")
        return None

def tail_logs(log_paths, lines=5000):
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
            if pattern.startswith('/^/'): 
                try:
                    regex_pattern = pattern[3:]
                    if re.match(regex_pattern, path):
                        matched.add((ip, path, pattern))
                except re.error:
                    continue
            elif fnmatch(path, pattern):
                matched.add((ip, path, pattern))
    return matched

def print_ban_info(ip: str, path: str, pattern: str) -> None:
    print("\033[32m+" + "="*50 + "+\033[0m")
    print(f"\033[32m| IP地址: {ip:<42} |\033[0m")
    print(f"\033[36m| 访问路径: {path:<40} |\033[0m")
    print(f"\033[33m| 匹配规则: {pattern:<40} |\033[0m")
    print("\033[32m+" + "="*50 + "+\033[0m")

def get_application_path():
    """获取应用程序路径，处理 PyInstaller 打包和开发环境的情况"""
    if getattr(sys, 'frozen', False):
        # PyInstaller 打包后的路径
        return os.path.dirname(sys.executable)
    # 开发环境下的路径
    return os.path.dirname(os.path.abspath(__file__))