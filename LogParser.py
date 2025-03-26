from typing import List, Tuple
import subprocess
import os
import re
from fnmatch import fnmatch

def tail_logs(log_paths: List[str], lines: int = 1000) -> List[str]:
    """
    读取指定日志文件的末尾内容
    
    Args:
        log_paths: 日志文件路径列表
        lines: 要读取的行数
    
    Returns:
        合并后的日志行列表
    """
    log_data = []
    for log_path in log_paths:
        if os.path.isfile(log_path):
            output = subprocess.run(['tail', '-n', str(lines), log_path], 
                                  capture_output=True, text=True)
            log_data.extend(output.stdout.strip().split("\n"))
    return log_data

def extract_ip_and_path(log_data: List[str]) -> List[Tuple[str, str]]:
    """
    从日志数据中提取IP和访问路径
    
    Args:
        log_data: 原始日志行列表
    
    Returns:
        包含(IP地址, 访问路径)的元组列表
    """
    pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+).+?"(GET|POST|HEAD|PUT|DELETE)\s([^\s]+)')
    return [
        (m.group(1), m.group(3)) 
        for line in log_data 
        for m in pattern.finditer(line)
    ]

def match_paths(entries: List[Tuple[str, str]], 
               patterns: List[str]) -> set[Tuple[str, str, str]]:
    """
    匹配路径模式
    
    Args:
        entries: (IP, 路径)元组列表
        patterns: 要匹配的路径模式列表
    
    Returns:
        匹配的(IP, 路径, 模式)元组集合
    """
    return {
        (ip, path, pattern)
        for ip, path in entries
        for pattern in patterns
        if fnmatch(path, pattern)
    }