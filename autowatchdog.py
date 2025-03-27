#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import yaml
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileModifiedEvent
from collections import defaultdict

# 导入项目中的相关模块
from UFWClient import UFWClient
from DatabaseClient import DatabaseClient
from main import extract_ip_and_path, match_paths, print_ban_info, load_config


class LogFileHandler(FileSystemEventHandler):
    """处理日志文件变动的事件处理器"""
    
    def __init__(self, log_file, patterns, db_client, ufw_client, config):
        self.log_file = log_file
        self.patterns = patterns
        self.db_client = db_client
        self.ufw_client = ufw_client
        self.last_position = self._get_file_size()
        self.processed_ips = set()
        
        # 获取现有封禁列表
        self.existing_bans = {ip for ip, _ in db_client.get_existing_bans()}
        success, ufw_result = ufw_client.get_banned_ips()
        if success:
            self.ufw_bans = {ip for ip, _ in ufw_result}
        else:
            print(f"\033[31m[!] 无法获取UFW封禁列表: {ufw_result}\033[0m")
            self.ufw_bans = set()
        
        # 添加白名单支持
        self.whitelist = set(config.get('whitelist', []))
    
    def _get_file_size(self):
        """获取文件大小"""
        if os.path.exists(self.log_file):
            return os.path.getsize(self.log_file)
        return 0
    
    def on_modified(self, event):
        """当文件被修改时触发"""
        if not isinstance(event, FileModifiedEvent):
            return
            
        if event.src_path != self.log_file:
            return
            
        # 获取文件当前大小
        current_size = self._get_file_size()
        
        # 如果文件变小了（可能是日志轮转），重置位置
        if current_size < self.last_position:
            print(f"\033[33m[!] 检测到日志文件 {self.log_file} 可能已轮转，重置读取位置\033[0m")
            self.last_position = 0
        
        # 如果文件没有变化，直接返回
        if current_size <= self.last_position:
            return
            
        # 读取新增内容
        with open(self.log_file, 'r', encoding='utf-8', errors='ignore') as f:
            f.seek(self.last_position)
            new_content = f.read()
        
        # 更新文件位置
        self.last_position = current_size
        
        # 处理新增内容
        self._process_new_content(new_content)
    
    def _process_new_content(self, content):
        """处理新增的日志内容"""
        if not content.strip():
            return
            
        # 提取IP和访问路径
        log_lines = content.strip().split('\n')
        print(f"\033[36m[*] 检测到 {len(log_lines)} 条新日志记录\033[0m")
        
        ip_path_entries = extract_ip_and_path(log_lines)
        if not ip_path_entries:
            return
            
        # 过滤已存在的IP
        new_ips = {ip for ip, _ in ip_path_entries if ip not in self.existing_bans}
        if not new_ips:
            return
            
        new_entries = [(ip, path) for ip, path in ip_path_entries if ip in new_ips]
        matched_entries = match_paths(new_entries, self.patterns)
        
        if not matched_entries:
            return
            
        # 处理匹配的条目
        self._process_matched_entries(matched_entries)
    
    def _process_matched_entries(self, matched_entries):
        """处理匹配的条目"""
        banned_count = 0
        skipped_count = 0
        whitelist_count = 0
        whitelisted_ips = set()
        
        print("\033[36m[*] 处理新的封禁...\033[0m")
        
        for ip, path, pattern in matched_entries:
            # 跳过已处理的IP
            if ip in self.processed_ips:
                continue
            
            # 检查是否在白名单中
            if ip in self.whitelist:
                if ip not in whitelisted_ips:
                    print(f"\033[33m[!] 跳过白名单中的IP: {ip}\033[0m")
                    whitelisted_ips.add(ip)
                    whitelist_count += 1
                continue
                
            # 检查IP是否已在UFW黑名单中
            if ip in self.ufw_bans:
                print(f"\033[33m[!] 跳过已存在于UFW黑名单的IP: {ip}\033[0m")
                if self.db_client.save_ban(ip, path, pattern):
                    skipped_count += 1
                    self.processed_ips.add(ip)
                    self.existing_bans.add(ip)
                else:
                    print(f"\033[31m[!] 保存IP到数据库失败: {ip}\033[0m")
                continue
                
            # 执行封禁
            print_ban_info(ip, path, pattern)
            success, error = self.ufw_client.ban_ip(ip)
            if success:
                if self.db_client.save_ban(ip, path, pattern):
                    banned_count += 1
                    self.processed_ips.add(ip)
                    self.existing_bans.add(ip)
                    self.ufw_bans.add(ip)
                else:
                    print(f"\033[31m[!] 保存IP到数据库失败: {ip}\033[0m")
            else:
                print(f"\033[31m[!] 封禁IP失败 {ip}: {error}\033[0m")
        
        if banned_count > 0 or skipped_count > 0 or whitelist_count > 0:
            print("\033[36m" + "="*50 + "\033[0m")
            print(f"\033[1m本次封禁：\033[32m{banned_count}\033[0m 个IP")
            print(f"\033[1m本次跳过：\033[33m{skipped_count}\033[0m 个IP")
            print(f"\033[1m白名单跳过：\033[33m{whitelist_count}\033[0m 个IP")
            print("\033[36m" + "="*50 + "\033[0m")


class LogWatchdog:
    """日志文件监控守护进程"""
    
    def __init__(self, config_path='config.yaml'):
        self.config = load_config(config_path)
        self.db_client = DatabaseClient()
        self.ufw_client = UFWClient(self.db_client)
        self.observer = Observer()
        self.handlers = []
        
    def start(self):
        """启动监控"""
        log_paths = self.config.get('log', [])
        patterns = self.config.get('patterns', [])
        
        if not log_paths:
            print("\033[31m[!] 错误: 配置文件中未找到日志路径\033[0m")
            return False
            
        if not patterns:
            print("\033[31m[!] 错误: 配置文件中未找到匹配模式\033[0m")
            return False
        
        print("\033[36m[*] 启动日志监控守护进程...\033[0m")
        print(f"\033[36m[*] 监控日志文件: {', '.join(log_paths)}\033[0m")
        
        for log_path in log_paths:
            if not os.path.isfile(log_path):
                print(f"\033[33m[!] 警告: 日志文件不存在: {log_path}\033[0m")
                continue
                
            log_dir = os.path.dirname(log_path)
            handler = LogFileHandler(log_path, patterns, self.db_client, self.ufw_client, self.config)
            self.handlers.append(handler)
            
            self.observer.schedule(handler, log_dir, recursive=False)
            print(f"\033[32m[+] 成功添加监控: {log_path}\033[0m")
        
        if not self.handlers:
            print("\033[31m[!] 错误: 没有有效的日志文件可以监控\033[0m")
            return False
            
        self.observer.start()
        print("\033[32m[+] 监控守护进程已启动\033[0m")
        return True
        
    def stop(self):
        """停止监控"""
        self.observer.stop()
        self.observer.join()
        print("\033[36m[*] 监控守护进程已停止\033[0m")


def main():
    """主函数"""
    watchdog = LogWatchdog()
    if not watchdog.start():
        return 1
        
    try:
        print("\033[36m[*] 按 Ctrl+C 停止监控...\033[0m")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\033[36m[*] 接收到停止信号，正在停止...\033[0m")
    finally:
        watchdog.stop()
    
    return 0


if __name__ == '__main__':
    sys.exit(main())