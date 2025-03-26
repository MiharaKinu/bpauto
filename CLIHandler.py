from typing import Optional
import sys
from DatabaseClient import DatabaseClient
from UFWClient import UFWClient

class CLIHandler:
    def __init__(self):
        self.db_client = DatabaseClient()
        self.ufw = UFWClient(self.db_client)

    def handle_arguments(self, args: list) -> Optional[int]:
        if len(args) < 2:
            self.print_help()
            return 1

        command = args[1].lower()
        
        if command == 'bp':
            from main import process_bans
            process_bans()
        elif command == 'show':
            self.show_bans()
        elif command == 'unban':
            return self.handle_unban(args)
        elif command == 'get':
            return self.handle_get(args)
        elif command == 'clear': 
            return self.handle_clear()
        elif command == 'help':
            self.print_help()
        else:
            print("\033[31m未知命令。\033[0m")
            self.print_help()
            return 1

    def handle_get(self, args: list) -> int:
        """处理 get 命令"""
        if len(args) != 3:
            print("\033[31m错误：请指定要查询的 IP\033[0m")
            print("用法：python script.py get <ip>")
            return 1
            
        ip = args[2]
        result = self.db_client.get_ip_details(ip)

        if not result:
            print(f"\n\033[33m⚠️  IP [{ip}] 不在封禁列表中\033[0m\n")
            return 1

        ip_addr, access_path, patterns = result
        print(f"""
\033[1;36m📌 封禁详情\033[0m
\033[36m{'='*50}\033[0m
\033[1m🔒 IP 地址:\033[0m {ip_addr}
\033[1m🌐 访问路径:\033[0m {access_path}
\033[1m⚡ 匹配规则:\033[0m {patterns}
\033[36m{'='*50}\033[0m
""")
        return 0

    def handle_unban(self, args: list) -> int:
        if len(args) != 3:
            print("\033[31m错误：请指定要解封的 IP\033[0m")
            print("用法：python script.py unban <ip>")
            return 1
            
        ip = args[2]
        if not self.db_client.check_ip_exists(ip):
            print(f"\033[31m错误：IP {ip} 不在封禁列表中\033[0m")
            return 1
            
        success, error = self.ufw.unban_ip(ip)
        if success:
            self.db_client.delete_ban(ip)
            print(f"\033[32m成功解封 IP：{ip}\033[0m")
        else:
            print(f"\033[31m解封失败：{error}\033[0m")
        return 0

    def show_bans(self):
        success, result = self.ufw.get_banned_ips()
        if not success:
            print(f"\033[31m错误：{result}\033[0m")
            return
        
        print("\n\033[1m当前封禁列表：\033[0m")
        print("\033[36m" + "="*50 + "\033[0m")
        print("\033[1m{:<20} {:<15}\033[0m".format("IP 地址", "匹配规则"))
        for ip, source in result:
            matched_rule = self.db_client.get_rule_for_ip(ip) or "未知"
            print("{:<20} {:<15}".format(ip, matched_rule))
        print("\033[36m" + "="*50 + "\033[0m")
        print(f"\n总计: \033[1m{len(result)}\033[0m 条记录")

    def handle_clear(self) -> int:
        """处理 clear 命令，清除所有封禁"""
        success, result = self.ufw.get_banned_ips()
        if not success:
            print(f"\033[31m错误：无法获取封禁列表：{result}\033[0m")
            return 1

        if not result:
            print("\n\033[33m⚠️  当前没有已封禁的 IP\033[0m\n")
            return 0

        total = len(result)
        print(f"\n\033[1;36m🧹 开始清理封禁列表 (共 {total} 条记录)\033[0m")
        print("\033[36m" + "="*50 + "\033[0m")

        success_count = 0
        for ip, _ in result:
            print(f"\033[1m[{success_count + 1}/{total}]\033[0m 正在解封 IP: {ip}...", end=' ')
            success, error = self.ufw.unban_ip(ip)
            if success:
                self.db_client.delete_ban(ip)
                print("\033[32m✓\033[0m")
                success_count += 1
            else:
                print(f"\033[31m✗ ({error})\033[0m")

        print("\033[36m" + "="*50 + "\033[0m")
        print(f"\n\033[1m清理完成：\033[32m{success_count}\033[0m/\033[1m{total}\033[0m 条记录已处理")
        if success_count != total:
            print(f"\033[31m{total - success_count} 条记录处理失败\033[0m")
        print()
        return 0

    def print_help(self):
        print("\n\033[1m使用方法：\033[0m python main.py [command]")
        print("\n\033[1m可用命令：\033[0m")
        print("  \033[32mbp\033[0m     运行封禁进程（默认行为）")
        print("  \033[32mshow\033[0m   显示当前封禁列表")
        print("  \033[32mget\033[0m    获取指定 IP 的详细信息，用法：get <ip>")
        print("  \033[32munban\033[0m  解封指定 IP，用法：unban <ip>")
        print("  \033[32mclear\033[0m  清除所有封禁记录")
        print("  \033[32mhelp\033[0m   显示帮助信息\n")