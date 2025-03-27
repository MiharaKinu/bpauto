import sqlite3
import os
import sys

class DatabaseClient:
    def __init__(self, db_path='ban_address.db'):
        if getattr(sys, 'frozen', False):
            # PyInstaller 打包后的路径
            application_path = os.path.dirname(sys.executable)
        else:
            # 开发环境下的路径
            application_path = os.path.dirname(os.path.abspath(__file__))
            
        self.db_path = os.path.join(application_path, db_path)
        self._initialize_db()
    
    def _initialize_db(self):
        """Initialize the database if it doesn't exist"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS ban_address (ip_addr TEXT, access_path TEXT, patterns TEXT)")
        conn.commit()
        conn.close()
    
    def get_existing_bans(self):
        """Get all existing bans from the database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT ip_addr, access_path FROM ban_address")
        existing = set(cursor.fetchall())
        
        conn.close()
        return existing
    
    def save_ban(self, ip, path, pattern):
        """Save a ban to the database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("INSERT INTO ban_address (ip_addr, access_path, patterns) VALUES (?, ?, ?)", 
                       (ip, path, pattern))
        conn.commit()
        conn.close()
        return True
    
    def check_ip_exists(self, ip):
        """检查指定 IP 是否在封禁列表中"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM ban_address WHERE ip_addr = ?', (ip,))
        count = cursor.fetchone()[0]
        conn.close()
        return count > 0
    
    def delete_ban(self, ip):
        """从数据库中删除指定 IP 的封禁记录"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM ban_address WHERE ip_addr = ?', (ip,))
        conn.commit()
        conn.close()
    
    def get_rule_for_ip(self, ip):
        """获取指定 IP 的匹配规则"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT patterns FROM ban_address WHERE ip_addr = ?', (ip,))
        result = cursor.fetchone()
        conn.close()
        return result[0] if result else None

    def get_ip_details(self, ip):
        """获取指定 IP 的详细信息"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT ip_addr, access_path, patterns FROM ban_address WHERE ip_addr = ?', (ip,))
        result = cursor.fetchone()
        conn.close()
        return result
    
    def get_all_banned_ips(self) -> list:
        """获取所有被封禁的 IP 地址列表"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT ip_addr FROM ban_address')
        result = [row[0] for row in cursor.fetchall()]
        conn.close()
        return result
    