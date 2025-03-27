# 自动封禁IP工具

基于日志分析自动封禁恶意IP的UFW防火墙管理工具

## 功能特性
- 实时分析Nginx访问日志
- 支持自定义URL匹配模式
- 自动持久化封禁记录到SQLite
- 提供封禁列表查看功能
- 支持手动解封操作

## 安装说明
```bash
git clone https://github.com/MiharaKinu/bpauto.git
cd bpauto
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
sudo usermod -aG sudo $(whoami)  # 授予UFW权限
```

## 快速开始
1. 复制配置文件模板
```bash
cp config.yaml.template config.yaml
```
2. 编辑config.yaml配置日志路径和匹配规则
3. 运行封禁程序
```bash
python main.py bp
```

## 编译可执行文件

```bash
./build.sh
```

然后编译结果会在./dist/


## 命令参考
- `python main.py show` 查看当前封禁列表
- `python main.py clear` 清除所有封禁记录
- `python main.py unban <IP>` 解封指定IP
- `python main.py get <IP>` 获取指定IP的详细封禁信息
- `python main.py redo` 重新执行数据库中的封禁

## UFW调试命令
- `sudo ufw status` 查看当前UFW防火墙状态
- `sudo ufw deny from <IP>` 手动封禁指定IP
- `sudo ufw delete deny from <IP>` 手动解封指定IP  
- `sudo tail -f /var/log/ufw.log` 实时查看防火墙日志