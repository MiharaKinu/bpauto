# Bpauto 自动封禁IP工具

基于日志分析自动封禁恶意IP的UFW防火墙管理工具

## 功能特性
- 实时分析Nginx访问日志
- 支持自定义URL匹配模式
- 自动持久化封禁记录到SQLite
- 提供封禁列表查看功能
- 支持手动解封操作
- 支持一键清除所有封禁记录
- 支持查询指定IP的详细封禁信息
- 支持重新执行数据库中的封禁操作
- 支持实时监控日志文件变动
- 提供UFW防火墙状态查看功能

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

## 自动监控说明

执行下列命令，守护进程，将自动监控nginx日志文件变动，并自动执行bpauto的封禁功能

```bash
python main.py watch
```


## 命令参考
- `python main.py show` 查看当前封禁列表
- `python main.py clear` 清除所有封禁记录
- `python main.py unban <IP>` 解封指定IP
- `python main.py get <IP>` 获取指定IP的详细封禁信息
- `python main.py redo` 重新执行数据库中的封禁
- `python main.py watch` 启动自动监控日志文件变动

## UFW调试命令
- `sudo ufw status` 查看当前UFW防火墙状态
- `sudo ufw deny from <IP>` 手动封禁指定IP
- `sudo ufw delete deny from <IP>` 手动解封指定IP  
- `sudo tail -f /var/log/ufw.log` 实时查看防火墙日志