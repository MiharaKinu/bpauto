#!/bin/bash
set -e

echo "开始编译..."
if [ -d ".venv" ]; then
    source .venv/bin/activate
fi

pyinstaller --onefile -n bpauto main.py || { echo "编译失败"; exit 1; }

echo "复制配置文件..."
cp config.yaml.template dist/config.yaml || { echo "复制失败"; exit 1; }

echo -e "\033[32m[✓] 编译完成\033[0m"
echo "输出目录: $(pwd)/dist/bpauto"