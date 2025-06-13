#!/bin/bash

# 脚本功能：解压 .cpio.gz 或 .cpio 格式的文件系统压缩包
# 用法：script_name <压缩包文件路径>

# 检查是否传入了参数
if [ "$#" -ne 1 ]; then
  echo "用法: $0 <压缩包文件路径>"
  echo "示例: $0 ./initramfs.cpio.gz"
  echo "示例: $0 /path/to/my_filesystem.cpio"
  exit 1
fi

ARCHIVE_FILE="$1"
EXTRACT_DIR="./initramfs"

# 检查文件是否存在
if [ ! -f "$ARCHIVE_FILE" ]; then
  echo "错误：文件 '$ARCHIVE_FILE' 不存在！"
  exit 1
fi

# 移除已存在的解压目录并新建
echo "移除现有目录 '$EXTRACT_DIR'..."
rm -rf "$EXTRACT_DIR"
echo "创建解压目录 '$EXTRACT_DIR'..."
mkdir "$EXTRACT_DIR" || { echo "错误：无法创建目录 '$EXTRACT_DIR'！"; exit 1; }
cp $ARCHIVE_FILE $EXTRACT_DIR

# 进入解压目录
echo "进入目录 '$EXTRACT_DIR'..."
pushd "$EXTRACT_DIR" || { echo "错误：无法进入目录 '$EXTRACT_DIR'！"; exit 1; }

# 根据文件后缀判断是否需要解压缩
echo "解压文件 '$ARCHIVE_FILE'..."
if [[ "$ARCHIVE_FILE" == *.gz ]]; then
  # 如果是 .gz 结尾，使用 gzip 解压并通过管道传递给 cpio
  gzip -dc "$ARCHIVE_FILE" | cpio -idm
  rm -rf $ARCHIVE_FILE
  EXTRACT_STATUS=$? # 获取上一个命令的退出状态
else
  # 如果不是 .gz 结尾，直接使用 cpio 解压文件
  cpio -idm < "$ARCHIVE_FILE"
  EXTRACT_STATUS=$? # 获取上一个命令的退出状态
  rm -rf $ARCHIVE_FILE
fi

# 检查解压是否成功
if [ $EXTRACT_STATUS -ne 0 ]; then
  echo "错误：解压文件 '$ARCHIVE_FILE' 失败！退出状态：$EXTRACT_STATUS"
  popd # 退出目录栈，返回原目录
  rm -rf $EXTRACT_DIR
  exit $EXTRACT_STATUS
fi

# 返回原目录，并抑制 popd 的输出
popd > /dev/null

echo "成功将文件 '$ARCHIVE_FILE' 解压到 '$EXTRACT_DIR'。"
