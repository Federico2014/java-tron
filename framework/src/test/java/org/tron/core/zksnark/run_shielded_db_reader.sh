#!/bin/bash
# ============================================================================
# 直接读取 TRC10 匿名合约相关的三个系统级数据库（LevelDB 或 RocksDB）：
#   IncrementalMerkleTree / nullifier / zkProof
#
# 自动检测引擎：先尝试 RocksDB，失败则回退到 LevelDB。
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# 找 JAR（leveldbjni-all 已包含 org.iq80.leveldb API）
ROCKS_JAR=$(find ~/.gradle/caches -name "rocksdbjni-*.jar" ! -name "*-sources*" 2>/dev/null | head -1 || true)
LEVELDB_ALL=$(find ~/.gradle/caches -name "leveldbjni-all-*.jar" ! -name "*-sources*" 2>/dev/null | head -1 || true)

if [ -z "$ROCKS_JAR" ] && [ -z "$LEVELDB_ALL" ]; then
  echo "ERROR: 找不到 rocksdbjni 和 leveldbjni jar，请先执行 ./gradlew build"
  exit 1
fi

# 组装 classpath: LevelDB API 已包含在 leveldbjni-all 中
CP="$ROCKS_JAR:$LEVELDB_ALL"
# 去掉首尾多余的冒号
CP="${CP#:}"
CP="${CP%:}"

CLASS_NAME="org.tron.core.zksnark.ShieldedDBReader"
JAVA_FILE="ShieldedDBReader.java"

echo "RocksDB : ${ROCKS_JAR:-未找到}"
echo "LevelDB : ${LEVELDB_ALL:-未找到}"
echo ""

# 编译（-d . 确保 .class 按包路径生成在正确子目录下）
echo "编译..."
javac -cp "$CP" -d . "$JAVA_FILE"
echo "  编译完成"

# 运行
echo ""
java -cp ".:$CP" $CLASS_NAME "${@}"
