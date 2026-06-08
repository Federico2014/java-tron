package org.tron.core.zksnark;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.fusesource.leveldbjni.JniDBFactory;
import org.iq80.leveldb.DB;
import org.iq80.leveldb.DBIterator;
import org.rocksdb.RocksDB;
import org.rocksdb.RocksDBException;
import org.rocksdb.RocksIterator;

/**
 * 读取系统级数据库（LevelDB 或 RocksDB），检查 TRC10 匿名合约相关的三个 Store
 * （IncrementalMerkleTree、nullifier、zkProof）是否为空并统计条目数。
 *
 * <p>自动尝试 RocksDB → 失败则回退到 LevelDB。</p>
 *
 * <h3>编译</h3>
 * <pre>{@code
 * ROCKS_JAR=$(find ~/.gradle/caches -name "rocksdbjni-*.jar" ! -name "*-sources*" | head -1)
 * LEVELDB_JAR=$(find ~/.gradle/caches -name "leveldbjni-all-*.jar" ! -name "*-sources*" | head -1)
 * LEVELDB_API_JAR=$(find ~/.gradle/caches -name "leveldb-api-*.jar" ! -name "*-sources*" | head -1)
 * CP="$ROCKS_JAR:$LEVELDB_JAR:$LEVELDB_API_JAR"
 * javac -cp "$CP" ShieldedDBReader.java
 * }</pre>
 *
 * <h3>运行</h3>
 * <pre>{@code
 * java -cp ".:$CP" org.tron.core.zksnark.ShieldedDBReader                          # 默认路径
 * java -cp ".:$CP" org.tron.core.zksnark.ShieldedDBReader /data/tron/output-directory
 * }</pre>
 */
public class ShieldedDBReader {

  private static final String DEFAULT_OUTPUT_DIR = "output-directory";
  private static final String DEFAULT_DB_SUBDIR  = "database";

  private static final String[] DB_NAMES = {
      "IncrementalMerkleTree",
      "nullifier",
      "zkProof"
  };

  public static void main(String[] args) throws Exception {
    String outputDir = args.length > 0 ? args[0] : DEFAULT_OUTPUT_DIR;
    String dbSubDir  = args.length > 1 ? args[1] : DEFAULT_DB_SUBDIR;

    System.out.println("============================================================");
    System.out.println("  TRC10 匿名合约 — 系统级数据库内容诊断");
    System.out.println("  output-directory : " + Paths.get(outputDir).toAbsolutePath());
    System.out.println("  db.directory     : " + dbSubDir);
    System.out.println("============================================================\n");

    List<DbStats> statsList = new ArrayList<>();

    for (String dbName : DB_NAMES) {
      System.out.printf("[%s]%n", dbName);

      // 尝试多种路径组合（不同 node / 版本可能不同）：
      //   LevelDB 常见: outputDir/dbSubDir/dbName/
      //   RocksDB 常见:  outputDir/dbName/dbSubDir/dbName/
      //   LevelDB 简写:  outputDir/dbName/
      String[] paths = {
          Paths.get(outputDir, dbSubDir, dbName).toString(),              // LevelDB
          Paths.get(outputDir, dbName, dbSubDir, dbName).toString(),       // RocksDB
          Paths.get(outputDir, dbName).toString()                          // 简写 LevelDB
      };

      DbStats stats = new DbStats(dbName);

      boolean opened = false;
      for (String path : paths) {
        System.out.printf("  尝试: %s%n", path);
        if (tryReadRocksDB(path, stats) || tryReadLevelDB(path, stats)) {
          opened = true;
          break;
        }
      }
      if (!opened) {
        stats.errorMsg = "以上路径均无法打开";
      }
      statsList.add(stats);
      System.out.printf("  → %s%n%n", stats);
    }

    // -------- 汇总 --------
    System.out.println("============================================================");
    System.out.println("  汇总");
    System.out.println("============================================================");
    long total = 0;
    for (DbStats s : statsList) {
      System.out.printf("  %-28s  %d 条  [%s]%n", s.dbName, s.keyCount,
          s.engine != null ? s.engine : "未打开");
      total += s.keyCount;
    }

    System.out.println();
    if (total == 0) {
      System.out.println("  ► 结论: 三个数据库全部为空 —— TRC10 原生匿名交易从未执行。");
    } else {
      System.out.printf("  ► 总计 %d 条记录。%n", total);
    }
    System.out.println("============================================================");
  }

  // ======================== RocksDB ========================

  private static boolean tryReadRocksDB(String dbPath, DbStats stats) {
    Path p = Paths.get(dbPath);
    if (!Files.isDirectory(p)) {
      return false;
    }
    try {
      RocksDB.loadLibrary();
    } catch (Exception e) {
      return false; // 无法加载 native 库
    }
    try (org.rocksdb.Options opt = new org.rocksdb.Options().setCreateIfMissing(false);
         RocksDB db = RocksDB.openReadOnly(opt, dbPath)) {
      stats.engine = "RocksDB";
      try (RocksIterator it = db.newIterator()) {
        it.seekToFirst();
        while (it.isValid()) {
          stats.keyCount++;
          if (stats.keyCount <= 3) {
            stats.sampleKeys.add(hex(it.key()));
            stats.sampleValLen = it.value().length;
          }
          it.next();
        }
      }
      return true;
    } catch (RocksDBException e) {
      return false;
    }
  }

  // ======================== LevelDB ========================

  private static boolean tryReadLevelDB(String dbPath, DbStats stats) {
    File dir = new File(dbPath);
    if (!dir.isDirectory()) {
      return false;
    }
    org.iq80.leveldb.Options opts = new org.iq80.leveldb.Options();
    opts.createIfMissing(false);
    try (DB db = JniDBFactory.factory.open(dir, opts)) {
      stats.engine = "LevelDB";
      try (DBIterator it = db.iterator()) {
        for (it.seekToFirst(); it.hasNext(); ) {
          Map.Entry<byte[], byte[]> entry = it.next();
          stats.keyCount++;
          if (stats.keyCount <= 3) {
            stats.sampleKeys.add(hex(entry.getKey()));
            stats.sampleValLen = entry.getValue().length;
          }
        }
      }
      return true;
    } catch (IOException e) {
      return false;
    }
  }

  // ======================== helper ========================

  private static String hex(byte[] b) {
    if (b == null) return "null";
    StringBuilder sb = new StringBuilder(b.length * 2);
    for (byte v : b) {
      sb.append(String.format("%02x", v & 0xff));
    }
    String s = sb.toString();
    return s.length() > 80 ? s.substring(0, 80) + "..." : s;
  }

  static class DbStats {
    final String dbName;
    int keyCount;
    int sampleValLen;
    String errorMsg;
    String engine;
    final List<String> sampleKeys = new ArrayList<>();

    DbStats(String n) { this.dbName = n; }

    @Override
    public String toString() {
      if (errorMsg != null) {
        return "错误: " + errorMsg;
      }
      if (engine == null) {
        return "未打开";
      }
      if (keyCount == 0) {
        return engine + " — 数据库为空（0 条记录）";
      }
      StringBuilder sb = new StringBuilder();
      sb.append(String.format("%s — 共 %d 条记录", engine, keyCount));
      if (sampleValLen > 0) {
        sb.append(String.format(", value 长度 ≈ %d bytes", sampleValLen));
      }
      if (!sampleKeys.isEmpty()) {
        sb.append(", 样例 key: ").append(sampleKeys);
      }
      return sb.toString();
    }
  }
}
