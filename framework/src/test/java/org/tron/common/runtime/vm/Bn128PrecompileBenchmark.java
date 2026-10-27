package org.tron.common.runtime.vm;

import com.sun.management.ThreadMXBean;
import java.io.File;
import java.lang.management.ManagementFactory;
import java.net.URL;
import java.net.URLClassLoader;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Locale;
import java.util.function.Function;
import java.util.regex.Pattern;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.tron.common.utils.ByteArray;
import org.tron.core.vm.PrecompiledContracts;
import org.tron.core.vm.PrecompiledContracts.PrecompiledContract;

/**
 * Opt-in, single-threaded benchmarks of the actual BN128 execute() entry points.
 * Run through .github/scripts/benchmark_bn128.py in fresh JVMs without a coverage agent.
 * Inputs are generated before timing and rotated on every invocation.
 */
@Slf4j
public class Bn128PrecompileBenchmark {

  private static volatile int sink;

  @Before
  public void requireExplicitOptIn() {
    Assume.assumeTrue("set -DrunPrecompileBenchmark=true to run manual benchmarks",
        Boolean.getBoolean("runPrecompileBenchmark"));
  }

  @Test
  public void benchmark() throws Exception {
    int rounds = Integer.getInteger("bn128BenchmarkRounds", 7);
    Assert.assertTrue("at least three measurement rounds are required", rounds >= 3);
    String baselineClasspath = System.getProperty("bn128BaselineClasspath");
    Assert.assertNotNull("run through .github/scripts/benchmark_bn128.py", baselineClasspath);
    benchmarkPaired(baselineClasspath, rounds);
  }

  /** Provides a bootstrap-JDK interface across the isolated runtime class loaders. */
  public static Function<byte[], byte[]> executor(String name) {
    PrecompiledContract contract;
    if ("addition".equals(name)) {
      contract = new PrecompiledContracts.BN128Addition();
    } else if ("multiplication".equals(name)) {
      contract = new PrecompiledContracts.BN128Multiplication();
    } else {
      contract = Bn128PrecompileTest.pairing();
    }
    return input -> {
      Pair<Boolean, byte[]> result = contract.execute(input);
      if (!result.getLeft()) {
        throw new AssertionError("benchmark input was rejected");
      }
      return result.getRight();
    };
  }

  private static void benchmarkPaired(String baselineClasspath, int rounds) throws Exception {
    ClassLoader parent = ClassLoader.getSystemClassLoader().getParent();
    try (URLClassLoader baseline = new URLClassLoader(urls(baselineClasspath), parent);
        URLClassLoader optimized = new URLClassLoader(
            urls(System.getProperty("java.class.path")), parent)) {
      String fp2 = "org.tron.common.crypto.zksnark.Fp2";
      logger.info("BN128_ENV,baseline={},optimized={}",
          Class.forName(fp2, true, baseline).getProtectionDomain().getCodeSource().getLocation(),
          Class.forName(fp2, true, optimized).getProtectionDomain().getCodeSource().getLocation());
      measurePaired("addition", baseline, optimized,
          Bn128PrecompileTest.additionInputs(), 10000, 5000, rounds);
      measurePaired("multiplication", baseline, optimized,
          Bn128PrecompileTest.multiplicationInputs(), 1000, 100, rounds);
      measurePaired("pairing-1", baseline, optimized,
          Bn128PrecompileTest.pairingInputs(1), 100, 12, rounds);
      measurePaired("pairing-2", baseline, optimized,
          Bn128PrecompileTest.pairingInputs(2), 60, 8, rounds);
      measurePaired("pairing-4", baseline, optimized,
          Bn128PrecompileTest.pairingInputs(4), 40, 5, rounds);
    }
  }

  private static URL[] urls(String classpath) throws Exception {
    String[] paths = classpath.split(Pattern.quote(File.pathSeparator));
    URL[] result = new URL[paths.length];
    for (int i = 0; i < paths.length; i++) {
      result[i] = new File(paths[i]).toURI().toURL();
    }
    return result;
  }

  @SuppressWarnings("unchecked")
  private static Function<byte[], byte[]> isolatedExecutor(ClassLoader loader, String name)
      throws Exception {
    return (Function<byte[], byte[]>) Class.forName(Bn128PrecompileBenchmark.class.getName(),
        true, loader).getMethod("executor", String.class).invoke(null, name);
  }

  private static void measurePaired(String name, ClassLoader baseline, ClassLoader optimized,
      byte[][] inputs, int warmup, int iterations, int rounds) throws Exception {
    Function<byte[], byte[]> before = isolatedExecutor(baseline, name);
    Function<byte[], byte[]> after = isolatedExecutor(optimized, name);
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    for (byte[] input : inputs) {
      byte[] expected = before.apply(input);
      Assert.assertArrayEquals(expected, after.apply(input));
      digest.update(input);
      digest.update(expected);
    }
    String hash = ByteArray.toHexString(digest.digest());
    logger.info("BN128_CORPUS,baseline,{},{}", name, hash);
    logger.info("BN128_CORPUS,optimized,{},{}", name, hash);
    for (int i = 0; i < warmup; i += 10) {
      run(before, inputs, 10, i);
      run(after, inputs, 10, i);
    }
    ThreadMXBean allocation = allocationBean();
    long[][] timings = new long[2][rounds];
    long[][] allocations = new long[2][rounds];
    for (int round = 0; round < rounds; round++) {
      for (int turn = 0; turn < 2; turn++) {
        int variant = (round + turn + Integer.getInteger("bn128BenchmarkFork", 0)) % 2;
        long threadId = Thread.currentThread().getId();
        long allocatedBefore = allocation == null ? 0
            : allocation.getThreadAllocatedBytes(threadId);
        long start = System.nanoTime();
        run(variant == 0 ? before : after, inputs, iterations, round);
        timings[variant][round] = System.nanoTime() - start;
        allocations[variant][round] = allocation == null ? -1
            : allocation.getThreadAllocatedBytes(threadId) - allocatedBefore;
        logger.info(String.format(Locale.ROOT, "BN128_ROUND,%s,%s,%d,%d,%.3f,%.3f",
            variant == 0 ? "baseline" : "optimized", name, round, iterations,
            timings[variant][round] / (double) iterations,
            allocation == null ? -1 : allocations[variant][round] / (double) iterations));
      }
    }
    for (int variant = 0; variant < 2; variant++) {
      Arrays.sort(timings[variant]);
      Arrays.sort(allocations[variant]);
      logger.info(String.format(Locale.ROOT, "BN128_MEDIAN,%s,%s,%.3f,%.3f",
          variant == 0 ? "baseline" : "optimized", name,
          timings[variant][rounds / 2] / (double) iterations,
          allocation == null ? -1 : allocations[variant][rounds / 2] / (double) iterations));
    }
  }

  private static void run(Function<byte[], byte[]> executor, byte[][] inputs, int iterations,
      int offset) {
    int checksum = 0;
    for (int i = 0; i < iterations; i++) {
      byte[] result = executor.apply(inputs[(i + offset) % inputs.length]);
      checksum = 31 * checksum + Arrays.hashCode(result);
    }
    sink = checksum;
  }

  private static ThreadMXBean allocationBean() {
    java.lang.management.ThreadMXBean bean = ManagementFactory.getThreadMXBean();
    if (!(bean instanceof ThreadMXBean)) {
      return null;
    }
    ThreadMXBean allocation = (ThreadMXBean) bean;
    if (!allocation.isThreadAllocatedMemorySupported()) {
      return null;
    }
    if (!allocation.isThreadAllocatedMemoryEnabled()) {
      allocation.setThreadAllocatedMemoryEnabled(true);
    }
    return allocation;
  }
}
