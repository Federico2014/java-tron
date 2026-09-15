package org.tron.common.crypto;

import static org.junit.Assert.assertArrayEquals;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import lombok.extern.slf4j.Slf4j;
import org.junit.Assume;
import org.junit.Test;
import org.tron.common.crypto.ECKey.ECDSASignature;

/**
 * Manual microbenchmark for secp256k1 signing and signature address recovery.
 *
 * <p>Enable with {@code NATIVE_SECP256K1_BENCHMARK=true}. Optional environment variables
 * {@code NATIVE_SECP256K1_BENCHMARK_WARMUP} and {@code
 * NATIVE_SECP256K1_BENCHMARK_ITERATIONS} control the sample size. This is intended for quick
 * local comparisons; use JMH when statistically rigorous results are required.
 */
@Slf4j(topic = "benchmark")
public class NativeSecp256k1BenchmarkTest {

  private static final String ENABLE_ENV = "NATIVE_SECP256K1_BENCHMARK";
  private static final String WARMUP_ENV = "NATIVE_SECP256K1_BENCHMARK_WARMUP";
  private static final String ITERATIONS_ENV = "NATIVE_SECP256K1_BENCHMARK_ITERATIONS";
  private static final int DEFAULT_WARMUP = 2_000;
  private static final int DEFAULT_ITERATIONS = 10_000;
  private static final int MAX_ITERATIONS = 1_000_000;
  private static volatile int blackhole;

  @Test
  public void benchmarkSigningAndSignatureRecovery() throws Exception {
    Assume.assumeTrue("Set " + ENABLE_ENV + "=true to run this benchmark",
        Boolean.parseBoolean(System.getenv(ENABLE_ENV)));
    Assume.assumeTrue("Native secp256k1 library is unavailable",
        NativeSecp256k1.isAvailable());

    int warmup = readPositiveInt(WARMUP_ENV, DEFAULT_WARMUP);
    int iterations = readPositiveInt(ITERATIONS_ENV, DEFAULT_ITERATIONS);
    ECKey key = ECKey.fromPrivate(BigInteger.TEN);
    byte[] privateKey = key.getPrivateKey();
    byte[] messageHash = Hash.sha3(
        "native secp256k1 benchmark".getBytes(StandardCharsets.UTF_8));

    ECDSASignature javaSignature = key.sign(messageHash);
    ECDSASignature nativeSignature = NativeSecp256k1.sign(messageHash, privateKey);
    assertArrayEquals(javaSignature.toByteArray(), nativeSignature.toByteArray());
    assertArrayEquals(
        ECKey.signatureToAddress(messageHash, nativeSignature),
        NativeSecp256k1.signatureToAddress(messageHash, javaSignature));

    warmUp(warmup, () -> key.sign(messageHash));
    warmUp(warmup, () -> NativeSecp256k1.sign(messageHash, privateKey));
    long javaSignNs = measure(iterations, () -> key.sign(messageHash));
    long nativeSignNs = measure(
        iterations, () -> NativeSecp256k1.sign(messageHash, privateKey));
    report("sign", iterations, javaSignNs, nativeSignNs);

    warmUp(warmup, () -> ECKey.signatureToAddress(messageHash, javaSignature));
    warmUp(warmup,
        () -> NativeSecp256k1.signatureToAddress(messageHash, javaSignature));
    long javaRecoveryNs = measure(
        iterations, () -> ECKey.signatureToAddress(messageHash, javaSignature));
    long nativeRecoveryNs = measure(
        iterations, () -> NativeSecp256k1.signatureToAddress(messageHash, javaSignature));
    report("signature-address-recovery", iterations, javaRecoveryNs, nativeRecoveryNs);
  }

  private static int readPositiveInt(String environmentVariable, int defaultValue) {
    String configured = System.getenv(environmentVariable);
    if (configured == null || configured.trim().isEmpty()) {
      return defaultValue;
    }
    int value;
    try {
      value = Integer.parseInt(configured);
    } catch (NumberFormatException e) {
      throw new IllegalArgumentException(environmentVariable + " must be an integer", e);
    }
    if (value <= 0 || value > MAX_ITERATIONS) {
      throw new IllegalArgumentException(environmentVariable + " must be between 1 and "
          + MAX_ITERATIONS);
    }
    return value;
  }

  private static void warmUp(int iterations, Operation operation) throws Exception {
    for (int i = 0; i < iterations; i++) {
      consume(operation.run());
    }
  }

  private static long measure(int iterations, Operation operation) throws Exception {
    long startedAt = System.nanoTime();
    for (int i = 0; i < iterations; i++) {
      consume(operation.run());
    }
    return (System.nanoTime() - startedAt) / iterations;
  }

  private static void consume(Object value) {
    if (value instanceof byte[]) {
      byte[] bytes = (byte[]) value;
      blackhole ^= bytes.length == 0 ? 0 : bytes[0];
    } else if (value instanceof ECDSASignature) {
      ECDSASignature signature = (ECDSASignature) value;
      blackhole ^= signature.r.intValue() ^ signature.s.intValue() ^ signature.v;
    } else {
      blackhole ^= value.hashCode();
    }
  }

  private static void report(
      String operation, int iterations, long javaNsPerOperation, long nativeNsPerOperation) {
    long effectiveNative = nativeNsPerOperation == 0 ? 1 : nativeNsPerOperation;
    double speedup = (double) javaNsPerOperation / effectiveNative;
    logger.info(
        "secp256k1 benchmark: operation={}, iterations={}, ECKey={} ns/op, "
            + "NativeSecp256k1={} ns/op, speedup={}x",
        operation,
        iterations,
        javaNsPerOperation,
        nativeNsPerOperation,
        String.format(Locale.ROOT, "%.2f", speedup));
  }

  @FunctionalInterface
  private interface Operation {

    Object run() throws Exception;
  }
}
